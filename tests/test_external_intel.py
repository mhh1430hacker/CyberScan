"""External intelligence (core/external_intel.py): parsers, quotas, cache, verdict weighting and wiring.

Every HTTP call is replaced by a fake; a guard makes any real network request fail the test."""
from __future__ import annotations

import base64
import json
import time
import urllib.request

import pytest

from core import external_intel as ei
from core import hash_intel
from test_web_api import FakeDetectionService, _request  # imported before any patching: its urlopen is the real one

DAY = 86400
SHA = "ab" * 32


def vt_body(malicious=0, suspicious=0, harmless=0, undetected=70, label="", family="", first=None, detections=None):
    results = {f"Engine{i}": {"category": "malicious", "result": f"Trojan.Gen{i}"} for i in range(malicious)}
    attributes = {
        "last_analysis_stats": {"malicious": malicious, "suspicious": suspicious, "harmless": harmless, "undetected": undetected, "timeout": 0},
        "last_analysis_results": detections if detections is not None else results,
        "last_analysis_date": int(time.time()) - DAY,
        "reputation": -5 if malicious else 10,
        "times_submitted": 12,
    }
    if first is not None:
        attributes["first_submission_date"] = first
    if label or family:
        attributes["popular_threat_classification"] = {"suggested_threat_label": label,
                                                       "popular_threat_name": [{"value": family, "count": 9}] if family else []}
    return {"data": {"attributes": attributes}}


class FakeHttp:
    """Records requests and answers from a list of (predicate, (status, body))."""

    def __init__(self, routes=None, default=(404, None)):
        self.routes = list(routes or [])
        self.default = default
        self.calls: list[dict] = []

    def __call__(self, method, url, *, data=None, headers=None, timeout=None):
        self.calls.append({"method": method, "url": url, "data": data, "headers": headers or {}})
        for match, answer in self.routes:
            if match in url:
                if callable(answer):
                    return answer()
                return answer
        return self.default


@pytest.fixture(autouse=True)
def isolated(monkeypatch):
    real_urlopen = urllib.request.urlopen

    def no_network(request, *args, **kwargs):
        url = request.full_url if isinstance(request, urllib.request.Request) else str(request)
        if url.startswith("http://127.0.0.1:"):          # the test's own local server
            return real_urlopen(request, *args, **kwargs)
        raise AssertionError(f"a test tried to reach the network: {url}")

    monkeypatch.setattr(urllib.request, "urlopen", no_network)
    monkeypatch.setattr(ei, "_http", FakeHttp(default=(599, None)))   # replaced per test where answers matter
    for variable in ("VT_API_KEY", "ABUSECH_AUTH_KEY", "URLHAUS_API_KEY", "OTX_API_KEY", "GOOGLE_SAFE_BROWSING_KEY", "URLSCAN_API_KEY",
                     "AWS_LAMBDA_FUNCTION_NAME"):
        monkeypatch.delenv(variable, raising=False)
    ei.CACHE.clear()
    monkeypatch.setattr(ei.S3, "enabled", False)
    monkeypatch.setattr(ei, "BUCKETS", {name: ei.TokenBucket(1000, 100000) for name in ei.BUCKETS})
    monkeypatch.setattr(ei, "CLIENTS", ei.ClientLimiter())
    yield
    ei.CACHE.clear()


def keys(monkeypatch, **values):
    for name, value in values.items():
        monkeypatch.setenv(name, value)


# ---------------------------------------------------------------- VirusTotal parser and requests
def test_virustotal_parser_thresholds():
    strong = ei.parse_virustotal(vt_body(54, 2, 0, 16, label="trojan.agent/generic", family="agent"))
    assert strong["status"] == "match" and strong["malicious"] == 54 and strong["engines_total"] == 72
    assert strong["label"] == "trojan.agent/generic" and strong["family"] == "agent"
    assert len(strong["detections"]) == 6 and strong["detections"][0].startswith("Engine")
    assert ei.parse_virustotal(vt_body(6))["status"] == "several"            # 5+ without a family name
    assert ei.parse_virustotal(vt_body(6, family="emotet"))["status"] == "match"
    assert ei.parse_virustotal(vt_body(10))["status"] == "match"
    assert ei.parse_virustotal(vt_body(3))["status"] == "several"
    assert ei.parse_virustotal(vt_body(2))["status"] == "few"
    assert ei.parse_virustotal(vt_body(0, suspicious=1))["status"] == "few"
    clean = ei.parse_virustotal(vt_body(0, harmless=0, undetected=72, first=int(time.time()) - 400 * DAY))
    assert clean["status"] == "clean_report" and clean["engines_total"] == 72 and clean["first_seen"]


def test_vt_file_url_and_host_requests(monkeypatch):
    keys(monkeypatch, VT_API_KEY="fake-vt")
    fake = FakeHttp([("/files/", (200, vt_body(54, label="trojan.agent"))), ("/urls/", (200, vt_body(1))),
                     ("/domains/", (200, vt_body(0))), ("/ip_addresses/", (404, None))])
    monkeypatch.setattr(ei, "_http", fake)
    assert ei.vt_file(SHA.upper())["status"] == "match"
    assert fake.calls[0]["url"].endswith(f"/files/{SHA}") and fake.calls[0]["headers"]["x-apikey"] == "fake-vt"
    url = "https://example.com/a?b=1"
    assert ei.vt_url(url)["status"] == "few"
    url_id = fake.calls[1]["url"].rsplit("/", 1)[1]
    assert "=" not in url_id and base64.urlsafe_b64decode(url_id + "=" * (-len(url_id) % 4)).decode() == url
    assert ei.vt_host("example.com")["status"] == "clean_report"
    assert fake.calls[2]["url"].endswith("/domains/example.com")
    assert ei.vt_host("8.8.8.8")["status"] == "not_found"
    assert fake.calls[3]["url"].endswith("/ip_addresses/8.8.8.8")
    assert all(call["method"] == "GET" and call["data"] is None for call in fake.calls)   # lookups only, nothing uploaded


def test_not_configured_means_no_request(monkeypatch):
    fake = FakeHttp()
    monkeypatch.setattr(ei, "_http", fake)
    assert ei.vt_file(SHA) == {"status": "no_key"}
    assert ei.safebrowsing("https://example.com/") == {"status": "no_key"}
    assert ei.urlscan("example.com") == {"status": "no_key"}
    assert fake.calls == []
    assert ei.configured()["circl"] is True and ei.configured()["virustotal"] is False


def test_errors_and_quota_status(monkeypatch):
    keys(monkeypatch, VT_API_KEY="fake")
    monkeypatch.setattr(ei, "_http", FakeHttp([("/files/", (401, None))]))
    assert ei.vt_file(SHA)["status"] == "error"
    ei.CACHE.clear()
    monkeypatch.setattr(ei, "_http", FakeHttp([("/files/", (429, None))]))
    assert ei.vt_file(SHA)["status"] == "quota"
    assert ei.BUCKETS["virustotal"].acquire() is False          # the service said "too many": stop asking

    def boom():
        raise TimeoutError("timed out")
    ei.BUCKETS["virustotal"] = ei.TokenBucket(4, 500)
    monkeypatch.setattr(ei, "_http", FakeHttp([("/files/", boom)]))
    assert ei.vt_file("cd" * 32)["status"] == "timeout"


# ---------------------------------------------------------------- the other parsers
def test_circl_and_bazaar(monkeypatch):
    keys(monkeypatch, ABUSECH_AUTH_KEY="fake-abuse")
    fake = FakeHttp([("hashlookup.circl.lu", (200, {"FileName": "notepad.exe", "ProductCode": {"ProductName": "Windows"}, "source": "NSRL"})),
                     ("mb-api.abuse.ch", (200, {"query_status": "ok", "data": [{"signature": "AgentTesla", "tags": ["exe"], "first_seen": "2024-01-02"}]}))])
    monkeypatch.setattr(ei, "_http", fake)
    assert ei.circl(SHA)["status"] == "known_good"
    bazaar = ei.malwarebazaar(SHA)
    assert bazaar["status"] == "match" and bazaar["signature"] == "AgentTesla"
    post = fake.calls[1]
    assert post["method"] == "POST" and b"get_info" in post["data"] and post["headers"]["Auth-Key"] == "fake-abuse"
    assert ei.parse_circl(200, {"KnownMalicious": "feed"})["status"] == "match"
    assert ei.parse_circl(404, None)["status"] == "not_found"
    assert ei.parse_bazaar(200, {"query_status": "hash_not_found"})["status"] == "not_found"


def test_urlhaus_url_then_host(monkeypatch):
    keys(monkeypatch, ABUSECH_AUTH_KEY="fake")
    fake = FakeHttp([("/v1/url/", (200, {"query_status": "no_results"})),
                     ("/v1/host/", (200, {"query_status": "ok", "url_count": 3, "urls": [{"url_status": "online"}],
                                          "urlhaus_reference": "https://urlhaus.abuse.ch/host/bad.example/"}))])
    monkeypatch.setattr(ei, "_http", fake)
    answer = ei.urlhaus("https://bad.example/x", "bad.example")
    assert answer["status"] == "few" and answer["urls_count"] == 3 and len(fake.calls) == 2
    exact = ei.parse_urlhaus(200, {"query_status": "ok", "threat": "malware_download", "url_status": "online", "tags": ["exe"]}, host=False)
    assert exact["status"] == "match" and exact["threat"] == "malware_download"


def test_otx_safebrowsing_urlscan(monkeypatch):
    keys(monkeypatch, OTX_API_KEY="o", GOOGLE_SAFE_BROWSING_KEY="g k", URLSCAN_API_KEY="u")
    fake = FakeHttp([
        ("otx.alienvault.com", (200, {"pulse_info": {"count": 2, "pulses": [{"name": "Phishing kit"}]}, "validation": []})),
        ("safebrowsing.googleapis.com", (200, {"matches": [{"threatType": "SOCIAL_ENGINEERING"}]})),
        ("urlscan.io", (200, {"total": 4, "results": [{"_id": "0d3a1a5e-2222-4c4c-8888-123456789abc", "task": {"time": "2026-11-01T00:00:00Z"},
                                                       "verdicts": {"overall": {"malicious": True}}}]})),
    ])
    monkeypatch.setattr(ei, "_http", fake)
    assert ei.otx("bad.example")["status"] == "few"
    assert "/indicators/hostname/bad.example/general" in fake.calls[0]["url"]
    sb = ei.safebrowsing("https://bad.example/login")
    assert sb["status"] == "match" and sb["threats"] == ["SOCIAL_ENGINEERING"]
    request = fake.calls[1]
    assert request["url"].endswith("key=g%20k")
    assert json.loads(request["data"])["threatInfo"]["threatEntries"] == [{"url": "https://bad.example/login"}]
    us = ei.urlscan("bad.example")
    assert us["status"] == "few" and us["flagged"] == 1
    assert "/api/v1/search/" in fake.calls[2]["url"] and fake.calls[2]["method"] == "GET"   # search only, never submit
    assert ei.parse_safebrowsing(200, {})["status"] == "not_found"
    assert ei.parse_urlscan(200, {"results": []})["status"] == "not_found"
    assert ei.parse_urlscan(200, {"total": 1, "results": [{"_id": "x", "task": {}}]})["status"] == "seen"
    assert ei.parse_otx(200, {"pulse_info": {"count": 0}})["status"] == "not_found"
    assert ei.parse_otx(200, {"pulse_info": {"count": 3}, "validation": [{"name": "Majestic top"}]})["status"] == "clean_report"


# ---------------------------------------------------------------- rate limiting and cache
def test_token_bucket_minute_and_day():
    now = [1_000_000.0]
    bucket = ei.TokenBucket(4, 6, clock=lambda: now[0])
    assert [bucket.acquire() for _ in range(5)] == [True, True, True, True, False]
    now[0] += 15                                   # one token back after 15 s (4 a minute)
    assert bucket.acquire() is True and bucket.acquire() is False
    now[0] += 60
    assert bucket.acquire() is True                # 6th of the day
    now[0] += 60
    assert bucket.acquire() is False               # daily limit
    assert bucket.state()["used_today"] == 6
    now[0] += DAY
    assert bucket.acquire() is True                # a new day


def test_client_limiter():
    now = [0.0]
    limiter = ei.ClientLimiter(per_minute=2, per_hour=3, clock=lambda: now[0])
    assert [limiter.allow("1.2.3.4") for _ in range(3)] == [True, True, False]
    assert limiter.allow("5.6.7.8") is True
    now[0] += 61
    assert limiter.allow("1.2.3.4") is True
    now[0] += 61
    assert limiter.allow("1.2.3.4") is False       # 3 an hour
    now[0] += 3600
    assert limiter.allow("1.2.3.4") is True


def test_ttl_cache_expiry_and_lru():
    now = [0.0]
    cache = ei.TTLCache(ttl=10, max_entries=2, clock=lambda: now[0])
    cache.set("a", {"status": "x"})
    cache.set("b", {"status": "y"})
    assert cache.get("a") == {"status": "x"}       # "a" is now the most recent
    cache.set("c", {"status": "z"})                # evicts "b"
    assert cache.get("b") is None and cache.get("c") == {"status": "z"}
    now[0] += 11
    assert cache.get("a") is None


def test_answers_are_cached_including_not_found(monkeypatch):
    keys(monkeypatch, VT_API_KEY="fake")
    fake = FakeHttp([("/files/", (404, None))])
    monkeypatch.setattr(ei, "_http", fake)
    assert ei.vt_file(SHA)["status"] == "not_found"
    again = ei.vt_file(SHA)
    assert again["status"] == "not_found" and again["cached"] is True and len(fake.calls) == 1
    # errors are not cached
    fake.routes = [("/files/", (500, None))]
    assert ei.vt_file("ef" * 32)["status"] == "error"
    assert ei.vt_file("ef" * 32)["status"] == "error" and len(fake.calls) == 3


def test_quota_spent_returns_quota_without_request(monkeypatch):
    keys(monkeypatch, VT_API_KEY="fake")
    ei.BUCKETS["virustotal"] = ei.TokenBucket(4, 500)
    fake = FakeHttp([("/files/", (404, None))])
    monkeypatch.setattr(ei, "_http", fake)
    answers = [ei.vt_file(f"{i:064x}")["status"] for i in range(5)]
    assert answers == ["not_found"] * 4 + ["quota"] and len(fake.calls) == 4


def test_cached_values_never_hold_the_link(monkeypatch):
    keys(monkeypatch, VT_API_KEY="fake")
    monkeypatch.setattr(ei, "_http", FakeHttp([("/urls/", (200, vt_body(0)))]))
    ei.vt_url("https://secret.example/reset?token=abc")
    stored = json.dumps([value for _, value in ei.CACHE.data.values()])
    keys_text = " ".join(ei.CACHE.data)
    assert "secret.example" not in stored and "token" not in stored and "secret.example" not in keys_text


# ---------------------------------------------------------------- running together
def test_lookup_link_private_hosts_are_not_sent(monkeypatch):
    fake = FakeHttp()
    monkeypatch.setattr(ei, "_http", fake)
    for url in ("http://192.168.1.1/admin", "http://localhost:8080/", "http://printer.local/", "ftp://example.com/", "http://intranet/"):
        answers = ei.lookup_link(url)
        assert set(answers) == set(ei.LINK_SOURCES) and {a["status"] for a in answers.values()} == {"not_applicable"}
    assert fake.calls == []


def test_lookup_link_all_services(monkeypatch):
    keys(monkeypatch, VT_API_KEY="v", ABUSECH_AUTH_KEY="a", OTX_API_KEY="o", GOOGLE_SAFE_BROWSING_KEY="g", URLSCAN_API_KEY="u")
    fake = FakeHttp([("/urls/", (200, vt_body(7))), ("/domains/", (200, vt_body(0))), ("safebrowsing", (200, {})),
                     ("/v1/url/", (200, {"query_status": "no_results"})), ("/v1/host/", (200, {"query_status": "no_results"})),
                     ("otx", (200, {"pulse_info": {"count": 0}})), ("urlscan", (200, {"results": []}))])
    monkeypatch.setattr(ei, "_http", fake)
    answers = ei.lookup_link("https://shop.example.com/pay")
    assert answers["VirusTotal (link)"]["status"] == "several"
    assert answers["VirusTotal (site)"]["status"] == "clean_report"
    assert {answers[n]["status"] for n in ("Google Safe Browsing", "URLhaus", "AlienVault OTX", "urlscan.io")} == {"not_found"}


def test_budget_bounds_a_slow_service(monkeypatch):
    def slow():
        time.sleep(1.5)
        return (200, {})
    monkeypatch.setattr(ei, "_http", FakeHttp([("hashlookup", slow)]))
    started = time.monotonic()
    answers = ei.lookup_file(SHA, budget=0.3)
    assert time.monotonic() - started < 1.2
    assert answers["CIRCL hashlookup"]["status"] == "timeout"
    assert answers["VirusTotal"]["status"] == "no_key" and answers["MalwareBazaar"]["status"] == "no_key"


# ---------------------------------------------------------------- verdict weighting
def test_file_weighting_known_malware_shows_arithmetic():
    vt = ei.parse_virustotal(vt_body(54, 0, 0, 18, label="trojan.agent"))
    findings = ei.file_findings({"VirusTotal": vt})
    assert len(findings) == 1
    top = findings[0]
    assert top["severity"] == "critical" and top["contribution"] == 95 and top["label"] == "Known malware: trojan.agent"
    assert "54 of 72 engines" in top["explanation"] and "+95" in top["explanation"]


def test_file_weighting_weak_moderate_and_clean():
    few = ei.file_findings({"VirusTotal": ei.parse_virustotal(vt_body(1))})
    assert few[0]["contribution"] == 15 and "false positive" in few[0]["explanation"] and few[0]["severity"] == "medium"
    several = ei.file_findings({"VirusTotal": ei.parse_virustotal(vt_body(3))})
    assert several[0]["contribution"] == 45 and several[0]["severity"] == "high"
    assert ei.file_findings({"VirusTotal": ei.parse_virustotal(vt_body(7))})[0]["contribution"] == 60
    old = ei.parse_virustotal(vt_body(0, undetected=72, first=int(time.time()) - 900 * DAY))
    clean = ei.file_findings({"VirusTotal": old})
    assert clean[0]["label"] == "Widely seen as clean on VirusTotal" and clean[0]["contribution"] == 0
    young = ei.parse_virustotal(vt_body(0, undetected=72, first=int(time.time()) - 2 * DAY))
    assert ei.file_findings({"VirusTotal": young}) == []                 # too new to vouch for
    small = ei.parse_virustotal(vt_body(0, undetected=20, first=int(time.time()) - 900 * DAY))
    assert ei.file_findings({"VirusTotal": small}) == []                 # too few engines


def test_known_malware_from_virustotal_sets_the_classification(monkeypatch):
    from core.models import Finding, ScanResult
    from core.risk_engine import finalize_result

    monkeypatch.setattr(hash_intel, "online_lookup", lambda sha, budget=4.0: {
        "VirusTotal": ei.parse_virustotal(vt_body(30, label="ransom.lockbit")),
        "CIRCL hashlookup": {"status": "not_found"}, "MalwareBazaar": {"status": "no_key"}})
    known = hash_intel.assess(SHA, None, online=True)
    result = ScanResult(target="x", heuristic_score=0, ml_risk_score=None, combined_score=0, classification="", evidence=[])
    for item in known["findings"]:
        result.evidence.append(Finding("intel", item["severity"], item["label"], item["explanation"], item["contribution"]))
    finalize_result(result)
    assert result.classification == "KNOWN_MALWARE" and result.combined_score == 95


def test_link_weighting():
    sources = {"VirusTotal (link)": ei.parse_virustotal(vt_body(7)), "VirusTotal (site)": ei.parse_virustotal(vt_body(1)),
               "Google Safe Browsing": {"status": "match", "threats": ["MALWARE"], "detail": "listed as malware"},
               "URLhaus": {"status": "few", "detail": "the host has 3 listed malware link(s)"}, "AlienVault OTX": {"status": "few", "detail": "in 2 community pulse(s)"},
               "urlscan.io": {"status": "seen"}}
    by_source = {}
    for f in ei.link_findings(sources):
        by_source.setdefault(f["source"], []).append(f["contribution"])
    assert by_source["Google Safe Browsing"] == [80]
    assert by_source["URLhaus"] == [45]
    assert sorted(by_source["VirusTotal"]) == [10, 75]
    assert by_source["AlienVault OTX"] == [20]
    assert "urlscan.io" not in by_source
    intel = ei.link_intelligence(sources, "https://bad.example/")
    assert intel["status"] == "matched" and intel["link_sources"] is sources
    quiet = ei.link_intelligence({n: {"status": "no_key"} for n in ei.LINK_SOURCES}, "https://example.com/")
    assert quiet["status"] == "unavailable"


# ---------------------------------------------------------------- the scan pipeline and the web payload
def test_scan_service_link_scan_uses_external_findings(monkeypatch):
    from config import DEFAULT_SETTINGS
    from ui.scan_service import ScanService

    sources = {name: {"status": "not_found"} for name in ei.LINK_SOURCES}
    sources["VirusTotal (link)"] = ei.parse_virustotal(vt_body(9))
    monkeypatch.setattr(ei, "lookup_link", lambda url, budget=4.5: sources)
    result, *_rest, intelligence, _raw = ScanService().analyze("https://bad.example/x", "URL", {**DEFAULT_SETTINGS, "osint_enabled": True})
    assert intelligence["status"] == "matched"
    flagged = [f for f in result.evidence if f.category == "osint"]
    assert [f.evidence for f in flagged] == ["VirusTotal: security vendors flag this link"]
    assert flagged[0].contribution == 75 and flagged[0].engines == ["VirusTotal"]
    assert result.combined_score >= 75 and result.classification == "SUSPICIOUS"


def test_scan_service_reports_why_lookups_were_off():
    from config import DEFAULT_SETTINGS
    from ui.scan_service import ScanService

    for reason in ("off_for_scan", "rate_limited"):
        *_rest, intelligence, _raw = ScanService().analyze("https://example.com/", "URL",
                                                           {**DEFAULT_SETTINGS, "osint_enabled": False, "osint_off_reason": reason})
        assert intelligence["status"] == reason


def test_external_payload_rows_and_links(monkeypatch):
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "web_v"))
    import services  # noqa: PLC0415
    from core.models import ScanResult

    keys(monkeypatch, VT_API_KEY="fake")
    vt = ei.parse_virustotal(vt_body(54, 0, 0, 18, label="trojan.agent"))
    result = ScanResult(target="f", heuristic_score=0, ml_risk_score=None, combined_score=95, classification="KNOWN_MALWARE", evidence=[],
                        osint_summary={"status": "matched", "hash_sources": {"VirusTotal": vt, "CIRCL hashlookup": {"status": "not_found"},
                                                                             "MalwareBazaar": {"status": "no_key"}}})
    payload = services.external_payload(result, "C:/x/sample.bin", "File", SHA)
    rows = {row["name"]: row for row in payload["rows"]}
    assert payload["ran"] is True and payload["sent"] == "sha256"
    assert rows["VirusTotal"]["chip"] == "bad" and rows["VirusTotal"]["malicious"] == 54 and rows["VirusTotal"]["engines_total"] == 72
    assert rows["VirusTotal"]["link"] == f"https://www.virustotal.com/gui/file/{SHA}"
    assert rows["MalwareBazaar"]["chip"] == "not_configured"
    assert "fake" not in json.dumps(payload)                       # never a key
    off = ScanResult(target="u", heuristic_score=0, ml_risk_score=None, combined_score=0, classification="NO_INDICATORS_OBSERVED", evidence=[],
                     osint_summary={"status": "off_for_scan"})
    link = services.external_payload(off, "https://example.com/a", "URL", "")
    assert link["ran"] is False and [r["name"] for r in link["rows"]] == list(ei.LINK_SOURCES)
    by_name = {r["name"]: r for r in link["rows"]}
    assert by_name["VirusTotal (link)"]["chip"] == "off"            # configured, but switched off for this scan
    assert by_name["Google Safe Browsing"]["chip"] == "not_configured"
    assert by_name["VirusTotal (site)"]["link"] == "https://www.virustotal.com/gui/domain/example.com"


def test_web_scan_switch_and_per_visitor_limit(monkeypatch, tmp_path):
    import threading
    from http.server import ThreadingHTTPServer

    import server as web_server

    seen: list[dict] = []

    class RecordingScan:
        def analyze(self, candidate, mode, settings, progress=None):
            seen.append({"osint": settings.get("osint_enabled"), "reason": settings.get("osint_off_reason")})
            return object(), None, None, None, None, b"fixture"

    monkeypatch.setattr(web_server, "PUBLIC", True)
    monkeypatch.setattr(web_server, "ScanService", RecordingScan)
    monkeypatch.setattr(web_server.detection_service, "default_service", lambda: FakeDetectionService())
    monkeypatch.setattr(web_server, "serialize_result", lambda *a, **k: {"classification": "NO_INDICATORS_OBSERVED", "combined_score": 0, "evidence": [], "plain": {}})
    monkeypatch.setattr(ei, "CLIENTS", ei.ClientLimiter(per_minute=2, per_hour=10))
    app = web_server.App()
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), web_server.BaseHTTPRequestHandler)
    httpd.RequestHandlerClass = web_server.make_handler(app, httpd.server_address[1])
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    try:
        def scan_link(external=None):
            body = {"mode": "url", "value": "https://example.test/"}
            if external is not None:
                body["external"] = external
            status, _ = _request(app, base, "/api/scan", json.dumps(body).encode(), {"Content-Type": "application/json"})
            assert status == 200

        scan_link(False)
        status, _ = _request(app, base, "/api/scan/file", b"synthetic", {"X-Filename": "a.txt", "X-CyberScan-External": "0"})
        assert status == 200
        scan_link()          # default: on
        scan_link(True)
        scan_link(True)      # third online scan within a minute from the same address
        assert seen == [{"osint": False, "reason": "off_for_scan"}, {"osint": False, "reason": "off_for_scan"},
                        {"osint": True, "reason": ""}, {"osint": True, "reason": ""}, {"osint": False, "reason": "rate_limited"}]
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=3)
