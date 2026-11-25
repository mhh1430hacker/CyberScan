"""External threat intelligence: what outside services already know about a file's fingerprint or a link.

Only a fingerprint (SHA-256) or the link itself (and its host name) is sent, never a file's contents.
Nothing is ever submitted or uploaded for analysis: every call below is a report *lookup*.

    service                 indicator          key (environment)            endpoint
    VirusTotal              file SHA-256       VT_API_KEY                   GET /api/v3/files/{sha256}
                            link               VT_API_KEY                   GET /api/v3/urls/{base64url(url)}
                            host               VT_API_KEY                   GET /api/v3/domains/{d} or /ip_addresses/{ip}
    CIRCL hashlookup        file SHA-256       none                         GET /lookup/sha256/{sha256}
    MalwareBazaar           file SHA-256       ABUSECH_AUTH_KEY             POST query=get_info
    URLhaus                 link, then host    ABUSECH_AUTH_KEY             POST /v1/url/, /v1/host/
    AlienVault OTX          host               OTX_API_KEY                  GET /indicators/hostname/{h}/general
    Google Safe Browsing    link               GOOGLE_SAFE_BROWSING_KEY     POST /v4/threatMatches:find
    urlscan.io              host               URLSCAN_API_KEY              GET /api/v1/search/?q=domain:{d}  (search only)

Every answer has one ``status``:
    match        the service lists it as malicious (strong)
    several      several engines flag it (VirusTotal; moderate)
    few          one or two engines / a weak listing (often false positives)
    clean_report the service knows it and nothing flags it
    known_good   (CIRCL) a known, legitimate file
    seen         (urlscan) public scans exist, none marked malicious
    not_found    the service has never seen it
    no_key       not configured (no API key on this installation)
    quota        the free quota is used up for now
    error / timeout / not_applicable (e.g. a private address that no public service can know)

Free-tier protection: VirusTotal allows 4 requests a minute and 500 a day. A per-process token
bucket enforces that, and every answer (including "not found") is cached for 6 hours in memory,
and on AWS Lambda optionally in S3 (``intel-cache/`` in CYBERSCAN_STATS_BUCKET) so repeated scans of
the same thing don't spend quota. Cached values hold only the service's numbers, never the link.

The verdict weighting is in ``file_findings`` and ``link_findings``; each finding says the numbers
and the rule that turned them into a weight, so "Why this result?" can show the arithmetic.
"""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor, wait
from datetime import datetime, timezone
from typing import Any, Callable
from urllib.parse import urlsplit

UA = {"User-Agent": "CyberScan-intel/1.1"}
FILE_BUDGET_SECONDS = 4.0          # all file sources together
LINK_BUDGET_SECONDS = 4.5          # all link sources together
REQUEST_TIMEOUT_SECONDS = 3.5      # any single request
CACHE_TTL_SECONDS = 6 * 3600
CACHE_MAX_ENTRIES = 4096

# service id -> (display name, environment variable or "" when no key is needed, public site)
SERVICES: dict[str, tuple[str, str, str]] = {
    "virustotal": ("VirusTotal", "VT_API_KEY", "https://www.virustotal.com/"),
    "circl": ("CIRCL hashlookup", "", "https://hashlookup.circl.lu/"),
    "malwarebazaar": ("MalwareBazaar", "ABUSECH_AUTH_KEY", "https://bazaar.abuse.ch/"),
    "urlhaus": ("URLhaus", "ABUSECH_AUTH_KEY", "https://urlhaus.abuse.ch/"),
    "otx": ("AlienVault OTX", "OTX_API_KEY", "https://otx.alienvault.com/"),
    "safebrowsing": ("Google Safe Browsing", "GOOGLE_SAFE_BROWSING_KEY", "https://safebrowsing.google.com/"),
    "urlscan": ("urlscan.io", "URLSCAN_API_KEY", "https://urlscan.io/"),
}


def key(service: str) -> str:
    variable = SERVICES[service][1]
    if service == "urlhaus":
        return os.getenv("URLHAUS_API_KEY") or os.getenv(variable, "")
    return os.getenv(variable, "") if variable else ""


def configured() -> dict[str, bool]:
    """Which services can answer on this installation (CIRCL needs no key)."""
    return {name: (not SERVICES[name][1]) or bool(key(name)) for name in SERVICES}


# ---------------------------------------------------------------- rate limiting
class TokenBucket:
    """``per_minute`` tokens refilled continuously, and at most ``per_day`` per UTC day. Non-blocking."""

    def __init__(self, per_minute: float, per_day: int, clock: Callable[[], float] = time.time) -> None:
        self.capacity = float(per_minute)
        self.rate = float(per_minute) / 60.0
        self.per_day = int(per_day)
        self.clock = clock
        self.tokens = self.capacity
        self.stamp = clock()
        self.day = int(self.stamp // 86400)
        self.used_today = 0
        self.blocked_until = 0.0
        self.lock = threading.Lock()

    def _refill(self, now: float) -> None:
        self.tokens = min(self.capacity, self.tokens + (now - self.stamp) * self.rate)
        self.stamp = now
        if int(now // 86400) != self.day:
            self.day, self.used_today = int(now // 86400), 0

    def acquire(self) -> bool:
        with self.lock:
            now = self.clock()
            self._refill(now)
            if now < self.blocked_until or self.used_today >= self.per_day or self.tokens < 1.0:
                return False
            self.tokens -= 1.0
            self.used_today += 1
            return True

    def exhaust(self, seconds: float = 60.0) -> None:
        """The service itself said "too many requests": stop asking for a while."""
        with self.lock:
            self.tokens = 0.0
            self.blocked_until = self.clock() + seconds

    def state(self) -> dict[str, Any]:
        with self.lock:
            self._refill(self.clock())
            return {"per_minute": int(self.capacity), "per_day": self.per_day, "used_today": self.used_today,
                    "available_now": int(self.tokens)}


class ClientLimiter:
    """How many scans with online lookups one visitor (client address) may start: protects the quota."""

    def __init__(self, per_minute: int = 6, per_hour: int = 40, clock: Callable[[], float] = time.time) -> None:
        self.per_minute, self.per_hour, self.clock = per_minute, per_hour, clock
        self.hits: dict[str, list[float]] = {}
        self.lock = threading.Lock()

    def allow(self, client: str) -> bool:
        now = self.clock()
        with self.lock:
            if len(self.hits) > 20000:   # forget idle visitors
                self.hits = {c: h for c, h in self.hits.items() if h and now - h[-1] < 3600}
            recent = [t for t in self.hits.get(client, []) if now - t < 3600]
            if len(recent) >= self.per_hour or sum(1 for t in recent if now - t < 60) >= self.per_minute:
                self.hits[client] = recent
                return False
            recent.append(now)
            self.hits[client] = recent
            return True


# Free tiers: VirusTotal 4/min, 500/day. The others are generous; these caps only stop a runaway loop.
BUCKETS: dict[str, TokenBucket] = {
    "virustotal": TokenBucket(4, 500),
    "urlscan": TokenBucket(30, 1000),
    "safebrowsing": TokenBucket(60, 10000),
    "otx": TokenBucket(60, 10000),
    "urlhaus": TokenBucket(60, 10000),
    "malwarebazaar": TokenBucket(60, 10000),
    "circl": TokenBucket(60, 10000),
}
CLIENTS = ClientLimiter()


# ---------------------------------------------------------------- cache (memory, optionally S3)
class TTLCache:
    def __init__(self, ttl: float = CACHE_TTL_SECONDS, max_entries: int = CACHE_MAX_ENTRIES,
                 clock: Callable[[], float] = time.time) -> None:
        self.ttl, self.max_entries, self.clock = ttl, max_entries, clock
        self.data: OrderedDict[str, tuple[float, dict[str, Any]]] = OrderedDict()
        self.lock = threading.Lock()

    def get(self, cache_key: str) -> dict[str, Any] | None:
        with self.lock:
            entry = self.data.get(cache_key)
            if not entry:
                return None
            if self.clock() - entry[0] >= self.ttl:
                del self.data[cache_key]
                return None
            self.data.move_to_end(cache_key)
            return dict(entry[1])

    def set(self, cache_key: str, value: dict[str, Any], stamp: float | None = None) -> None:
        with self.lock:
            self.data[cache_key] = (self.clock() if stamp is None else stamp, dict(value))
            self.data.move_to_end(cache_key)
            while len(self.data) > self.max_entries:
                self.data.popitem(last=False)

    def clear(self) -> None:
        with self.lock:
            self.data.clear()


class S3Cache:
    """Shares cached answers between Lambda instances. Best effort: any failure turns it off for
    10 minutes and the memory cache carries on. Keys are hashes; values hold only service numbers."""

    def __init__(self) -> None:
        self.bucket = os.environ.get("CYBERSCAN_STATS_BUCKET", "cyberscan-assets")
        self.prefix = os.environ.get("CYBERSCAN_INTEL_CACHE_PREFIX", "intel-cache/")
        self.enabled = bool(os.environ.get("AWS_LAMBDA_FUNCTION_NAME")) and os.environ.get("CYBERSCAN_INTEL_CACHE_S3", "1") != "0"
        self.client: Any = None
        self.off_until = 0.0

    def _client(self) -> Any:
        if not self.enabled or time.time() < self.off_until:
            return None
        if self.client is None:
            try:
                import boto3  # noqa: PLC0415
                from botocore.config import Config  # noqa: PLC0415

                self.client = boto3.client("s3", config=Config(connect_timeout=1, read_timeout=1, retries={"max_attempts": 0}))
            except Exception:  # noqa: BLE001
                self.enabled = False
                return None
        return self.client

    def _fail(self) -> None:
        self.off_until = time.time() + 600

    def get(self, cache_key: str) -> tuple[float, dict[str, Any]] | None:
        client = self._client()
        if client is None:
            return None
        try:
            body = client.get_object(Bucket=self.bucket, Key=f"{self.prefix}{cache_key}.json")["Body"].read(65536)
            document = json.loads(body)
            stamp = float(document["at"])
            if time.time() - stamp >= CACHE_TTL_SECONDS:
                return None
            return stamp, dict(document["value"])
        except Exception as exc:  # noqa: BLE001
            if "NoSuchKey" not in type(exc).__name__ and "NoSuchKey" not in str(exc) and "404" not in str(exc):
                self._fail()
            return None

    def put(self, cache_key: str, value: dict[str, Any]) -> None:
        client = self._client()
        if client is None:
            return
        try:
            client.put_object(Bucket=self.bucket, Key=f"{self.prefix}{cache_key}.json",
                              Body=json.dumps({"at": time.time(), "value": value}).encode(), ContentType="application/json")
        except Exception:  # noqa: BLE001
            self._fail()


CACHE = TTLCache()
S3 = S3Cache()
CACHEABLE = {"match", "several", "few", "clean_report", "known_good", "seen", "not_found"}


def _cache_key(service: str, kind: str, indicator: str) -> str:
    digest = hashlib.sha256(f"{service}|{kind}|{indicator}".encode("utf-8")).hexdigest()[:40]
    return f"{service}/{kind}/{digest}"


def _cached_call(service: str, kind: str, indicator: str, fetch: Callable[[], dict[str, Any]]) -> dict[str, Any]:
    """The cached answer, else one fresh request (if the service is configured and within quota)."""
    if SERVICES[service][1] and not key(service):
        return {"status": "no_key"}
    cache_key = _cache_key(service, kind, indicator)
    hit = CACHE.get(cache_key)
    if hit is None:
        remote = S3.get(cache_key)
        if remote is not None:
            CACHE.set(cache_key, remote[1], stamp=remote[0])
            hit = remote[1]
    if hit is not None:
        return {**hit, "cached": True}
    if not BUCKETS[service].acquire():
        return {"status": "quota"}
    try:
        answer = fetch()
    except (OSError, ValueError, urllib.error.URLError) as exc:
        answer = {"status": "timeout" if "timed out" in str(exc).lower() else "error", "error": type(exc).__name__}
    if answer.get("status") == "quota":
        BUCKETS[service].exhaust()
    if answer.get("status") in CACHEABLE:
        CACHE.set(cache_key, answer)
        S3.put(cache_key, answer)
    return answer


# ---------------------------------------------------------------- HTTP
def _http(method: str, url: str, *, data: bytes | None = None, headers: dict[str, str] | None = None,
          timeout: float = REQUEST_TIMEOUT_SECONDS) -> tuple[int, Any]:
    """One request -> (HTTP status, parsed JSON or None). Tests replace this function."""
    request = urllib.request.Request(url, data=data, method=method, headers={**UA, **(headers or {})})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - fixed https endpoints
            raw = response.read(2_000_000)
            return response.status, (json.loads(raw) if raw.strip() else {})
    except urllib.error.HTTPError as exc:
        return exc.code, None


def _common_errors(status: int, body: Any, name: str) -> dict[str, Any] | None:
    if status in (401, 403):
        return {"status": "error", "error": f"the {name} key was refused"}
    if status == 429:
        return {"status": "quota"}
    if status != 200 or not isinstance(body, dict):
        return {"status": "error", "error": f"HTTP {status}"}
    return None


def _date(value: Any) -> str | None:
    try:
        return datetime.fromtimestamp(int(value), tz=timezone.utc).strftime("%Y-%m-%d") if value else None
    except (TypeError, ValueError, OSError, OverflowError):
        return None


# ---------------------------------------------------------------- VirusTotal
VT_BASE = "https://www.virustotal.com/api/v3"


def vt_url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")


def parse_virustotal(body: dict[str, Any]) -> dict[str, Any]:
    """A VirusTotal object report (file, URL, domain or IP) -> the numbers and a status."""
    attributes = (body.get("data") or {}).get("attributes") or {}
    stats = attributes.get("last_analysis_stats") or {}
    count = {k: int(stats.get(k, 0) or 0) for k in ("malicious", "suspicious", "harmless", "undetected", "timeout")}
    total = sum(int(v) for k, v in stats.items() if isinstance(v, int) and k not in ("type-unsupported", "confirmed-timeout", "failure"))
    popular = attributes.get("popular_threat_classification") or {}
    label = str(popular.get("suggested_threat_label") or "")[:80]
    family = next((str(x.get("value")) for x in popular.get("popular_threat_name") or [] if isinstance(x, dict) and x.get("value")), "")[:60]
    engines = [(str(name), str((row or {}).get("result") or "")[:60])
               for name, row in (attributes.get("last_analysis_results") or {}).items()
               if isinstance(row, dict) and row.get("category") == "malicious"]
    first = attributes.get("first_submission_date") or attributes.get("creation_date")
    out = {"malicious": count["malicious"], "suspicious": count["suspicious"], "harmless": count["harmless"],
           "undetected": count["undetected"], "engines_total": total, "label": label, "family": family,
           "first_seen": _date(first), "first_seen_ts": int(first) if isinstance(first, (int, float)) else None,
           "last_analysis": _date(attributes.get("last_analysis_date")),
           "reputation": attributes.get("reputation") if isinstance(attributes.get("reputation"), int) else None,
           "times_submitted": attributes.get("times_submitted") if isinstance(attributes.get("times_submitted"), int) else None,
           "detections": [f"{n}: {r}" if r else n for n, r in sorted(engines)[:6]]}
    malicious = count["malicious"]
    if malicious >= 10 or (malicious >= 5 and (label or family)):
        status = "match"
    elif malicious >= 3:
        status = "several"
    elif malicious or count["suspicious"]:
        status = "few"
    else:
        status = "clean_report"
    detail = f"{malicious} / {total} engines" + (f" · {label or family}" if (label or family) and malicious else "")
    return {"status": status, **out, "detail": detail}


def _vt_get(path: str, timeout: float) -> dict[str, Any]:
    status, body = _http("GET", f"{VT_BASE}/{path}", headers={"x-apikey": key("virustotal")}, timeout=timeout)
    if status == 404:
        return {"status": "not_found"}
    return _common_errors(status, body, "VirusTotal") or parse_virustotal(body)


def vt_file(sha256: str, timeout: float = REQUEST_TIMEOUT_SECONDS) -> dict[str, Any]:
    return _cached_call("virustotal", "file", sha256.lower(), lambda: _vt_get(f"files/{sha256.lower()}", timeout))


def vt_url(url: str, timeout: float = REQUEST_TIMEOUT_SECONDS) -> dict[str, Any]:
    return _cached_call("virustotal", "url", url, lambda: _vt_get(f"urls/{vt_url_id(url)}", timeout))


def vt_host(host: str, timeout: float = REQUEST_TIMEOUT_SECONDS) -> dict[str, Any]:
    path = f"ip_addresses/{host}" if _is_ip(host) else f"domains/{host}"
    return _cached_call("virustotal", "host", host, lambda: _vt_get(path, timeout))


# ---------------------------------------------------------------- file sources
def parse_circl(status: int, body: Any) -> dict[str, Any]:
    if status == 404:
        return {"status": "not_found"}
    if status != 200 or not isinstance(body, dict):
        return {"status": "error", "error": f"HTTP {status}"}
    malicious = body.get("KnownMalicious")
    if malicious:
        return {"status": "match", "detail": f"listed as malicious by {malicious}", "name": body.get("FileName")}
    sources = body.get("source") or body.get("db") or "NSRL"
    return {"status": "known_good", "name": body.get("FileName"), "product": (body.get("ProductCode") or {}).get("ProductName"),
            "detail": f"known file ({sources})"}


def circl(sha256: str, timeout: float = REQUEST_TIMEOUT_SECONDS) -> dict[str, Any]:
    def fetch() -> dict[str, Any]:
        return parse_circl(*_http("GET", f"https://hashlookup.circl.lu/lookup/sha256/{sha256.lower()}", timeout=timeout))
    return _cached_call("circl", "file", sha256.lower(), fetch)


def parse_bazaar(status: int, body: Any) -> dict[str, Any]:
    failed = _common_errors(status, body, "abuse.ch")
    if failed:
        return failed
    if body.get("query_status") != "ok":
        return {"status": "not_found"}
    item = (body.get("data") or [{}])[0] or {}
    signature = item.get("signature")
    return {"status": "match", "signature": signature, "tags": (item.get("tags") or [])[:6], "first_seen": item.get("first_seen"),
            "detail": "MalwareBazaar sample" + (f" · {signature}" if signature else "")}


def malwarebazaar(sha256: str, timeout: float = REQUEST_TIMEOUT_SECONDS) -> dict[str, Any]:
    def fetch() -> dict[str, Any]:
        data = urllib.parse.urlencode({"query": "get_info", "hash": sha256.lower()}).encode()
        return parse_bazaar(*_http("POST", "https://mb-api.abuse.ch/api/v1/", data=data,
                                   headers={"Auth-Key": key("malwarebazaar")}, timeout=timeout))
    return _cached_call("malwarebazaar", "file", sha256.lower(), fetch)


# ---------------------------------------------------------------- link sources
def parse_urlhaus(status: int, body: Any, *, host: bool) -> dict[str, Any]:
    failed = _common_errors(status, body, "abuse.ch")
    if failed:
        return failed
    query = str(body.get("query_status", "")).lower()
    if query in {"no_results", "no_result", "invalid_host", "invalid_url"}:
        return {"status": "not_found"}
    if query != "ok":
        return {"status": "error", "error": query or "unexpected answer"}
    if host:
        urls = [u for u in body.get("urls") or [] if isinstance(u, dict)]
        online = sum(1 for u in urls if u.get("url_status") == "online")
        return {"status": "few", "scope": "host", "urls_count": int(body.get("url_count") or len(urls) or 0), "online": online,
                "reference": str(body.get("urlhaus_reference") or "")[:300],
                "detail": f"the host has {int(body.get('url_count') or len(urls) or 0)} listed malware link(s)"}
    return {"status": "match", "scope": "url", "threat": str(body.get("threat") or "")[:60], "url_status": body.get("url_status"),
            "tags": [str(t)[:40] for t in (body.get("tags") or [])[:6]], "first_seen": str(body.get("date_added") or "")[:40],
            "reference": str(body.get("urlhaus_reference") or "")[:300],
            "detail": "listed as a malware link" + (f" · {body.get('threat')}" if body.get("threat") else "")}


def urlhaus(url: str, host: str, timeout: float = REQUEST_TIMEOUT_SECONDS) -> dict[str, Any]:
    def fetch() -> dict[str, Any]:
        headers = {"Auth-Key": key("urlhaus")}
        exact = parse_urlhaus(*_http("POST", "https://urlhaus-api.abuse.ch/v1/url/", data=urllib.parse.urlencode({"url": url}).encode(),
                                     headers=headers, timeout=timeout), host=False)
        if exact["status"] != "not_found" or not host:
            return exact
        return parse_urlhaus(*_http("POST", "https://urlhaus-api.abuse.ch/v1/host/", data=urllib.parse.urlencode({"host": host}).encode(),
                                    headers=headers, timeout=timeout), host=True)
    return _cached_call("urlhaus", "url", url, fetch)


def parse_otx(status: int, body: Any) -> dict[str, Any]:
    if status == 404:
        return {"status": "not_found"}
    failed = _common_errors(status, body, "OTX")
    if failed:
        return failed
    pulse_info = body.get("pulse_info") or {}
    count = int(pulse_info.get("count") or 0)
    names = [str(p.get("name"))[:80] for p in pulse_info.get("pulses") or [] if isinstance(p, dict) and p.get("name")][:3]
    allow = [str(v.get("name") or v.get("source"))[:60] for v in body.get("validation") or [] if isinstance(v, dict)]
    if count and not allow:
        return {"status": "few", "pulses": count, "pulse_names": names, "detail": f"in {count} community pulse(s)"}
    if count:
        return {"status": "clean_report", "pulses": count, "allowlisted": allow,
                "detail": f"in {count} pulse(s), but on an allow list ({', '.join(allow)})"}
    return {"status": "not_found", "pulses": 0, "allowlisted": allow}


def otx(host: str, timeout: float = REQUEST_TIMEOUT_SECONDS) -> dict[str, Any]:
    kind = ("IPv6" if ":" in host else "IPv4") if _is_ip(host) else "hostname"

    def fetch() -> dict[str, Any]:
        return parse_otx(*_http("GET", f"https://otx.alienvault.com/api/v1/indicators/{kind}/{urllib.parse.quote(host, safe='')}/general",
                                headers={"X-OTX-API-KEY": key("otx")}, timeout=timeout))
    return _cached_call("otx", "host", host, fetch)


SB_THREATS = ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"]


def parse_safebrowsing(status: int, body: Any) -> dict[str, Any]:
    failed = _common_errors(status, body, "Google Safe Browsing")
    if status == 400:
        return {"status": "error", "error": "the Google Safe Browsing key or request was refused"}
    if failed:
        return failed
    matches = [m for m in body.get("matches") or [] if isinstance(m, dict)]
    if not matches:
        return {"status": "not_found"}
    threats = sorted({str(m.get("threatType") or "")[:40] for m in matches if m.get("threatType")})
    return {"status": "match", "threats": threats, "detail": "listed as " + ", ".join(t.replace("_", " ").lower() for t in threats)}


def safebrowsing(url: str, timeout: float = REQUEST_TIMEOUT_SECONDS) -> dict[str, Any]:
    def fetch() -> dict[str, Any]:
        payload = {"client": {"clientId": "cyberscan", "clientVersion": "1.1"},
                   "threatInfo": {"threatTypes": SB_THREATS, "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"],
                                  "threatEntries": [{"url": url}]}}
        endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + urllib.parse.quote(key("safebrowsing"), safe="")
        return parse_safebrowsing(*_http("POST", endpoint, data=json.dumps(payload).encode(),
                                         headers={"Content-Type": "application/json"}, timeout=timeout))
    return _cached_call("safebrowsing", "url", url, fetch)


def parse_urlscan(status: int, body: Any) -> dict[str, Any]:
    failed = _common_errors(status, body, "urlscan.io")
    if failed:
        return failed
    results = [r for r in body.get("results") or [] if isinstance(r, dict)]
    if not results:
        return {"status": "not_found", "scans": 0}
    flagged = [r for r in results if ((r.get("verdicts") or {}).get("overall") or {}).get("malicious")]
    latest = results[0]
    out = {"scans": int(body.get("total") or len(results)), "flagged": len(flagged),
           "latest": str((latest.get("task") or {}).get("time") or "")[:10], "result_id": str(latest.get("_id") or "")[:64]}
    if flagged:
        return {"status": "few", **out, "result_id": str(flagged[0].get("_id") or "")[:64],
                "detail": f"{len(flagged)} of {len(results)} public scans marked malicious"}
    return {"status": "seen", **out, "detail": f"{out['scans']} public scan(s), none marked malicious"}


def urlscan(host: str, timeout: float = REQUEST_TIMEOUT_SECONDS) -> dict[str, Any]:
    def fetch() -> dict[str, Any]:
        query = urllib.parse.quote(f"domain:{host}", safe="")
        return parse_urlscan(*_http("GET", f"https://urlscan.io/api/v1/search/?q={query}&size=10",
                                    headers={"API-Key": key("urlscan")}, timeout=timeout))
    return _cached_call("urlscan", "host", host, fetch)


# ---------------------------------------------------------------- running them together
def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def public_host(url: str) -> str | None:
    """The link's host if a public service could know it (not a private, local or reserved address)."""
    try:
        parts = urlsplit(url.strip())
        host = (parts.hostname or "").rstrip(".").lower()
    except ValueError:
        return None
    if parts.scheme.lower() not in {"http", "https"} or not host:
        return None
    if _is_ip(host):
        address = ipaddress.ip_address(host.strip("[]"))
        if not address.is_global:
            return None
        return str(address)
    if "." not in host or host.endswith((".local", ".lan", ".internal", ".localhost", ".home.arpa", ".corp")):
        return None
    return host


def _run(jobs: dict[str, Callable[[], dict[str, Any]]], budget: float) -> dict[str, dict[str, Any]]:
    results: dict[str, dict[str, Any]] = {}
    pool = ThreadPoolExecutor(max_workers=max(1, len(jobs)), thread_name_prefix="cyberscan-intel")
    futures = {pool.submit(fn): name for name, fn in jobs.items()}
    done, pending = wait(futures, timeout=budget)
    for future in done:
        try:
            results[futures[future]] = future.result()
        except Exception as exc:  # noqa: BLE001 - an unreachable source is a status
            results[futures[future]] = {"status": "error", "error": type(exc).__name__}
    for future in pending:
        results[futures[future]] = {"status": "timeout"}
    pool.shutdown(wait=False, cancel_futures=True)
    return {name: results[name] for name in jobs}


def lookup_file(sha256: str, budget: float = FILE_BUDGET_SECONDS) -> dict[str, dict[str, Any]]:
    """CIRCL, MalwareBazaar and VirusTotal for one SHA-256, together, within ``budget`` seconds."""
    timeout = min(REQUEST_TIMEOUT_SECONDS, budget)
    return _run({"CIRCL hashlookup": lambda: circl(sha256, timeout),
                 "MalwareBazaar": lambda: malwarebazaar(sha256, timeout),
                 "VirusTotal": lambda: vt_file(sha256, timeout)}, budget)


LINK_SOURCES = ("VirusTotal (link)", "VirusTotal (site)", "Google Safe Browsing", "URLhaus", "AlienVault OTX", "urlscan.io")
LINK_SERVICE = {"VirusTotal (link)": "virustotal", "VirusTotal (site)": "virustotal", "Google Safe Browsing": "safebrowsing",
                "URLhaus": "urlhaus", "AlienVault OTX": "otx", "urlscan.io": "urlscan"}


def lookup_link(url: str, budget: float = LINK_BUDGET_SECONDS) -> dict[str, dict[str, Any]]:
    """Every link source for one link (and its host), together, within ``budget`` seconds."""
    url = url.strip()
    host = public_host(url)
    if not host:
        return {name: {"status": "not_applicable"} for name in LINK_SOURCES}
    timeout = min(REQUEST_TIMEOUT_SECONDS, budget)
    return _run({"VirusTotal (link)": lambda: vt_url(url, timeout),
                 "VirusTotal (site)": lambda: vt_host(host, timeout),
                 "Google Safe Browsing": lambda: safebrowsing(url, timeout),
                 "URLhaus": lambda: urlhaus(url, host, timeout),
                 "AlienVault OTX": lambda: otx(host, timeout),
                 "urlscan.io": lambda: urlscan(host, timeout)}, budget)


# ---------------------------------------------------------------- the verdict weighting
# Files (VirusTotal, by SHA-256):
#   >= 10 engines, or >= 5 engines and a family name   -> "Known malware" (critical, +95: KNOWN_MALWARE)
#   3-9 engines                                         -> several engines (high, +60; +45 for 3-4)
#   1-2 engines (or only "suspicious")                  -> a few engines (medium, +15: often false positives)
#   0 of 60+ engines, first seen 30+ days ago           -> widely seen as clean (info, 0: supporting only)
# Links: Safe Browsing / URLhaus exact listing +80; VirusTotal link >=5 vendors +75, 2-4 +40, 1 +15;
#   VirusTotal site >=5 +55, 2-4 +30, 1 +10; URLhaus host +45; OTX pulses +20; urlscan malicious scans +30.
# A clean answer never lowers the score: CyberScan's own evidence and rules keep the final say.
CLEAN_MIN_ENGINES = 60
CLEAN_MIN_AGE_DAYS = 30


def _age_days(entry: dict[str, Any], now: float | None = None) -> int | None:
    stamp = entry.get("first_seen_ts")
    if not isinstance(stamp, (int, float)):
        return None
    return int(((now or time.time()) - stamp) // 86400)


def _vt_numbers(entry: dict[str, Any], what: str) -> str:
    ratio = f"{entry.get('malicious', 0)} of {entry.get('engines_total', 0)} {what}"
    extra = []
    if entry.get("suspicious"):
        extra.append(f"{entry['suspicious']} more say suspicious")
    if entry.get("label") or entry.get("family"):
        extra.append(f"label {entry.get('label') or entry.get('family')}")
    if entry.get("first_seen"):
        extra.append(f"first seen {entry['first_seen']}")
    if entry.get("detections"):
        extra.append("e.g. " + "; ".join(entry["detections"][:3]))
    return ratio + (f" ({', '.join(extra)})" if extra else "")


def widely_clean(entry: dict[str, Any], now: float | None = None) -> bool:
    age = _age_days(entry, now)
    return (entry.get("status") == "clean_report" and int(entry.get("engines_total") or 0) >= CLEAN_MIN_ENGINES
            and age is not None and age >= CLEAN_MIN_AGE_DAYS)


def file_findings(sources: dict[str, dict[str, Any]], now: float | None = None) -> list[dict[str, Any]]:
    """Findings (severity, label, contribution, explanation, source) from the online file sources."""
    findings: list[dict[str, Any]] = []
    vt = sources.get("VirusTotal") or {}
    known_bad = [(name, r) for name, r in sources.items() if r.get("status") == "match"]
    if known_bad:
        names = ", ".join(name for name, _ in known_bad)
        detail = []
        for name, r in known_bad:
            if name == "VirusTotal":
                detail.append(f"VirusTotal: {_vt_numbers(r, 'engines')}; rule: 10+ engines, or 5+ with a family name, means known malware (+95)")
            elif r.get("detail"):
                detail.append(f"{name}: {r['detail']}")
        signature = next((r.get("signature") or r.get("label") or r.get("family") for _, r in known_bad
                          if r.get("signature") or r.get("label") or r.get("family")), "")
        findings.append({"severity": "critical", "label": "Known malware" + (f": {signature}" if signature else ""), "contribution": 95,
                         "explanation": f"This exact file (same SHA-256) is listed as malware by {names}." + (f" {'. '.join(detail)}." if detail else ""),
                         "source": names})
        return findings
    if vt.get("status") == "several":
        weight = 60 if int(vt.get("malicious") or 0) >= 5 else 45
        findings.append({"severity": "high", "label": "Several antivirus engines flag this file", "contribution": weight,
                         "explanation": f"VirusTotal: {_vt_numbers(vt, 'engines')}. Rule: 3-4 engines weigh +45, 5-9 without a family name +60; "
                                        "it takes 10+ (or 5+ with a family name) to call it known malware.",
                         "source": "VirusTotal"})
    elif vt.get("status") == "few":
        findings.append({"severity": "medium", "label": "A few antivirus engines flag this file", "contribution": 15,
                         "explanation": f"VirusTotal: {_vt_numbers(vt, 'engines')}. One or two detections are often false positives, "
                                        "so this weighs only +15; read the other evidence.",
                         "source": "VirusTotal"})
    elif widely_clean(vt, now):
        findings.append({"severity": "info", "label": "Widely seen as clean on VirusTotal", "contribution": 0,
                         "explanation": f"VirusTotal: {_vt_numbers(vt, 'engines')}, known for {_age_days(vt, now)} days. Supporting evidence only (+0): "
                                        "it does not lower the score, and CyberScan's own checks keep the final say.",
                         "source": "VirusTotal"})
    good = sources.get("CIRCL hashlookup") or {}
    if good.get("status") == "known_good":
        what = " · ".join(str(x) for x in (good.get("product"), good.get("name")) if x)
        findings.append({"severity": "info", "label": "Known software", "contribution": 0,
                         "explanation": f"This exact file is in CIRCL's database of known files ({what or 'NSRL'}). Known files can still be misused, but this one is not a modified copy.",
                         "source": "CIRCL hashlookup"})
    return findings


def link_findings(sources: dict[str, dict[str, Any]], now: float | None = None) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    def add(severity: str, label: str, weight: int, explanation: str, source: str) -> None:
        findings.append({"severity": severity, "label": label, "contribution": weight, "explanation": explanation, "source": source})

    sb = sources.get("Google Safe Browsing") or {}
    if sb.get("status") == "match":
        add("high", "Google Safe Browsing lists this link", 80,
            f"Google Safe Browsing: {sb.get('detail', 'listed')}. Rule: an exact Safe Browsing listing weighs +80.", "Google Safe Browsing")
    uh = sources.get("URLhaus") or {}
    if uh.get("status") == "match":
        add("high", "URLhaus lists this link as malware", 80,
            f"URLhaus: {uh.get('detail', 'listed')}" + (f", status {uh['url_status']}" if uh.get("url_status") else "")
            + ". Rule: an exact URLhaus listing weighs +80.", "URLhaus")
    elif uh.get("status") == "few":
        add("medium", "URLhaus lists other malware links on this site", 45,
            f"URLhaus: {uh.get('detail')}. This link itself isn't listed; a host with listed links weighs +45.", "URLhaus")
    for name, what, weights in (("VirusTotal (link)", "this link", (75, 40, 15)), ("VirusTotal (site)", "the site", (55, 30, 10))):
        vt = sources.get(name) or {}
        bad = int(vt.get("malicious") or 0)
        if vt.get("status") not in {"match", "several", "few"}:
            if widely_clean(vt, now) and name == "VirusTotal (site)":
                add("info", "The site is widely seen as clean on VirusTotal", 0,
                    f"VirusTotal: {_vt_numbers(vt, 'security vendors')}. Supporting evidence only (+0); it does not lower the score.", "VirusTotal")
            continue
        weight = weights[0] if bad >= 5 else weights[1] if bad >= 2 else weights[2]
        severity = "high" if bad >= 5 else "medium" if bad >= 2 else "low"
        add(severity, f"VirusTotal: security vendors flag {what}", weight,
            f"VirusTotal: {_vt_numbers(vt, 'security vendors')} flag {what}. Rule: 5+ weigh +{weights[0]}, 2-4 +{weights[1]}, "
            f"1 only +{weights[2]} (a single vendor is often a false positive).", "VirusTotal")
    ox = sources.get("AlienVault OTX") or {}
    if ox.get("status") == "few":
        add("low", "Mentioned in AlienVault OTX threat pulses", 20,
            f"AlienVault OTX: the host is {ox.get('detail')}" + (f" ({'; '.join(ox.get('pulse_names') or [])})" if ox.get("pulse_names") else "")
            + ". Pulses are community reports with mixed context, so this weighs +20.", "AlienVault OTX")
    us = sources.get("urlscan.io") or {}
    if us.get("status") == "few":
        add("medium", "Public urlscan.io scans marked this site malicious", 30,
            f"urlscan.io: {us.get('detail')}. Rule: weighs +30 (other people's scans of the same site).", "urlscan.io")
    return findings


def link_intelligence(sources: dict[str, dict[str, Any]], url: str) -> dict[str, Any]:
    """The scan's ``osint_summary`` for a link (same shape the public-feed engine returns)."""
    statuses = [s.get("status") for s in sources.values()]
    if any(s in {"match", "several"} for s in statuses):
        status = "matched"
    elif all(s in {"no_key", "not_applicable", "quota"} for s in statuses):
        status = "unavailable"
    elif any(s == "timeout" for s in statuses):
        status = "partial_timeout"
    else:
        status = "no_match"
    feeds = {name: {"status": {"match": "matched", "several": "matched", "few": "matched", "no_key": "authentication_required",
                               "not_found": "no_match", "clean_report": "no_match", "seen": "no_match"}.get(str(s.get("status")), str(s.get("status"))),
                    "error": s.get("error"), "records": [], "match_count": 0} for name, s in sources.items()}
    return {"status": status, "indicator": url[:2048], "indicator_type": "url", "feeds": feeds, "matches": [],
            "attributions": [], "classifications": sorted({str(s.get("label") or s.get("threat") or "") for s in sources.values()} - {""}),
            "link_sources": sources,
            "interpretation": "Report lookups only; a listing is an external report, and no listing is not proof of safety."}


def state() -> dict[str, Any]:
    """For the protection panel: which services are configured, and VirusTotal's quota now."""
    return {"configured": configured(), "virustotal_quota": BUCKETS["virustotal"].state()}
