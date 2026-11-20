"""Known-file intelligence by hash: is this exact file already known as malware, or as known software?

Offline (always, no network):
    intel/data/malware-hashes.bin   sorted 8-byte prefixes of SHA-256 / MD5 digests of known malware
                                    (built by intel/fetch.py from the sources it can reach; see manifest.json)

Online (only when the user turns on online lookups; only the file's hash is sent, never its contents):
    CIRCL hashlookup    hashlookup.circl.lu   no key   known software (NSRL and other sets) and a
                                                       "KnownMalicious" marker from other feeds
    MalwareBazaar       mb-api.abuse.ch        key: ABUSECH_AUTH_KEY (free at auth.abuse.ch)
    VirusTotal          virustotal.com/api/v3  key: VT_API_KEY (free community key)

Every source answers "match", "known good", "not found", or why it could not answer
(no key, timeout, offline). A match is reported with its source; nothing here guesses.
"""
from __future__ import annotations

import bisect
import json
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, wait
from pathlib import Path
from typing import Any

from core import protection

UA = {"User-Agent": "CyberScan-hash-intel/1.0"}
ONLINE_BUDGET_SECONDS = 4.0
_lock = threading.Lock()
_db: dict[str, Any] = {"mtime": None, "prefixes": None}
_cache: dict[str, tuple[float, dict[str, Any]]] = {}
CACHE_TTL = 6 * 3600


# ---------------------------------------------------------------- offline database
def _db_path() -> Path:
    return protection.DATA / "malware-hashes.bin"


def _prefixes() -> bytes | None:
    """The sorted prefix table, reloaded when the updater replaces the file."""
    path = _db_path()
    try:
        mtime = path.stat().st_mtime_ns
    except OSError:
        return None
    with _lock:
        if _db["mtime"] != mtime:
            raw = path.read_bytes()
            _db.update(mtime=mtime, prefixes=raw[: len(raw) - len(raw) % 8])
        return _db["prefixes"]


def offline_count() -> int:
    table = _prefixes()
    return len(table) // 8 if table else 0


def _contains(table: bytes, prefix: bytes) -> bool:
    count = len(table) // 8
    lo, hi = 0, count
    while lo < hi:
        mid = (lo + hi) // 2
        value = table[mid * 8: mid * 8 + 8]
        if value < prefix:
            lo = mid + 1
        else:
            hi = mid
    return lo < count and table[lo * 8: lo * 8 + 8] == prefix


def offline_lookup(sha256: str, md5: str | None = None) -> dict[str, Any]:
    table = _prefixes()
    if not table:
        return {"status": "unavailable", "entries": 0}
    for name, digest in (("sha256", sha256), ("md5", md5)):
        if digest and _contains(table, bytes.fromhex(digest)[:8]):
            return {"status": "match", "entries": len(table) // 8, "matched": name}
    return {"status": "not_found", "entries": len(table) // 8}


def build_prefix_table(digests: list[str]) -> bytes:
    """hex digests (any length >= 16 hex chars) -> sorted, de-duplicated 8-byte prefixes."""
    prefixes = sorted({bytes.fromhex(d[:16]) for d in digests if len(d) >= 16})
    return b"".join(prefixes)


# ---------------------------------------------------------------- online sources
def _keys() -> dict[str, str]:
    return {"abusech": os.getenv("ABUSECH_AUTH_KEY", ""), "virustotal": os.getenv("VT_API_KEY", "")}


def _get_json(url: str, *, data: bytes | None = None, headers: dict[str, str] | None = None, timeout: float) -> tuple[int, Any]:
    request = urllib.request.Request(url, data=data, headers={**UA, **(headers or {})})
    started = time.monotonic()
    while True:
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.status, json.loads(response.read(2_000_000) or b"{}")
        except urllib.error.HTTPError as exc:
            return exc.code, None
        except urllib.error.URLError:
            # one retry for a passing name-resolution or connection failure, inside the same budget
            if time.monotonic() - started > timeout / 2:
                raise
            started = -1e9


def _circl(sha256: str, timeout: float) -> dict[str, Any]:
    status, body = _get_json(f"https://hashlookup.circl.lu/lookup/sha256/{sha256}", timeout=timeout)
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


def _bazaar(sha256: str, key: str, timeout: float) -> dict[str, Any]:
    if not key:
        return {"status": "no_key"}
    status, body = _get_json("https://mb-api.abuse.ch/api/v1/", data=urllib.parse.urlencode({"query": "get_info", "hash": sha256}).encode(),
                             headers={"Auth-Key": key}, timeout=timeout)
    if status in (401, 403):
        return {"status": "error", "error": "the abuse.ch key was refused"}
    if status != 200 or not isinstance(body, dict):
        return {"status": "error", "error": f"HTTP {status}"}
    if body.get("query_status") != "ok":
        return {"status": "not_found"}
    item = (body.get("data") or [{}])[0]
    return {"status": "match", "signature": item.get("signature"), "tags": (item.get("tags") or [])[:6],
            "first_seen": item.get("first_seen"), "detail": f"MalwareBazaar sample{(' · ' + item['signature']) if item.get('signature') else ''}"}


def _virustotal(sha256: str, key: str, timeout: float) -> dict[str, Any]:
    if not key:
        return {"status": "no_key"}
    status, body = _get_json(f"https://www.virustotal.com/api/v3/files/{sha256}", headers={"x-apikey": key}, timeout=timeout)
    if status == 404:
        return {"status": "not_found"}
    if status in (401, 403):
        return {"status": "error", "error": "the VirusTotal key was refused"}
    if status == 429:
        return {"status": "error", "error": "VirusTotal quota reached"}
    if status != 200 or not isinstance(body, dict):
        return {"status": "error", "error": f"HTTP {status}"}
    attributes = (body.get("data") or {}).get("attributes") or {}
    stats = attributes.get("last_analysis_stats") or {}
    malicious, total = int(stats.get("malicious", 0)), sum(int(v) for v in stats.values() if isinstance(v, int))
    label = ((attributes.get("popular_threat_classification") or {}).get("suggested_threat_label")) or ""
    result = {"malicious": malicious, "engines": total, "label": label, "detail": f"{malicious}/{total} engines"}
    if malicious >= 3:
        return {"status": "match", **result}
    if malicious:
        return {"status": "few", **result}
    return {"status": "clean_report", **result}


def online_lookup(sha256: str, budget: float = ONLINE_BUDGET_SECONDS) -> dict[str, Any]:
    """All online sources at once, bounded by ``budget`` seconds in total."""
    cached = _cache.get(sha256)
    if cached and time.time() - cached[0] < CACHE_TTL:
        return cached[1]
    keys = _keys()
    jobs = {"CIRCL hashlookup": lambda: _circl(sha256, budget),
            "MalwareBazaar": lambda: _bazaar(sha256, keys["abusech"], budget),
            "VirusTotal": lambda: _virustotal(sha256, keys["virustotal"], budget)}
    results: dict[str, Any] = {}
    pool = ThreadPoolExecutor(max_workers=len(jobs))
    futures = {pool.submit(fn): name for name, fn in jobs.items()}
    done, pending = wait(futures, timeout=budget + 0.5)
    for future in done:
        try:
            results[futures[future]] = future.result()
        except (OSError, ValueError, urllib.error.URLError) as exc:
            results[futures[future]] = {"status": "error", "error": type(exc).__name__}
    for future in pending:
        results[futures[future]] = {"status": "timeout"}
    pool.shutdown(wait=False, cancel_futures=True)
    if not any(r.get("status") in {"error", "timeout"} for r in results.values()):
        _cache[sha256] = (time.time(), results)
    return results


# ---------------------------------------------------------------- the verdict pieces
def assess(sha256: str, md5: str | None, *, online: bool) -> dict[str, Any]:
    """Every source's answer plus the findings they justify (dicts: severity, label, contribution, explanation)."""
    sources: dict[str, Any] = {"Offline hash database": offline_lookup(sha256, md5)}
    if online:
        sources.update(online_lookup(sha256))
    findings: list[dict[str, Any]] = []
    known_bad = [(name, r) for name, r in sources.items() if r.get("status") == "match"]
    if known_bad:
        names = ", ".join(name for name, _ in known_bad)
        detail = "; ".join(f"{name}: {r['detail']}" for name, r in known_bad if r.get("detail"))
        signature = next((r.get("signature") or r.get("label") for _, r in known_bad if r.get("signature") or r.get("label")), "")
        findings.append({"severity": "critical", "label": "Known malware" + (f": {signature}" if signature else ""), "contribution": 95,
                         "explanation": f"This exact file (same SHA-256) is listed as malware by {names}." + (f" {detail}." if detail else ""),
                         "source": names})
    few = sources.get("VirusTotal", {})
    if not known_bad and few.get("status") == "few":
        findings.append({"severity": "medium", "label": "A few antivirus engines flag this file", "contribution": 30,
                         "explanation": f"VirusTotal: {few['detail']} report it. A small number of detections is often a false positive; read the other evidence.",
                         "source": "VirusTotal"})
    good = sources.get("CIRCL hashlookup", {})
    if not known_bad and good.get("status") == "known_good":
        what = " · ".join(x for x in (good.get("product"), good.get("name")) if x)
        findings.append({"severity": "info", "label": "Known software", "contribution": 0,
                         "explanation": f"This exact file is in CIRCL's database of known files ({what or 'NSRL'}). Known files can still be misused, but this one is not a modified copy.",
                         "source": "CIRCL hashlookup"})
    return {"sources": sources, "findings": findings, "online": online}
