"""Known-file intelligence by hash: is this exact file already known as malware, or as known software?

Offline (always, no network):
    intel/data/malware-hashes.bin   sorted 8-byte prefixes of SHA-256 / MD5 digests of known malware
                                    (built by intel/fetch.py from the sources it can reach; see manifest.json)

Online (only when online lookups are on; only the file's hash is sent, never its contents; the
requests, quotas and caching live in core/external_intel.py):
    CIRCL hashlookup    hashlookup.circl.lu   no key   known software (NSRL and other sets) and a
                                                       "KnownMalicious" marker from other feeds
    MalwareBazaar       mb-api.abuse.ch        key: ABUSECH_AUTH_KEY (free at auth.abuse.ch)
    VirusTotal          virustotal.com/api/v3  key: VT_API_KEY (free community key)

Every source answers "match", "known good", "not found", or why it could not answer
(no key, timeout, offline). A match is reported with its source; nothing here guesses.
"""
from __future__ import annotations

import bisect
import threading
from pathlib import Path
from typing import Any

from core import protection

ONLINE_BUDGET_SECONDS = 4.0
_lock = threading.Lock()
_db: dict[str, Any] = {"mtime": None, "prefixes": None}


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
def online_lookup(sha256: str, budget: float = ONLINE_BUDGET_SECONDS) -> dict[str, Any]:
    """All online sources at once (core.external_intel: rate-limited and cached), bounded by ``budget``."""
    from core import external_intel  # noqa: PLC0415

    return external_intel.lookup_file(sha256, budget)


# ---------------------------------------------------------------- the verdict pieces
def assess(sha256: str, md5: str | None, *, online: bool) -> dict[str, Any]:
    """Every source's answer plus the findings they justify (dicts: severity, label, contribution, explanation).
    The weighting rules for the online answers live in ``core.external_intel.file_findings``."""
    from core import external_intel  # noqa: PLC0415

    sources: dict[str, Any] = {"Offline hash database": offline_lookup(sha256, md5)}
    if online:
        sources.update(online_lookup(sha256))
    return {"sources": sources, "findings": external_intel.file_findings(sources), "online": online}
