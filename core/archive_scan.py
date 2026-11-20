"""Scan the files inside a ZIP archive, in memory, within fixed limits.

Each member is decompressed into memory only (never written to disk, never run) and checked by
the same rule engines and hash database as a top-level file. Limits keep a decompression bomb
from exhausting the scanner; members beyond them are counted and reported as not scanned.
"""
from __future__ import annotations

import hashlib
import io
import time
import zipfile
from typing import Any

MAX_MEMBERS = 64
MAX_MEMBER_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_RATIO = 200          # decompressed / compressed; above this a member is treated as a bomb
MAX_SECONDS = 8.0


def scan_members(data: bytes, *, yara_bytes, hash_lookup) -> dict[str, Any]:
    """``yara_bytes(bytes) -> list[match]``; ``hash_lookup(sha256, md5) -> dict``."""
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, ValueError, OSError):
        return {"status": "not_zip", "members": [], "scanned": 0, "skipped": 0}
    started, total = time.monotonic(), 0
    members, skipped, reasons = [], 0, {}
    with archive:
        infos = [i for i in archive.infolist() if not i.is_dir()]
        for info in infos:
            why = None
            if len(members) >= MAX_MEMBERS:
                why = "member limit"
            elif info.flag_bits & 0x1:
                why = "encrypted"
            elif info.file_size > MAX_MEMBER_BYTES:
                why = "too large"
            elif info.compress_size and info.file_size / max(1, info.compress_size) > MAX_RATIO:
                why = "compression ratio (possible bomb)"
            elif total + info.file_size > MAX_TOTAL_BYTES:
                why = "total size limit"
            elif time.monotonic() - started > MAX_SECONDS:
                why = "time limit"
            if why:
                skipped += 1
                reasons[why] = reasons.get(why, 0) + 1
                continue
            try:
                with archive.open(info) as handle:
                    body = handle.read(MAX_MEMBER_BYTES + 1)
            except Exception:  # noqa: BLE001 - a damaged member is reported, not fatal
                skipped += 1
                reasons["unreadable"] = reasons.get("unreadable", 0) + 1
                continue
            total += len(body)
            sha256 = hashlib.sha256(body).hexdigest()
            entry = {"name": info.filename[:200], "size": len(body), "sha256": sha256,
                     "program": body[:2] == b"MZ" or body[:4] == b"\x7fELF"}
            entry["hash"] = hash_lookup(sha256, hashlib.md5(body).hexdigest())  # noqa: S324 - lookup key only
            entry["yara"] = yara_bytes(body)
            members.append(entry)
    return {"status": "ok", "members": members, "scanned": len(members), "skipped": skipped, "skip_reasons": reasons}
