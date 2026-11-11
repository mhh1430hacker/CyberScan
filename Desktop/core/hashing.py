from __future__ import annotations

import hashlib
import re
from pathlib import Path


def compute_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compute_file_sha256(file_path: str | Path) -> str:
    path = Path(file_path)
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def is_valid_sha256(value: str) -> bool:
    return bool(re.fullmatch(r"[a-fA-F0-9]{64}", value or ""))


def is_valid_md5(value: str) -> bool:
    return bool(re.fullmatch(r"[a-fA-F0-9]{32}", value or ""))


def is_valid_sha1(value: str) -> bool:
    return bool(re.fullmatch(r"[a-fA-F0-9]{40}", value or ""))


def compute_hashes(data: bytes) -> dict[str, str]:
    return {
        "sha256": compute_sha256(data),
        "sha1": hashlib.sha1(data).hexdigest(),
        "md5": hashlib.md5(data).hexdigest(),
    }
