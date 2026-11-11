"""Removed regions go to the encrypted quarantine, never to plain disk.

Each removed byte range is sealed with AES-GCM in the project's existing
vault format (``CSQ1`` + nonce + ciphertext + tag, as written by
``core.scanner.quarantine_file``), so ``core.scanner.restore_quarantined_file``
opens it with the same key. A JSON sidecar records only non-secret facts:
offsets, label, size and the SHA-256 of the plaintext.
"""
from __future__ import annotations

import hashlib
import json
import secrets
import uuid
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from repair_engine.executor.common import Removed

MAGIC = b"CSQ1"


def seal(removed: list[Removed], key: bytes, vault: Path, source_sha256: str) -> list[Path]:
    if not isinstance(key, bytes) or len(key) not in {16, 24, 32}:
        raise ValueError("AES-GCM key must be 16, 24 or 32 bytes, supplied by the caller")
    vault.mkdir(parents=True, exist_ok=True)
    cipher = AESGCM(key)
    written = []
    for region in removed:
        nonce = secrets.token_bytes(12)
        sealed = cipher.encrypt(nonce, region.data, None)  # ciphertext + 16-byte tag
        stem = f"{source_sha256[:16]}.{region.start:x}-{region.end:x}.{uuid.uuid4().hex[:8]}"
        path = vault / f"{stem}.csq"
        path.write_bytes(MAGIC + nonce + sealed)
        (vault / f"{stem}.json").write_text(json.dumps({
            "source_sha256": source_sha256, "start": region.start, "end": region.end, "label": region.label,
            "size": len(region.data), "sha256": hashlib.sha256(region.data).hexdigest(),
        }, indent=2), encoding="utf-8")
        written.append(path)
    return written
