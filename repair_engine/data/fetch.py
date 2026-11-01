"""HTTP downloads that resume, respect the budget and verify what arrived.

A file is only renamed into place after its size and published hash match;
a mismatch deletes the partial file and raises. Nothing downloaded is ever
opened by another program.
"""
from __future__ import annotations

import hashlib
from collections.abc import Iterator
from pathlib import Path

import requests
import truststore

from repair_engine.data.store import DataStore

# Verify TLS against the Windows certificate store (Python's bundled list
# lacks roots this machine trusts). Verification itself is never disabled.
truststore.inject_into_ssl()

CHUNK = 1 << 20
TIMEOUT = 60
HEADERS = {"User-Agent": "CyberScan-repair-engine-data/1.0 (research dataset fetch)"}


class VerificationError(RuntimeError):
    """A download did not match its published size or hash."""


def head_size(url: str) -> int | None:
    response = requests.head(url, allow_redirects=True, timeout=TIMEOUT, headers=HEADERS)
    response.raise_for_status()
    value = response.headers.get("Content-Length")
    return int(value) if value else None


def s3_multipart_etag(path: Path, parts: int, part_size: int = 8 * 1024 * 1024) -> str:
    """S3's ETag for a multipart upload: md5 of the parts' md5s, then "-<parts>"."""
    digests = b""
    with path.open("rb") as handle:
        while chunk := handle.read(part_size):
            digests += hashlib.md5(chunk).digest()
    return f"{hashlib.md5(digests).hexdigest()}-{parts}"


def download(
    store: DataStore,
    url: str,
    destination: Path,
    *,
    size: int | None = None,
    sha256: str | None = None,
    md5: str | None = None,
) -> Path:
    """Fetch ``url`` to ``destination`` (resuming a .part file), then verify."""
    if destination.exists():
        return destination
    expected = size if size is not None else head_size(url)
    partial = destination.with_name(destination.name + ".part")
    have = partial.stat().st_size if partial.exists() else 0
    if expected is not None:
        store.ensure_room(expected - have, destination.name)
    headers = dict(HEADERS)
    if have:
        headers["Range"] = f"bytes={have}-"
    with requests.get(url, stream=True, timeout=TIMEOUT, headers=headers, allow_redirects=True) as response:
        if have and response.status_code != 206:  # the server ignored the range: start again
            have = 0
        response.raise_for_status()
        with partial.open("ab" if have else "wb") as handle:
            for chunk in response.iter_content(CHUNK):
                handle.write(chunk)
    got = partial.stat().st_size
    if expected is not None and got != expected:
        partial.unlink()
        raise VerificationError(f"{destination.name}: {got} bytes, expected {expected}")
    for name, value in (("sha256", sha256), ("md5", md5)):
        if value:
            digest = _file_digest(partial, name)
            if digest != value.lower():
                partial.unlink()
                store.log("download_rejected", url=url, check=name, expected=value, got=digest)
                raise VerificationError(f"{destination.name}: {name} {digest} != published {value}")
    partial.replace(destination)
    store.log("downloaded", url=url, path=str(destination), bytes=got,
              verified=[name for name, value in (("sha256", sha256), ("md5", md5)) if value] or ["size"])
    return destination


def stream(url: str) -> Iterator[bytes]:
    """The response body as chunks, for archives read without storing them."""
    with requests.get(url, stream=True, timeout=TIMEOUT, headers=HEADERS, allow_redirects=True) as response:
        response.raise_for_status()
        yield from response.iter_content(CHUNK)


def fetch_bytes(url: str) -> bytes:
    response = requests.get(url, timeout=TIMEOUT, headers=HEADERS, allow_redirects=True)
    response.raise_for_status()
    return response.content


def _file_digest(path: Path, name: str) -> str:
    digest = hashlib.new(name)
    with path.open("rb") as handle:
        while chunk := handle.read(CHUNK):
            digest.update(chunk)
    return digest.hexdigest()
