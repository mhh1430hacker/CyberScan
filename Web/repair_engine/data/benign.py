"""Benign raw files: Govdocs1, NapierOne (plain variants), and a streamed slice
of Assemblage_PE. Everything lands in ``samples/pending`` and only moves to
``samples/benign`` after ClamAV and YARA find nothing (``verify.py``).

Archives are read member by member in memory (zip) or as a stream (tar.xz);
nothing is extracted by path, so archive member names cannot write outside
the store. Every stored file is renamed to its own SHA-256.
"""
from __future__ import annotations

import re
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

import pyarrow as pa
import pyarrow.parquet as pq

from repair_engine.data.fetch import download, fetch_bytes, stream
from repair_engine.data.store import DataStore

MAX_MEMBER = 64 * 1024 * 1024
_SHA256_LINE = re.compile(r"SHA[- ]?256\s+\d+\s+([0-9a-fA-F]{64})")


class _Chunks:
    """A read()-able view of an iterator of byte chunks (for tarfile's stream mode)."""

    def __init__(self, chunks):
        self._chunks, self._buffer = iter(chunks), b""

    def read(self, size: int = -1) -> bytes:
        while size < 0 or len(self._buffer) < size:
            try:
                self._buffer += next(self._chunks)
            except StopIteration:
                break
        if size < 0:
            data, self._buffer = self._buffer, b""
        else:
            data, self._buffer = self._buffer[:size], self._buffer[size:]
        return data


def _checkpoint(store: DataStore, rows: list[dict]) -> None:
    pq.write_table(pa.Table.from_pylist(rows), store.meta / "benign_collected.parquet")


def _done(rows: list[dict], source: str) -> bool:
    return any(row["source"] == source for row in rows)


def _store_zip_members(store: DataStore, archive: Path, source: str, rows: list[dict]) -> None:
    with zipfile.ZipFile(archive) as bundle:
        for member in bundle.infolist():
            if member.is_dir() or member.file_size == 0 or member.file_size > MAX_MEMBER:
                continue
            if member.flag_bits & 0x1:  # encrypted member: not a plain benign file
                store.log("member_skipped", source=source, name=member.filename, reason="encrypted")
                continue
            data = bundle.read(member)
            sha256, _path = store.put_sample("pending", data)
            rows.append({"sha256": sha256, "source": source, "original_name": PurePosixPath(member.filename).name,
                         "extension": PurePosixPath(member.filename).suffix.lower(), "size": len(data)})


def govdocs(store: DataStore, rows: list[dict]) -> None:
    settings = store.config["benign"]["govdocs1"]
    published = {}
    for line in fetch_bytes(settings["md5_list"]).decode().splitlines():
        parts = line.split()
        if len(parts) == 2:
            published[PurePosixPath(parts[1]).name] = parts[0]
    for thread in settings["threads"]:
        name = f"{thread}.zip"
        if _done(rows, f"govdocs1/{thread}"):
            continue
        archive = download(store, f"{settings['base_url']}/{name}", store.downloads / f"govdocs1_{name}", md5=published[name])
        _store_zip_members(store, archive, f"govdocs1/{thread}", rows)
        _checkpoint(store, rows)
        archive.unlink()
        store.log("deleted", path=str(archive), reason="members stored as samples")


def napierone(store: DataStore, rows: list[dict]) -> None:
    settings = store.config["benign"]["napierone"]
    for level in ("small", "tiny"):
        for kind in settings[level]:
            stem = f"{kind}/{kind}-{level}"
            if _done(rows, f"napierone/{kind}-{level}"):
                continue
            if any(part in stem.upper() for part in ("EXTRA", "ENCRYPTED", "PASSWORD", "NOMAGIC")):
                raise ValueError(f"{stem}: not a plain, clean NapierOne subset")
            listing = fetch_bytes(f"{settings['base_url']}/{stem}_zip_hashes.txt").decode("latin-1")
            match = _SHA256_LINE.search(listing)
            if match is None:
                raise ValueError(f"{stem}: no SHA-256 in the published hash file")
            archive = download(store, f"{settings['base_url']}/{stem}.zip", store.downloads / f"napierone_{kind}-{level}.zip",
                               sha256=match.group(1))
            _store_zip_members(store, archive, f"napierone/{kind}-{level}", rows)
            _checkpoint(store, rows)
            archive.unlink()
            store.log("deleted", path=str(archive), reason="members stored as samples")


def assemblage(store: DataStore, rows: list[dict]) -> None:
    settings = store.config["benign"]["assemblage"]
    wanted, found = int(settings["stream_first"]), 0
    if _done(rows, "assemblage_pe"):
        return
    store.ensure_room(wanted * 1024 * 1024, "assemblage stream")
    with tarfile.open(fileobj=_Chunks(stream(settings["url"])), mode="r|xz") as archive:
        for member in archive:
            if found >= wanted:
                break
            if not member.isfile() or member.size == 0 or member.size > MAX_MEMBER:
                continue
            handle = archive.extractfile(member)
            data = handle.read() if handle else b""
            if data[:2] != b"MZ":
                continue
            sha256, _path = store.put_sample("pending", data)
            rows.append({"sha256": sha256, "source": "assemblage_pe", "original_name": PurePosixPath(member.name).name,
                         "extension": PurePosixPath(member.name).suffix.lower(), "size": len(data)})
            found += 1
    _checkpoint(store, rows)
    store.log("assemblage_streamed", files=found, note="archive hash not checkable on a partial stream")


def run(store: DataStore) -> int:
    target = store.meta / "benign_collected.parquet"
    rows: list[dict] = pq.read_table(target).to_pylist() if target.exists() else []
    for step in (govdocs, napierone, assemblage):
        step(store, rows)  # each archive checkpoints itself, so a rerun resumes
    return len(rows)
