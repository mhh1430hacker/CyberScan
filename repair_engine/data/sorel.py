"""SOREL-20M: metadata for a seeded sample of malware, and their disarmed bytes.

``meta.db`` is verified against its S3 multipart ETag, read with sqlite
(read-only), and only the rows for the chosen samples are kept (as parquet)
before the 3.8 GB database is deleted. Binaries are fetched exactly as
Sophos distributes them, disarmed (Machine and Subsystem header fields set
to 0) and zlib-compressed, and are stored that way. They are decompressed
only in memory, to check they are what they claim to be; the disarmed
fields are never restored.

Split: SOREL's own temporal boundaries on first-seen time (``rl_fs_t``).
"""
from __future__ import annotations

import random
import sqlite3
import struct
import zlib

import pyarrow as pa
import pyarrow.parquet as pq
import requests

from repair_engine.data.fetch import HEADERS, TIMEOUT, VerificationError, download, retrying, s3_multipart_etag
from repair_engine.data.store import DataStore

# From the SOREL-20M baseline configuration: train before, test after.
TRAIN_BEFORE = 1547279640.0
TEST_FROM = 1551052800.0


def _etag(url: str) -> tuple[str, int]:
    response = requests.head(url, timeout=TIMEOUT, headers=HEADERS)
    response.raise_for_status()
    return response.headers["ETag"].strip('"'), int(response.headers["Content-Length"])


def split_of(first_seen: float) -> str:
    if first_seen < TRAIN_BEFORE:
        return "train"
    return "validation" if first_seen < TEST_FROM else "test"


def fetch_meta(store: DataStore):
    settings = store.config["sorel20m"]
    url = f"{settings['base_url']}/{settings['meta_db']}"
    etag, size = _etag(url)
    path = download(store, url, store.downloads / "sorel_meta.db", size=size)
    if not store.meta.joinpath("sorel_meta_checked").exists():
        parts = int(etag.rsplit("-", 1)[1]) if "-" in etag else 1
        got = s3_multipart_etag(path, parts) if parts > 1 else None
        if got is not None and got != etag:
            path.unlink()
            raise VerificationError(f"meta.db: multipart ETag {got} != published {etag}")
        store.meta.joinpath("sorel_meta_checked").write_text(etag)
        store.log("verified", path=str(path), check="s3_multipart_etag", etag=etag)
    return path


def select(store: DataStore, db_path) -> list[dict]:
    """A seeded uniform sample of malware rows, with every column kept."""
    settings = store.config["sorel20m"]
    target = store.meta / "sorel_selected.parquet"
    if target.exists():
        return pq.read_table(target).to_pylist()
    connection = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        columns = [row[1] for row in connection.execute("PRAGMA table_info(meta)")]
        (highest,) = connection.execute("SELECT MAX(rowid) FROM meta").fetchone()
        rng = random.Random(settings["selection_seed"])
        chosen: list[dict] = []
        seen: set[int] = set()
        while len(chosen) < settings["binaries"] * 1.15:  # spare rows for failed downloads
            batch = [rowid for rowid in rng.sample(range(1, highest + 1), 4000) if rowid not in seen]
            seen.update(batch)
            marks = ",".join("?" * len(batch))
            for row in connection.execute(f"SELECT * FROM meta WHERE rowid IN ({marks}) AND is_malware = 1", batch):
                chosen.append(dict(zip(columns, row)))
        (malware,) = connection.execute("SELECT COUNT(*) FROM meta WHERE is_malware = 1").fetchone()
    finally:
        connection.close()
    for row in chosen:
        row["split"] = split_of(float(row.get("rl_fs_t") or 0))
    pq.write_table(pa.Table.from_pylist(chosen), target)
    store.log("sorel_selected", rows=len(chosen), columns=columns, malware_in_db=malware)
    return chosen


def check_disarmed(blob: bytes) -> dict:
    """Decompress in memory; confirm a PE whose Machine field is 0 (disarmed)."""
    data = zlib.decompressobj().decompress(blob, 256 * 1024 * 1024)
    if data[:2] != b"MZ" or len(data) < 0x40:
        raise ValueError("not a PE after decompression")
    lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    machine = struct.unpack_from("<H", data, lfanew + 4)[0] if lfanew + 6 <= len(data) else None
    return {"decompressed_size": len(data), "machine_field": machine}


def fetch_binaries(store: DataStore, rows: list[dict]) -> list[dict]:
    settings = store.config["sorel20m"]
    fetched: list[dict] = []
    for row in rows:
        if len(fetched) >= settings["binaries"]:
            break
        sha256 = row["sha256"]
        path = store.sample_path("malicious", sha256)
        url = f"{settings['base_url']}/binaries/{sha256}"
        try:
            if not path.exists():
                etag, size = retrying(_etag, url, store=store, what=sha256)
                download(store, url, path, size=size, md5=etag if "-" not in etag else None)
            info = check_disarmed(path.read_bytes())
        except Exception as exc:  # noqa: BLE001 - a bad sample is skipped and logged, never patched
            if path.exists():
                path.unlink()
            store.log("sorel_skipped", sha256=sha256, reason=f"{type(exc).__name__}: {exc}")
            continue
        fetched.append({**row, **info, "stored_size": path.stat().st_size, "path": str(path)})
    pq.write_table(pa.Table.from_pylist(fetched), store.meta / "sorel_binaries.parquet")
    store.log("sorel_binaries", count=len(fetched))
    return fetched


def run(store: DataStore) -> int:
    settings = store.config["sorel20m"]
    if not (store.meta / "sorel_selected.parquet").exists():
        db_path = fetch_meta(store)
        select(store, db_path)
        if settings.get("delete_meta_db_after_extract"):
            db_path.unlink()
            store.log("deleted", path=str(db_path), reason="selected rows kept in meta/sorel_selected.parquet")
    rows = pq.read_table(store.meta / "sorel_selected.parquet").to_pylist()
    return len(fetch_binaries(store, rows))
