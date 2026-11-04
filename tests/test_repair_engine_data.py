"""Phase 1 plumbing, tested offline: storage, budget, verification, streaming,
SOREL disarm check, EMBER vectorisation and the manifest. No network."""
from __future__ import annotations

import hashlib
import io
import json
import socket
import struct
import tarfile
import threading
import zipfile
import zlib

import numpy as np
import pyarrow.parquet as pq
import pytest

from repair_engine.data import benign, ember, manifest, sorel, verify
from repair_engine.data.fetch import s3_multipart_etag
from repair_engine.data.store import BudgetError, DataStore
from repair_fixtures import PLACEHOLDER, build_pe


@pytest.fixture
def store(tmp_path):
    return DataStore({
        "data_root": str(tmp_path / "data"),
        "budget": {"max_total_gb": 1, "min_free_gb": 0},
        "sorel20m": {"binaries": 2, "base_url": "https://invalid", "selection_seed": 1},
        "benign": {"assemblage": {"stream_first": 2, "url": "https://invalid"}},
    })


def test_samples_are_named_by_hash_and_never_by_their_original_name(store):
    sha256, path = store.put_sample("pending", b"hello")
    assert sha256 == hashlib.sha256(b"hello").hexdigest() and path.name == f"{sha256}.bin"
    with pytest.raises(ValueError):
        store.sample_path("pending", "../../evil")


def test_budget_refuses_downloads_that_do_not_fit(store):
    with pytest.raises(BudgetError):
        store.ensure_room(2 * 1024 ** 3, "too big")
    store.ensure_room(1024, "small")


def test_s3_multipart_etag(tmp_path):
    data = bytes(range(256)) * 100
    path = tmp_path / "blob"
    path.write_bytes(data)
    parts = [data[i:i + 10_000] for i in range(0, len(data), 10_000)]
    expected = hashlib.md5(b"".join(hashlib.md5(p).digest() for p in parts)).hexdigest() + f"-{len(parts)}"
    assert s3_multipart_etag(path, len(parts), part_size=10_000) == expected


def test_napierone_hash_file_sha256_is_found():
    text = " MD5               16               99f1\n\n SHA-256           32               " + "ab" * 32 + "\n"
    assert benign._SHA256_LINE.search(text).group(1) == "ab" * 32


def test_assemblage_stream_keeps_only_pe_files_and_stops_early(store, monkeypatch):
    pe, _facts = build_pe()
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:xz") as archive:
        for name, data in (("a.txt", b"text"), ("b.exe", pe), ("c.dll", pe + b"x"), ("d.exe", pe + b"yy")):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    blob = buffer.getvalue()
    monkeypatch.setattr(benign, "stream", lambda url: (blob[i:i + 777] for i in range(0, len(blob), 777)))
    rows: list[dict] = []
    benign.assemblage(store, rows)
    assert [row["original_name"] for row in rows] == ["b.exe", "c.dll"]  # stream_first = 2
    assert all(store.sample_path("pending", row["sha256"]).exists() for row in rows)


def test_sorel_disarm_check_reads_the_zeroed_machine_field_in_memory():
    pe, _facts = build_pe()
    disarmed = bytearray(pe)
    struct.pack_into("<H", disarmed, 0x80 + 4, 0)  # Machine = 0, as Sophos distributes
    info = sorel.check_disarmed(zlib.compress(bytes(disarmed)))
    assert info == {"decompressed_size": len(pe), "machine_field": 0}
    with pytest.raises(ValueError):
        sorel.check_disarmed(zlib.compress(b"not a pe"))
    assert sorel.split_of(1.0) == "train" and sorel.split_of(1_600_000_000) == "test"


class FakeClamd:
    """Answers PING and INSTREAM; reports a find when the stream holds a marker."""

    def __init__(self):
        self.server = socket.socket()
        self.server.bind(("127.0.0.1", 0))
        self.server.listen()
        self.address = self.server.getsockname()
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                connection, _ = self.server.accept()
            except OSError:
                return
            with connection:
                command = connection.recv(10)
                if command.startswith(b"zPING"):
                    connection.sendall(b"PONG\0")
                    continue
                payload = b""
                while True:
                    (size,) = struct.unpack(">I", self._exact(connection, 4))
                    if size == 0:
                        break
                    payload += self._exact(connection, size)
                found = b"MARKER-FOR-TEST" in payload
                connection.sendall(b"stream: Test.Marker FOUND\0" if found else b"stream: OK\0")

    @staticmethod
    def _exact(connection, size):
        data = b""
        while len(data) < size:
            data += connection.recv(size - len(data))
        return data


def test_verification_moves_clean_files_and_drops_any_hit(store, monkeypatch):
    clamd = FakeClamd()
    monkeypatch.setattr(verify, "CLAMD", clamd.address)
    import yara

    monkeypatch.setattr(verify, "yara_rules", lambda _store: yara.compile(source='rule Yr { strings: $a = "YARA-HIT" condition: $a }'))
    clean, _ = store.put_sample("pending", PLACEHOLDER * 3)
    clam_hit, _ = store.put_sample("pending", b"MARKER-FOR-TEST" + bytes(3_000_000))  # spans several chunks
    yara_hit, _ = store.put_sample("pending", b"some YARA-HIT bytes")
    counts = verify.run(store)
    assert counts == {"clean": 1, "dropped": 2}
    assert store.sample_path("benign", clean).exists()
    assert not store.sample_path("pending", clam_hit).exists() and not store.sample_path("benign", clam_hit).exists()
    table = {row["sha256"]: row for row in pq.read_table(store.meta / "benign_verification.parquet").to_pylist()}
    assert table[clam_hit]["clamav"] == "Test.Marker" and table[yara_hit]["yara"] == ["Yr"]


def test_ember_records_are_vectorised_from_the_zip_without_unpacking(store, tmp_path):
    from thrember.features import PEFeatureExtractor

    extractor = PEFeatureExtractor()
    records = []
    for index in range(5):
        pe, _ = build_pe(overlay=bytes([index]) * 64)
        raw = extractor.raw_features(pe)
        raw.update({"label": index % 2, "family": "fam" if index % 2 else "", "behavior": ["dropper"] if index % 2 else [],
                    "first_submission_date": f"2024-01-0{index + 1}", "file_type": "Win32"})
        records.append(raw)
    archive = tmp_path / "Win32_test.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("Win32_test/part0.jsonl", "\n".join(json.dumps(r) for r in records))
    summary = ember.vectorise(store, archive, "Win32_test.zip", limit=None)
    assert summary["rows"] == 5
    vectors = np.load(store.features / "ember_Win32_test.npy")
    assert vectors.shape == (5, extractor.dim)
    assert np.allclose(vectors[0], extractor.process_raw_features(records[0]))
    meta = pq.read_table(store.features / "ember_Win32_test.parquet").to_pylist()
    assert [m["label"] for m in meta] == [0, 1, 0, 1, 0] and meta[1]["behavior"] == ["dropper"]
    assert {m["split"] for m in meta} == {"test"}


def test_manifest_lists_raw_files_and_feature_rows(store):
    sha256, path = store.put_sample("benign", PLACEHOLDER)
    import pyarrow as pa

    pq.write_table(pa.Table.from_pylist([{"sha256": sha256, "source": "govdocs1/000", "original_name": "a.txt",
                                          "extension": ".txt", "size": len(PLACEHOLDER)}]),
                   store.meta / "benign_collected.parquet")
    counts = manifest.build(store)
    rows = pq.read_table(store.root / "manifest.parquet").to_pylist()
    assert counts == {"govdocs1:benign:" + manifest.hash_split(sha256): 1}
    assert rows[0]["path"] == str(path.relative_to(store.root)) and rows[0]["label"] == "benign"


def test_shrink_keeps_exactly_the_written_rows(tmp_path):
    """Found when vectorising EMBER PDF_train: the last chunk overran the trimmed array."""
    import numpy as np

    from repair_engine.data.ember import _shrink

    path = tmp_path / "vectors.npy"
    full = np.lib.format.open_memmap(path, mode="w+", dtype=np.float32, shape=(6096, 8))
    full[:] = np.arange(6096, dtype=np.float32)[:, None]
    full.flush()
    del full
    _shrink(path, 4000, 8)
    kept = np.load(path)
    assert kept.shape == (4000, 8) and kept[-1, 0] == 3999
