"""Benign sets must be clean: every pending file is scanned by ClamAV and by
the YARA Forge core rules; any hit is dropped and logged, the rest move to
``samples/benign``.

ClamAV is reached through clamd's INSTREAM command on localhost: the file's
bytes are sent over the socket, so no sample path is ever handed to another
program. YARA matches the bytes in memory.
"""
from __future__ import annotations

import socket
import struct
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq
import yara

from repair_engine.data.store import DataStore

CLAMD = ("127.0.0.1", 3310)
CHUNK = 1 << 20


def clamd_config(store: DataStore) -> dict[str, Path]:
    """Write freshclam/clamd configs next to the portable ClamAV build."""
    home = next(store.tools.joinpath("clamav").glob("clamav-*"), store.tools / "clamav")
    database = store.tools / "clamav-db"
    database.mkdir(exist_ok=True)
    freshclam = home / "freshclam.conf"
    freshclam.write_text(f'DatabaseDirectory "{database}"\nDatabaseMirror database.clamav.net\n', encoding="utf-8")
    clamd = home / "clamd.conf"
    clamd.write_text(
        f'DatabaseDirectory "{database}"\nTCPSocket {CLAMD[1]}\nTCPAddr {CLAMD[0]}\n'
        "StreamMaxLength 100M\nMaxFileSize 100M\nMaxScanSize 400M\n",
        encoding="utf-8",
    )
    return {"home": home, "freshclam": freshclam, "clamd": clamd, "database": database}


def clamd_ping() -> bool:
    try:
        with socket.create_connection(CLAMD, timeout=5) as connection:
            connection.sendall(b"zPING\0")
            return connection.recv(64).startswith(b"PONG")
    except OSError:
        return False


def clamd_scan(data: bytes) -> str | None:
    """None when clean, else the signature name ClamAV reported."""
    with socket.create_connection(CLAMD, timeout=120) as connection:
        connection.sendall(b"zINSTREAM\0")
        for start in range(0, len(data), CHUNK):
            chunk = data[start:start + CHUNK]
            connection.sendall(struct.pack(">I", len(chunk)) + chunk)
        connection.sendall(struct.pack(">I", 0))
        reply = b""
        while not reply.endswith(b"\0"):
            part = connection.recv(4096)
            if not part:
                break
            reply += part
    text = reply.rstrip(b"\0").decode("utf-8", "replace")
    if text.endswith("OK"):
        return None
    if text.endswith("FOUND"):
        return text.removeprefix("stream: ").removesuffix(" FOUND")
    raise RuntimeError(f"clamd: {text}")


def yara_rules(store: DataStore) -> yara.Rules:
    rule_files = sorted(store.tools.joinpath("yara").rglob("*.yar"))
    if not rule_files:
        raise FileNotFoundError("YARA Forge rules are missing; run the tools step first")
    return yara.compile(filepaths={str(index): str(path) for index, path in enumerate(rule_files)})


def run(store: DataStore) -> dict[str, int]:
    if not clamd_ping():
        raise RuntimeError("clamd is not answering on 127.0.0.1:3310; start it first (see the README)")
    rules = yara_rules(store)
    results_path = store.meta / "benign_verification.parquet"
    results = pq.read_table(results_path).to_pylist() if results_path.exists() else []
    counts = {"clean": 0, "dropped": 0}
    pending = sorted(store.samples.joinpath("pending").glob("*.bin"))
    for number, path in enumerate(pending, 1):
        sha256 = path.stem
        try:
            data = path.read_bytes()
        except OSError as exc:  # a local antivirus can block a file after it is written
            store.drop_sample("pending", sha256, reason=f"unreadable after writing (local antivirus?): {exc}")
            results.append({"sha256": sha256, "clamav": None, "yara": [], "clean": False, "blocked": True})
            counts["dropped"] += 1
            continue
        clam = clamd_scan(data)
        try:
            hits = [match.rule for match in rules.match(data=data, timeout=60)]
        except yara.TimeoutError:
            hits = ["<yara timeout>"]
        if clam or hits:
            store.drop_sample("pending", sha256, reason=f"clamav={clam} yara={hits}")
            counts["dropped"] += 1
        else:
            store.move_sample(sha256, "pending", "benign")
            counts["clean"] += 1
        results.append({"sha256": sha256, "clamav": clam, "yara": hits, "clean": not (clam or hits)})
        if number % 500 == 0:
            pq.write_table(pa.Table.from_pylist(results), results_path)
    pq.write_table(pa.Table.from_pylist(results), results_path)
    store.log("benign_verified", **counts)
    return counts
