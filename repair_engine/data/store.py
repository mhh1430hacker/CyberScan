"""Where Phase 1 data lives, how much room it may take, and what was done.

Layout under ``data_root`` (outside the repository)::

    samples/malicious/<sha256>.bin   SOREL binaries, zlib-compressed as distributed
    samples/benign/<sha256>.bin      verified-clean benign files
    samples/pending/<sha256>.bin     benign files waiting for ClamAV + YARA
    features/                        EMBER2024 vectors and their metadata
    downloads/                       archives while they are being processed
    meta/                            per-source metadata (parquet / jsonl)
    logs/phase1.jsonl                every download, check, drop and deletion
    tools/                           ClamAV, YARA rules (the only place with programs)

Samples are written as bytes and never given an executable name; the
samples folder also carries an NTFS deny-execute ACL (set up once, see the
README). Nothing in this module runs, opens or loads a sample.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import time
from pathlib import Path
from typing import Any

import yaml

CONFIG = Path(__file__).resolve().parents[1] / "config" / "data.yaml"
GB = 1024 ** 3


class BudgetError(RuntimeError):
    """A download would break the disk budget in data.yaml."""


def load_config(path: Path = CONFIG) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        return yaml.safe_load(handle)


class DataStore:
    GROUPS = ("malicious", "benign", "pending")

    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or load_config()
        self.root = Path(self.config["data_root"])
        self.samples = self.root / "samples"
        self.features = self.root / "features"
        self.downloads = self.root / "downloads"
        self.meta = self.root / "meta"
        self.logs = self.root / "logs"
        self.tools = self.root / "tools"
        for folder in (self.features, self.downloads, self.meta, self.logs, self.tools,
                       *(self.samples / group for group in self.GROUPS)):
            folder.mkdir(parents=True, exist_ok=True)
        budget = self.config["budget"]
        self.max_total = float(budget["max_total_gb"]) * GB
        self.min_free = float(budget["min_free_gb"]) * GB

    # -- bookkeeping -------------------------------------------------------------
    def log(self, event: str, **fields: Any) -> None:
        record = {"time": time.strftime("%Y-%m-%dT%H:%M:%S"), "event": event, **fields}
        with (self.logs / "phase1.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, default=str) + "\n")

    def used_bytes(self) -> int:
        return sum(path.stat().st_size for path in self.root.rglob("*") if path.is_file())

    def free_bytes(self) -> int:
        return shutil.disk_usage(self.root).free

    def ensure_room(self, incoming: int, what: str) -> None:
        free, used = self.free_bytes(), self.used_bytes()
        if free - incoming < self.min_free:
            raise BudgetError(f"{what}: {incoming / GB:.2f} GB would leave {(free - incoming) / GB:.2f} GB free "
                              f"(minimum {self.min_free / GB:.0f} GB)")
        if used + incoming > self.max_total:
            raise BudgetError(f"{what}: data_root would reach {(used + incoming) / GB:.2f} GB "
                              f"(budget {self.max_total / GB:.0f} GB)")

    # -- samples ----------------------------------------------------------------------
    def sample_path(self, group: str, sha256: str) -> Path:
        if group not in self.GROUPS or len(sha256) != 64 or any(c not in "0123456789abcdef" for c in sha256):
            raise ValueError(f"bad sample address {group}/{sha256}")
        return self.samples / group / f"{sha256}.bin"

    def put_sample(self, group: str, data: bytes, sha256: str | None = None) -> tuple[str, Path]:
        """Store bytes as <sha256>.bin. ``sha256`` is given only for SOREL, whose
        published id is the hash of the original (pre-disarming) file."""
        digest = sha256 or hashlib.sha256(data).hexdigest()
        path = self.sample_path(group, digest)
        if not path.exists():
            temporary = path.with_suffix(".part")
            temporary.write_bytes(data)
            temporary.replace(path)
        return digest, path

    def move_sample(self, sha256: str, source: str, target: str) -> Path:
        destination = self.sample_path(target, sha256)
        self.sample_path(source, sha256).replace(destination)
        return destination

    def drop_sample(self, group: str, sha256: str, reason: str) -> None:
        path = self.sample_path(group, sha256)
        try:
            path.unlink(missing_ok=True)
        except OSError as exc:  # locked by a local antivirus: leave it, but never count it as clean
            reason = f"{reason}; could not delete: {exc}"
        self.log("sample_dropped", group=group, sha256=sha256, reason=reason)
