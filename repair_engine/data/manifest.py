"""``manifest.parquet``: one row per sample, raw file or feature vector.

Columns: sha256, source, file_type, size, label, tags, split, path,
compression. Raw-file paths point at ``samples/``; EMBER2024 rows point
at their feature row (``features/ember_<file>.npy#<row>``) because the
dataset has no raw files.

Splits:
- EMBER2024: the official split, which is temporal.
- SOREL-20M: SOREL's own temporal boundaries on first-seen time.
- Benign raw sets: no trustworthy timestamps exist, so a deterministic
  80/10/10 split by hash. This is stated, not hidden: benign-side metrics
  are not temporal.
"""
from __future__ import annotations

import pyarrow as pa
import pyarrow.parquet as pq

from repair_engine.data.store import DataStore
from repair_engine.parsers import detect

SOREL_TAGS = ("adware", "flooder", "ransomware", "dropper", "spyware", "packed",
              "crypto_miner", "file_infector", "installer", "worm", "downloader")
EMBER_TAGS = ("behavior", "file_property", "packer", "exploit", "group")


def hash_split(sha256: str) -> str:
    bucket = int(sha256[:8], 16) % 10
    return "train" if bucket < 8 else ("validation" if bucket == 8 else "test")


def _ember_rows(store: DataStore) -> list[dict]:
    rows = []
    for table_path in sorted(store.features.glob("ember_*.parquet")):
        table = pq.read_table(table_path).to_pylist()
        vectors = table_path.with_suffix(".npy").name
        for record in table:
            tags = [f"{field}:{value}" for field in EMBER_TAGS for value in (record.get(field) or [])]
            if record.get("family"):
                tags.append(f"family:{record['family']}")
            label = {1: "malicious", 0: "benign"}.get(record["label"], "unlabelled")
            rows.append({"sha256": record["sha256"], "source": "ember2024", "file_type": str(record.get("file_type") or ""),
                         "size": None, "label": label, "tags": tags, "split": record["split"],
                         "path": f"features/{vectors}#{record['row']}", "compression": None})
    return rows


def _sorel_rows(store: DataStore) -> list[dict]:
    path = store.meta / "sorel_binaries.parquet"
    if not path.exists():
        return []
    rows = []
    for record in pq.read_table(path).to_pylist():
        tags = [tag for tag in SOREL_TAGS if (record.get(tag) or 0) > 0]
        rows.append({"sha256": record["sha256"], "source": "sorel20m", "file_type": "pe", "size": record["decompressed_size"],
                     "label": "malicious", "tags": tags, "split": record["split"],
                     "path": str(store.sample_path("malicious", record["sha256"]).relative_to(store.root)),
                     "compression": "zlib"})
    return rows


def _benign_rows(store: DataStore) -> list[dict]:
    collected = store.meta / "benign_collected.parquet"
    if not collected.exists():
        return []
    rows, seen = [], set()
    for record in pq.read_table(collected).to_pylist():
        sha256 = record["sha256"]
        path = store.sample_path("benign", sha256)
        if sha256 in seen or not path.exists():  # duplicate, or dropped / not yet verified
            continue
        seen.add(sha256)
        with path.open("rb") as handle:
            head = handle.read(64 * 1024)
        rows.append({"sha256": sha256, "source": record["source"], "file_type": detect(head),
                     "size": record["size"], "label": "benign", "tags": [f"extension:{record['extension']}"],
                     "split": hash_split(sha256), "path": str(path.relative_to(store.root)), "compression": None})
    return rows


def build(store: DataStore) -> dict[str, int]:
    rows = _ember_rows(store) + _sorel_rows(store) + _benign_rows(store)
    schema = pa.schema([("sha256", pa.string()), ("source", pa.string()), ("file_type", pa.string()), ("size", pa.int64()),
                        ("label", pa.string()), ("tags", pa.list_(pa.string())), ("split", pa.string()),
                        ("path", pa.string()), ("compression", pa.string())])
    pq.write_table(pa.Table.from_pylist(rows, schema=schema), store.root / "manifest.parquet")
    counts: dict[str, int] = {}
    for row in rows:
        key = f"{row['source'].split('/')[0]}:{row['label']}:{row['split']}"
        counts[key] = counts.get(key, 0) + 1
    store.log("manifest_built", rows=len(rows), counts=counts)
    return counts
