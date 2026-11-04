"""EMBER2024: features, labels and tags; no raw files exist in this dataset.

Each official zip (HF ``joyce8/EMBER2024``, SHA-256 checked against the
Hub's LFS record) holds JSON-lines raw features. They are streamed out of
the zip, never unpacked to disk, turned into EMBER v3 vectors with the
official ``thrember`` extractor, and written to a float32 memmap plus a
parquet of metadata (hash, label, first-seen date, family, every tag).

The official train/test split is temporal (test files appeared after the
training period), so it is kept as is. A large train file can be
subsampled uniformly by hash, which is deterministic and unbiased in time.
"""
from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq
import requests

from repair_engine.data.fetch import HEADERS, TIMEOUT, download
from repair_engine.data.store import DataStore

TAG_FIELDS = ("behavior", "file_property", "packer", "exploit", "group")
META_FIELDS = ("sha256", "label", "first_submission_date", "last_analysis_date", "detection_ratio", "family",
               "family_confidence", "file_type")


def hub_files(repo: str) -> dict[str, dict]:
    url = f"https://huggingface.co/api/datasets/{repo}/tree/main"
    listing = requests.get(url, timeout=TIMEOUT, headers=HEADERS).json()
    return {item["path"]: item for item in listing if item.get("type") == "file"}


def _records(archive: Path):
    with zipfile.ZipFile(archive) as bundle:
        for member in bundle.infolist():
            if member.is_dir() or not member.filename.endswith(".jsonl"):
                continue
            with bundle.open(member) as handle:
                for line in io.TextIOWrapper(handle, encoding="utf-8"):
                    if line.strip():
                        yield json.loads(line)


def _keep(sha256: str, fraction: float) -> bool:
    return fraction >= 1.0 or int(sha256[:8], 16) < fraction * 0x100000000


def vectorise(store: DataStore, archive: Path, name: str, limit: int | None) -> dict:
    from thrember.features import PEFeatureExtractor  # heavy import, only when needed

    extractor = PEFeatureExtractor()
    total = sum(1 for _ in _records(archive)) if limit else None
    fraction = min(1.0, limit / total) if limit and total else 1.0
    stem = name.removesuffix(".zip")
    rows = int(total * fraction * 1.02) + 16 if total else sum(1 for _ in _records(archive))
    store.ensure_room(rows * extractor.dim * 4, f"{stem} vectors")
    vectors_path = store.features / f"ember_{stem}.npy"
    vectors = np.lib.format.open_memmap(vectors_path, mode="w+", dtype=np.float32, shape=(rows, extractor.dim))
    meta = {field: [] for field in META_FIELDS + TAG_FIELDS}
    kept = 0
    for record in _records(archive):
        sha256 = str(record.get("sha256", ""))
        if not sha256 or not _keep(sha256, fraction) or kept >= rows:
            continue
        vectors[kept] = np.asarray(extractor.process_raw_features(record), dtype=np.float32)
        for field in META_FIELDS:
            meta[field].append(record.get(field))
        for field in TAG_FIELDS:
            value = record.get(field) or []
            meta[field].append([str(v) for v in value] if isinstance(value, list) else [str(value)])
        kept += 1
    vectors.flush()
    del vectors
    _shrink(vectors_path, kept, extractor.dim)
    meta["label"] = [int(v) if v is not None else -1 for v in meta["label"]]
    meta["row"] = list(range(kept))
    meta["split"] = ["challenge" if stem == "challenge" else stem.rsplit("_", 1)[-1]] * kept
    meta["source_file"] = [name] * kept
    pq.write_table(pa.table(meta), store.features / f"ember_{stem}.parquet")
    summary = {"file": name, "rows": kept, "of": total, "dim": extractor.dim}
    store.log("ember_vectorised", **summary)
    return summary


def _shrink(path: Path, rows: int, dim: int) -> None:
    """Drop the unused tail rows of an .npy memmap."""
    full = np.load(path, mmap_mode="r")
    if full.shape[0] == rows:
        return
    trimmed = path.with_name(path.stem + ".trim.npy")
    out = np.lib.format.open_memmap(trimmed, mode="w+", dtype=np.float32, shape=(rows, dim))
    for start in range(0, rows, 50_000):
        end = min(start + 50_000, rows)  # the source has more rows than are kept: stop at the last kept one
        out[start:end] = full[start:end]
    out.flush()
    del out, full
    trimmed.replace(path)


def run(store: DataStore, names: list[str] | None = None) -> list[dict]:
    settings = store.config["ember2024"]
    listing = hub_files(settings["repo"])
    done = []
    for name in names if names is not None else settings["files"]:
        stem = name.removesuffix(".zip")
        if (store.features / f"ember_{stem}.parquet").exists():
            continue
        entry = listing[name]
        archive = download(store, f"https://huggingface.co/datasets/{settings['repo']}/resolve/main/{name}",
                           store.downloads / name, size=entry["size"], sha256=entry["lfs"]["oid"])
        limit = settings["max_train_per_file"] if name.endswith("_train.zip") else None
        done.append(vectorise(store, archive, name, limit))
        if name in settings.get("delete_zip_after_vectorising", []):
            archive.unlink()
            store.log("deleted", path=str(archive), reason="vectorised; re-downloadable and verifiable")
    return done
