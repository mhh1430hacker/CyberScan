from __future__ import annotations

import hashlib
import json
import random
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np

from ml.dataset_manifest import ManifestEntry, load_manifest
from ml.feature_schema import LATENT_DIMENSION
from core.deep_embedding import HighDimensionalEmbedding


@dataclass
class DatasetSplit:
    train_indices: list[int]
    val_indices: list[int]
    test_indices: list[int]
    groups: dict[int, str]
    group_counts: dict[str, int]


@dataclass
class DatasetBundle:
    X: np.ndarray
    y: np.ndarray
    entries: list[ManifestEntry]
    splits: DatasetSplit
    feature_schema_version: str
    manifest_hash: str
    config_hash: str


def _hash_config(config: dict[str, Any]) -> str:
    serialized = json.dumps(config, sort_keys=True)
    return hashlib.sha256(serialized.encode()).hexdigest()[:16]


def _hash_manifest(entries: list[ManifestEntry]) -> str:
    serialized = "".join(e.sha256 for e in sorted(entries, key=lambda e: e.sha256))
    return hashlib.sha256(serialized.encode()).hexdigest()[:16]


def _infer_group(entry: ManifestEntry) -> str:
    # Use family if available (most specific)
    if entry.family:
        return f"family:{entry.family}"
    # For synthetic/internal data, use hash prefix to create meaningful groups
    # Only use source as grouping if it's not a generic/internal source
    if entry.source and entry.source.lower() not in ("internal", "synthetic", "unknown", ""):
        return f"source:{entry.source}"
    # Default: use hash prefix (first 4 chars gives up to 65536 groups)
    return f"hash:{entry.sha256[:4]}"


def group_aware_split(
    entries: list[ManifestEntry],
    train_ratio: float = 0.7,
    val_ratio: float = 0.15,
    test_ratio: float = 0.15,
    seed: int = 42,
) -> DatasetSplit:
    if abs(train_ratio + val_ratio + test_ratio - 1.0) > 1e-9:
        raise ValueError("Split ratios must sum to 1.0")

    groups = [_infer_group(e) for e in entries]
    group_to_indices: dict[str, list[int]] = defaultdict(list)
    for idx, g in enumerate(groups):
        group_to_indices[g].append(idx)

    group_names = list(group_to_indices.keys())
    rng = random.Random(seed)
    rng.shuffle(group_names)

    n_groups = len(group_names)
    n_train = int(n_groups * train_ratio)
    n_val = int(n_groups * val_ratio)

    train_groups = set(group_names[:n_train])
    val_groups = set(group_names[n_train:n_train + n_val])
    test_groups = set(group_names[n_train + n_val:])

    train_indices = [i for i, g in enumerate(groups) if g in train_groups]
    val_indices = [i for i, g in enumerate(groups) if g in val_groups]
    test_indices = [i for i, g in enumerate(groups) if g in test_groups]

    if not train_indices or not val_indices or not test_indices:
        raise ValueError(
            "Split produced empty partition. Increase dataset size or adjust ratios. "
            f"Groups: {len(group_names)}, train: {len(train_indices)}, val: {len(val_indices)}, test: {len(test_indices)}"
        )

    group_counts = {g: len(idxs) for g, idxs in group_to_indices.items()}

    return DatasetSplit(
        train_indices=train_indices,
        val_indices=val_indices,
        test_indices=test_indices,
        groups={i: g for i, g in enumerate(groups)},
        group_counts=group_counts,
    )


def random_split(
    entries: list[ManifestEntry],
    train_ratio: float = 0.7,
    val_ratio: float = 0.15,
    test_ratio: float = 0.15,
    seed: int = 42,
) -> DatasetSplit:
    if abs(train_ratio + val_ratio + test_ratio - 1.0) > 1e-9:
        raise ValueError("Split ratios must sum to 1.0")

    n = len(entries)
    indices = list(range(n))
    rng = random.Random(seed)
    rng.shuffle(indices)

    n_train = int(n * train_ratio)
    n_val = int(n * val_ratio)

    train_indices = indices[:n_train]
    val_indices = indices[n_train:n_train + n_val]
    test_indices = indices[n_train + n_val:]

    if not train_indices or not test_indices:
        raise ValueError("Split produced empty train or test partition. Increase dataset size.")

    groups = {i: f"singleton:{i}" for i in range(n)}
    group_counts = {f"singleton:{i}": 1 for i in range(n)}

    return DatasetSplit(
        train_indices=train_indices,
        val_indices=val_indices,
        test_indices=test_indices,
        groups=groups,
        group_counts=group_counts,
    )


def compute_embeddings(
    entries: list[ManifestEntry],
    dataset_root: Path,
    *,
    show_progress: bool = False,
) -> np.ndarray:
    embeddings = np.zeros((len(entries), LATENT_DIMENSION), dtype=np.float32)
    embedder = HighDimensionalEmbedding()

    for i, entry in enumerate(entries):
        file_path = dataset_root / entry.path
        try:
            with file_path.open("rb") as f:
                data = f.read()
        except OSError:
            embeddings[i] = 0.0
            continue

        try:
            vec = embedder.embed(data)
            embeddings[i] = np.array(vec, dtype=np.float32)
        except Exception:
            embeddings[i] = 0.0

        if show_progress and (i + 1) % 50 == 0:
            print(f"  Computed {i + 1}/{len(entries)} embeddings")

    return embeddings


def prepare_dataset(
    manifest_path: Path,
    dataset_root: Path,
    *,
    split_method: str = "group_aware",
    train_ratio: float = 0.7,
    val_ratio: float = 0.15,
    test_ratio: float = 0.15,
    seed: int = 42,
    compute_hashes: bool = True,
) -> DatasetBundle:
    entries = load_manifest(manifest_path, dataset_root, compute_hashes=compute_hashes)

    if split_method == "group_aware":
        splits = group_aware_split(entries, train_ratio, val_ratio, test_ratio, seed)
    elif split_method == "random":
        splits = random_split(entries, train_ratio, val_ratio, test_ratio, seed)
    else:
        raise ValueError(f"Unknown split_method: {split_method}")

    X = compute_embeddings(entries, dataset_root)

    label_to_int = {"clean": 0, "suspicious": 1, "malware": 2}
    y = np.array([label_to_int[e.label] for e in entries], dtype=np.int64)

    feature_schema_version = "cyberscan-4096-v1"
    manifest_hash = _hash_manifest(entries)
    config = {
        "split_method": split_method,
        "train_ratio": train_ratio,
        "val_ratio": val_ratio,
        "test_ratio": test_ratio,
        "seed": seed,
    }
    config_hash = _hash_config(config)

    return DatasetBundle(
        X=X,
        y=y,
        entries=entries,
        splits=splits,
        feature_schema_version=feature_schema_version,
        manifest_hash=manifest_hash,
        config_hash=config_hash,
    )


def get_split_data(bundle: DatasetBundle, split: str) -> tuple[np.ndarray, np.ndarray, list[int]]:
    if split == "train":
        indices = bundle.splits.train_indices
    elif split == "val":
        indices = bundle.splits.val_indices
    elif split == "test":
        indices = bundle.splits.test_indices
    else:
        raise ValueError(f"Unknown split: {split}")
    return bundle.X[indices], bundle.y[indices], indices


def check_leakage(bundle: DatasetBundle) -> list[str]:
    issues = []
    train_hashes = {bundle.entries[i].sha256 for i in bundle.splits.train_indices}
    val_hashes = {bundle.entries[i].sha256 for i in bundle.splits.val_indices}
    test_hashes = {bundle.entries[i].sha256 for i in bundle.splits.test_indices}

    if train_hashes & val_hashes:
        issues.append(f"Hash leakage between train and val: {train_hashes & val_hashes}")
    if train_hashes & test_hashes:
        issues.append(f"Hash leakage between train and test: {train_hashes & test_hashes}")
    if val_hashes & test_hashes:
        issues.append(f"Hash leakage between val and test: {val_hashes & test_hashes}")

    train_groups = {bundle.splits.groups[i] for i in bundle.splits.train_indices}
    val_groups = {bundle.splits.groups[i] for i in bundle.splits.val_indices}
    test_groups = {bundle.splits.groups[i] for i in bundle.splits.test_indices}

    if train_groups & val_groups:
        issues.append(f"Group leakage between train and val: {train_groups & val_groups}")
    if train_groups & test_groups:
        issues.append(f"Group leakage between train and test: {train_groups & test_groups}")
    if val_groups & test_groups:
        issues.append(f"Group leakage between val and test: {val_groups & test_groups}")

    return issues