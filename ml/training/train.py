from __future__ import annotations

import csv
import hashlib
import json
import math
import os
import sys
import warnings
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    confusion_matrix,
    f1_score,
)
from sklearn.model_selection import GroupKFold, StratifiedKFold, train_test_split

from ml.dataset_loader import compute_embeddings
from ml.dataset_manifest import ManifestEntry, load_manifest
from ml.feature_schema import LATENT_DIMENSION
from ml.structural_classifier import StructuralClassifier

CLASS_LABELS = ("clean", "suspicious", "malware")


def _load_manifest(manifest_path: Path) -> List[ManifestEntry]:
    """Load manifest CSV and return list of ManifestEntry objects."""
    with manifest_path.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    entries = []
    for row in rows:
        entries.append(ManifestEntry(
            path=row["path"],
            label=row["label"],
            sha256=row.get("sha256", ""),
            source=row.get("source", ""),
            family=row.get("family", ""),
        ))
    return entries


def _split_rows(
    entries: List[ManifestEntry],
    split_method: str = "random",
    test_size: float = 0.25,
    random_state: int = 42,
) -> Tuple[List[ManifestEntry], List[ManifestEntry]]:
    """Split manifest entries into train and validation sets."""
    if split_method == "group":
        # Group by family to prevent leakage
        groups = [e.family or f"no_family_{i}" for i, e in enumerate(entries)]
        gkf = GroupKFold(n_splits=int(1 / test_size))
        train_idx, val_idx = next(gkf.split(entries, groups=groups))
        train_entries = [entries[i] for i in train_idx]
        val_entries = [entries[i] for i in val_idx]
    else:
        # Random or stratified split
        labels = [e.label for e in entries]
        train_entries, val_entries = train_test_split(
            entries, test_size=test_size, random_state=random_state, stratify=labels
        )
    return train_entries, val_entries


def _classification_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_proba: np.ndarray,
    labels: List[str],
) -> Dict[str, Any]:
    """Compute comprehensive classification metrics."""
    n_samples = len(y_true)

    # Convert string labels to numeric indices for sklearn metrics
    label_to_idx = {label: i for i, label in enumerate(labels)}
    y_true_int = np.array([label_to_idx.get(l, -1) for l in y_true], dtype=np.int64)
    y_pred_int = np.array([label_to_idx.get(l, -1) for l in y_pred], dtype=np.int64)

    # Filter out any unknown labels
    valid_mask = (y_true_int >= 0) & (y_pred_int >= 0)
    y_true_int = y_true_int[valid_mask]
    y_pred_int = y_pred_int[valid_mask]
    y_proba = y_proba[valid_mask]

    n_classes = len(labels)
    cm = confusion_matrix(y_true_int, y_pred_int, labels=range(n_classes))
    per_class: Dict[str, Dict[str, float]] = {}
    for idx, label in enumerate(labels):
        tp = int(cm[idx, idx])
        fp = int(cm[:, idx].sum() - tp)
        fn = int(cm[idx, :].sum() - tp)
        tn = int(cm.sum() - tp - fp - fn)
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (
            2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
        )
        support = int(cm[idx, :].sum())
        per_class[label] = {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "support": support,
        }

    accuracy = float(accuracy_score(y_true_int, y_pred_int))
    balanced_acc = float(balanced_accuracy_score(y_true_int, y_pred_int))
    macro_f1 = float(f1_score(y_true_int, y_pred_int, average="macro", zero_division=0))
    weighted_f1 = float(f1_score(y_true_int, y_pred_int, average="weighted", zero_division=0))

    metrics: Dict[str, Any] = {
        "accuracy": round(accuracy, 4),
        "balanced_accuracy": round(balanced_acc, 4),
        "macro_f1": round(macro_f1, 4),
        "weighted_f1": round(weighted_f1, 4),
        "per_class": per_class,
        "confusion_matrix": cm.tolist(),
        "labels": labels,
    }

    # Calibration diagnostics only when all three labels are present
    if set(labels if labels else CLASS_LABELS) == set(CLASS_LABELS):
        proba_max = y_proba.max(axis=1)
        pred_max = y_proba.argmax(axis=1)
        correct = (pred_max == y_true_int).astype(float)
        bins = np.linspace(0.0, 1.0, 11)
        ece = 0.0
        for i in range(10):
            mask = (proba_max >= bins[i]) & (proba_max < bins[i + 1])
            if i == 9:
                mask = (proba_max >= bins[i]) & (proba_max <= bins[i + 1])
            if not mask.any():
                continue
            bin_conf = y_proba[mask].max(axis=1).mean() if mask.sum() > 0 else 0.0
            bin_acc = correct[mask].mean()
            ece += mask.mean() * abs(bin_acc - bin_conf)
        metrics["top_label_ece_10_bins"] = round(float(ece), 4)
        metrics["calibration_note"] = (
            "Diagnostics on uncalibrated Random Forest scores; not calibrated probabilities."
        )

    return metrics


def train_from_manifest(
    manifest_path: Path,
    model_output_path: Path,
    dataset_root: Optional[Path] = None,
    split_method: str = "random",
    test_size: float = 0.25,
    n_estimators: int = 200,
    max_depth: Optional[int] = None,
    min_samples_leaf: int = 1,
    random_state: int = 42,
) -> Dict[str, Any]:
    """Train a structural classifier from a manifest file."""
    if dataset_root is None:
        dataset_root = manifest_path.parent

    entries = _load_manifest(manifest_path)

    # Split into train and validation
    train_entries, val_entries = _split_rows(
        entries, split_method=split_method, test_size=test_size, random_state=random_state
    )

    # Compute embeddings for training data
    X_train = compute_embeddings(train_entries, dataset_root)
    int_to_label = {0: "clean", 1: "suspicious", 2: "malware"}
    label_to_int = {"clean": 0, "suspicious": 1, "malware": 2}
    y_train = np.array([label_to_int[e.label] for e in train_entries], dtype=np.int64)
    y_train_str = np.array([e.label for e in train_entries], dtype=object)

    # Compute embeddings for validation data
    X_val = compute_embeddings(val_entries, dataset_root)
    y_val = np.array([label_to_int[e.label] for e in val_entries], dtype=np.int64)
    y_val_str = np.array([e.label for e in val_entries], dtype=object)

    # Train the structural classifier
    clf = StructuralClassifier()
    train_result = clf.train(X_train, y_train_str)
    print(f"Training result: {train_result}")

    # Get predictions - predict() now returns dict with labels in "label" field
    pred_result = clf.predict(X_val)
    y_pred = pred_result["label"]

    # Get prediction probabilities
    y_proba = clf.predict_proba(X_val)

# Compute metrics
    metrics = _classification_metrics(y_val_str, y_pred, y_proba, list(CLASS_LABELS))
    metrics["split_method"] = split_method
    metrics["training_examples"] = len(train_entries)
    metrics["validation_examples"] = len(val_entries)
    metrics["sample_count"] = len(val_entries)

    # Save the trained model with metadata
    metadata = {
        "n_estimators": n_estimators,
        "max_depth": max_depth,
        "min_samples_leaf": min_samples_leaf,
        "embedding_dim": LATENT_DIMENSION,
        "labels": CLASS_LABELS,
        "training_examples": len(train_entries),
        "validation_metrics": metrics,
        "split_method": split_method,
    }
    # Only scalar provenance is stored in the artifact; full metrics are returned to the caller.
    provenance = {
        "training_examples": len(train_entries),
        "validation_examples": len(val_entries),
        "split_method": split_method,
    }
    saved_path = clf.save(model_output_path, metadata=provenance)
    return {"model_path": str(saved_path), "sha256": clf.artifact_sha256, **metadata}


def _parse_args():
    """Parse command line arguments."""
    import argparse
    parser = argparse.ArgumentParser(description="Train StructuralClassifier from manifest")
    parser.add_argument("--manifest", type=Path, required=True, help="Path to manifest CSV")
    parser.add_argument("--output", type=Path, default=Path("ml/models/structural_classifier.json"), help="Output model path")
    parser.add_argument("--dataset-root", type=Path, help="Dataset root directory")
    parser.add_argument("--split", choices=["random", "group_aware", "group"], default="group_aware", help="Split method")
    parser.add_argument("--train-ratio", type=float, default=0.7, help="Training ratio")
    parser.add_argument("--val-ratio", type=float, default=0.15, help="Validation ratio")
    parser.add_argument("--test-ratio", type=float, default=0.15, help="Test ratio")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    parser.add_argument("--n-estimators", type=int, default=200, help="Number of trees in RandomForest")
    parser.add_argument("--max-depth", type=int, default=None, help="Max depth of trees")
    parser.add_argument("--min-samples-leaf", type=int, default=1, help="Min samples per leaf")
    return parser.parse_args()


def main():
    """CLI entry point for training."""
    args = _parse_args()
    
    # Convert group_aware to group for the internal function
    split_method = "group" if args.split == "group_aware" else args.split
    
    result = train_from_manifest(
        manifest_path=args.manifest,
        model_output_path=args.output,
        dataset_root=args.dataset_root,
        split_method=split_method,
        test_size=1.0 - args.train_ratio,  # This function only does train/val, not test
        n_estimators=args.n_estimators,
        max_depth=args.max_depth,
        min_samples_leaf=args.min_samples_leaf,
        random_state=args.seed,
    )
    print(f"Training complete. Model saved to: {result['model_path']}")
    print(f"Validation metrics: {result['validation_metrics']}")


if __name__ == "__main__":
    main()