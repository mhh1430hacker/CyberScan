from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any

import numpy as np
from sklearn.model_selection import train_test_split

from config import DEFAULT_SETTINGS
from core.feature_extractor import extract_features_from_bytes
from ml.anomaly_detector import AnomalyDetector
from ml.feature_schema import serialize_feature_vector

MIN_BENIGN_TRAINING_SAMPLES = 30
MIN_BENIGN_MANIFEST_SAMPLES = 40
MIN_MALICIOUS_MANIFEST_SAMPLES = 20
ALLOWED_LABELS = {"benign", "malicious"}


def load_labeled_manifest(
    manifest_path: str | Path,
    *,
    require_training_minimums: bool = True,
) -> tuple[list[dict[str, Any]], str]:
    """Extract static features from a user-curated path,label,source CSV."""
    manifest = Path(manifest_path).expanduser().resolve()
    if not manifest.is_file():
        raise FileNotFoundError(f"Manifest not found: {manifest}")
    manifest_digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
    samples: list[dict[str, Any]] = []
    seen_hashes: dict[str, str] = {}
    max_bytes = int(DEFAULT_SETTINGS["maximum_file_size"])

    with manifest.open("r", newline="", encoding="utf-8-sig") as stream:
        reader = csv.DictReader(stream)
        required_columns = {"path", "label", "source"}
        if not reader.fieldnames or not required_columns.issubset(reader.fieldnames):
            raise ValueError("Manifest CSV must contain path,label,source columns.")
        for row_number, row in enumerate(reader, start=2):
            label = (row.get("label") or "").strip().lower()
            source = (row.get("source") or "").strip()
            sample_path_text = (row.get("path") or "").strip()
            if label not in ALLOWED_LABELS:
                raise ValueError(f"Row {row_number}: label must be benign or malicious.")
            if not source:
                raise ValueError(f"Row {row_number}: source/provenance description is required.")
            if not sample_path_text:
                raise ValueError(f"Row {row_number}: sample path is empty.")

            sample_path = Path(sample_path_text).expanduser()
            if not sample_path.is_absolute():
                sample_path = manifest.parent / sample_path
            sample_path = sample_path.resolve()
            if not sample_path.is_file():
                raise FileNotFoundError(f"Row {row_number}: sample file not found: {sample_path}")
            if sample_path.stat().st_size > max_bytes:
                raise ValueError(f"Row {row_number}: sample exceeds the configured file-size limit.")

            data = sample_path.read_bytes()
            sample_hash = hashlib.sha256(data).hexdigest()
            prior_label = seen_hashes.get(sample_hash)
            if prior_label is not None:
                if prior_label != label:
                    raise ValueError(f"Row {row_number}: identical file bytes have conflicting labels.")
                continue
            seen_hashes[sample_hash] = label
            features = extract_features_from_bytes(data[:1_000_000], file_name=sample_path.name)
            samples.append({"label": label, "source": source, "sha256": sample_hash, "features": features})

    counts = Counter(sample["label"] for sample in samples)
    if require_training_minimums and counts["benign"] < MIN_BENIGN_MANIFEST_SAMPLES:
        raise ValueError(f"At least {MIN_BENIGN_MANIFEST_SAMPLES} unique benign samples are required; found {counts['benign']}.")
    if require_training_minimums and counts["malicious"] < MIN_MALICIOUS_MANIFEST_SAMPLES:
        raise ValueError(f"At least {MIN_MALICIOUS_MANIFEST_SAMPLES} unique malicious samples are required for holdout evaluation; found {counts['malicious']}.")
    return samples, manifest_digest


def calculate_metrics(labels: list[str], anomaly_predictions: list[bool]) -> dict[str, float | int]:
    if len(labels) != len(anomaly_predictions) or not labels:
        raise ValueError("Evaluation labels and predictions must have the same non-zero length.")
    true_positive = sum(label == "malicious" and prediction for label, prediction in zip(labels, anomaly_predictions))
    false_positive = sum(label == "benign" and prediction for label, prediction in zip(labels, anomaly_predictions))
    false_negative = sum(label == "malicious" and not prediction for label, prediction in zip(labels, anomaly_predictions))
    true_negative = sum(label == "benign" and not prediction for label, prediction in zip(labels, anomaly_predictions))
    precision = true_positive / (true_positive + false_positive) if true_positive + false_positive else 0.0
    recall = true_positive / (true_positive + false_negative) if true_positive + false_negative else 0.0
    specificity = true_negative / (true_negative + false_positive) if true_negative + false_positive else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "sample_count": len(labels),
        "true_positive": true_positive,
        "false_positive": false_positive,
        "false_negative": false_negative,
        "true_negative": true_negative,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "specificity": round(specificity, 4),
        "f1": round(f1, 4),
    }


def train_from_manifest(manifest_path: str | Path, model_path: str | Path | None = None) -> dict[str, Any]:
    samples, manifest_digest = load_labeled_manifest(manifest_path)
    labels = [sample["label"] for sample in samples]
    indices = np.arange(len(samples))
    train_indices, validation_indices = train_test_split(
        indices,
        test_size=0.25,
        random_state=42,
        stratify=labels,
    )
    benign_training = [samples[int(index)]["features"] for index in train_indices if labels[int(index)] == "benign"]
    validation = [samples[int(index)] for index in validation_indices]
    if len(benign_training) < MIN_BENIGN_TRAINING_SAMPLES:
        raise ValueError(
            f"The split left {len(benign_training)} benign training samples; "
            f"at least {MIN_BENIGN_TRAINING_SAMPLES} are required."
        )

    counts = Counter(labels)
    metadata: dict[str, Any] = {
        "training_data_type": "curated_benign_manifest",
        "label_provenance": "user-provided source field; not independently verified by CyberScan",
        "manifest_sha256": manifest_digest,
        "manifest_sample_count": len(samples),
        "benign_sample_count": len(benign_training),
        "malicious_sample_count": counts["malicious"],
        "training_sha256s": [
            samples[int(index)]["sha256"]
            for index in train_indices
            if labels[int(index)] == "benign"
        ],
        "validation_method": "stratified 25% holdout; IsolationForest fit on benign training partition only",
    }
    detector = AnomalyDetector(model_path)
    detector.train(benign_training, training_metadata=metadata)

    validation_vectors = np.asarray(
        [serialize_feature_vector(sample["features"]) for sample in validation],
        dtype=float,
    )
    model_predictions = detector.model.predict(validation_vectors)
    metrics = calculate_metrics(
        [sample["label"] for sample in validation],
        [int(prediction) == -1 for prediction in model_predictions],
    )
    detector.metadata["validation_metrics"] = metrics
    detector.model_path.with_suffix(".json").write_text(json.dumps(detector.metadata, indent=2), encoding="utf-8")
    return {
        "model_path": str(detector.model_path),
        "schema_version": detector.metadata["schema_version"],
        "training_examples": len(benign_training),
        "validation_metrics": metrics,
        "label_provenance": metadata["label_provenance"],
        "confidence_is_calibrated": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Train CyberScan on a curated, locally labeled sample manifest.")
    parser.add_argument("--manifest", required=True, help="CSV with path,label,source columns; labels are benign or malicious.")
    parser.add_argument("--model-path", help="Optional output path for the trained joblib model.")
    args = parser.parse_args()
    print(json.dumps(train_from_manifest(args.manifest, args.model_path), indent=2))


if __name__ == "__main__":
    main()
