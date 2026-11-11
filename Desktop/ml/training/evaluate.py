from __future__ import annotations

import argparse
import json

import numpy as np

from ml.anomaly_detector import AnomalyDetector
from ml.feature_schema import serialize_feature_vector
from ml.training.train import calculate_metrics, load_labeled_manifest


def evaluate_manifest(manifest_path: str) -> dict[str, object]:
    detector = AnomalyDetector()
    if not detector.load():
        reason = detector.metadata.get("load_error", "No trained model was found.")
        raise RuntimeError(f"Cannot evaluate an unverified model: {reason}")

    samples, manifest_digest = load_labeled_manifest(manifest_path, require_training_minimums=False)
    trained_hashes = set(detector.metadata.get("training_sha256s", []))
    overlap = trained_hashes.intersection(sample["sha256"] for sample in samples)
    if overlap:
        raise ValueError("Evaluation manifest overlaps training samples; use an independent holdout set.")

    if {sample["label"] for sample in samples} != {"benign", "malicious"}:
        raise ValueError("Evaluation manifest must include both benign and malicious samples.")
    features = np.asarray([serialize_feature_vector(sample["features"]) for sample in samples], dtype=float)
    predictions = detector.model.predict(features)
    metrics = calculate_metrics(
        [sample["label"] for sample in samples],
        [int(prediction) == -1 for prediction in predictions],
    )
    return {
        "model_type": detector.metadata.get("model_type"),
        "model_manifest_sha256": detector.metadata.get("manifest_sha256"),
        "evaluation_manifest_sha256": manifest_digest,
        "sample_count": len(samples),
        "metrics": metrics,
        "confidence_is_calibrated": False,
        "identity_claim": "Labels and provenance fields are user-supplied and not independently verified by CyberScan.",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate a trusted CyberScan model on an independent labeled manifest.")
    parser.add_argument("--manifest", required=True, help="Independent CSV with path,label,source columns.")
    args = parser.parse_args()
    print(json.dumps(evaluate_manifest(args.manifest), indent=2))


if __name__ == "__main__":
    main()
