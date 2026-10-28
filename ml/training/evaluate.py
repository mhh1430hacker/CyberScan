from __future__ import annotations

import argparse
import json
import warnings
from pathlib import Path
from typing import Any

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    roc_auc_score,
)

from ml.dataset_loader import check_leakage, get_split_data, prepare_dataset
from ml.structural_classifier import StructuralClassifier


def evaluate_model(
    model_path: Path,
    manifest_path: Path,
    dataset_root: Path | None = None,
    splits: list[str] | None = None,
    compute_embeddings: bool = True,
    *,
    expected_sha256: str,
) -> dict[str, Any]:
    """
    Evaluate a trained StructuralClassifier on dataset splits.
    
    Args:
        model_path: Path to the trained model JSON file
        manifest_path: Path to the manifest CSV
        dataset_root: Root directory containing binary files (defaults to manifest parent)
        splits: List of splits to evaluate (default: ["val", "test"])
        expected_sha256: Approved SHA-256 of the model file from a trusted source
    """
    if dataset_root is None:
        dataset_root = manifest_path.parent
    
    if splits is None:
        splits = ["val", "test"]
    
    # Load the trained model
    classifier = StructuralClassifier()
    if not classifier.load(model_path, expected_sha256=expected_sha256):
        raise RuntimeError(f"Failed to load model: {classifier.metadata.get('load_error', 'unknown')}")
    
    # Load and prepare dataset (use random split for evaluation to match training)
    bundle = prepare_dataset(
        manifest_path,
        dataset_root,
        split_method="random",  # Use random split for evaluation
        compute_hashes=False,  # Don't recompute hashes for evaluation
    )
    
    # Check for data leakage
    leakage_issues = check_leakage(bundle)

    # Evaluate on each split
    results = {
        "model_path": str(model_path),
        "manifest_path": str(manifest_path),
        "model_metadata": {
            "n_estimators": classifier.metadata.get("n_estimators"),
            "embedding_dim": classifier.metadata.get("embedding_dim"),
            "labels": classifier.metadata.get("labels"),
            "training_examples": classifier.metadata.get("training_examples"),
        },
        "leakage_check": {
            "issues_found": len(leakage_issues) > 0,
            "issues": leakage_issues,
        },
        "splits": {},
    }

    class_labels = ["clean", "suspicious", "malware"]
    class_to_int = {label: i for i, label in enumerate(class_labels)}

    for split_name in splits:
        X_split, y_split, _ = get_split_data(bundle, split_name)
        
        if len(X_split) == 0:
            results["splits"][split_name] = {"error": f"No samples in {split_name} split"}
            continue
        
        # Get predictions
        preds = classifier.predict(X_split)
        y_pred = np.array([class_to_int[label] for label in preds["label"]])
        
        # Get probabilities
        y_proba = classifier.predict_proba(X_split)
        
        # Compute metrics
        metrics = compute_metrics(y_split, y_pred, y_proba, class_labels)
        results["splits"][split_name] = metrics
    
    return results


def compute_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_proba: np.ndarray,
    class_labels: list[str],
) -> dict[str, Any]:
    """Compute comprehensive evaluation metrics."""
    metrics = {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "balanced_accuracy": float(balanced_accuracy_score(y_true, y_pred)),
        "f1_macro": float(f1_score(y_true, y_pred, average="macro", zero_division=0)),
        "f1_weighted": float(f1_score(y_true, y_pred, average="weighted", zero_division=0)),
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=range(len(class_labels))).tolist(),
        "per_class": {},
    }
    
    for i, label in enumerate(class_labels):
        if np.sum(y_true == i) > 0:
            metrics["per_class"][label] = {
                "precision": float(
                    np.sum((y_pred == i) & (y_true == i)) / max(np.sum(y_pred == i), 1)
                ),
                "recall": float(
                    np.sum((y_pred == i) & (y_true == i)) / np.sum(y_true == i)
                ),
                "f1": float(f1_score(y_true == i, y_pred == i, zero_division=0)),
                "support": int(np.sum(y_true == i)),
            }
        else:
            metrics["per_class"][label] = {
                "precision": 0.0,
                "recall": 0.0,
                "f1": 0.0,
                "support": 0,
            }
    
    # ROC AUC (one-vs-rest for multiclass)
    try:
        if y_proba.shape[1] == len(class_labels):
            metrics["roc_auc_ovr"] = float(roc_auc_score(y_true, y_proba, multi_class="ovr", average="macro"))
            metrics["roc_auc_ovr_weighted"] = float(roc_auc_score(y_true, y_proba, multi_class="ovr", average="weighted"))
    except Exception:
        metrics["roc_auc_ovr"] = None
        metrics["roc_auc_ovr_weighted"] = None
    
    # Classification report as dict
    try:
        report = classification_report(y_true, y_pred, target_names=class_labels, output_dict=True, zero_division=0)
        metrics["classification_report"] = report
    except Exception:
        metrics["classification_report"] = {}
    
    return metrics


def evaluate_model_consistency(
    model_path: Path,
    manifest_path: Path,
    dataset_root: Path | None = None,
    *,
    expected_sha256: str,
) -> dict[str, Any]:
    """
    Evaluate model consistency after reload.
    
    Loads a model, gets predictions, reloads it, and compares predictions.
    """
    if dataset_root is None:
        dataset_root = manifest_path.parent
    
    # Load original model
    original = StructuralClassifier()
    if not original.load(model_path, expected_sha256=expected_sha256):
        raise RuntimeError(f"Failed to load original model: {original.metadata.get('load_error', 'unknown')}")
    
    # Prepare dataset
    bundle = prepare_dataset(manifest_path, dataset_root, split_method="random", compute_hashes=False)
    X_test, y_test, _ = get_split_data(bundle, "test")
    
    if len(X_test) == 0:
        return {"error": "No test samples"}
    
    # Get original predictions
    original_preds = original.predict(X_test)
    original_proba = original.predict_proba(X_test)
    
    # Reload model
    reloaded = StructuralClassifier()
    if not reloaded.load(model_path, expected_sha256=expected_sha256):
        raise RuntimeError(f"Failed to reload model: {reloaded.metadata.get('load_error', 'unknown')}")
    
    # Get reloaded predictions
    reloaded_preds = reloaded.predict(X_test)
    reloaded_proba = reloaded.predict_proba(X_test)
    
    # Compare
    labels_match = np.array_equal(original_preds["label"], reloaded_preds["label"])
    proba_close = np.allclose(original_proba, reloaded_proba, rtol=1e-10, atol=1e-12)
    
    return {
        "labels_match": bool(labels_match),
        "probabilities_match": bool(proba_close),
        "max_prob_diff": float(np.max(np.abs(original_proba - reloaded_proba))),
        "test_samples": len(X_test),
    }


def main():
    """CLI entry point for evaluation."""
    parser = argparse.ArgumentParser(description="Evaluate StructuralClassifier model")
    parser.add_argument("--model", type=Path, required=True, help="Path to trained model JSON")
    parser.add_argument(
        "--sha256",
        required=True,
        help="Approved SHA-256 of the model file, taken from a trusted record (not from the file)",
    )
    parser.add_argument("--manifest", type=Path, required=True, help="Path to manifest CSV")
    parser.add_argument("--dataset-root", type=Path, help="Dataset root directory")
    parser.add_argument("--splits", nargs="+", default=["val", "test"], help="Splits to evaluate")
    parser.add_argument("--output", type=Path, help="Output JSON path for results")
    parser.add_argument("--consistency", action="store_true", help="Run consistency check after evaluation")
    
    args = parser.parse_args()
    
    results = evaluate_model(
        model_path=args.model,
        manifest_path=args.manifest,
        dataset_root=args.dataset_root,
        splits=args.splits,
        expected_sha256=args.sha256,
    )
    
    if args.consistency:
        results["consistency_check"] = evaluate_model_consistency(
            model_path=args.model,
            manifest_path=args.manifest,
            dataset_root=args.dataset_root,
            expected_sha256=args.sha256,
        )
    
    if args.output:
        with args.output.open("w") as f:
            json.dump(results, f, indent=2)
        print(f"Results saved to {args.output}")
    else:
        print(json.dumps(results, indent=2))
    
    # Print summary
    for split_name, metrics in results["splits"].items():
        if "error" not in metrics:
            print(f"\n{split_name.upper()} split:")
            print(f"  Accuracy: {metrics['accuracy']:.4f}")
            print(f"  Balanced Accuracy: {metrics['balanced_accuracy']:.4f}")
            print(f"  F1 Macro: {metrics['f1_macro']:.4f}")
            print(f"  F1 Weighted: {metrics['f1_weighted']:.4f}")
            if metrics.get("roc_auc_ovr") is not None:
                print(f"  ROC AUC OVR: {metrics['roc_auc_ovr']:.4f}")


if __name__ == "__main__":
    main()