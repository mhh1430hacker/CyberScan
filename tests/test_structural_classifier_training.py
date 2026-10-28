import json
import os
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

import numpy as np
import pytest
from sklearn.ensemble import RandomForestClassifier

from ml.dataset_loader import prepare_dataset
from ml.structural_classifier import StructuralClassifier, CLASS_LABELS

def test_structural_classifier_can_train_on_synthetic_data(tmp_path: Path):
    # Create minimal synthetic dataset with enough samples for valid split
    dataset_root = tmp_path / "data"
    dataset_root.mkdir()

    files = []
    labels = []
    # Create 10 samples: 4 clean, 3 suspicious, 3 malware
    for i in range(4):
        path = dataset_root / f"clean{i}.bin"
        path.write_bytes(b"A" * 1024 + bytes([i]))
        files.append(path)
        labels.append("clean")
    for i in range(3):
        path = dataset_root / f"suspicious{i}.bin"
        path.write_bytes(b"B" * 1024 + bytes([i]))
        files.append(path)
        labels.append("suspicious")
    for i in range(3):
        path = dataset_root / f"malware{i}.bin"
        path.write_bytes(b"X" * 1024 + bytes([i]))
        files.append(path)
        labels.append("malware")

    # Compute SHA-256 hashes
    from ml.dataset_manifest import compute_sha256
    hashes = [compute_sha256(f) for f in files]

    manifest_path = dataset_root / "manifest.csv"
    with manifest_path.open("w", encoding="utf-8") as f:
        f.write("path,label,sha256,source\n")
        for path, label, sha_val in zip(files, labels, hashes):
            f.write(f"{path.name},{label},{sha_val},internal\n")

    # Prepare dataset
    bundle = prepare_dataset(manifest_path, dataset_root, split_method="random", train_ratio=0.6, val_ratio=0.2, test_ratio=0.2, seed=42)
    assert bundle.X.shape == (10, 4096)
    assert bundle.y.shape == (10,)
    assert len(bundle.splits.train_indices) > 0
    assert len(bundle.splits.test_indices) > 0
    # Train classifier
    model_path = tmp_path / "trained_model.json"
    classifier = StructuralClassifier(model_path)
    classifier.train(
        bundle.X[bundle.splits.train_indices],
        bundle.y[bundle.splits.train_indices],
    )

    # Save the model manually after training
    classifier.save(model_path)

    # Verify model saved
    assert model_path.is_file()

# Verify classifier can predict
    test_X = bundle.X[bundle.splits.test_indices]
    preds = classifier.predict(test_X)
    assert preds["status"] == "classified"
    assert preds["label"] is not None
    assert len(preds["label"]) == len(test_X)

def test_structural_classifier_fails_without_training(tmp_path: Path):
    # Ensure classifier doesn't load without trained model
    classifier = StructuralClassifier()
    assert not classifier.load()
    # Try to predict (should fail gracefully)
    prediction = classifier.predict(np.zeros((1, 4096)))
    assert prediction["status"] == "untrained"
    assert prediction["infection_score"] is None


def test_structural_classifier_validation_rejects_raw_scores_as_probabilities(tmp_path: Path):
    # Train a classifier and verify it doesn't claim scores are calibrated probabilities
    dataset_root = tmp_path / "data"
    dataset_root.mkdir()
    
    # Create enough samples for valid split
    files = []
    labels = []
    for i in range(8):
        path = dataset_root / f"sample{i}.bin"
        path.write_bytes(bytes([i]) * 1024)
        files.append(path)
        labels.append("clean" if i < 4 else "malware")

    from ml.dataset_manifest import compute_sha256
    hashes = [compute_sha256(f) for f in files]

    manifest_path = dataset_root / "manifest.csv"
    with manifest_path.open("w", encoding="utf-8") as f:
        f.write("path,label,sha256,source\n")
        for path, label, sha_val in zip(files, labels, hashes):
            f.write(f"{path.name},{label},{sha_val},internal\n")

    bundle = prepare_dataset(manifest_path, dataset_root, split_method="random", train_ratio=0.7, val_ratio=0.15, test_ratio=0.15, seed=42)
    classifier = StructuralClassifier()
    classifier.train(bundle.X[bundle.splits.train_indices], bundle.y[bundle.splits.train_indices])
# Verify model metadata doesn't contain probability calibration claims
    assert classifier.metadata["scores_are_calibrated"] is False
    # Verify predictions are class labels, not probabilities
    preds = classifier.predict(bundle.X[bundle.splits.test_indices][:1])
    assert preds["status"] == "classified"
    assert "label" in preds