from __future__ import annotations

import csv
import hashlib
import json

import pytest
import numpy as np

from ml.dataset_manifest import ManifestEntry, load_manifest
from ml.structural_classifier import (
    CLASS_LABELS,
    EMBEDDING_SCHEMA,
    MODEL_FORMAT,
    StructuralClassifier,
    LATENT_DIMENSION,
)
from ml.training.train import _load_manifest, _split_rows, train_from_manifest


def test_classifier_is_untrained_without_a_model(tmp_path):
    classifier = StructuralClassifier(tmp_path / "missing.json")

    assert classifier.load() is False
    prediction = classifier.predict([0.0] * 4096)
    assert prediction["status"] == "untrained"
    assert prediction["infection_score"] is None


def test_classifier_rejects_incompatible_metadata(tmp_path):
    model_path = tmp_path / "model.json"
    model_path.write_text(
        json.dumps({
            "format": MODEL_FORMAT,
            "model": {
                "estimators": [],
            },
            "metadata": {
                "schema_version": 1,
                "embedding_schema": "old",
                "embedding_dimension": 4096,
                "classes": [],
                "training_data_type": "user_reviewed_three_class_manifest",
                "manifest_sha256": "0" * 64,
            },
        }),
        encoding="utf-8",
    )
    classifier = StructuralClassifier(model_path)

    assert classifier.load() is False
    assert "Missing metadata keys" in classifier.metadata["load_error"] or "incompatible" in classifier.metadata["load_error"].lower()


def test_classifier_validates_embedding_dimension(tmp_path):
    classifier = StructuralClassifier(tmp_path / "missing.json")
    assert classifier.load() is False
    prediction = classifier.predict(np.array([0.0] * LATENT_DIMENSION))
    assert prediction["status"] == "untrained"
    assert prediction["infection_score"] is None


def test_three_class_manifest_trains_and_reloads_classifier(tmp_path):
    manifest = tmp_path / "manifest.csv"
    rows = []
    for label in CLASS_LABELS:
        for index in range(40):
            sample = tmp_path / f"{label}-{index}.bin"
            marker = label.encode("ascii")
            sample.write_bytes(marker + b"-sample-" + str(index).encode("ascii") + bytes([index]))
            rows.append({
                "path": sample.name,
                "label": label,
                "source": "unit-test fixture only",
            })
    with manifest.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=("path", "label", "source"))
        writer.writeheader()
        writer.writerows(rows)

    model_path = tmp_path / "trained.json"
    training = train_from_manifest(manifest, model_path, dataset_root=tmp_path, split_method="random", test_size=0.25)
    classifier = StructuralClassifier(model_path)

    assert training["training_examples"] == 90
    assert training["validation_metrics"]["sample_count"] == 30
    assert classifier.load()
    assert classifier.metadata["embedding_schema"] == EMBEDDING_SCHEMA
    assert classifier.metadata["scores_are_calibrated"] is False
    vector = classifier.embed_bytes(b"sample held out from the training manifest")
    prediction = classifier.predict(vector)
    assert prediction["status"] == "classified"
    assert set(prediction["class_scores"]) == set(CLASS_LABELS)
    assert sum(prediction["class_scores"].values()) == pytest.approx(100.0)
    assert prediction["scores_are_calibrated"] is False
    assert prediction["repair_review_candidate"] is None
    assert '"format": "cyberscan-random-forest-json-v1"' in model_path.read_text(
        encoding="utf-8"
    )[:100]


def test_family_group_holdout_has_no_group_leakage():
    entries = [
        ManifestEntry(
            path=f"sample-{i}.bin",
            label=label,
            family=f"{label}-group-{group}",
            sha256=hashlib.sha256(f"sample-{i}".encode()).hexdigest(),
            source="unit-test fixture only",
        )
        for label in CLASS_LABELS
        for group in range(5)
        for i in range(10)
    ]

    train_entries, validation_entries = _split_rows(entries, split_method="group")

    train_families = {e.family for e in train_entries if e.family}
    val_families = {e.family for e in validation_entries if e.family}
    assert train_families.isdisjoint(val_families)
    assert {e.label for e in train_entries} == set(CLASS_LABELS)
    assert {e.label for e in validation_entries} == set(CLASS_LABELS)


def test_classifier_rejects_non_finite_inference_vectors(tmp_path):
    classifier = StructuralClassifier(tmp_path / "missing.json")

    with pytest.raises(ValueError, match="finite"):
        classifier.predict([float("nan")] * 4096)


def test_classifier_rejects_non_finite_inference_vectors_with_scores(tmp_path):
    """Test that predict raises on NaN vectors even with trained model."""
    rf = StructuralClassifier()
    X = np.random.rand(5, LATENT_DIMENSION)
    y = np.array(["clean", "clean", "suspicious", "malware", "clean"])
    rf.train(X, y)

    with pytest.raises(ValueError, match="finite"):
        rf.predict([float("nan")] * LATENT_DIMENSION)


def test_classifier_does_not_load_executable_pickle_artifacts(tmp_path):
    model_path = tmp_path / "legacy.json"
    model_path.write_bytes(b"\x80\x04cos\nsystem\n.")
    classifier = StructuralClassifier(model_path)

    assert classifier.load() is False
    assert "executable model files are not loaded" in classifier.metadata["load_error"]


def test_dataset_manifest_rejects_identical_content_with_conflicting_labels(tmp_path):
    first = tmp_path / "first.bin"
    second = tmp_path / "second.bin"
    first.write_bytes(b"same sample bytes")
    second.write_bytes(b"same sample bytes")
    manifest = tmp_path / "conflicting.csv"
    with manifest.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=("path", "label", "source", "sha256"))
        writer.writeheader()
        sha256_val = hashlib.sha256(b"same sample bytes").hexdigest()
        writer.writerows((
            {"path": first.name, "label": "clean", "source": "known-good source", "sha256": sha256_val},
            {"path": second.name, "label": "malware", "source": "verified report", "sha256": sha256_val},
        ))

    with pytest.raises(ValueError, match="Conflicting labels|conflicting"):
        load_manifest(manifest, dataset_root=tmp_path)


def test_dataset_manifest_rejects_empty_and_duplicate_column_schemas(tmp_path):
    empty_manifest = tmp_path / "empty.csv"
    empty_manifest.write_text("path,label,source\n", encoding="utf-8")

    with pytest.raises(ValueError):
        load_manifest(empty_manifest, dataset_root=tmp_path)

    duplicate_columns = tmp_path / "duplicate-columns.csv"
    duplicate_columns.write_text("path,path,label,source\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_manifest(duplicate_columns, dataset_root=tmp_path)
