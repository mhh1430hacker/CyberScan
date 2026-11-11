"""Mathematical parity between scikit-learn and the safe forest evaluator.

These tests train fresh forests in memory on the committed synthetic fixtures.
They establish that exporting and reloading preserves scikit-learn's
predictions; they say nothing about real-world malware-detection quality.
No legacy model artifact is read.
"""
from __future__ import annotations

import csv
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import numpy as np
import pytest
from sklearn.ensemble import RandomForestClassifier

from ml.dataset_loader import compute_embeddings
from ml.dataset_manifest import load_manifest
from ml.feature_schema import LATENT_DIMENSION, MODEL_CLASS_ORDER
from ml.forest_export import export_random_forest, write_model_artifact
from ml.forest_format import load_model

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATASET_ROOT = PROJECT_ROOT / "data" / "datasets" / "synthetic_integration"
MANIFEST = DATASET_ROOT / "manifest.csv"

SEEDS = (42, 1337)
PROBABILITY_TOLERANCE = 1e-12
SUM_TOLERANCE = 1e-12
TIE_TOLERANCE = 1e-12
VECTOR_SEED = 20261028

# Same configuration as StructuralClassifier.train, with the seed varied and a
# single job so tree accumulation order is deterministic.
FOREST_PARAMS = dict(
    n_estimators=200,
    max_depth=20,
    min_samples_split=5,
    min_samples_leaf=2,
    max_features="sqrt",
    class_weight="balanced",
    n_jobs=1,
)


@pytest.fixture(scope="module")
def synthetic_dataset():
    with MANIFEST.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 30
    assert {row["source"] for row in rows} == {"synthetic"}
    for row in rows:
        data = (DATASET_ROOT / row["path"]).read_bytes()
        assert hashlib.sha256(data).hexdigest() == row["sha256"]

    entries = load_manifest(MANIFEST, DATASET_ROOT, compute_hashes=True)
    assert len(entries) == 30
    labels = [entry.label for entry in entries]
    assert {label: labels.count(label) for label in MODEL_CLASS_ORDER} == {
        "clean": 10,
        "suspicious": 10,
        "malware": 10,
    }

    X = compute_embeddings(entries, DATASET_ROOT)
    assert X.shape == (30, LATENT_DIMENSION)
    assert X.dtype == np.float32
    # compute_embeddings writes zeros when a sample fails; none may have failed.
    assert np.all(np.any(X != 0, axis=1))
    return X, np.array(labels)


def train_forest(X, labels, seed):
    return RandomForestClassifier(random_state=seed, **FOREST_PARAMS).fit(X, labels)


def boundary_vectors(forest, base, count, rng):
    """Vectors placed exactly at, just below, and just above split thresholds."""
    nodes = [
        (tree.tree_.feature[node], tree.tree_.threshold[node])
        for tree in forest.estimators_
        for node in np.flatnonzero(tree.tree_.children_left != -1)
    ]
    vectors = []
    for index in range(count):
        feature, threshold = nodes[rng.integers(len(nodes))]
        nearest = np.float32(threshold)
        below = nearest if float(nearest) <= threshold else np.nextafter(nearest, np.float32(-np.inf))
        above = np.nextafter(below, np.float32(np.inf))
        candidate = base[index % len(base)].astype(np.float64).copy()
        candidate[feature] = (threshold, float(below), float(above))[index % 3]
        vectors.append(candidate)
    return np.array(vectors)


def parity_vectors(forest, X):
    """500 deterministic 4096-D vectors: zeros, random, and threshold boundaries."""
    rng = np.random.default_rng(VECTOR_SEED)
    zeros = np.zeros((5, LATENT_DIMENSION))
    uniform = rng.uniform(-1.0, 1.0, size=(195, LATENT_DIMENSION))
    gaussian = rng.normal(size=(150, LATENT_DIMENSION))
    gaussian /= np.linalg.norm(gaussian, axis=1, keepdims=True)
    boundaries = boundary_vectors(forest, X, 150, rng)
    vectors = np.vstack([zeros, uniform, gaussian, boundaries])
    assert vectors.shape == (500, LATENT_DIMENSION)
    return vectors


def compare(forest, class_labels, model, X):
    """Return parity statistics between scikit-learn and the safe evaluator."""
    column_order = [list(class_labels).index(name) for name in MODEL_CLASS_ORDER]
    expected = forest.predict_proba(X)[:, column_order]
    actual = model.predict_proba(X)

    assert np.all(np.isfinite(actual))
    assert np.all(actual >= 0)
    assert np.max(np.abs(actual.sum(axis=1) - 1.0)) <= SUM_TOLERANCE

    sklearn_labels = [class_labels[index] for index in np.argmax(forest.predict_proba(X), axis=1)]
    assert sklearn_labels == [str(label) for label in np.asarray(class_labels)[
        np.searchsorted(forest.classes_, forest.predict(X))
    ]]
    our_labels = model.predict(X)

    ordered = np.sort(actual, axis=1)
    ties = ordered[:, -1] - ordered[:, -2] <= TIE_TOLERANCE
    mismatches = 0
    for row, tied in enumerate(ties):
        if tied:
            winners = np.flatnonzero(actual[row] >= actual[row].max() - TIE_TOLERANCE)
            assert our_labels[row] == MODEL_CLASS_ORDER[winners[0]]
        elif our_labels[row] != sklearn_labels[row]:
            mismatches += 1
    return {
        "max_abs_diff": float(np.max(np.abs(expected - actual))),
        "max_sum_error": float(np.max(np.abs(actual.sum(axis=1) - 1.0))),
        "ties": int(ties.sum()),
        "label_mismatches": mismatches,
    }


@pytest.fixture(scope="module", params=SEEDS, ids=lambda seed: f"seed{seed}")
def exported(request, synthetic_dataset, tmp_path_factory):
    X, labels = synthetic_dataset
    seed = request.param
    forest = train_forest(X, labels, seed)
    document = export_random_forest(forest, provenance={"training_samples": len(labels)})
    path = tmp_path_factory.mktemp(f"seed{seed}") / "model.json"
    write_model_artifact(document, path)
    data = path.read_bytes()
    # The test supplies the digest it computed itself; the file never vouches for itself.
    digest = hashlib.sha256(data).hexdigest()
    return seed, forest, document, data, load_model(path, digest)


def test_forest_classes_are_alphabetical_and_need_reordering(exported):
    _seed, forest, document, _data, model = exported
    assert list(forest.classes_) == ["clean", "malware", "suspicious"]
    assert document["classes"] == list(MODEL_CLASS_ORDER)
    assert model.classes == MODEL_CLASS_ORDER


def test_exported_structure_matches_the_fitted_forest(exported):
    _seed, forest, document, _data, model = exported
    assert len(model.trees) == len(forest.estimators_) == 200
    column_order = [list(forest.classes_).index(name) for name in MODEL_CLASS_ORDER]
    for estimator, tree in zip(forest.estimators_, model.trees):
        source = estimator.tree_
        np.testing.assert_array_equal(tree.children_left, source.children_left)
        np.testing.assert_array_equal(tree.children_right, source.children_right)
        np.testing.assert_array_equal(tree.feature, source.feature)
        np.testing.assert_array_equal(tree.threshold, source.threshold)
        np.testing.assert_array_equal(tree.value, source.value[:, 0, column_order])
        assert tree.depth == source.max_depth
    assert document["provenance"]["random_state"] == _seed


def test_node_values_are_normalized_distributions(exported):
    _seed, forest, _document, _data, _model = exported
    worst = max(
        float(np.max(np.abs(estimator.tree_.value[:, 0, :].sum(axis=1) - 1.0)))
        for estimator in forest.estimators_
    )
    assert worst <= 1e-12


def test_parity_on_all_thirty_synthetic_samples(exported, synthetic_dataset):
    _seed, forest, _document, _data, model = exported
    X, _labels = synthetic_dataset
    assert len(X) == 30

    stats = compare(forest, list(forest.classes_), model, X)

    assert stats["max_abs_diff"] <= PROBABILITY_TOLERANCE
    assert stats["label_mismatches"] == 0


def test_parity_on_500_deterministic_vectors(exported, synthetic_dataset):
    _seed, forest, _document, _data, model = exported
    X, _labels = synthetic_dataset
    vectors = parity_vectors(forest, X)

    stats = compare(forest, list(forest.classes_), model, vectors)

    assert stats["max_abs_diff"] <= PROBABILITY_TOLERANCE
    assert stats["label_mismatches"] == 0


def test_threshold_boundaries_follow_float32_less_or_equal(exported, synthetic_dataset):
    _seed, forest, _document, _data, model = exported
    X, _labels = synthetic_dataset
    rng = np.random.default_rng(VECTOR_SEED + 1)
    vectors = boundary_vectors(forest, X, 300, rng)

    # Every boundary vector must take the same path as scikit-learn in every tree.
    for estimator, tree in zip(forest.estimators_, model.trees):
        expected_leaves = estimator.apply(vectors.astype(np.float32))
        node = np.zeros(len(vectors), dtype=np.int64)
        samples = vectors.astype(np.float32)
        for _ in range(tree.depth):
            internal = tree.children_left[node] != -1
            go_left = samples[np.arange(len(node)), np.where(internal, tree.feature[node], 0)] <= tree.threshold[node]
            node = np.where(internal, np.where(go_left, tree.children_left[node], tree.children_right[node]), node)
        np.testing.assert_array_equal(node, expected_leaves)
    assert compare(forest, list(forest.classes_), model, vectors)["max_abs_diff"] <= PROBABILITY_TOLERANCE


def test_exported_artifact_is_plain_json_without_executable_payload(exported):
    _seed, _forest, document, data, _model = exported
    for marker in (b"estimators_b64", b"gASV", b"gAWV", b"\x80\x04", b"\x80\x05", b"joblib", b"pickle"):
        assert marker not in data

    def strings(value):
        if isinstance(value, str):
            yield value
        elif isinstance(value, dict):
            for key, item in value.items():
                yield key
                yield from strings(item)
        elif isinstance(value, list):
            for item in value:
                yield from strings(item)

    assert json.loads(data) == document
    assert max(len(item) for item in strings(document)) <= 64


def test_structural_classifier_training_path_exports_with_parity(synthetic_dataset, tmp_path):
    """The project's own training path fits on encoded labels; export must map them back."""
    from ml.structural_classifier import StructuralClassifier

    X, labels = synthetic_dataset
    classifier = StructuralClassifier()
    classifier.train(X, list(labels))
    forest = classifier.model
    class_labels = list(classifier.label_encoder.inverse_transform(forest.classes_))
    assert list(forest.classes_) == [0, 1, 2]
    assert class_labels == ["clean", "malware", "suspicious"]

    document = export_random_forest(forest, class_labels=class_labels)
    path = tmp_path / "model.json"
    digest = write_model_artifact(document, path)
    assert digest == hashlib.sha256(path.read_bytes()).hexdigest()
    model = load_model(path, digest)

    stats = compare(forest, class_labels, model, np.vstack([X, parity_vectors(forest, X)]))
    assert stats["max_abs_diff"] <= PROBABILITY_TOLERANCE
    assert stats["label_mismatches"] == 0


# --- Exporter guards -------------------------------------------------------


@pytest.fixture(scope="module")
def tiny_forest():
    rng = np.random.default_rng(3)
    X = rng.random((30, LATENT_DIMENSION)).astype(np.float32)
    y = np.array(list(MODEL_CLASS_ORDER) * 10)
    return RandomForestClassifier(n_estimators=3, random_state=0, n_jobs=1).fit(X, y)


def test_exporter_rejects_unfitted_and_foreign_models():
    with pytest.raises(ValueError):
        export_random_forest(RandomForestClassifier())
    with pytest.raises(TypeError):
        export_random_forest(object())


def test_exporter_rejects_wrong_feature_count():
    forest = RandomForestClassifier(n_estimators=2, random_state=0).fit(
        np.random.default_rng(0).random((9, 10)), list(MODEL_CLASS_ORDER) * 3
    )
    with pytest.raises(ValueError, match="features"):
        export_random_forest(forest)


@pytest.mark.parametrize(
    "class_labels",
    [
        ["clean", "suspicious"],
        ["clean", "clean", "malware"],
        ["clean", "malware", "infected"],
    ],
)
def test_exporter_rejects_invalid_class_labels(tiny_forest, class_labels):
    with pytest.raises(ValueError):
        export_random_forest(tiny_forest, class_labels=class_labels)


def test_exporter_rejects_reserved_provenance_keys(tiny_forest):
    with pytest.raises(ValueError, match="reserved"):
        export_random_forest(tiny_forest, provenance={"sklearn_version": "forged"})


def test_importing_exporter_does_not_import_sklearn_until_export():
    code = (
        "import sys; import ml.forest_export, ml.forest_format; "
        "print(sorted(m for m in sys.modules if m.split('.')[0] in {'sklearn', 'joblib'}))"
    )
    completed = subprocess.run(
        [sys.executable, "-c", code], cwd=PROJECT_ROOT, capture_output=True, text=True, check=True
    )
    assert completed.stdout.strip() == "[]"
