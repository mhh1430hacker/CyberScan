"""Explicit, digest-first model loading in StructuralClassifier.

Models here are trained fresh in memory or in pytest temporary directories.
No legacy model artifact is read.
"""
from __future__ import annotations

import ast
import base64
import hashlib
import json
import pickle
from pathlib import Path

import numpy as np
import pytest

import ml.structural_classifier as structural_classifier
from ml.forest_format import encode_document, load_model
from ml.structural_classifier import CLASS_LABELS, LATENT_DIMENSION, StructuralClassifier

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PRODUCTION_PATHS = ("config.py", "main.py", "core", "ml", "ui", "reports", "monitoring")
SYNTHETIC_MANIFEST = PROJECT_ROOT / "data" / "datasets" / "synthetic_integration" / "manifest.csv"


@pytest.fixture
def forbid_pickle(monkeypatch):
    calls: list[str] = []

    def forbidden(name):
        def _raise(*_args, **_kwargs):
            calls.append(name)
            raise AssertionError(f"{name} must never be called")

        return _raise

    for name in ("load", "loads", "Unpickler"):
        monkeypatch.setattr(pickle, name, forbidden(f"pickle.{name}"))
    return calls


@pytest.fixture(scope="module")
def trained_classifier():
    rng = np.random.default_rng(11)
    X = rng.random((30, LATENT_DIMENSION)).astype(np.float32)
    y = np.array(list(CLASS_LABELS) * 10)
    classifier = StructuralClassifier()
    classifier.train(X, y)
    return classifier, X


@pytest.fixture
def saved_model(trained_classifier, tmp_path):
    classifier, X = trained_classifier
    path = tmp_path / "model.json"
    classifier.save(path, metadata={"training_examples": len(X)})
    # Digest computed independently by the test from the bytes on disk.
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return path, digest


def test_constructor_never_reads_or_deserializes(saved_model, monkeypatch, forbid_pickle):
    path, _digest = saved_model

    def no_load(*_args, **_kwargs):
        raise AssertionError("constructing a classifier must not load a model")

    monkeypatch.setattr(structural_classifier, "load_model", no_load)
    monkeypatch.setattr(Path, "open", no_load)
    monkeypatch.setattr(Path, "read_bytes", no_load)

    classifier = StructuralClassifier(path)

    assert classifier.is_ready is False
    assert classifier.forest is None and classifier.model is None
    assert classifier.predict(np.zeros(LATENT_DIMENSION))["status"] == "untrained"
    assert forbid_pickle == []


@pytest.mark.parametrize("approved", [None, "", "not-a-digest"])
def test_load_without_a_trusted_digest_reads_nothing(saved_model, monkeypatch, approved):
    path, _digest = saved_model

    def no_file_access(*_args, **_kwargs):
        raise AssertionError("an unapproved model file must not be touched")

    monkeypatch.setattr(Path, "stat", no_file_access)
    monkeypatch.setattr(Path, "open", no_file_access)

    classifier = StructuralClassifier()
    assert classifier.load(path, expected_sha256=approved) is False
    assert classifier.metadata["load_error"].startswith("Model not approved")
    assert classifier.is_ready is False


def test_default_load_call_without_digest_is_rejected():
    # core.file_analyzer calls load() with no arguments; it must never load.
    classifier = StructuralClassifier()

    assert classifier.load() is False
    assert "not approved" in classifier.metadata["load_error"]


def test_legacy_pickle_in_json_layout_is_rejected(tmp_path, forbid_pickle):
    payload = base64.b64encode(b"\x80\x04cos\nsystem\n(S'echo unsafe'\ntR.").decode("ascii")
    document = {
        "format": "cyberscan-random-forest-json-v1",
        "model": {"estimators_b64": payload},
        "metadata": {
            "schema_version": 1,
            "embedding_schema": "byte-histogram-entropy-v1",
            "embedding_dimension": 4096,
            "classes": list(CLASS_LABELS),
            "_model_hash": "0" * 64,
        },
    }
    path = tmp_path / "legacy.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    classifier = StructuralClassifier()
    digest = hashlib.sha256(path.read_bytes()).hexdigest()

    assert classifier.load(path, expected_sha256=digest) is False
    assert classifier.metadata["load_error"].startswith("Incompatible model artifact")
    assert forbid_pickle == []


def test_tampered_artifact_is_rejected(saved_model):
    path, digest = saved_model
    data = bytearray(path.read_bytes())
    data[data.index(b'"threshold":[') + 13] ^= 0x01
    path.write_bytes(bytes(data))

    classifier = StructuralClassifier()

    assert classifier.load(path, expected_sha256=digest) is False
    assert classifier.metadata["load_error"].startswith("Model file does not match the approved digest")


def test_wrong_digest_is_rejected(saved_model):
    path, digest = saved_model
    wrong = ("0" if digest[0] != "0" else "1") + digest[1:]

    classifier = StructuralClassifier()

    assert classifier.load(path, expected_sha256=wrong) is False
    assert "does not match" in classifier.metadata["load_error"]


def test_exported_model_loads_with_independent_digest(trained_classifier, saved_model):
    classifier, _X = trained_classifier
    path, digest = saved_model

    loaded = StructuralClassifier()

    assert classifier.artifact_sha256 == digest
    assert loaded.load(path, expected_sha256=digest) is True
    assert loaded.is_ready and loaded.model is None and loaded.forest is not None
    assert loaded.metadata["artifact_sha256"] == digest
    assert loaded.metadata["embedding_schema"] == structural_classifier.EMBEDDING_SCHEMA
    assert loaded.metadata["classes"] == list(CLASS_LABELS)
    assert loaded.metadata["training_examples"] == 30
    assert loaded.metadata["scores_are_calibrated"] is False
    assert loaded.metadata["load_error"] is None


def test_loaded_predictions_match_safe_evaluator_and_training_forest(trained_classifier, saved_model):
    classifier, X = trained_classifier
    path, digest = saved_model
    vectors = np.vstack([X, np.random.default_rng(12).uniform(-1, 1, (100, LATENT_DIMENSION))])

    loaded = StructuralClassifier()
    assert loaded.load(path, expected_sha256=digest)
    evaluator = load_model(path, digest)

    np.testing.assert_array_equal(loaded.predict_proba(vectors), evaluator.predict_proba(vectors))
    assert np.max(np.abs(loaded.predict_proba(vectors) - classifier.predict_proba(vectors))) <= 1e-12
    assert loaded.predict(vectors)["label"] == evaluator.predict(vectors)
    assert loaded.predict(vectors)["label"] == classifier.predict(vectors)["label"]
    single = loaded.predict(vectors[0])
    assert single["status"] == "classified"
    assert list(single["class_scores"]) == list(CLASS_LABELS)
    assert sum(single["class_scores"].values()) == pytest.approx(100.0)


def test_in_memory_probabilities_use_declared_class_order(trained_classifier):
    classifier, X = trained_classifier
    raw = classifier.model.predict_proba(X)
    names = classifier._trained_class_labels()

    ordered = classifier.predict_proba(X)

    assert names == ["clean", "malware", "suspicious"]
    # The in-memory forest uses n_jobs=-1, so tree accumulation order (and the
    # last bits of each sum) can differ between two predict_proba calls.
    for column, name in enumerate(CLASS_LABELS):
        np.testing.assert_allclose(ordered[:, column], raw[:, names.index(name)], rtol=0, atol=1e-12)


def test_failed_load_discards_previously_loaded_model(saved_model, tmp_path):
    path, digest = saved_model
    classifier = StructuralClassifier()
    assert classifier.load(path, expected_sha256=digest)

    assert classifier.load(tmp_path / "missing.json", expected_sha256=digest) is False
    assert classifier.forest is None
    assert classifier.is_ready is False
    assert classifier.artifact_sha256 is None


def test_save_rejects_non_scalar_metadata(trained_classifier, tmp_path):
    classifier, _X = trained_classifier

    with pytest.raises(ValueError, match="metadata"):
        classifier.save(tmp_path / "model.json", metadata={"validation_metrics": {"accuracy": 1.0}})


def test_saved_artifact_is_plain_safe_json(saved_model):
    path, digest = saved_model
    data = path.read_bytes()

    for marker in (b"estimators_b64", b"gASV", b"gAWV", b"\x80\x04", b"\x80\x05"):
        assert marker not in data
    assert data == encode_document(json.loads(data))
    assert load_model(path, digest).sha256 == digest


def test_evaluation_requires_and_uses_an_explicit_digest(tmp_path):
    from ml.training.evaluate import evaluate_model, evaluate_model_consistency
    from ml.training.train import train_from_manifest

    model_path = tmp_path / "model.json"
    training = train_from_manifest(
        SYNTHETIC_MANIFEST, model_path, split_method="random", test_size=0.25
    )
    digest = hashlib.sha256(model_path.read_bytes()).hexdigest()
    assert training["sha256"] == digest

    with pytest.raises(TypeError):
        evaluate_model(model_path, SYNTHETIC_MANIFEST)  # digest is a required argument
    with pytest.raises(RuntimeError, match="does not match"):
        evaluate_model(model_path, SYNTHETIC_MANIFEST, expected_sha256="0" * 64)

    results = evaluate_model(model_path, SYNTHETIC_MANIFEST, expected_sha256=digest)
    assert results["model_metadata"]["n_estimators"] == 200
    assert results["model_metadata"]["labels"] == list(CLASS_LABELS)
    consistency = evaluate_model_consistency(model_path, SYNTHETIC_MANIFEST, expected_sha256=digest)
    assert consistency["labels_match"] and consistency["probabilities_match"]
    assert consistency["max_prob_diff"] == 0.0


# --- Production code contains no executable deserialization -----------------

FORBIDDEN_MODULES = {"pickle", "cPickle", "_pickle", "joblib", "dill", "cloudpickle", "marshal", "shelve"}
FORBIDDEN_CALLS = {"read_pickle", "torch.load"}


def _production_files():
    for entry in PRODUCTION_PATHS:
        path = PROJECT_ROOT / entry
        if path.is_file():
            yield path
        else:
            yield from sorted(path.rglob("*.py"))


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{_dotted(node.value)}.{node.attr}"
    return ""


def test_production_code_has_no_executable_deserialization_path():
    findings = []
    files = list(_production_files())
    assert len(files) > 20
    for path in files:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".")[0] in FORBIDDEN_MODULES:
                        findings.append(f"{path.name}:{node.lineno} import {alias.name}")
            elif isinstance(node, ast.ImportFrom) and node.module:
                if node.module.split(".")[0] in FORBIDDEN_MODULES:
                    findings.append(f"{path.name}:{node.lineno} from {node.module}")
            elif isinstance(node, ast.Call):
                name = _dotted(node.func)
                if name.endswith(tuple(FORBIDDEN_CALLS)) or name.split(".")[-1] == "read_pickle":
                    findings.append(f"{path.name}:{node.lineno} call {name}")
                if name.split(".")[-1] == "load" and any(
                    keyword.arg == "allow_pickle" for keyword in node.keywords
                ):
                    findings.append(f"{path.name}:{node.lineno} {name}(allow_pickle=...)")
    assert findings == []
