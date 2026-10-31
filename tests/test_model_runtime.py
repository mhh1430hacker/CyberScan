"""Only a person-approved structural model runs, verified by its SHA-256."""
from __future__ import annotations

import json
import pickle

import numpy as np
import pytest

import config
from core import file_analyzer
from ml import approve_model, model_runtime
from ml.structural_classifier import CLASS_LABELS, LATENT_DIMENSION, StructuralClassifier


@pytest.fixture
def registry(tmp_path, monkeypatch):
    path = tmp_path / "trusted_models.json"
    monkeypatch.setattr(config, "TRUSTED_MODELS_FILE", path)
    model_runtime.revoke()
    yield path
    model_runtime.revoke()


@pytest.fixture
def model_file(tmp_path):
    rng = np.random.default_rng(7)
    X = rng.random((30, LATENT_DIMENSION)).astype(np.float32)
    classifier = StructuralClassifier()
    classifier.train(X, np.array(list(CLASS_LABELS) * 10))
    path = tmp_path / "structural.json"
    classifier.save(path, metadata={"training_examples": 30})
    return path


@pytest.fixture
def no_pickle(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("pickle must never be used")

    for name in ("load", "loads", "Unpickler"):
        monkeypatch.setattr(pickle, name, forbidden)


def test_nothing_is_approved_by_default(registry):
    classifier, state = model_runtime.load_approved()
    assert classifier is None and state.state == "unapproved"
    assert state.detail == model_runtime.UNAPPROVED_STATUS


def test_disabled_never_reads_the_registry(registry):
    registry.write_text("not json", encoding="utf-8")
    assert model_runtime.load_approved(enabled=False)[1].state == "disabled"


def test_approved_model_loads_and_scans_use_it(registry, model_file, tmp_path, no_pickle):
    entry = model_runtime.approve(model_file)
    assert json.loads(registry.read_text(encoding="utf-8"))["structural"]["sha256"] == entry["sha256"]
    classifier, state = model_runtime.load_approved()
    assert state.state == "ready" and classifier is not None
    sample = tmp_path / "sample.txt"
    sample.write_bytes(b"ordinary content")
    result = file_analyzer.analyze_file(str(sample))
    assert result.structural_prediction["status"] == "classified"
    assert result.engine_status["ML"] == model_runtime.READY_STATUS
    assert sample.read_bytes() == b"ordinary content"


def test_a_file_changed_after_approval_is_rejected(registry, model_file):
    model_runtime.approve(model_file)
    document = json.loads(model_file.read_text(encoding="utf-8"))
    document["provenance"] = {**document.get("provenance", {}), "edited": True}
    model_file.write_text(json.dumps(document), encoding="utf-8")
    classifier, state = model_runtime.load_approved()
    assert classifier is None and state.state == "rejected"


def test_missing_file_and_broken_registry_fail_closed(registry, model_file):
    model_runtime.approve(model_file)
    model_file.unlink()
    assert model_runtime.load_approved()[1].state == "missing"
    registry.write_text("{bad", encoding="utf-8")
    assert model_runtime.load_approved()[1].state == "error"


def test_non_model_files_cannot_be_approved(registry, tmp_path):
    bogus = tmp_path / "bogus.json"
    bogus.write_text('{"format": "something-else"}', encoding="utf-8")
    with pytest.raises(ValueError):
        model_runtime.approve(bogus)
    assert not registry.exists()


def test_legacy_artifact_cannot_be_approved(registry):
    legacy = config.MODEL_DIR / "structural_classifier_4096.json"
    if not legacy.is_file():
        pytest.skip("legacy artifact not present")
    before = legacy.read_bytes()
    with pytest.raises(ValueError):
        model_runtime.approve(legacy)
    assert legacy.read_bytes() == before


def test_cli_asks_before_approving(registry, model_file, monkeypatch, capsys):
    monkeypatch.setattr("builtins.input", lambda _prompt: "no")
    assert approve_model.main([str(model_file)]) == 1
    assert not registry.exists()
    assert approve_model.main([str(model_file), "--yes"]) == 0
    assert model_runtime.model_state().state == "ready"
    assert approve_model.main(["--revoke"]) == 0
    assert model_runtime.model_state().state == "unapproved"
