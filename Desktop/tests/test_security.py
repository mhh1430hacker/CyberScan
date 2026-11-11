from __future__ import annotations

import json
import re
from pathlib import Path

import core.global_intelligence as global_intelligence
from core.global_intelligence import GlobalIntelligenceEngine
from ml.anomaly_detector import AnomalyDetector
from ml.feature_schema import FEATURE_ORDER, SCHEMA_VERSION

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_no_api_keys_are_embedded_in_source():
    suspicious = re.compile(r"""(?:KEY|TOKEN|SECRET)\s*=\s*["'][A-Za-z0-9_\-]{24,}["']""")
    offenders = [
        str(path.relative_to(PROJECT_ROOT))
        for path in PROJECT_ROOT.rglob("*.py")
        if "tests" not in path.parts and suspicious.search(path.read_text(encoding="utf-8"))
    ]
    assert offenders == []


def test_feeds_without_keys_report_authentication_required(monkeypatch):
    for name in ("ABUSECH_AUTH_KEY", "THREATFOX_API_KEY", "URLHAUS_API_KEY", "OTX_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    engine = GlobalIntelligenceEngine()
    assert engine.api_keys == {"threatfox": "", "urlhaus": "", "otx": ""}


def test_environment_keys_are_picked_up(monkeypatch):
    monkeypatch.setenv("ABUSECH_AUTH_KEY", "env-key")
    engine = GlobalIntelligenceEngine()
    assert engine.api_keys["threatfox"] == "env-key"
    assert engine.api_keys["urlhaus"] == "env-key"


def _write_model_files(tmp_path, digest):
    model_path = tmp_path / "model.joblib"
    model_path.write_bytes(b"pretend this is a pickle")
    metadata = {
        "schema_version": SCHEMA_VERSION,
        "feature_order": FEATURE_ORDER,
        "training_data_type": "curated_benign_manifest",
    }
    if digest is not None:
        metadata["model_sha256"] = digest
    model_path.with_suffix(".json").write_text(json.dumps(metadata), encoding="utf-8")
    return model_path


def test_model_without_digest_is_refused_before_unpickling(tmp_path):
    detector = AnomalyDetector(_write_model_files(tmp_path, None))
    assert detector.load() is False
    assert "integrity" in detector.metadata["load_error"]


def test_model_with_wrong_digest_is_refused_before_unpickling(tmp_path):
    detector = AnomalyDetector(_write_model_files(tmp_path, "0" * 64))
    assert detector.load() is False
    assert "integrity" in detector.metadata["load_error"]
