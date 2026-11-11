import hashlib
import builtins

import pytest

import core.file_analyzer as file_analyzer
from core.feature_extractor import extract_file_features
from core.models import Finding, ScanResult
from core.risk_engine import finalize_result
from core.scanner import scan_target
from core.url_analyzer import analyze_url


def test_training_and_scanning_use_identical_file_features(tmp_path):
    content = b"powershell -enc " + bytes(range(256)) * 5
    sample = tmp_path / "sample.txt"
    sample.write_bytes(content)

    expected = extract_file_features(content, sample.name)
    result = file_analyzer.analyze_file(str(sample))

    for name in (
        "file_size",
        "entropy",
        "average_section_entropy",
        "max_section_entropy",
        "suspicious_string_count",
        "string_count",
    ):
        assert result.feature_summary[name] == expected[name]
    assert result.feature_summary["sha256"] == hashlib.sha256(content).hexdigest()


def test_url_heuristics_do_not_add_the_same_signal_twice():
    url = "http://192.0.2.10/payload"

    result = analyze_url(url)

    assert result["score"] == 30
    assert len(result["findings"]) == 1


def test_text_indicators_preserve_explainable_findings():
    result = scan_target("powershell -enc abc")

    assert result.evidence
    assert result.classification == "SUSPICIOUS"
    assert result.combined_score == result.heuristic_score


def test_disabling_heuristics_is_honored_for_text_targets():
    result = scan_target("powershell -enc abc", settings={"heuristic_rules": False})

    assert result.evidence == []
    assert result.classification == "NO_INDICATORS_OBSERVED"


def test_direct_evidence_floor_and_canonical_classification():
    result = ScanResult(
        target="sample.bin",
        heuristic_score=0,
        ml_risk_score=0,
        combined_score=0,
        classification="NO_INDICATORS_OBSERVED",
        evidence=[Finding("yara", "high", "rule", "matched rule", 50)],
    )

    finalize_result(result, heuristic_weight=0.7, ml_weight=0.3)

    assert result.combined_score == 50
    assert result.classification == "SUSPICIOUS"
    assert "classification: SUSPICIOUS" in result.summary


def test_default_risk_score_does_not_mix_uncalibrated_ml_scores():
    result = ScanResult(
        target="sample.bin",
        heuristic_score=20,
        ml_risk_score=95,
        combined_score=0,
        classification="REVIEW",
    )

    finalize_result(result)

    assert result.combined_score == 20


def test_invalid_risk_weights_are_rejected():
    result = ScanResult("sample", 0, None, 0, "NO_INDICATORS_OBSERVED")

    with pytest.raises(ValueError, match="non-negative"):
        finalize_result(result, heuristic_weight=-1, ml_weight=1)


def test_yara_failures_are_reported_as_engine_status(tmp_path, monkeypatch):
    sample = tmp_path / "sample.txt"
    sample.write_text("ordinary text", encoding="utf-8")
    monkeypatch.setattr(
        file_analyzer,
        "scan_file_for_yara",
        lambda *_args, **_kwargs: {
            "available": False,
            "error": "test dependency error",
            "matches": [],
            "rules_loaded": 0,
        },
    )

    result = file_analyzer.analyze_file(str(sample))

    assert "unavailable" in result.engine_status["YARA"]
    assert "test dependency error" in result.engine_status["YARA"]


def test_file_analysis_deadline_is_checked_between_stages(tmp_path, monkeypatch):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"sample content")
    original = file_analyzer.extract_file_features

    def slow_features(*args, **kwargs):
        import time

        time.sleep(0.03)
        return original(*args, **kwargs)

    monkeypatch.setattr(file_analyzer, "extract_file_features", slow_features)

    with pytest.raises(TimeoutError, match="deadline"):
        file_analyzer.analyze_file(str(sample), settings={"analysis_timeout": 0.01})


def test_file_size_is_checked_before_reading_the_file(tmp_path, monkeypatch):
    sample = tmp_path / "large.bin"
    sample.write_bytes(b"0123456789")

    def forbidden_open(*_args, **_kwargs):
        raise AssertionError("oversized file must be rejected before reading")

    monkeypatch.setattr(builtins, "open", forbidden_open)

    with pytest.raises(ValueError, match="maximum file size"):
        file_analyzer.analyze_file(str(sample), settings={"maximum_file_size": 5})


def test_file_read_is_bounded_when_size_changes_after_initial_check(tmp_path, monkeypatch):
    sample = tmp_path / "growing.bin"
    sample.write_bytes(b"0123456789")
    monkeypatch.setattr(file_analyzer.os.path, "getsize", lambda _path: 0)

    with pytest.raises(ValueError, match="maximum file size"):
        file_analyzer.analyze_file(
            str(sample),
            settings={"maximum_file_size": 5},
        )


def test_disabling_ml_does_not_load_the_model(tmp_path, monkeypatch):
    sample = tmp_path / "sample.txt"
    sample.write_text("ordinary text", encoding="utf-8")

    class DisabledModel:
        metadata = {}

        def load(self):
            raise AssertionError("disabled ML must not load the model")

    monkeypatch.setattr(file_analyzer, "StructuralClassifier", DisabledModel)

    result = file_analyzer.analyze_file(str(sample), settings={"ml_analysis": False})

    assert result.ml_risk_score is None
    assert result.model_status == "ML analysis disabled by settings."


def test_structural_model_scores_file_without_modifying_it(tmp_path, monkeypatch):
    sample = tmp_path / "sample.txt"
    original = b"ordinary file content for structural classification"
    sample.write_bytes(original)

    class LoadedModel:
        metadata = {}

        def load(self):
            return True

        def predict(self, vector):
            assert len(vector) == 4096
            return {
                "status": "classified",
                "label": "clean",
                "class_scores": {"clean": 75.0, "suspicious": 20.0, "malware": 5.0},
                "infection_score": 25.0,
                "scores_are_calibrated": False,
                "repair_review_candidate": None,
                "repair_status": "not_available",
            }

    monkeypatch.setattr(file_analyzer, "StructuralClassifier", LoadedModel)

    result = file_analyzer.analyze_file(str(sample))

    assert result.ml_risk_score == 25.0
    assert result.structural_prediction["label"] == "clean"
    assert result.structural_prediction["repair_review_candidate"] is None
    assert sample.read_bytes() == original
