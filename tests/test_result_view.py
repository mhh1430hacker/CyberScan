"""Presentation rules for the results screen (no Qt required)."""
from __future__ import annotations

import math

import pytest

from core.models import Finding, ScanResult
from ui.result_view import build_result_view, classify_engine_status


def make_result(classification="REVIEW", score=25, evidence=(), engine_status=None, **extra):
    return ScanResult(
        target=extra.pop("target", "C:/samples/sample.bin"),
        heuristic_score=score if isinstance(score, int) else 0,
        ml_risk_score=None,
        combined_score=score,
        classification=classification,
        evidence=list(evidence),
        feature_summary=extra.pop("feature_summary", {"file_size": 2048, "sha256": "ab" * 32}),
        engine_status=engine_status if engine_status is not None else {"YARA": "available; 1 rule(s) loaded"},
        **extra,
    )


@pytest.mark.parametrize(
    ("status", "state"),
    [
        # Values produced by the current engines.
        ("available; 1 rule(s) loaded", "ran"),
        ("available; 1 rule(s) loaded (error: rule compile failed)", "failed"),
        ("unavailable", "unavailable"),
        ("no rules configured", "unavailable"),
        ("ok", "ran"),
        ("not_pe", "not_applicable"),
        ("missing", "unavailable"),
        ("dependency_missing", "unavailable"),
        ("decoder_unavailable", "unavailable"),
        ("Structural model rejected: Model not approved: No valid approved SHA-256 digest", "unavailable"),
        ("ML analysis disabled by settings.", "disabled"),
        ("4096-D supervised structural classifier loaded; class scores are uncalibrated.", "ran"),
        ("not a ZIP container", "not_applicable"),
        ("bounded structure inspection; ok; 1 member(s); member contents not malware-scanned", "ran"),
        ("bounded structure inspection; partial; 3 member(s)", "partial"),
        ("bounded structure inspection; unsupported; 0 member(s)", "unavailable"),
        ("disabled", "disabled"),
        ("not requested", "disabled"),
        ("matched", "ran"),
        ("no_match", "ran"),
        ("partial_timeout", "partial"),
        ("invalid_indicator", "not_applicable"),
        ("enabled", "ran"),
        ("", "unknown"),
        ("something new", "unknown"),
    ],
)
def test_engine_status_classification(status, state):
    assert classify_engine_status(status) == state


@pytest.mark.parametrize(
    ("classification", "key", "tone"),
    [
        ("SUSPICIOUS", "high", "danger"),
        ("REVIEW", "review", "warn"),
        ("NO_INDICATORS_OBSERVED", "low", "ok"),
    ],
)
def test_verdict_follows_engine_classification(classification, key, tone):
    view = build_result_view(make_result(classification, 0 if key == "low" else 60))

    assert view.verdict.key == key
    assert view.verdict.tone == tone
    assert view.classification == classification


def test_low_risk_never_claims_safety():
    view = build_result_view(make_result("NO_INDICATORS_OBSERVED", 0))

    assert "does not prove the target is safe" in view.verdict.detail
    assert "safe" not in view.verdict.title.lower()


def test_failed_engine_makes_an_empty_result_inconclusive():
    view = build_result_view(
        make_result("NO_INDICATORS_OBSERVED", 0, engine_status={"YARA": "error: rule load failed", "PE": "ok"})
    )

    assert view.verdict.key == "inconclusive"
    assert view.verdict.tone == "neutral"


def test_failed_engine_does_not_soften_observed_indicators():
    view = build_result_view(
        make_result("SUSPICIOUS", 70, engine_status={"YARA": "error: rule load failed"})
    )

    assert view.verdict.key == "high"


def test_unavailable_structural_model_does_not_make_result_inconclusive():
    view = build_result_view(
        make_result(
            "NO_INDICATORS_OBSERVED",
            0,
            engine_status={"YARA": "available; 1 rule(s) loaded", "ML": "Structural model rejected: Load failed"},
        )
    )

    assert view.verdict.key == "low"


def test_unknown_classification_is_inconclusive():
    view = build_result_view(make_result("SOMETHING_ELSE", 10))

    assert view.verdict.key == "inconclusive"
    assert "does not recognise" in view.verdict.detail


@pytest.mark.parametrize("score", [None, -1, 101, math.nan, math.inf, "25", True])
def test_invalid_scores_are_not_shown(score):
    result = make_result("REVIEW", 25)
    result.combined_score = score

    assert build_result_view(result).score is None


def test_findings_sorted_by_contribution_and_severity_normalized():
    evidence = (
        Finding("statistical", "medium", "High entropy", "explanation a", 18),
        Finding("yara", "critical", "Rule matched", "explanation b", 50),
        Finding("test_marker", "informational", "EICAR test marker", "harmless", 0),
        Finding("structural", "moderate", "Header mismatch", "explanation c", 18),
    )
    view = build_result_view(make_result("SUSPICIOUS", 50, evidence))

    assert [f.title for f in view.findings] == [
        "Rule matched",
        "Header mismatch",
        "High entropy",
        "EICAR test marker",
    ]
    assert [f.severity for f in view.findings] == ["high", "medium", "medium", "info"]
    assert view.highest_severity == "high"
    # Raw engine text is carried unchanged.
    assert view.findings[0].explanation == "explanation b"


def test_category_counts_come_from_findings():
    evidence = (
        Finding("structural", "high", "a", "", 25),
        Finding("structural", "medium", "b", "", 15),
        Finding("statistical", "medium", "c", "", 18),
    )
    view = build_result_view(make_result("REVIEW", 25, evidence))

    assert [(c.category, c.count, c.top_severity) for c in view.categories] == [
        ("structural", 2, "high"),
        ("statistical", 1, "medium"),
    ]


def test_mitre_placeholder_is_not_counted():
    result = make_result("REVIEW", 25, mitre_techniques=[{"id": "N/A", "name": "No mapped ATT&CK technique"}])
    assert build_result_view(result).mitre_count == 0
    result.mitre_techniques = [{"id": "T1027", "name": "Obfuscated Files or Information"}]
    assert build_result_view(result).mitre_count == 1


def test_missing_and_empty_fields_do_not_invent_values():
    result = make_result("REVIEW", 25, engine_status={}, feature_summary={})
    result.pe_analysis = None
    result.yara_matches = None
    result.mitre_techniques = None
    result.evidence = None

    view = build_result_view(result, nextgen=None)

    assert view.findings == ()
    assert view.categories == ()
    assert view.coverage == ()
    assert view.highest_severity is None
    assert view.file_size is None and view.sha256 is None
    assert view.mean_entropy is None and view.pe_status is None and view.input_profile is None
    assert view.mitre_count == 0 and view.yara_count == 0
    assert view.score == 25


def test_file_facts_are_read_from_the_result():
    result = make_result("REVIEW", 25, feature_summary={"file_size": 1278, "sha256": "cd" * 32})
    result.pe_analysis = {"status": "not_pe"}
    nextgen = {"input_profile": "binary-content", "entropy_topography": {"mean_entropy": 7.851}}

    view = build_result_view(result, nextgen)

    assert view.display_name == "sample.bin"
    assert view.file_size == 1278
    assert view.sha256 == "cd" * 32
    assert view.pe_status == "not_pe"
    assert view.input_profile == "binary-content"
    assert view.mean_entropy == pytest.approx(7.851)
