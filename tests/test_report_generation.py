import json

from core.models import Finding, ScanResult
from reports.exporter import export_report
from reports.report_generator import generate_report


def test_report_generation_includes_fields():
    result = ScanResult(
        target="demo.txt",
        heuristic_score=42,
        ml_risk_score=None,
        combined_score=42,
        classification="UNKNOWN",
        evidence=[Finding("heuristic", "medium", "Suspicious string", "Test explanation", 10)],
        feature_summary={"entropy": 6.5},
        model_status="ML model not available.",
        limitations="Static analysis active; ML unavailable.",
        summary="Heuristic summary",
    )
    report = generate_report(result)
    assert "Heuristic score: 42/100" in report
    assert "Classification: UNKNOWN" in report
    assert "Evidence:" in report


def test_report_exports_include_structural_analysis(tmp_path):
    result = ScanResult(
        target="demo.bin",
        heuristic_score=10,
        ml_risk_score=None,
        combined_score=10,
        classification="REVIEW",
        nextgen_analysis={
            "input_profile": "binary-content",
            "composite_innovation_score": 23.5,
            "entropy_topography": {"mean_entropy": 5.2, "peak_entropy": 7.1},
            "cfg_topology": {"architecture": "x86", "cyclomatic_complexity": 3},
        },
    )
    text_path = tmp_path / "report.txt"
    json_path = tmp_path / "report.json"

    export_report(result, text_path)
    export_report(result, json_path, "json")

    assert "Additional structural analysis:" in text_path.read_text(encoding="utf-8")
    assert json.loads(json_path.read_text(encoding="utf-8"))["nextgen_analysis"] == result.nextgen_analysis
