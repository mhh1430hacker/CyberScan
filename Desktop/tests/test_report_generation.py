from core.models import Finding, ScanResult
from reports.report_generator import generate_report


def test_report_generation_includes_fields():
    result = ScanResult(
        target="demo.txt",
        heuristic_score=42,
        ml_anomaly_score=None,
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
