"""Results screen: verdict-first layout driven only by real scan data."""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PySide6")

from PySide6.QtCore import Qt  # noqa: E402
from PySide6.QtWidgets import QApplication, QPushButton  # noqa: E402

import ui.qt_app as qt_app  # noqa: E402
from config import DEFAULT_SETTINGS  # noqa: E402
from core.models import Finding, ScanResult  # noqa: E402
from ui.result_view import build_result_view  # noqa: E402
from ui.scan_service import ScanService  # noqa: E402


@pytest.fixture(scope="module")
def qapplication():
    app = QApplication.instance() or QApplication([])
    yield app


@pytest.fixture
def window(tmp_path, monkeypatch, qapplication):
    monkeypatch.setattr(qt_app, "DATA_DIR", tmp_path / "data")
    monkeypatch.setattr(qt_app, "REPORT_DIR", tmp_path / "reports")
    monkeypatch.setattr(qt_app, "ensure_directories", lambda: None)
    monkeypatch.setattr(qt_app.QApplication, "primaryScreen", lambda: None)
    app = qt_app.CyberScanApp()
    try:
        yield app
    finally:
        app.close()


def payload(classification="REVIEW", score=25, evidence=(), engine_status=None, feature_summary=None):
    result = ScanResult(
        target="C:/samples/sample.bin",
        heuristic_score=score if isinstance(score, int) else 0,
        ml_risk_score=None,
        combined_score=score,
        classification=classification,
        evidence=list(evidence),
        feature_summary={"file_size": 1278, "sha256": "ab" * 32} if feature_summary is None else feature_summary,
        engine_status={"YARA": "available; 1 rule(s) loaded", "PE": "not_pe", "OSINT": "disabled"}
        if engine_status is None
        else engine_status,
        mitre_techniques=[{"id": "T1027", "name": "Obfuscated Files or Information", "evidence": []}],
        pe_analysis={"status": "not_pe"},
    )
    nextgen = {
        "entropy_topography": {"trajectory": (1.0, 2.0), "mean_entropy": 7.85},
        "cfg_topology": {"cyclomatic_complexity": 2},
        "forensic_storyboard": ["Measured story line."],
        "input_profile": "binary-content",
    }
    prediction = {"status": "untrained", "label": None, "class_scores": {}}
    intelligence = {"status": "disabled", "indicator_type": None, "feeds": {}}
    return (result, nextgen, (0.0,) * 16, prediction, intelligence, b"sample-bytes")


def render(window, data):
    window.last_payload = data
    window._render_result(*data)
    return window._results_view


FINDINGS = (
    Finding("structural", "high", "Header mismatch", "The file extension does not match the observed magic bytes.", 25),
    Finding("statistical", "medium", "High entropy", "The content deviates from typical low-entropy data.", 18),
    Finding("structural", "medium", "Static decoding indicator", "ANTI_DISASSEMBLY_GAP", 15),
)


@pytest.mark.parametrize(
    ("classification", "score", "evidence", "engines", "title", "tone", "banner"),
    [
        ("SUSPICIOUS", 70, FINDINGS, None, "High risk", "danger", "error"),
        ("REVIEW", 25, FINDINGS, None, "Needs review", "warn", "warning"),
        ("NO_INDICATORS_OBSERVED", 0, (), None, "Low risk", "ok", "success"),
        ("NO_INDICATORS_OBSERVED", 0, (), {"YARA": "error: rule load failed", "PE": "ok"}, "Inconclusive", "neutral", "warning"),
    ],
)
def test_each_verdict_state_renders_with_title_symbol_and_colour(
    window, classification, score, evidence, engines, title, tone, banner
):
    view = render(window, payload(classification, score, evidence, engines))

    assert view.verdict.title == title and view.verdict.tone == tone
    assert title in window.verdict_badge._label
    assert window.verdict_badge._label.startswith(view.verdict.symbol)
    assert window.verdict_badge._color.name() == qt_app.tone_color(tone)
    assert window.status_banner.property("tone") == banner
    assert window.risk_gauge.isHidden() is False
    assert window.risk_caption.text() == f"{score}/100"
    assert window.stat_tiles["findings"].value.text() == str(len(evidence))
    assert len(window.finding_cards) == len(evidence)
    assert window.no_findings_state.isHidden() is bool(evidence)


def test_low_risk_text_never_says_safe(window):
    render(window, payload("NO_INDICATORS_OBSERVED", 0))

    assert "does not prove the target is safe" in window.verdict_badge._detail
    assert "does not prove the target is safe" in window.status_banner.detail.text()


def test_missing_score_hides_gauge_instead_of_inventing_one(window):
    data = payload("REVIEW", 25, FINDINGS)
    data[0].combined_score = None

    render(window, data)

    assert window.risk_gauge.isHidden() is True
    assert window.risk_unavailable.isHidden() is False
    assert window.risk_unavailable.text() == "Risk index not available"
    assert window.risk_caption.text() == ""


def test_empty_and_missing_fields_show_not_available(window):
    data = payload("REVIEW", 10, (), engine_status={}, feature_summary={})
    data[0].pe_analysis = {}
    data[1].pop("input_profile")
    data[1]["entropy_topography"] = {"trajectory": (), "mean_entropy": 0.0}

    render(window, data)

    assert window.no_findings_state.isHidden() is False
    assert window.category_bars.isHidden() is True
    assert window.category_unavailable.isHidden() is False
    assert window.coverage_unavailable.isHidden() is False
    assert window.stat_tiles["coverage"].value.text() == "Not available"
    assert window.stat_tiles["severity"].value.text() == "None"
    for key in ("size", "sha256", "type", "pe"):
        assert window.file_rows[key].value.text() == "Not available"


def test_cards_show_engine_text_unchanged_strongest_first(window):
    render(window, payload("REVIEW", 25, tuple(reversed(FINDINGS))))

    titles = [card.title.text() for card in window.finding_cards]
    assert titles == ["Header mismatch", "High entropy", "Static decoding indicator"]
    first = window.finding_cards[0]
    assert first.severity.text() == "\u25b2 High"
    assert first.explanation.text() == FINDINGS[0].explanation
    assert first.contribution.text() == "Weight 25/100"


def test_more_than_five_findings_offer_the_full_list(window, qapplication):
    many = tuple(Finding("heuristic", "low", f"Indicator {i}", f"Detail {i}", 10 - i) for i in range(7))
    render(window, payload("REVIEW", 10, many))

    assert len(window.finding_cards) == 5
    assert window.findings_overflow_button.isHidden() is False
    assert "7" in window.findings_overflow_button.text()
    window.findings_overflow_button.click()
    assert window.technical_section.is_expanded() is True
    assert window.detail_tabs.currentIndex() == 2
    assert window.findings_list.count() == 7


def test_category_chart_and_coverage_use_real_counts(window):
    render(window, payload("REVIEW", 25, FINDINGS))

    rows = [(name.text(), value.text()) for name, _bar, value in window.category_bars.rows]
    assert rows == [("File structure", "2"), ("Entropy and statistics", "1")]
    assert window.coverage_chips["YARA"].text() == "\u2713 Ran"
    assert window.coverage_chips["PE"].text() == "\u2013 Not applicable"
    assert window.coverage_chips["OSINT"].text() == "\u25cb Off"
    # 3 engines: YARA ran; PE not applicable and OSINT off are excluded from the total.
    assert window.stat_tiles["coverage"].value.text() == "1 of 1"
    assert "1 not applicable" in window.stat_tiles["coverage"].note.text()
    assert window.stat_tiles["mitre"].value.text() == "1"


def test_disabled_engine_is_not_reported_as_partial_coverage(window):
    render(window, payload("REVIEW", 25, FINDINGS))

    assert "Partial coverage" not in window.completeness_chip.text()
    assert window.completeness_chip.text() == "All enabled engines ran"


def test_arabic_layout_translates_labels_but_not_raw_evidence(window):
    render(window, payload("REVIEW", 25, FINDINGS))
    window.toggle_language()

    assert window.language == "ar"
    assert window.layoutDirection() == Qt.LayoutDirection.RightToLeft
    assert "يحتاج إلى مراجعة" in window.verdict_badge._label
    assert window.finding_cards[0].severity.text() == "\u25b2 مرتفعة"
    assert window.finding_cards[0].title.text() == "Header mismatch"
    assert window.evidence_header.title.text() == "أهم الأدلة"
    assert window.stat_tiles["coverage"].value.text() == "1 من 1"
    sha_row = window.file_rows["sha256"].value
    assert sha_row.text() == "ab" * 32
    assert sha_row.layoutDirection() == Qt.LayoutDirection.LeftToRight
    assert window.file_rows["entropy"].value.text() == "7.85 من 8 بت لكل بايت"
    assert window.details_button.text() == "عرض التفاصيل التقنية"
    window.toggle_language()
    assert window.verdict_badge._label.endswith("Needs review")


def test_details_button_toggles_technical_section(window):
    render(window, payload("REVIEW", 25, FINDINGS))

    assert window.technical_section.is_expanded() is False
    window.details_button.click()
    assert window.technical_section.is_expanded() is True
    assert window.details_button.text() == "Hide technical details"
    window.details_button.click()
    assert window.technical_section.is_expanded() is False


def test_file_section_expands_with_its_header(window):
    render(window, payload("REVIEW", 25, FINDINGS))

    window.file_section.header.click()
    assert window.file_section.body.isHidden() is False
    assert window.file_rows["sha256"].value.text() == "ab" * 32


def test_export_button_writes_the_displayed_result(window, tmp_path, monkeypatch):
    data = payload("SUSPICIOUS", 70, FINDINGS)
    render(window, data)
    destination = tmp_path / "report.json"
    monkeypatch.setattr(
        qt_app.QFileDialog, "getSaveFileName", lambda *a, **k: (str(destination), "JSON (*.json)")
    )
    monkeypatch.setattr(qt_app.QMessageBox, "information", lambda *a, **k: None)

    window.export_button.click()

    exported = json.loads(destination.read_text(encoding="utf-8"))
    assert exported["combined_score"] == 70
    assert exported["classification"] == "SUSPICIOUS"
    assert [item["evidence"] for item in exported["evidence"]] == [f.evidence for f in FINDINGS]


def test_new_scan_returns_to_the_composer(window):
    render(window, payload("REVIEW", 25, FINDINGS))
    window._show_page("settings")
    window.target_entry.setText("previous target")

    window.new_scan_button.click()

    assert window.current_page == "analysis"
    assert window.target_entry.selectedText() == "previous target"


def test_every_visible_results_button_is_wired(window, qapplication):
    render(window, payload("REVIEW", 25, tuple(Finding("heuristic", "low", f"i{n}", "", 5) for n in range(6))))
    window.resize(1400, 900)
    window.show()
    qapplication.processEvents()

    buttons = [b for b in window.results_panel.findChildren(QPushButton) if b.isVisible()]
    assert len(buttons) >= 6
    for button in buttons:
        meta = button.metaObject()
        clicked = meta.method(meta.indexOfSignal("clicked(bool)"))
        toggled = meta.method(meta.indexOfSignal("toggled(bool)"))
        assert button.isSignalConnected(clicked) or button.isSignalConnected(toggled), button.text()
    window.hide()


def test_narrow_window_stacks_the_result_columns(window):
    window.resize(1500, 900)
    window._apply_layout_mode()
    assert window.results_columns.direction() == qt_app.QBoxLayout.Direction.LeftToRight
    window.resize(1000, 760)
    window._apply_layout_mode()
    assert window.results_columns.direction() == qt_app.QBoxLayout.Direction.TopToBottom


def test_screen_matches_a_real_scan(window, tmp_path):
    sample = tmp_path / "note.txt"
    sample.write_text("run: powershell -enc AAAA and powershell -encodedcommand BBBB", encoding="utf-8")
    data = ScanService().analyze(str(sample), "File", {**DEFAULT_SETTINGS, "osint_enabled": False})
    result = data[0]

    view = render(window, data)

    expected = build_result_view(result, data[1])
    assert view == expected
    assert window.risk_caption.text() == f"{result.combined_score}/100"
    assert window.stat_tiles["findings"].value.text() == str(len(result.evidence))
    assert [card.title.text() for card in window.finding_cards] == [f.title for f in expected.findings[:5]]
    assert sum(int(value.text()) for _n, _b, value in window.category_bars.rows) == len(result.evidence)
    assert set(window.coverage_chips) == set(result.engine_status)
    assert window.file_rows["sha256"].value.text() == result.feature_summary["sha256"]
    assert window.target_result_label.text() == str(sample)
