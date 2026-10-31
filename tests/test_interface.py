"""The rail, the three result levels, settings, languages and layout."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from conftest import scan, settle, wait_for

pytest.importorskip("PySide6")

from PySide6.QtCore import Qt  # noqa: E402
from PySide6.QtWidgets import QAbstractButton, QLabel  # noqa: E402

import ui.qt_app as qt_app  # noqa: E402
from core.models import Finding, ScanResult  # noqa: E402
from reports.exporter import export_report  # noqa: E402

SUSPICIOUS = (
    b"MZ" + b"\x00" * 200
    + b"powershell -nop -w hidden -enc SQBFAFgA\x00cmd.exe /c vssadmin delete shadows /all /quiet\x00"
    + b"VirtualAlloc\x00WriteProcessMemory\x00CreateRemoteThread\x00"
)


@pytest.fixture
def program(tmp_path):
    path = tmp_path / "invoice.pdf.exe"
    path.write_bytes(SUSPICIOUS)
    return path


@pytest.fixture
def notes(tmp_path):
    path = tmp_path / "meeting_notes.txt"
    path.write_text("Agenda for Thursday.\n" * 30, encoding="utf-8")
    return path


def saved_record(window, tmp_path, record_id, result, timestamp="2026-10-29T09:12:00+03:00"):
    history = Path(qt_app.REPORT_DIR) / "history"
    history.mkdir(parents=True, exist_ok=True)
    report = history / f"scan_{record_id}.json"
    export_report(result, report, "json")
    return {
        "id": record_id,
        "timestamp": timestamp,
        "target": result.target,
        "classification": result.classification,
        "score": result.combined_score,
        "sha256": "",
        "report_path": str(report.resolve()),
    }


def engine_result(target, classification="NO_INDICATORS_OBSERVED", engine_status=None, evidence=None):
    return ScanResult(
        target=target,
        heuristic_score=0,
        ml_risk_score=None,
        combined_score=0,
        classification=classification,
        evidence=evidence or [],
        feature_summary={"file_size": 10},
        engine_status=engine_status or {"YARA": "available; 1 rule(s) loaded"},
    )


# --- level 1 -> 2 -> 3 --------------------------------------------------------------


def test_levels_unfold_in_order(window, qapplication, program):
    scan(qapplication, window, str(program))
    panel = window.result_panel
    assert not panel.details.isVisibleTo(panel)
    assert not panel.advanced_button.isVisibleTo(panel)  # level 3 is reached only through level 2
    panel.why_button.click()
    assert wait_for(qapplication, lambda: panel.details.isVisibleTo(panel) and panel.details.maximumHeight() > 10000, 3)
    assert panel.advanced_button.isVisibleTo(panel)
    assert panel.why_button.text() == "Hide the details"
    panel.advanced_button.click()
    assert wait_for(qapplication, lambda: panel.advanced.isVisibleTo(panel), 3)
    panel.why_button.click()  # closing level 2 closes level 3 too
    assert wait_for(qapplication, lambda: not panel.details.isVisibleTo(panel) and not panel.advanced.isVisibleTo(panel), 3)


def test_advanced_data_is_the_engine_output_unchanged(window, qapplication, program):
    scan(qapplication, window, str(program))
    result = window._current["result"]
    texts = window.result_panel.tab_texts
    for finding in result.evidence:
        assert finding.evidence in texts["Findings"].toPlainText()
        assert finding.explanation in texts["Findings"].toPlainText()
    for name, status in result.engine_status.items():
        assert f"{name}: {status}" in texts["Engines"].toPlainText()
    assert texts["Report"].toPlainText() == result.as_text()
    json.loads(texts["JSON"].toPlainText())


def test_details_show_all_findings_on_request(window, qapplication, program):
    scan(qapplication, window, str(program))
    panel = window.result_panel
    panel.why_button.click()
    total = len(window._current["view"].findings)
    assert total > 5
    assert panel.findings_list.count() == 5
    assert panel.more_button.text() == f"Show all {total}"
    panel.more_button.click()
    assert panel.findings_list.count() == total


def test_export_writes_the_shown_result(window, qapplication, program, tmp_path, monkeypatch):
    scan(qapplication, window, str(program))
    destination = tmp_path / "out.json"
    monkeypatch.setattr(qt_app.QFileDialog, "getSaveFileName", lambda *a, **k: (str(destination), "JSON (*.json)"))
    window.result_panel.why_button.click()
    window.result_panel.export_button.click()
    assert json.loads(destination.read_text(encoding="utf-8"))["target"] == window._current["result"].target


def test_every_visible_button_does_something(window, qapplication, program):
    scan(qapplication, window, str(program))
    window.result_panel.why_button.click()
    settle(qapplication, 0.4)
    buttons = [b for b in window.findChildren(QAbstractButton) if b.isVisible()]
    assert len(buttons) >= 8
    for button in buttons:
        meta = button.metaObject()
        signal = meta.method(meta.indexOfSignal("clicked(bool)"))
        assert button.isSignalConnected(signal), button.text() or button.accessibleName()


# --- the rail -------------------------------------------------------------------------


def test_rail_lists_saved_scans_newest_first_grouped(window, qapplication, program, notes):
    scan(qapplication, window, str(program))
    window.new_scan()
    scan(qapplication, window, str(notes))
    rail = window.rail
    assert [card.item.name for card in rail.cards] == ["meeting_notes.txt", "invoice.pdf.exe"]
    assert rail.cards[0].item.group == "Today"
    assert rail.cards[0].item.verdict_word == "Nothing found"
    assert rail.cards[1].item.verdict_word == "High risk"
    assert rail.cards[1].item.kind.key == "program"
    assert rail.cards[0].isChecked()  # the scan just shown is selected
    assert rail.count.text() == "2 scans"


def test_unfinished_scan_is_never_listed_as_low_risk(window, qapplication, tmp_path):
    """Regression (audit UI-003): the rail reads the coverage-aware verdict."""
    result = engine_result("C:/x/report.pdf", engine_status={"YARA": "error: failed to load rules"})
    window.scan_history = [saved_record(window, tmp_path, "r1", result)]
    window.refresh_history()
    item = window.rail.cards[0].item
    assert item.verdict_key == "inconclusive"
    assert item.verdict_word == "Not sure"


def test_opening_a_saved_scan_shows_its_result(window, qapplication, tmp_path):
    result = engine_result("C:/x/report.pdf", "REVIEW", evidence=[Finding("heuristic", "medium", "Odd macro", "explained", 20)])
    window.scan_history = [saved_record(window, tmp_path, "r1", result)]
    window.refresh_history()
    window.rail.cards[0].click()
    assert window.view == "result"
    assert window.result_panel.headline.text() == "Take a second look"
    assert window.result_panel.origin.text().startswith("From your scans")
    assert window.rail.cards[0].isChecked()


def test_search_filters_the_rail(window, qapplication, tmp_path):
    window.scan_history = [
        saved_record(window, tmp_path, "a", engine_result("C:/x/alpha.pdf")),
        saved_record(window, tmp_path, "b", engine_result("https://beta.example/login", "REVIEW")),
    ]
    window.refresh_history()
    window.rail.search.setText("beta")
    assert [card.item.record_id for card in window.rail.cards] == ["b"]
    window.rail.search.setText("nothing-like-this")
    assert window.rail.cards == [] and window.rail.empty_title.text() == "No scan matches your search"


def test_removing_a_scan_deletes_its_report_but_not_the_file(window, qapplication, program):
    scan(qapplication, window, str(program))
    record = window.scan_history[0]
    report = Path(record["report_path"])
    window.remove_history_record(record["id"])
    assert window.scan_history == [] and not report.exists() and program.exists()
    assert window.rail.cards == []


def test_rail_cards_are_reachable_and_named(window, qapplication, program):
    scan(qapplication, window, str(program))
    card = window.rail.cards[0]
    assert card.focusPolicy() & Qt.FocusPolicy.TabFocus
    assert card.accessibleName().startswith("High risk: invoice.pdf.exe")


# --- settings ---------------------------------------------------------------------------


def test_settings_sheet_tracks_changes_and_saves(window, qapplication, monkeypatch):
    window.open_settings()
    sheet = window.sheet
    assert sheet.isVisible() and sheet.saved_pill.text() == "Saved" and not sheet.save_button.isEnabled()
    sheet.checks["heuristic_rules"].setChecked(False)
    assert sheet.saved_pill.text() == "Unsaved changes" and sheet.save_button.isEnabled()
    sheet.save_button.click()
    assert window.settings["heuristic_rules"] is False
    saved = json.loads((Path(qt_app.DATA_DIR) / "ui_settings.json").read_text(encoding="utf-8"))
    assert saved["heuristic_rules"] is False
    window.close_settings()
    assert wait_for(qapplication, lambda: not sheet.isVisible(), 2)


def test_large_text_makes_text_larger(window, qapplication):
    before = window.styleSheet()
    window.open_settings()
    window.sheet.checks["large_text"].setChecked(True)
    window.sheet.save_button.click()
    assert window.styleSheet() != before
    assert "font-size: 17px" in window.styleSheet()


def test_online_lookups_are_announced_on_the_lens(window, qapplication):
    assert window.lens.notice.isHidden()
    window.open_settings()
    window.sheet.checks["osint_enabled"].setChecked(True)
    window.sheet.save_button.click()
    assert window.lens.notice.text().startswith("Online lookups are on")


# --- language -------------------------------------------------------------------------------


def test_language_switch_after_several_scans_is_complete(window, qapplication, program, notes):
    """Regression (audit UI-002): switching after two results used to crash."""
    scan(qapplication, window, str(program))
    window.new_scan()
    scan(qapplication, window, str(notes))
    window.result_panel.why_button.click()
    window.toggle_language()
    assert window.layoutDirection() == Qt.LayoutDirection.RightToLeft
    assert window.result_panel.headline.text() == "لم نجد ما يقلق"
    assert window.result_panel.why_button.text() == "إخفاء التفاصيل"
    assert window.result_panel.details.isVisibleTo(window.result_panel)
    assert window.rail.title.text() == "فحوصاتك"
    assert window.rail.cards[0].item.verdict_word == "لم نجد شيئًا"
    saved = json.loads((Path(qt_app.DATA_DIR) / "ui_settings.json").read_text(encoding="utf-8"))
    assert saved["ui_language"] == "ar"
    window.toggle_language()
    assert window.result_panel.headline.text() == "Nothing worrying found"


def test_arabic_translates_the_interface_but_not_engine_evidence(window, qapplication, program):
    window.toggle_language()
    scan(qapplication, window, str(program))
    panel = window.result_panel
    panel.why_button.click()
    assert panel.headline.text() == "انتبه لهذا الملف"
    titles = [w.text() for w in panel.findings_card.findChildren(qt_app.QWidget) if hasattr(w, "text") and callable(w.text)]
    assert "Double extension spoofing" in titles  # engine text shown as produced
    assert panel.findings_title.text() == "ما الذي لفت انتباهنا"


# --- layout ---------------------------------------------------------------------------------


@pytest.mark.parametrize("language", ["en", "ar"])
def test_no_view_needs_horizontal_scrolling(window, qapplication, program, tmp_path, language):
    long_name = tmp_path / ("Quarterly_financial_reconciliation_statement_for_the_regional_operations_division_final_" * 2 + ".pdf.exe")
    long_name.write_bytes(SUSPICIOUS)
    if language == "ar":
        window.toggle_language()
    for width in (880, 1040, 1440, 1920):
        window.resize(width, 640)
        settle(qapplication, 0.1)
        window.new_scan()
        window.lens.set_target(str(long_name))
        settle(qapplication, 0.2)
        stage = window.scroll.widget()
        assert stage.width() <= window.scroll.viewport().width() + 1, f"lens {language} {width}"
        scan(qapplication, window, str(long_name))
        window.result_panel.why_button.click()
        window.result_panel.advanced_button.click()
        settle(qapplication, 0.4)
        assert stage.minimumSizeHint().width() <= window.scroll.viewport().width() + 1, f"result {language} {width}"
    assert window.rail.isHidden() is False or window.width() < 1040


def test_narrow_window_folds_the_rail_away(window, qapplication):
    window.resize(900, 640)
    window._apply_layout_mode()
    assert window.rail.isHidden() and window.rail_button.isVisible()
    window.rail_button.click()
    assert window.rail.isVisible()
    window.resize(1400, 900)
    window._apply_layout_mode()
    assert window.rail.isVisible() and not window.rail_button.isVisible()


def test_lens_makes_no_unsupported_promises(window):
    shown = " ".join(
        w.text().lower() for w in window.lens.findChildren(QLabel) if w.text()
    )
    for claim in ("protected", "you are safe", "system is safe", "100%", "guarantee"):
        assert claim not in shown


def test_icons_fall_back_without_the_icon_font(monkeypatch):
    import ui.icons as icons

    monkeypatch.setattr(icons, "icon_font_available", lambda: False)
    assert icons.glyph("history") == "◴"
    assert not icons.glyph_pixmap("history", "#ffffff").isNull()
