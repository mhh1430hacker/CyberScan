"""Main screen: identity art, hero facts, scan modes, recent activity."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PySide6")

from PySide6.QtCore import Qt  # noqa: E402
from PySide6.QtWidgets import QApplication, QPushButton  # noqa: E402

import ui.home as home  # noqa: E402
import ui.qt_app as qt_app  # noqa: E402
from core.models import Finding, ScanResult  # noqa: E402

RECORDS = [
    {"id": "r1", "timestamp": "2026-10-28T17:05:00+03:00", "target": "http://example.com/login.php?x=1",
     "classification": "REVIEW", "score": 18, "sha256": "", "report_path": "reports/history/r1.json"},
    {"id": "r2", "timestamp": "2026-10-29T08:40:00+03:00", "target": str(Path.cwd() / "README.md"),
     "classification": "NO_INDICATORS_OBSERVED", "score": 0, "sha256": "cd" * 32, "report_path": "reports/history/r2.json"},
    {"id": "r3", "timestamp": "2026-10-29T09:12:00+03:00", "target": str(Path.cwd() / "invoice.pdf.exe"),
     "classification": "SUSPICIOUS", "score": 72, "sha256": "ab" * 32, "report_path": "reports/history/r3.json"},
]


@pytest.fixture(scope="module")
def qapplication():
    app = QApplication.instance() or QApplication([])
    yield app


@pytest.fixture
def window(tmp_path, monkeypatch, qapplication):
    monkeypatch.setenv("CYBERSCAN_REDUCE_MOTION", "0")
    monkeypatch.setattr(qt_app, "DATA_DIR", tmp_path / "data")
    monkeypatch.setattr(qt_app, "REPORT_DIR", tmp_path / "reports")
    monkeypatch.setattr(qt_app, "ensure_directories", lambda: None)
    monkeypatch.setattr(qt_app.QApplication, "primaryScreen", lambda: None)
    app = qt_app.CyberScanApp()
    try:
        yield app
    finally:
        app.close()


def with_history(window, records=RECORDS):
    window.scan_history = [dict(record) for record in records]
    window.refresh_history()


def payload(classification="REVIEW", score=25):
    result = ScanResult(
        target="C:/samples/sample.bin",
        heuristic_score=score,
        ml_risk_score=None,
        combined_score=score,
        classification=classification,
        evidence=[Finding("structural", "high", "Header mismatch", "Explanation", score)],
        feature_summary={"file_size": 10, "sha256": "ef" * 32},
        engine_status={"YARA": "available; 1 rule(s) loaded"},
    )
    nextgen = {
        "entropy_topography": {"trajectory": (1.0,), "mean_entropy": 2.0},
        "cfg_topology": {"cyclomatic_complexity": 1},
        "forensic_storyboard": [],
    }
    return (result, nextgen, (0.0,) * 8, {"status": "untrained"}, {"status": "disabled", "feeds": {}}, b"x")


# --- hero ---------------------------------------------------------------


def test_hero_states_only_verifiable_facts(window):
    assert window.hero_title.text() == "Inspect before you trust."
    assert window.detection_summary.text().startswith("Enabled in Settings: ")
    assert window.fact_lookups.text.text() == "Public lookups off · nothing is sent from this device"
    assert window.fact_monitor.text.text() == "Downloads monitor off"
    shown = " ".join(
        label.text().lower()
        for label in (window.hero_title, window.hero_body, window.fact_engines.text,
                      window.fact_lookups.text, window.fact_monitor.text)
    )
    for claim in ("protected", "protection is active", "system is safe", "you are safe", "secure"):
        assert claim not in shown


def test_hero_facts_follow_settings(window):
    window.settings = {**window.settings, "osint_enabled": True}
    window._refresh_home()
    assert window.fact_lookups.text.text().startswith("Public lookups on")


def test_page_heading_is_carried_by_the_hero_on_the_main_screen(window):
    window._show_page("analysis")
    assert window.page_title.isHidden() and window.page_subtitle.isHidden()
    window._show_page("settings")
    assert not window.page_title.isHidden()


def test_idle_screen_hides_banner_and_empty_pipeline(window):
    assert window.status_banner.isHidden() is True
    assert window._pipeline_panel.isHidden() is True
    window._show_input_problem("Add a target first", "detail")
    assert window.status_banner.isHidden() is False


# --- scan modes ----------------------------------------------------------


def test_mode_segment_drives_the_real_mode(window):
    window.mode_segment.buttons["URL"].click()
    assert window.input_mode.currentData() == "URL"
    assert window.browse_button.isHidden() is True
    assert window.mode_segment.buttons["URL"].property("selected") is True

    window._choose_mode_without_dialog("File")
    assert window.mode_segment.buttons["File"].isChecked() is True
    assert window.browse_button.isHidden() is False
    assert window.target_entry.placeholderText() == "Paste a file path or choose a local file…"


# --- recent activity -------------------------------------------------------


def test_empty_history_shows_a_designed_empty_state(window):
    activity = window.recent_activity
    assert activity.rows == []
    assert activity.empty.isHidden() is False
    assert activity.mix_row.isHidden() is True
    assert activity.view_all.isHidden() is True
    assert activity.empty_title.text() == "No scans yet"


def test_recent_activity_lists_saved_scans_newest_first(window):
    with_history(window)
    activity = window.recent_activity

    assert [row.record_id for row in activity.rows] == ["r3", "r2", "r1"]
    first = activity.rows[0]
    assert first.verdict.text() == "\u25b2 High risk"
    assert first.name.text() == "invoice.pdf.exe"
    assert first.score.text() == "72/100"
    assert first.meta.text().startswith("File · ")
    assert activity.rows[2].meta.text().startswith("URL · ")
    assert activity.caption.text() == "3 saved scans · on this device only"
    assert sorted(count for count, _color in activity.mix.segments) == [1, 1, 1]


def test_recent_activity_is_capped(window):
    many = [dict(RECORDS[0], id=f"x{i}") for i in range(9)]
    with_history(window, many)
    assert len(window.recent_activity.rows) == home.RecentActivity.MAX_ROWS


def test_activity_row_opens_the_record_in_history(window):
    with_history(window)
    window.recent_activity.rows[0].click()

    assert window.current_page == "history"
    assert window.history_list.currentItem().data(Qt.ItemDataRole.UserRole) == "r3"


def test_open_history_button(window):
    with_history(window)
    window.recent_activity.view_all.click()
    assert window.current_page == "history"


# --- identity art follows the real pipeline -------------------------------


def test_scan_core_follows_reported_stages_and_verdict(window, monkeypatch):
    core = window.scan_core
    assert core.state == "idle"
    core.begin()
    window._update_stage(0, "complete", "done")
    window._update_stage(1, "running", "working")
    assert core.stage_states == ["complete", "running", "waiting", "waiting"]

    window._scan_completed(payload("SUSPICIOUS", 70))
    assert core.state == "complete"
    assert core.result_color.name() == qt_app.tone_color("danger")


def test_scan_core_marks_only_the_failed_stage(window, monkeypatch):
    monkeypatch.setattr(qt_app.QMessageBox, "critical", lambda *a, **k: None)
    window.scan_core.begin()
    window._update_stage(0, "complete", "done")
    window._update_stage(1, "running", "working")

    window._scan_failed("ValueError: example")

    assert window.scan_core.state == "failed"
    assert window.scan_core.stage_states[:2] == ["complete", "failed"]


def test_art_animates_only_while_visible(window, qapplication):
    core = window.scan_core
    window.show()
    qapplication.processEvents()
    assert core.animating is True
    window._show_page("settings")
    qapplication.processEvents()
    assert core.animating is False
    window._show_page("analysis")
    qapplication.processEvents()
    assert core.animating is True
    window.close()
    assert core.animating is False
    assert window.signal_canvas._timer.isActive() is False
    assert window._workspace_timer.isActive() is False


def test_reduced_motion_never_starts_the_timer(qapplication, monkeypatch):
    monkeypatch.setenv("CYBERSCAN_REDUCE_MOTION", "1")
    assert home.prefers_reduced_motion() is True
    core = home.ScanCore()
    core.show()
    core.begin()
    qapplication.processEvents()
    assert core.animating is False
    core.close()
    monkeypatch.setenv("CYBERSCAN_REDUCE_MOTION", "0")
    assert home.prefers_reduced_motion() is False


# --- language, layout, controls ---------------------------------------------


def test_arabic_main_screen(window):
    with_history(window)
    window.toggle_language()

    assert window.layoutDirection() == Qt.LayoutDirection.RightToLeft
    assert window.hero_title.text() == "افحص قبل أن تثق."
    assert window.mode_segment.buttons["File"].text() == "ملف"
    assert window.recent_activity.rows[0].verdict.text() == "\u25b2 خطر مرتفع"
    assert window.recent_activity.rows[0].name.text() == "invoice.pdf.exe"
    assert window.recent_activity.rows[0].name.alignment() & Qt.AlignmentFlag.AlignRight
    assert [group.text() for group, _source in window._rail_groups][:3] == ["التحليل", "الأدلة", "النظام"]
    assert window.connection_status.text() == "جاهز"
    window.toggle_language()
    assert window.hero_title.text() == "Inspect before you trust."
    assert window.connection_status.text() == "READY"


def test_narrow_window_shrinks_art_and_rail(window):
    window.resize(1500, 900)
    window._apply_layout_mode()
    assert window.scan_core.width() == 248
    window.resize(1000, 760)
    window._apply_layout_mode()
    assert window.scan_core.width() == 196
    assert window.sidebar.width() <= 240


def test_every_visible_main_screen_button_is_wired(window, qapplication):
    with_history(window)
    window.resize(1400, 900)
    window.show()
    qapplication.processEvents()
    buttons = [
        button
        for root in (window.sidebar, window.hero, window._composer, window.recent_activity)
        for button in root.findChildren(QPushButton)
        if button.isVisible()
    ]
    assert len(buttons) >= 15
    for button in buttons:
        meta = button.metaObject()
        clicked = meta.method(meta.indexOfSignal("clicked(bool)"))
        toggled = meta.method(meta.indexOfSignal("toggled(bool)"))
        assert button.isSignalConnected(clicked) or button.isSignalConnected(toggled), button.text()
    window.hide()


def test_icons_fall_back_without_the_icon_font(monkeypatch):
    monkeypatch.setattr(home, "icon_font_available", lambda: False)
    assert home.glyph("history") == "\u25f4"
    assert not home.glyph_pixmap("history", "#ffffff").isNull()
