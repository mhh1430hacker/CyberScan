"""UI-only regression tests for the CyberScan Qt interface (Agent 2 / NOR).

These tests exercise interface state, control enablement, accessibility
scaling and animation behaviour. They do not change or re-test the scan
pipeline logic owned by Agent 1.
"""

import os
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PySide6")

from PySide6.QtWidgets import QApplication  # noqa: E402

import ui.qt_app as qt_app  # noqa: E402
from config import DEFAULT_SETTINGS  # noqa: E402


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


def _minimal_payload(tmp_path, classification="REVIEW", score=25, evidence=()):
    from core.models import ScanResult

    result = ScanResult(
        target=str(tmp_path / "sample.bin"),
        heuristic_score=score,
        ml_risk_score=None,
        combined_score=score,
        classification=classification,
        evidence=list(evidence),
        feature_summary={"file_size": 128},
        engine_status={"YARA": "ok", "PE": "not_pe", "OSINT": "disabled"},
    )
    nextgen = {
        "entropy_topography": {"trajectory": (1.0, 2.0), "mean_entropy": 3.5},
        "cfg_topology": {"cyclomatic_complexity": 4},
        "forensic_storyboard": ["Measured story line."],
    }
    prediction = {"status": "untrained", "label": None, "class_scores": {}}
    intelligence = {"status": "disabled", "indicator_type": None, "feeds": {}}
    return (result, nextgen, (0.0,) * 16, prediction, intelligence, b"sample-bytes")


def test_export_button_is_disabled_until_a_result_exists(window):
    assert window.export_button.isEnabled() is False

    payload = _minimal_payload(Path("."))
    window.last_payload = payload
    window._render_result(*payload)

    assert window.export_button.isEnabled() is True


def test_failed_scan_is_reported_as_failure_not_ready(window, monkeypatch):
    monkeypatch.setattr(qt_app.QMessageBox, "critical", lambda *args, **kwargs: None)

    window._scan_failed("ValueError: example failure")

    assert window.connection_status.property("tone") == "error"
    assert "FAILED" in window.connection_status.text()
    assert window.status_banner.property("tone") == "error"
    assert window.analyze_button.isEnabled() is True
    assert window.analyze_button.text() == "Analyze target"
    assert window.export_button.isEnabled() is False


def test_empty_target_reports_in_banner_instead_of_modal(window, monkeypatch):
    modal_calls = []
    monkeypatch.setattr(
        qt_app.QMessageBox, "warning", lambda *args, **kwargs: modal_calls.append(args)
    )
    window.target_entry.setText("")
    window.run_scan()

    assert modal_calls == []
    assert window.status_banner.property("tone") == "warning"
    assert window.status_banner.title.text() == "Add a target first"


def test_history_actions_require_a_selection(window, qapplication):
    window.show()
    qapplication.processEvents()
    buttons = (
        window.history_open_button,
        window.history_export_button,
        window.history_remove_button,
    )
    assert all(button.isEnabled() is False for button in buttons)

    window.scan_history = [
        {
            "id": "scan-1",
            "timestamp": "2025-01-01T00:00:00+00:00",
            "target": "sample.bin",
            "classification": "REVIEW",
            "score": 12,
            "sha256": "abc",
            "report_path": "reports/history/scan-1.json",
        }
    ]
    window.refresh_history()
    assert window.history_empty.isHidden() is True
    assert window.history_list.isHidden() is False
    window.history_list.setCurrentItem(window.history_list.item(0))
    assert all(button.isEnabled() is True for button in buttons)

    window.scan_history = []
    window.refresh_history()
    assert window.history_empty.isHidden() is False
    assert window.history_list.isHidden() is True
    assert all(button.isEnabled() is False for button in buttons)
    window.hide()


def test_sidebar_primary_action_tracks_the_current_page(window):
    window._show_page("settings")
    assert window.sidebar_primary.property("selected") is False
    assert window._nav_buttons["settings"].property("selected") is True

    window._show_analysis()
    assert window.sidebar_primary.property("selected") is True


def test_large_text_setting_scales_font_and_control_height(window):
    base_height = window.analyze_button.minimumHeight()
    assert window.styleSheet() == qt_app.APP_STYLE

    window.settings = {**window.settings, "large_text": True}
    window._apply_text_scale()
    assert window.font().pixelSize() > 13 or window.font().pointSizeF() > 9.0
    assert window.analyze_button.minimumHeight() > base_height
    assert "font-size: 15px;" in window.styleSheet()

    window.settings = {**window.settings, "large_text": False}
    window._apply_text_scale()
    assert window.styleSheet() == qt_app.APP_STYLE
    assert window.analyze_button.minimumHeight() == base_height


def test_settings_track_unsaved_changes_without_a_modal(window, monkeypatch):
    assert window.apply_settings_button.isEnabled() is False

    check = window.setting_checks["entropy_analysis"]
    check.setChecked(not check.isChecked())

    assert window.apply_settings_button.isEnabled() is True
    assert window.settings_saved_chip.text() == "Unsaved changes"

    check.setChecked(not check.isChecked())
    assert window.apply_settings_button.isEnabled() is False
    assert window.settings_saved_chip.text() == "Saved · applied"


def test_apply_settings_persists_and_reports_saved_state(window, monkeypatch):
    monkeypatch.setattr(qt_app.QMessageBox, "information", lambda *a, **k: None)
    window.setting_checks["large_text"].setChecked(True)
    window.apply_settings()

    assert window.settings["large_text"] is True
    assert window.apply_settings_button.isEnabled() is False
    assert window.settings_saved_chip.text() == "Saved · applied"
    stored = window.ui_store.load_settings({**DEFAULT_SETTINGS, "ui_language": "en"})
    assert stored["large_text"] is True


def test_file_browser_is_only_offered_for_file_targets(window):
    window._choose_mode_without_dialog("URL")
    assert window.browse_button.isHidden() is True
    window._choose_mode_without_dialog("File")
    assert window.browse_button.isHidden() is False


def test_result_animation_runs_and_ends_with_visible_content(window):
    payload = _minimal_payload(Path("."))
    window._render_result(*payload)

    animation = window._results_animation
    assert animation is not None
    window._finish_results_entry()
    assert window._results_effect.opacity() == pytest.approx(1.0)
    assert window.results_panel.isHidden() is False


def test_page_transition_uses_a_property_animation(window):
    from PySide6.QtCore import QAbstractAnimation
    window._show_page("about")
    assert window._page_animation.state() in (
        QAbstractAnimation.State.Running,
        QAbstractAnimation.State.Paused,
        QAbstractAnimation.State.Stopped,
    )
    window._page_animation.stop()
    assert window.current_page == "about"


def test_narrow_window_reflows_stage_cards(window):
    window.resize(1500, 900)
    window._apply_layout_mode()
    assert window._stage_columns == 4

    window.resize(1000, 760)
    window._apply_layout_mode()
    assert window._stage_columns == 2
    assert window.sidebar.width() <= 240


def test_tone_styles_are_applied_with_properties(window):
    qt_app.apply_tone(window.connection_status, "busy")
    assert window.connection_status.property("tone") == "busy"
    qt_app.apply_tone(window.connection_status, "ready")
    assert window.connection_status.property("tone") == "ready"


def test_arabic_translation_covers_new_interface_strings():
    from ui.translations import AR_TRANSLATIONS

    for text in (
        "Ready for a new target",
        "Analysis incomplete · nothing was concluded about this target",
        "No saved scans yet",
        "Unsaved changes",
        "Larger text and controls",
    ):
        assert AR_TRANSLATIONS[text] != text


def test_result_with_weak_indicators_does_not_claim_safety(window):
    payload = _minimal_payload(Path("."), "REVIEW", 20)
    window._render_result(*payload)

    assert window.status_banner.property("tone") == "warning"
    summary = window.status_banner.detail.text()
    assert "not a malware probability" in summary


def test_missing_engine_is_reported_as_partial_coverage(window):
    from core.models import Finding

    payload = _minimal_payload(
        Path("."),
        "SUSPICIOUS",
        70,
        (Finding("yara", "high", "Rule matched", "Explanation", 40),),
    )
    payload[0].engine_status = {"YARA": "error: rule load failed", "PE": "ok"}
    window._render_result(*payload)

    assert window.completeness_chip.isHidden() is False
    assert "Partial coverage" in window.completeness_chip.text()
    assert "YARA" in window.completeness_chip.text()


def test_no_result_claim_is_made_when_nothing_was_observed(window):
    payload = _minimal_payload(Path("."), "NO_INDICATORS_OBSERVED", 0)
    window._render_result(*payload)

    detail = window.status_banner.detail.text()
    assert "does not prove the target is safe" in detail
    assert window.status_banner.property("tone") == "success"


def test_language_switch_keeps_nav_and_banner_consistent(window):
    window._show_page("settings")
    window.toggle_language()

    assert window.language == "ar"
    assert window.breadcrumb.text() == "الإعدادات"
    assert window.settings_saved_chip.text() in {"محفوظ", "محفوظ · مطبَّق"}
    window.toggle_language()
    assert window.language == "en"
    assert window.apply_settings_button.isEnabled() is False
