import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PySide6")

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication

import ui.qt_app as qt_app
from config import DEFAULT_SETTINGS
from ui.qt_widgets import AnimatedBackground, BrandMark
from ui.scan_service import ScanService


@pytest.fixture(scope="module")
def qapplication():
    app = QApplication.instance() or QApplication([])
    yield app


def test_native_interface_keeps_all_tools_and_switches_language(tmp_path, monkeypatch, qapplication):
    monkeypatch.setattr(qt_app, "DATA_DIR", tmp_path / "data")
    monkeypatch.setattr(qt_app, "REPORT_DIR", tmp_path / "reports")
    monkeypatch.setattr(qt_app, "ensure_directories", lambda: None)
    monkeypatch.setattr(qt_app.QApplication, "primaryScreen", lambda: None)

    window = qt_app.CyberScanApp()
    try:
        assert isinstance(window.centralWidget(), AnimatedBackground)
        assert window.findChild(BrandMark) is not None
        assert window.styleSheet() == qt_app.APP_STYLE
        assert window.pages.widget(1).objectName() == "page"
        assert "background: transparent" in qt_app.APP_STYLE
        assert "#070b12" in qt_app.APP_STYLE
        assert window.pages.count() == 8
        assert set(window.page_indices) == {
            "analysis",
            "history",
            "yara",
            "mitre",
            "model",
            "logs",
            "settings",
            "about",
        }
        assert len(window.stage_labels) == 4
        assert len(window.mode_values) == 3

        sample = tmp_path / "actual-workspace-note.txt"
        sample.write_text("A benign local sample with ordinary text.", encoding="utf-8")
        payload = ScanService().analyze(
            str(sample),
            "File",
            {**DEFAULT_SETTINGS, "osint_enabled": False},
        )
        window.last_payload = payload
        window._render_result(*payload)
        assert not window.results_panel.isHidden()
        assert window.target_result_label.text() == str(sample)
        assert window.evidence_summary.toPlainText()
        assert "Position-aware evidence (measured only):" in window.evidence_summary.toPlainText()
        assert window.last_payload is payload
        window.show()
        qapplication.processEvents()
        assert window.signal_canvas._timer.isActive()
        phase = window.signal_canvas._phase
        window.signal_canvas._tick()
        assert window.signal_canvas._phase != phase

        window.toggle_language()
        assert window.language == "ar"
        assert window.layoutDirection() == Qt.LayoutDirection.RightToLeft
        assert window.breadcrumb.text() == "تحليل جديد"
        assert window.sidebar.property("rtl") is True
        assert all(button.property("rtl") is True for button in window._nav_buttons.values())
        assert "أدلة مرتبطة بالمواضع" in window.evidence_summary.toPlainText()
        assert window.findChild(BrandMark).parent() is window.sidebar
        window.toggle_language()
        assert window.language == "en"
        assert window.layoutDirection() == Qt.LayoutDirection.LeftToRight
        assert window.sidebar.property("rtl") is False

        settings = window.ui_store.load_settings(
            {**DEFAULT_SETTINGS, "ui_language": "en"}
        )
        assert settings["ui_language"] == "en"
    finally:
        window.close()
