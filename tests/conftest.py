"""Shared fixtures for the Qt interface tests.

Every window writes only into pytest's tmp_path; message boxes are recorded
instead of shown, so no test can block on a modal or touch the user's data.
"""
from __future__ import annotations

import os
import time

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


@pytest.fixture(scope="session")
def qapplication():
    pytest.importorskip("PySide6")
    from PySide6.QtWidgets import QApplication

    app = QApplication.instance() or QApplication([])
    yield app


def settle(app, seconds: float) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        app.processEvents()
        time.sleep(0.005)


def wait_for(app, predicate, timeout: float = 30.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        app.processEvents()
        if predicate():
            return True
        time.sleep(0.005)
    app.processEvents()
    return predicate()


@pytest.fixture
def dialogs():
    return []


@pytest.fixture
def window(tmp_path, monkeypatch, qapplication, dialogs):
    import ui.qt_app as qt_app

    monkeypatch.setenv("CYBERSCAN_REDUCE_MOTION", "0")
    monkeypatch.setattr(qt_app, "DATA_DIR", tmp_path / "data")
    monkeypatch.setattr(qt_app, "REPORT_DIR", tmp_path / "reports")
    monkeypatch.setattr(qt_app, "ensure_directories", lambda: None)
    monkeypatch.setattr(qt_app.QApplication, "primaryScreen", lambda: None)
    # Never reach a real local model from tests: point the AI at a closed port.
    import ui.ai_summary as ai_summary

    monkeypatch.setattr(ai_summary, "OLLAMA_URL", "http://127.0.0.1:9")
    (tmp_path / "data").mkdir()

    def record(kind, answer=None):
        def box(_parent, title, text, *args, **kwargs):
            dialogs.append((kind, title, text))
            return answer if answer is not None else qt_app.QMessageBox.StandardButton.Ok
        return staticmethod(box)

    monkeypatch.setattr(qt_app.QMessageBox, "critical", record("critical"))
    monkeypatch.setattr(qt_app.QMessageBox, "warning", record("warning"))
    monkeypatch.setattr(qt_app.QMessageBox, "information", record("information"))
    monkeypatch.setattr(qt_app.QMessageBox, "question", record("question", qt_app.QMessageBox.StandardButton.Yes))
    app = qt_app.CyberScanApp()
    app.resize(1400, 900)
    app.show()
    settle(qapplication, 0.05)
    try:
        yield app
    finally:
        for worker in [app.worker, *app._abandoned_workers]:
            if worker is not None:
                worker.wait(20000)
        app.close()


def scan(app, window, target: str, timeout: float = 40.0) -> None:
    """Scan as a user would: put the target in the field and press the button."""
    window.lens.set_target(target)
    window.lens.scan_button.click()
    assert wait_for(app, lambda: window.view == "result" or window.journey.phase in {"failed", "cancelled"}, timeout)
