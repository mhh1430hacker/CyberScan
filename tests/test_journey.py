"""Scan journey: the scene follows real worker events; cancel discards honestly."""
from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PySide6")

from PySide6.QtWidgets import QApplication  # noqa: E402

import ui.qt_app as qt_app  # noqa: E402
from core.models import Finding, ScanResult  # noqa: E402
from ui.journey import MAX_MARKERS, JourneyScene  # noqa: E402

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SAMPLE = PROJECT_ROOT / "data" / "datasets" / "synthetic_integration" / "malware_00.bin"


@pytest.fixture(scope="module")
def qapplication():
    app = QApplication.instance() or QApplication([])
    yield app


def settle(app, seconds: float) -> None:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        app.processEvents()
        time.sleep(0.01)


def wait_for(app, condition, timeout: float = 60.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        app.processEvents()
        if condition():
            return True
        time.sleep(0.02)
    return condition()


@pytest.fixture
def window(tmp_path, monkeypatch, qapplication):
    monkeypatch.setenv("CYBERSCAN_REDUCE_MOTION", "0")
    monkeypatch.setattr(qt_app, "DATA_DIR", tmp_path / "data")
    monkeypatch.setattr(qt_app, "REPORT_DIR", tmp_path / "reports")
    monkeypatch.setattr(qt_app, "ensure_directories", lambda: None)
    monkeypatch.setattr(qt_app.QApplication, "primaryScreen", lambda: None)
    monkeypatch.setattr(qt_app.QMessageBox, "critical", lambda *a, **k: None)
    monkeypatch.setattr(qt_app.QMessageBox, "information", lambda *a, **k: None)
    app = qt_app.CyberScanApp()
    try:
        yield app
    finally:
        wait_for(QApplication.instance(), lambda: not any(w.isRunning() for w in app._abandoned_workers), 30)
        if app.worker is not None:
            app.worker.wait(30000)
        app.close()


def payload(classification="SUSPICIOUS", score=70, findings=3):
    evidence = [Finding("structural", "high" if i == 0 else "medium", f"Finding {i}", "Explanation", 30 - i) for i in range(findings)]
    result = ScanResult(
        target=str(SAMPLE),
        heuristic_score=score,
        ml_risk_score=None,
        combined_score=score,
        classification=classification,
        evidence=evidence,
        feature_summary={"file_size": 1278, "sha256": "ab" * 32},
        engine_status={"YARA": "available; 1 rule(s) loaded"},
    )
    nextgen = {"entropy_topography": {"trajectory": (1.0,), "mean_entropy": 7.8}, "cfg_topology": {"cyclomatic_complexity": 2}, "forensic_storyboard": []}
    return (result, nextgen, (0.0,) * 8, {"status": "untrained"}, {"status": "disabled", "feeds": {}}, b"x")


# --- scene unit behaviour --------------------------------------------------


def test_scene_follows_reported_stages(qapplication):
    scene = JourneyScene(reduced_motion=True)
    scene.start("sample.bin", "file", "BIN file · 1.2 KiB")
    assert scene.phase == "analyzing"
    scene.set_stage_states(["complete", "running", "bogus", "waiting"])
    assert scene.stage_states == ["complete", "running", "waiting", "waiting"]


def test_failure_marks_only_the_stage_that_failed(qapplication):
    scene = JourneyScene(reduced_motion=True)
    scene.start("sample.bin", "file", "")
    scene.set_stage_states(["complete", "running", "waiting", "waiting"])
    scene.fail("Failed")
    assert scene.phase == "failed"
    assert scene.stage_states == ["complete", "failed", "waiting", "waiting"]


def test_cancel_does_not_mark_any_stage_complete_or_failed(qapplication):
    scene = JourneyScene(reduced_motion=True)
    scene.start("sample.bin", "file", "")
    scene.set_stage_states(["complete", "running", "waiting", "waiting"])
    scene.cancel("Cancelled")
    assert scene.phase == "cancelled"
    assert scene.stage_states == ["complete", "waiting", "waiting", "waiting"]


def test_evidence_markers_are_capped_but_the_label_keeps_the_real_count(qapplication):
    scene = JourneyScene(reduced_motion=True)
    scene.start("sample.bin", "file", "")
    scene.show_evidence([("#f0645f", "▲")] * 20, 20, "20 indicators observed")
    assert len(scene.markers) == MAX_MARKERS
    assert scene.finding_total == 20
    assert scene.evidence_label == "20 indicators observed"
    assert scene.stage_states == ["complete"] * 4


def test_reduced_motion_concludes_immediately_and_compacts(qapplication):
    scene = JourneyScene(reduced_motion=True)
    fired = []
    scene.concluded.connect(lambda: fired.append(True))
    scene.start("sample.bin", "file", "")
    scene.show_evidence([], 0, "No indicators observed")
    scene.conclude("Low risk", "●", "#4ade80")
    assert scene.phase == "concluded" and fired == [True]
    assert scene.compact is True and scene.height() == JourneyScene.COMPACT_HEIGHT
    assert scene.animating is False


def test_scene_animates_only_while_visible(qapplication):
    scene = JourneyScene(reduced_motion=False)
    scene.resize(900, JourneyScene.FULL_HEIGHT)
    scene.show()
    scene.start("sample.bin", "file", "")
    qapplication.processEvents()
    assert scene.animating is True
    scene.hide()
    assert scene.animating is False
    scene.show()
    qapplication.processEvents()
    assert scene.animating is True
    scene.close()
    assert scene.animating is False


def test_animated_conclusion_waits_for_markers_then_settles(qapplication):
    scene = JourneyScene(reduced_motion=False)
    scene.resize(900, JourneyScene.FULL_HEIGHT)
    scene.show()
    fired = []
    scene.concluded.connect(lambda: fired.append(True))
    scene.start("sample.bin", "file", "")
    scene.set_stage_states(["complete"] * 4)
    scene.show_evidence([("#f5b544", "◆")] * 3, 3, "3 indicators observed")
    scene.conclude("Needs review", "◆", "#f5b544")
    assert scene.phase == "evidence"
    assert wait_for(qapplication, lambda: bool(fired), 5)
    assert wait_for(qapplication, lambda: scene.height() == JourneyScene.COMPACT_HEIGHT, 5)
    assert wait_for(qapplication, lambda: not scene.animating, 5)
    scene.close()


# --- window integration -------------------------------------------------------


def test_real_scan_travels_the_journey_and_reveals_results(window, qapplication):
    window.resize(1400, 900)
    window.show()
    window.target_entry.setText(str(SAMPLE))
    window.run_scan()
    assert window.stage_stack.currentIndex() == 1
    assert window.cancel_button.isVisible() is True
    assert window.status_banner.isHidden() is True  # progress lives in the journey

    assert wait_for(qapplication, lambda: window.worker is None, 60)
    assert window.journey.stage_states == ["complete"] * 4
    assert window.results_panel.isHidden() is True  # follows the conclusion
    assert wait_for(qapplication, lambda: window.journey.phase == "concluded", 10)
    assert wait_for(qapplication, lambda: not window.results_panel.isHidden(), 5)
    assert window.journey.verdict_title == window._results_view.verdict.title
    assert window.journey.finding_total == len(window._results_view.findings)
    assert window.status_banner.isHidden() is True  # the verdict card says it
    assert window.journey_new_scan_button.isVisible() and not window.cancel_button.isVisible()
    assert len(window.scan_history) == 1


def test_a_new_scan_starts_with_clean_stages(window, qapplication):
    window._update_stage(0, "complete", "done")
    window._update_stage(1, "complete", "done")
    window._start_journey(str(SAMPLE), "File")
    assert window.stage_track._states == ["idle"] * 4
    window._update_stage(0, "running", "reading")
    assert window.journey.stage_states == ["running", "waiting", "waiting", "waiting"]


def test_cancel_discards_the_result_and_never_saves_it(window, qapplication):
    window.resize(1400, 900)
    window.show()
    window.target_entry.setText(str(SAMPLE))
    window.run_scan()
    worker = window.worker
    assert worker is not None and worker.isRunning()

    window.cancel_button.click()

    assert window.worker is None
    assert window.journey.phase == "cancelled"
    assert window.analyze_button.isEnabled() is True
    assert window.status_banner.isHidden() is False
    assert window.status_banner.property("tone") == "warning"
    assert "discarded" in window.status_banner.detail.text()
    # The background read finishes; its result must not reach the screen or history.
    assert wait_for(qapplication, lambda: not worker.isRunning(), 60)
    settle(qapplication, 0.3)
    assert window.scan_history == []
    assert window.results_panel.isHidden() is True
    assert window.journey.phase == "cancelled"
    assert window._abandoned_workers == []


def test_close_is_refused_while_a_cancelled_read_is_still_running(window, qapplication, monkeypatch):
    import threading

    release = threading.Event()
    real_analyze = qt_app.ScanService.analyze

    def held_analyze(self, *args, **kwargs):
        release.wait(30)
        return real_analyze(self, *args, **kwargs)

    monkeypatch.setattr(qt_app.ScanService, "analyze", held_analyze)
    window.show()
    window.target_entry.setText(str(SAMPLE))
    window.run_scan()
    window.cancel_scan()
    assert any(w.isRunning() for w in window._abandoned_workers)

    window.close()
    assert window.isVisible() is True  # refused: a thread is still reading

    release.set()
    assert wait_for(qapplication, lambda: window._abandoned_workers == [], 60)
    window.close()
    assert window.isVisible() is False
    assert window.scan_history == []


def test_failure_in_the_window_shows_where_it_stopped(window):
    window._start_journey(str(SAMPLE), "File")
    window._update_stage(0, "complete", "done")
    window._update_stage(1, "running", "working")
    window._scan_failed("TimeoutError: deadline")
    assert window.journey.phase == "failed"
    assert window.journey.stage_states[:2] == ["complete", "failed"]
    assert window.status_banner.property("tone") == "error"
    assert window.journey_new_scan_button.isHidden() is False


def test_new_scan_returns_from_the_journey_to_readiness(window):
    window._start_journey(str(SAMPLE), "File")
    window._scan_completed(payload())
    window.journey_new_scan_button.click()
    assert window.stage_stack.currentIndex() == 0
    assert window.results_panel.isHidden() is True
    assert window.journey.phase == "idle"
    assert window.scan_core.state == "idle"


def test_results_show_file_card_and_category_donut(window):
    window._render_result(*payload("REVIEW", 25, 3))
    assert window.file_card.name.text() == "malware_00.bin"
    assert "1.2 KiB" in window.file_card.meta.text()
    assert window.file_card.hash.text().startswith("SHA-256 abababab")
    assert window.category_donut.isHidden() is False
    assert window.category_donut.segments == [(3, qt_app.tone_color("danger"))]
    assert window.category_donut.center_value == "1"


def test_arabic_journey_titles(window):
    window.toggle_language()
    window._start_journey(str(SAMPLE), "File")
    assert window.journey.stage_titles[0] == "الأدلة الساكنة"
    assert window.journey_caption.text() == "التحليل جارٍ"
    assert window.cancel_button.text() == "إلغاء"


def test_closing_during_animation_stops_every_timer(window, qapplication):
    window.show()
    window._start_journey(str(SAMPLE), "File")
    qapplication.processEvents()
    assert window.journey.animating is True
    window.close()
    assert window.journey.animating is False
    assert window.scan_core.animating is False


def test_drop_zone_highlights_while_dragging(window):
    window._set_drop_armed(True)
    assert window._composer.property("armed") is True
    window._set_drop_armed(False)
    assert window._composer.property("armed") is False


@pytest.mark.parametrize("language", ["en", "ar"])
def test_no_width_ever_needs_horizontal_scrolling(window, qapplication, language):
    window.scan_history = [
        {"id": "x", "timestamp": "2026-10-29T09:00:00+03:00",
         "target": "C:/samples/" + "very_long_file_name_" * 4 + ".exe",
         "classification": "SUSPICIOUS", "score": 70, "sha256": "", "report_path": "r"}
    ]
    window.refresh_history()
    if language == "ar":
        window.toggle_language()
    window.show()
    for width in (880, 1000, 1440):
        window.resize(width, 760)
        window._apply_layout_mode()
        for stage in (0, 1):
            window._show_stage(stage)
            settle(qapplication, 0.15)
            scroll = window._scroll_area_for(window.hero)
            assert scroll.horizontalScrollBar().maximum() == 0, f"{language} {width}px stage {stage} overflows"
    window.resize(880, 760)
    window._apply_layout_mode()
    assert window.facts_layout.direction() == qt_app.QBoxLayout.Direction.TopToBottom
    assert window._entry_stacked is True
