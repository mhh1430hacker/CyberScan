"""Scanning through the real window and the real worker thread."""
from __future__ import annotations

import threading

import pytest

from conftest import scan, settle, wait_for

pytest.importorskip("PySide6")

import ui.qt_app as qt_app  # noqa: E402
from ui.journey import JourneyScene  # noqa: E402
from ui.file_kind import KINDS  # noqa: E402

SUSPICIOUS = (
    b"MZ" + b"\x00" * 200
    + b"powershell -nop -w hidden -enc SQBFAFgA\x00cmd.exe /c vssadmin delete shadows /all /quiet\x00"
    + b"VirtualAlloc\x00WriteProcessMemory\x00CreateRemoteThread\x00"
)


@pytest.fixture
def samples(tmp_path):
    folder = tmp_path / "samples"
    folder.mkdir()
    notes = folder / "meeting_notes.txt"
    notes.write_text("Agenda for Thursday. Review the budget.\n" * 30, encoding="utf-8")
    program = folder / "invoice.pdf.exe"
    program.write_bytes(SUSPICIOUS)
    return {"notes": notes, "program": program}


@pytest.fixture
def held(monkeypatch):
    """Hold the real engine inside a chosen stage until released."""
    gate = {"event": threading.Event(), "stage": 1}
    original = qt_app.ScanService.analyze

    def analyze(self, candidate, mode, settings, progress=None):
        def report(index, state, detail):
            progress(index, state, detail)
            if index == gate["stage"] and state == "running":
                gate["event"].wait(30)
        return original(self, candidate, mode, settings, report)

    monkeypatch.setattr(qt_app.ScanService, "analyze", analyze)
    yield gate
    gate["event"].set()


# --- the journey follows real events -------------------------------------------------


def test_a_scan_with_nothing_found_reaches_its_result(window, qapplication, samples):
    """Regression (audit UI-001): zero findings used to leave the journey stuck."""
    scan(qapplication, window, str(samples["notes"]))
    assert window.view == "result"
    assert window.journey.phase == "concluded"
    assert window.result_panel.headline.text() == "Nothing worrying found"
    assert window.result_panel.limit.text() == "This isn't a guarantee that it's safe."
    assert len(window.scan_history) == 1


def test_a_suspicious_target_ends_on_its_verdict(window, qapplication, samples):
    scan(qapplication, window, str(samples["program"]))
    assert window.view == "result"
    assert window.result_panel.headline.text() == "Be careful with this one"
    assert window.result_panel.meter.level == 3
    assert window.status_pill.text().endswith("Done")


def test_stations_follow_reported_stages_and_nothing_moves_while_the_engine_waits(window, qapplication, samples, held):
    window.lens.set_target(str(samples["program"]))
    window.lens.scan_button.click()
    assert wait_for(qapplication, lambda: window.journey.stage_states[1] == "running", 20)
    assert window.journey.stage_states == ["complete", "running", "waiting", "waiting"]
    assert window.journey._links[1] == 0.0
    settle(qapplication, 0.6)
    assert window.journey.stage_states == ["complete", "running", "waiting", "waiting"]
    assert window.journey._links[1] == 0.0  # no connector fills on a timer
    assert window.journey_caption.text() == "Looking for unusual patterns…"
    held["event"].set()
    assert wait_for(qapplication, lambda: window.view == "result", 40)


def test_failure_is_reported_once_in_plain_words(window, qapplication, samples, dialogs):
    window.settings["maximum_file_size"] = 16
    scan(qapplication, window, str(samples["notes"]))
    assert window.journey.phase == "failed"
    assert window.journey.stage_states[0] == "failed"
    assert window.outcome_title.text() == "The scan couldn't finish"
    assert window.outcome_body.text() == "The file is bigger than the size limit in your settings."
    assert window.outcome_note.text() == "Nothing was concluded about this target."
    assert "exceeds the configured limit" in window.technical_text.text()
    assert window.technical_text.isHidden()
    assert window.status_pill.text().endswith("Stopped")
    assert dialogs == []  # no modal on top of the inline message
    assert window.scan_history == []
    window.retry_button.click()
    assert wait_for(qapplication, lambda: window.journey.phase == "failed", 20)


def test_cancel_discards_the_result_and_never_saves_it(window, qapplication, samples, held):
    window.lens.set_target(str(samples["program"]))
    window.lens.scan_button.click()
    assert wait_for(qapplication, lambda: window.journey.stage_states[1] == "running", 20)
    window.stop_button.click()
    assert window.journey.phase == "cancelled"
    assert "complete" not in window.journey.stage_states[1:]
    assert window.outcome_title.text() == "Scan stopped"
    held["event"].set()
    assert wait_for(qapplication, lambda: not window._abandoned_workers or not window._abandoned_workers[0].isRunning(), 30)
    settle(qapplication, 0.3)
    assert window.view == "journey"
    assert window.scan_history == []


def test_close_is_refused_while_a_scan_or_a_cancelled_read_is_running(window, qapplication, samples, held, dialogs):
    window.lens.set_target(str(samples["program"]))
    window.lens.scan_button.click()
    assert wait_for(qapplication, lambda: window.journey.stage_states[1] == "running", 20)
    window.close()
    assert window.isVisible() and dialogs[-1][1] == "Analysis in progress"
    window.cancel_scan()
    window.close()
    assert window.isVisible()
    held["event"].set()
    assert wait_for(qapplication, lambda: not any(w.isRunning() for w in window._abandoned_workers), 30)


def test_consecutive_scans_start_clean(window, qapplication, samples):
    scan(qapplication, window, str(samples["program"]))
    window.result_panel.again_button.click()
    assert window.view == "lens"
    window.lens.set_target(str(samples["notes"]))
    window.lens.scan_button.click()
    assert window.journey.stage_states[1:] == ["waiting"] * 3
    assert wait_for(qapplication, lambda: window.view == "result", 40)
    assert len(window.scan_history) == 2


def test_input_problems_are_shown_under_the_field_and_clear_on_edit(window, qapplication, dialogs):
    window.lens.set_target("")
    window.lens.scan_button.click()
    assert window.lens.error.text() == "Add something to scan first."
    window.lens.set_target("C:\\does\\not\\exist\\file.exe")
    window.lens.scan_button.click()
    assert window.lens.error.text().startswith("That file doesn't exist")
    assert window.lens.field.property("invalid") is True
    window.lens.field.setText("https://example.com")
    assert window.lens.error.isHidden()
    assert dialogs == [] and window.view == "lens"


def test_the_lens_names_what_it_will_scan(window, qapplication, samples):
    window.lens.set_target(str(samples["program"]))
    assert window.lens.kind.key == "program"
    assert window.lens.scan_button.text() == "Scan this program"
    assert "Program" in window.lens.preview_meta.text()
    window.lens.set_target("https://example.com/login")
    assert window.lens.kind.key == "url"
    window.lens.set_target("")
    assert window.lens.preview.isHidden()


# --- motion ---------------------------------------------------------------------------


def test_reduced_motion_concludes_immediately(qapplication):
    scene = JourneyScene(reduced_motion=True)
    scene.show()
    fired = []
    scene.concluded.connect(lambda: fired.append(True))
    scene.start("a.bin", KINDS["file"], "")
    scene.set_stage_states(["running", "waiting", "waiting", "waiting"])
    assert scene.animating is False
    scene.conclude("●", "#4ade80")
    assert fired == [True] and scene.phase == "concluded"
    scene.close()


def test_animated_conclusion_without_findings_settles(qapplication):
    scene = JourneyScene(reduced_motion=False)
    scene.resize(800, 300)
    scene.show()
    fired = []
    scene.concluded.connect(lambda: fired.append(True))
    scene.start("notes.txt", KINDS["text"], "")
    scene.set_stage_states(["complete"] * 4)
    scene.conclude("●", "#4ade80")
    assert wait_for(qapplication, lambda: bool(fired), 3)
    assert wait_for(qapplication, lambda: not scene.animating, 2)
    scene.close()


def test_the_spinner_runs_only_while_a_stage_runs_and_the_scene_is_visible(qapplication):
    scene = JourneyScene(reduced_motion=False)
    scene.show()
    scene.start("a.bin", KINDS["file"], "")
    assert scene.animating is False
    scene.set_stage_states(["running", "waiting", "waiting", "waiting"])
    assert scene._timer.isActive()
    scene.hide()
    assert not scene._timer.isActive()
    scene.show()
    scene.fail("Stopped")
    assert not scene._timer.isActive()
    scene.close()


def test_failure_before_the_next_report_marks_the_stage_that_was_due(qapplication):
    scene = JourneyScene(reduced_motion=True)
    scene.start("a.bin", KINDS["file"], "")
    scene.set_stage_states(["complete", "waiting", "waiting", "waiting"])
    scene.fail("Stopped")
    assert scene.stage_states == ["complete", "failed", "waiting", "waiting"]


def test_nothing_ticks_while_the_app_is_idle(window, qapplication, samples):
    from PySide6.QtCore import QTimer

    settle(qapplication, 0.3)
    assert [t for t in window.findChildren(QTimer) if t.isActive()] == []
    scan(qapplication, window, str(samples["notes"]))
    settle(qapplication, 0.6)
    assert [t for t in window.findChildren(QTimer) if t.isActive()] == []
    assert window.journey.animating is False


def test_closing_stops_everything(window, qapplication, samples):
    from PySide6.QtCore import QTimer

    scan(qapplication, window, str(samples["notes"]))
    window.close()
    assert not window.isVisible()
    assert [t for t in window.findChildren(QTimer) if t.isActive()] == []
