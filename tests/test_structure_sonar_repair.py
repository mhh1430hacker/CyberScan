"""The file structure cube, out-of-process scanning, and the repair preview."""
from __future__ import annotations

import os
import time

import numpy as np
import pytest

from conftest import scan, settle, wait_for
from ui.structure import MAX_CELLS, _CURVE, build_structure, hilbert_point

pytest.importorskip("PySide6")

# --- structure (no Qt) ------------------------------------------------------------------


def test_hilbert_curve_keeps_neighbouring_bytes_together():
    steps = np.abs(np.diff(_CURVE, axis=0)).sum(axis=1)
    assert bool((steps == 1).all())  # every next slice is an adjacent cell
    assert len({tuple(point) for point in _CURVE}) == MAX_CELLS
    assert hilbert_point(0) == (0, 0, 0)


def test_slices_cover_the_whole_file_exactly():
    data = os.urandom(10_000) + bytes(30_000)
    structure = build_structure(data, None, {}, {})
    assert structure.count == MAX_CELLS
    assert structure.offsets[0, 0] == 0 and structure.offsets[-1, 1] == len(data)
    assert bool((structure.offsets[1:, 0] == structure.offsets[:-1, 1]).all())
    # measured, not invented: random bytes are dense, zeros are empty
    assert structure.entropy[structure.cell_at_offset(1_000)] > 7.0
    assert structure.entropy[structure.cell_at_offset(35_000)] == 0.0


def test_only_engine_located_regions_are_flagged():
    data = bytes(20_000)
    position = {"entropy_boundaries": [{"offset_start": 4_000, "offset_end": 6_000, "severity": "high", "entropy_delta_bits_per_byte": 5.0}]}
    structure = build_structure(data, None, {}, position)
    flagged = np.nonzero(structure.flags)[0]
    assert flagged.size > 0
    assert structure.offsets[flagged].min() < 6_000 and structure.offsets[flagged].max() > 4_000
    assert all(structure.offsets[i, 1] > 4_000 and structure.offsets[i, 0] < 6_000 for i in flagged)
    assert structure.regions[0].severity == "high"
    assert build_structure(data, None, {}, {}).flags.sum() == 0


def test_older_reports_use_entropy_anomalies_and_saved_windows():
    topography = {
        "trajectory": [1.0, 7.5, 1.0],
        "window_offsets": [0, 1_000, 2_000],
        "anomalies": [{"offset_start": 1_000, "offset_end": 2_000, "severity": "medium", "delta": 6.5}],
    }
    structure = build_structure(None, 3_000, topography, {})
    assert structure.source == "windows"
    assert structure.entropy[structure.cell_at_offset(1_500)] == pytest.approx(7.5)
    assert structure.regions[0].severity == "medium"


def test_nothing_to_draw_returns_none():
    assert build_structure(b"", None, {}, {}) is None
    assert build_structure(None, 500, {}, {}) is None


# --- the sonar cube ----------------------------------------------------------------------------


@pytest.fixture
def cube(qapplication):
    from ui.sonar import SonarCube

    widget = SonarCube(reduced_motion=False)
    widget.resize(700, 360)
    widget.show()
    yield widget
    widget.close()


def test_scanning_loops_until_the_real_result_arrives(cube, qapplication):
    cube.start("#a78bfa")
    settle(qapplication, 1.2)
    assert cube.phase == "scanning" and cube.animating  # still waiting, still moving
    finished = []
    cube.finished.connect(lambda: finished.append(True))
    structure = build_structure(os.urandom(5_000), None, {}, {"entropy_boundaries": [{"offset_start": 0, "offset_end": 500, "severity": "high"}]})
    cube.reveal(structure)
    assert cube.phase == "echo"
    assert wait_for(qapplication, lambda: bool(finished), 6)
    assert cube.phase == "explore" and not cube.animating


def test_a_click_skips_the_reveal(cube, qapplication):
    from PySide6.QtCore import QPointF, Qt
    from PySide6.QtGui import QMouseEvent
    from PySide6.QtCore import QEvent

    cube.start("#a78bfa")
    cube.reveal(build_structure(os.urandom(2_000), None, {}, {}))
    event = QMouseEvent(QEvent.Type.MouseButtonPress, QPointF(10, 10), QPointF(10, 10), Qt.MouseButton.LeftButton, Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier)
    cube.mousePressEvent(event)
    assert cube.phase == "explore"


def test_reduced_motion_reveals_at_once(qapplication):
    from ui.sonar import SonarCube

    widget = SonarCube(reduced_motion=True)
    widget.show()
    finished = []
    widget.finished.connect(lambda: finished.append(True))
    widget.start("#5ee0d0")
    assert not widget.animating
    widget.reveal(build_structure(os.urandom(1_000), None, {}, {}))
    assert finished == [True] and not widget.animating
    widget.close()


def test_explore_mode_names_the_point_under_the_pointer(qapplication):
    from PySide6.QtCore import QPointF
    from ui.sonar import SonarCube

    widget = SonarCube(interactive=True, reduced_motion=True)
    widget.resize(600, 360)
    widget.show()
    structure = build_structure(os.urandom(4_096), None, {}, {})
    widget.show_structure(structure, "#5ee0d0")
    widget.repaint()
    assert not widget.animating
    x, y = widget._project(structure.positions)[100, :2]
    assert widget.cell_at(QPointF(float(x), float(y))) is not None
    widget.close()


# --- the journey and the result ------------------------------------------------------------------


def test_the_result_waits_for_the_sonar_and_shows_the_file_inside(window, qapplication, tmp_path):
    sample = tmp_path / "invoice.pdf.exe"
    sample.write_bytes(b"MZ" + bytes(4_000) + os.urandom(30_000) + b"powershell -nop -w hidden -enc SQBFAFgA")
    window.lens.set_target(str(sample))
    window.lens.scan_button.click()
    assert window.sonar.phase in {"drawing", "scanning"}
    assert wait_for(qapplication, lambda: window.view == "result", 40)
    assert window.sonar.phase == "explore"
    panel = window.result_panel
    assert panel.inside_card.isVisible()
    assert panel.structure is not None and panel.structure.source == "bytes"
    assert panel.cube.phase == "explore" and not panel.cube.animating


def test_saved_scans_rebuild_the_cube_from_measurements(window, qapplication, tmp_path):
    sample = tmp_path / "blob.bin"
    sample.write_bytes(os.urandom(20_000) + bytes(20_000))
    scan(qapplication, window, str(sample))
    record_id = window.scan_history[-1]["id"]
    window.new_scan()
    window.open_record(record_id)
    assert window.result_panel.structure is not None
    assert window.result_panel.structure.source == "windows"
    assert "Rebuilt from the measurements" in window.result_panel.inside_note.text()


# --- scanning in a separate process ----------------------------------------------------------------


def test_a_real_scan_runs_in_the_worker_process(qapplication, tmp_path, monkeypatch):
    import ui.qt_app as qt_app
    from ui import scan_process

    monkeypatch.setenv("CYBERSCAN_SCAN_IN_PROCESS", "1")
    sample = tmp_path / "notes.txt"
    sample.write_text("Agenda for Thursday.\n" * 50, encoding="utf-8")
    worker = qt_app.ScanWorker(str(sample), "File", {"osint_enabled": False})
    stages, done = [], []
    worker.progress.connect(lambda index, state, detail: stages.append((index, state)))
    worker.completed.connect(lambda payload: done.append(payload))
    worker.failed.connect(lambda message: done.append(message))
    gaps, last = [], [time.perf_counter()]
    try:
        worker.start()
        while not done and time.perf_counter() - last[0] < 120:
            qapplication.processEvents()
            time.sleep(0.005)
        worker.wait(10_000)
        qapplication.processEvents()
    finally:
        scan_process.HOST.shutdown()
    assert done and not isinstance(done[0], str), done
    assert done[0][0].classification == "NO_INDICATORS_OBSERVED"
    assert stages[0] == (0, "running") and (3, "complete") in stages


# --- repair preview ------------------------------------------------------------------------------------


def test_repair_mode_changes_the_look_and_cannot_change_files(window, qapplication):
    from PySide6.QtWidgets import QPushButton

    assert "#5ee0d0" in window.styleSheet()
    window.mode_buttons["repair"].click()
    assert window.app_mode == "repair" and window.view == "repair"
    assert "#a594ff" in window.styleSheet()
    assert window.status_pill.text().endswith("Repair · preview")
    assert "isn't available in this version" in window.repair_view.lead.text()
    enabled = [b for b in window.repair_view.findChildren(QPushButton) if b.isEnabled()]
    assert enabled == []  # nothing on the repair screen can act
    window.mode_buttons["scan"].click()
    assert window.app_mode == "scan" and window.view == "lens"
    assert "#5ee0d0" in window.styleSheet()


def test_repair_cannot_be_entered_while_a_scan_runs(window, qapplication, tmp_path, monkeypatch):
    import threading

    import ui.qt_app as qt_app

    gate = threading.Event()
    original = qt_app.ScanService.analyze

    def analyze(self, candidate, mode, settings, progress=None):
        def report(index, state, detail):
            progress(index, state, detail)
            if index == 1 and state == "running":
                gate.wait(30)
        return original(self, candidate, mode, settings, report)

    monkeypatch.setattr(qt_app.ScanService, "analyze", analyze)
    sample = tmp_path / "a.txt"
    sample.write_text("hello\n" * 30, encoding="utf-8")
    window.lens.set_target(str(sample))
    window.lens.scan_button.click()
    assert wait_for(qapplication, lambda: window.journey.stage_states[1] == "running", 20)
    assert not window.mode_buttons["repair"].isEnabled()
    window.set_mode("repair")
    assert window.app_mode == "scan"
    gate.set()
    assert wait_for(qapplication, lambda: window.view == "result", 40)
    assert window.mode_buttons["repair"].isEnabled()


def test_sonar_walls_rise_where_the_content_changes():
    data = os.urandom(32_768) + bytes(32_768)
    structure = build_structure(data, None, {}, {})
    middle = structure.cell_at_offset(32_768)
    assert structure.walls[middle - 1 : middle + 1].max() > 0.9  # random meets zeros
    assert structure.walls[structure.cell_at_offset(60_000)] == 0.0  # uniform zeros: open space


def test_a_scan_still_works_after_visiting_repair(window, qapplication, tmp_path):
    window.set_mode("repair")
    window.set_mode("scan")
    assert window.mode == "File"  # the target kind is not the app mode
    sample = tmp_path / "notes.txt"
    sample.write_text("Agenda for Thursday.\n" * 40, encoding="utf-8")
    scan(qapplication, window, str(sample))
    assert window.view == "result" and window._failure is None
