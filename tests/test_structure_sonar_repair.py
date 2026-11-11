"""The file structure cube, out-of-process scanning, and the Repair screen."""
from __future__ import annotations

import os
import re
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


# --- repair ------------------------------------------------------------------------------------------


def test_repair_mode_changes_the_look_and_starts_empty(window, qapplication):
    from PySide6.QtWidgets import QPushButton

    assert "#5ee0d0" in window.styleSheet()
    window.mode_buttons["repair"].click()
    assert window.app_mode == "repair" and window.view == "repair"
    assert "#a594ff" in window.styleSheet()
    assert window.status_pill.text().endswith("Repair")
    assert not window.repair_view.review.isVisible() and not window.repair_view.outcome.isVisible()
    window.repair_view.analyze_field()  # nothing chosen: a clear message, no work
    assert "Choose a file" in window.repair_view.error.text()
    window.mode_buttons["scan"].click()
    assert window.app_mode == "scan" and window.view == "lens"
    assert "#5ee0d0" in window.styleSheet()


def _repair_round(window, qapplication, path):
    view = window.repair_view
    window._file_dropped(str(path))  # in repair mode a dropped file goes to repair
    assert wait_for(qapplication, lambda: view.report is not None and view.analyze_button.isEnabled(), 30)
    return view


def test_repair_cuts_an_appended_program_out_of_a_copy(window, qapplication, tmp_path):
    from repair_fixtures import build_png

    original = build_png()[0] + b"MZ" + bytes(range(256)) * 8
    path = tmp_path / "holiday.png"
    path.write_bytes(original)
    window.set_mode("repair")
    view = _repair_round(window, qapplication, path)
    assert [f.kind for f in view.selected()] == ["after_eof"]  # pre-selected: it starts like a program
    assert view.cube.structure is not None and view.cube.structure.flags.any()
    view.repair_button.click()
    assert wait_for(qapplication, lambda: view.output is not None or view.outcome_title.text().startswith("✕"), 30)
    view.wait()
    assert view.output == tmp_path / "holiday (repaired).png"
    assert view.output.read_bytes() == build_png()[0]
    assert path.read_bytes() == original  # the original is untouched
    assert "0 after" in view.outcome_body.text() and "1 before" in view.outcome_body.text()
    assert list((tmp_path / "data" / "quarantine" / "repair").iterdir())  # the cut bytes are sealed
    assert any("Repaired copy written" in line for line in window.audit_log)
    # a second repair never overwrites the first copy
    view.repair_button.click()
    assert wait_for(qapplication, lambda: view.output == tmp_path / "holiday (repaired 2).png", 30)
    view.wait()


def test_repair_removes_macros_from_a_document_cleanly(window, qapplication, tmp_path):
    import io
    import zipfile

    from repair_fixtures import build_zip

    content_types = (b'<Types><Default Extension="xml" ContentType="application/xml"/>'
                     b'<Override PartName="/word/document.xml" ContentType="doc"/>'
                     b'<Override PartName="/word/vbaProject.bin" ContentType="application/vnd.ms-office.vbaProject"/></Types>')
    rels = (b'<Relationships><Relationship Id="rId1" Type="http://schemas.microsoft.com/office/2006/relationships/vbaProject" Target="vbaProject.bin"/>'
            b'<Relationship Id="rId2" Type="http://x/styles" Target="styles.xml"/></Relationships>')
    data, _ = build_zip(members={"[Content_Types].xml": content_types, "_rels/.rels": b"<Relationships/>",
                                 "word/document.xml": b"<w:document/>", "word/styles.xml": b"<w:styles/>",
                                 "word/_rels/document.xml.rels": rels, "word/vbaProject.bin": bytes(range(256)) * 4})
    path = tmp_path / "report.docx"  # a .docx isn't supposed to hold macros
    path.write_bytes(data)
    window.set_mode("repair")
    view = _repair_round(window, qapplication, path)
    macro = [f for f in view.report.findings if f.kind == "ooxml_vba_project"]
    assert macro and macro[0].severity == "high" and macro[0] in view.selected()
    view.repair_button.click()
    assert wait_for(qapplication, lambda: view.output is not None, 30)
    view.wait()
    with zipfile.ZipFile(io.BytesIO(view.output.read_bytes())) as package:
        assert package.testzip() is None
        assert "word/vbaProject.bin" not in package.namelist()
        assert b"vbaProject" not in package.read("[Content_Types].xml")
        remaining = package.read("word/_rels/document.xml.rels")
        assert b"vbaProject" not in remaining and b"styles.xml" in remaining


def test_a_disguised_program_is_offered_its_true_name_but_never_preselected(window, qapplication, tmp_path):
    from repair_fixtures import build_pdf

    path = tmp_path / "invoice.pdf.exe"
    path.write_bytes(build_pdf()[0])
    window.set_mode("repair")
    view = _repair_round(window, qapplication, path)
    rename = [f for f in view.report.findings if f.key == "name_double"]
    assert rename and rename[0].repairable and not rename[0].recommended
    assert "name_double" not in [f.key for f in view.selected()]  # renaming a program doesn't make it safe
    assert view.caution.isVisible() and "quarantine" in view.caution.text()
    view.language = "ar"
    view._render()  # Arabic rows read a translated sentence, not the engine's English
    assert re.search("[؀-ۿ]", view.summary.text()) and not re.search("[A-Za-z]{3,}", view.summary.text())


def test_a_clean_file_has_nothing_to_repair(window, qapplication, tmp_path):
    path = tmp_path / "notes.txt"
    path.write_text("Agenda for Thursday.\n" * 40, encoding="utf-8")
    window.set_mode("repair")
    view = _repair_round(window, qapplication, path)
    assert view.report.findings == [] and not view.repair_button.isVisible()
    assert "doesn't prove the file is safe" in view.summary.text()


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


# --- scan -> repair ------------------------------------------------------------------------------------


def test_a_scan_result_offers_repair_and_hands_over_with_the_sonar_wave(window, qapplication, tmp_path):
    from repair_fixtures import build_png

    clean = build_png()[0]
    path = tmp_path / "beach.png"
    path.write_bytes(clean + b"MZ" + bytes(range(256)) * 16)
    scan(qapplication, window, str(path))
    panel = window.result_panel
    assert wait_for(qapplication, lambda: panel.repair_button.isVisible(), 30)
    assert panel.repair_count == 1 and "1 can be fixed" in panel.repair_button.text()
    panel.repair_button.click()
    assert window.view == "repair" and window.app_mode == "repair"
    assert window._transition is not None  # the wave is playing over the switch
    assert wait_for(qapplication, lambda: window._transition is None, 10)
    view = window.repair_view
    assert view.path == path and [f.kind for f in view.selected()] == ["after_eof"]
    assert wait_for(qapplication, lambda: view.cube.structure is not None and view.cube.structure.flags.any(), 10)
    view.repair_button.click()
    assert wait_for(qapplication, lambda: view.output is not None, 30)
    view.wait()
    assert view.output.read_bytes() == clean and path.read_bytes() != clean  # a repaired copy; the original kept
    window.set_mode("scan")
    assert window.view == "result"  # back where the visitor came from


def test_a_clean_scan_offers_no_repair(window, qapplication, tmp_path):
    path = tmp_path / "notes.txt"
    path.write_text("Agenda for Thursday.\n" * 40, encoding="utf-8")
    scan(qapplication, window, str(path))
    qapplication.processEvents()
    assert wait_for(qapplication, lambda: (window._current or {}).get("repair_probe") is not None, 20)
    assert not window.result_panel.repair_button.isVisible()
    window.repair_current()  # nothing to hand over: nothing happens
    assert window.view == "result"


def test_a_dangerous_scan_result_never_offers_repair(window, qapplication, tmp_path):
    """Repairing a disguised program would write another copy of it and call it repaired."""
    path = tmp_path / "invoice.pdf.exe"
    path.write_bytes(b"MZ" + bytes(200) + b"powershell -nop -w hidden -enc SQBFAFgA\x00VirtualAlloc\x00CreateRemoteThread\x00")
    scan(qapplication, window, str(path))
    assert wait_for(qapplication, lambda: (window._current or {}).get("repair_probe") is not None, 20)
    report = window._current["repair_probe"][0]
    assert any(f.repairable for f in report.findings)  # the engine could rename it...
    assert not window.result_panel.repair_button.isVisible()  # ...but the result doesn't offer it
    window.repair_current()
    assert window.view == "result"
    assert window.result_panel.quarantine_button.isVisible()


def test_a_folder_is_named_a_folder(window, qapplication, tmp_path):
    window.lens.set_target(str(tmp_path))
    window.lens.scan_button.click()
    assert "folder" in window.lens.error.text()


def test_mode_switch_restyles_only_what_the_accent_touches(window, qapplication):
    import time

    sheet = window.styleSheet()
    started = time.perf_counter()
    window.set_mode("repair")
    qapplication.processEvents()
    elapsed = time.perf_counter() - started
    assert window.styleSheet() == sheet  # the stylesheet itself isn't rebuilt
    assert window.property("appMode") == "repair"
    assert elapsed < 0.5
    window.set_mode("scan")


def test_the_background_rests_when_nobody_uses_the_window(window, qapplication, monkeypatch):
    import ui.backdrop as backdrop

    window.backdrop._last_input -= backdrop.IDLE_SECONDS + 1
    window.backdrop.update()
    assert wait_for(qapplication, lambda: not window.backdrop.animating, 3)
    window.backdrop.wake()
    assert window.backdrop._resting is False
