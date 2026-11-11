"""Exhibit mode: every round is a real infection, a real scan and a real heal."""
from __future__ import annotations

import hashlib
import random

import pytest

from conftest import wait_for

pytest.importorskip("PySide6")


@pytest.fixture
def exhibit(qapplication, tmp_path):
    from ui.exhibit import ExhibitWindow

    window = ExhibitWindow("en", tmp_path / "data")
    window.sounds.enabled = False
    window.resize(1400, 1000)
    window.show()
    yield window
    window.close()


def press(window, key, text=""):
    from PySide6.QtCore import Qt
    from PySide6.QtGui import QKeyEvent

    window.keyPressEvent(QKeyEvent(QKeyEvent.Type.KeyPress, key, Qt.KeyboardModifier.NoModifier, text))


@pytest.mark.parametrize("index", [0, 1, 2, 3])
def test_every_sample_is_infected_found_and_healed_exactly(qapplication, index):
    from repair_engine.analyze import analyze
    from ui.exhibit import SAMPLES, Round, heal, infect, same_parts

    sample = SAMPLES[index]
    data = sample.build()
    if data is None:
        pytest.skip("Notepad isn't available on this machine")
    assert not any(f.repairable for f in analyze(data, sample.name).findings)  # the samples start clean
    for seed in range(4):
        infected, family, content = infect(sample, data, random.Random(seed))
        assert family in sample.families and content != "zeros" and infected != data
        round_ = Round(sample, data, infected, family, content, analyze(infected, sample.name))
        result = heal(round_)
        assert result.ok and result.after == 0
        assert result.repaired == data or same_parts(result.repaired, data)


def test_injected_content_is_inert(qapplication):
    from ui.exhibit import SAMPLES, infect

    data = SAMPLES[0].build()
    for seed in range(6):
        infected, _family, _content = infect(SAMPLES[0], data, random.Random(seed))
        tail = infected[len(data):]
        assert b"MZ" not in tail[:2] and b"<script" not in tail.lower()


def test_a_full_round_by_keyboard(exhibit, qapplication, tmp_path):
    from PySide6.QtCore import Qt

    press(exhibit, Qt.Key.Key_3, "3")  # the Word report
    assert exhibit.step == 1 and exhibit.round.sample.key == "word"
    press(exhibit, Qt.Key.Key_Space, " ")
    assert exhibit.step == 2 and exhibit.round.infected != exhibit.round.original
    press(exhibit, Qt.Key.Key_Space, " ")
    assert exhibit.step == 3 and exhibit.round.report.findings
    assert wait_for(qapplication, lambda: exhibit.headline.text().startswith("Found it in"), 20)
    assert exhibit.cube.highlighted  # the found region glows
    press(exhibit, Qt.Key.Key_Space, " ")
    assert exhibit.step == 4 and exhibit.headline.text() == "Healed. It's the original again."
    press(exhibit, Qt.Key.Key_S, "s")
    souvenirs = list((tmp_path / "data" / "exhibit" / "souvenirs").iterdir())
    assert sorted(p.suffix for p in souvenirs) == [".ply", ".png"]
    ply = next(p for p in souvenirs if p.suffix == ".ply").read_text(encoding="ascii")
    assert ply.startswith("ply\n") and "element vertex" in ply
    # nothing but the souvenirs was written: the samples never touch the disk
    written = {p.relative_to(tmp_path / "data").parts[0:2] for p in (tmp_path / "data").rglob("*") if p.is_file()}
    assert written == {("exhibit", "souvenirs")}
    press(exhibit, Qt.Key.Key_L, "l")
    assert exhibit.language == "ar" and "جراحة" in exhibit.brand_label.text()


def test_the_disguise_game_and_its_leaderboard(exhibit, qapplication, tmp_path):
    from PySide6.QtCore import Qt

    from ui.exhibit import ROUNDS
    from ui.names import inspect

    press(exhibit, Qt.Key.Key_G, "g")
    for _round in range(ROUNDS):
        names, answer = exhibit.game["names"], exhibit.game["answer"]
        assert inspect(names[answer]).disguised or "     " in names[answer]
        assert not any(inspect(n).disguised for i, n in enumerate(names) if i != answer)
        press(exhibit, Qt.Key.Key_1 + answer, str(answer + 1))
        assert "Right!" in exhibit.caption.text()
        press(exhibit, Qt.Key.Key_1, "1")  # continue
    assert exhibit.game["initials"] == ""
    for letter in "ABC":
        press(exhibit, getattr(Qt.Key, f"Key_{letter}"), letter.lower())
    press(exhibit, Qt.Key.Key_Return, "\r")
    assert exhibit.game is None and "#1" in exhibit.caption.text()
    rows = exhibit.board.load()
    assert rows[0]["initials"] == "ABC" and rows[0]["score"] >= 100 * ROUNDS
    assert "ABC" in exhibit.board_label.text()


def test_attract_loop_plays_itself_and_any_key_hands_over(exhibit, qapplication):
    from PySide6.QtCore import Qt

    exhibit.start_attract()
    assert exhibit.attract and exhibit.step == 1
    exhibit._attract_step()
    assert exhibit.step == 2
    press(exhibit, Qt.Key.Key_X, "x")
    assert not exhibit.attract and exhibit.step == 0 and not exhibit.attract_timer.isActive()


def test_the_main_window_opens_the_exhibit(window, qapplication):
    window.open_exhibit()
    assert window.exhibit.isVisible()
    window.exhibit.close()


def test_a_pdf_attachment_update_is_removed_back_to_the_original():
    from repair_engine.analyze import analyze, repair
    from repair_engine.synth.injector import inject
    from tests.test_repair_engine_synth import simple_pdf

    data = simple_pdf()
    for seed in range(3):
        infected = inject(data, "a.pdf", "pdf_embedded_file", seed).modified
        finding = [f for f in analyze(infected, "a.pdf").findings if f.kind == "pdf_update"][0]
        assert finding.repairable and finding.recommended
        assert hashlib.sha256(repair(infected, "a.pdf", [finding]).repaired).digest() == hashlib.sha256(data).digest()
