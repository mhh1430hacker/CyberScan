"""The finishing touches: each answers an event, and none of them blocks or loops."""
from __future__ import annotations

import pytest

from conftest import settle, wait_for

pytest.importorskip("PySide6")


def test_the_mode_pill_glides_to_the_chosen_side(window, qapplication):
    window.show()
    settle(qapplication, 0.3)
    glider = window.glider
    assert glider.geometry() == window.mode_buttons["scan"].geometry()
    window.set_mode("repair")
    assert wait_for(qapplication, lambda: glider.geometry() == window.mode_buttons["repair"].geometry(), 5)
    assert glider.color.name() == "#a594ff"  # the pill takes the mode's colour
    window.set_mode("scan")
    assert wait_for(qapplication, lambda: glider.geometry() == window.mode_buttons["scan"].geometry(), 5)


def test_glass_cards_catch_the_pointer_light(window, qapplication):
    from PySide6.QtCore import QEvent, QPointF
    from PySide6.QtGui import QHoverEvent
    from PySide6.QtWidgets import QFrame

    window.show()
    settle(qapplication, 0.2)
    cards = window.findChildren(QFrame, "card")
    assert cards and all(card in window.cursor_light.lights for card in cards)
    card = cards[0]
    light = window.cursor_light.lights[card]
    enter = QHoverEvent(QEvent.Type.HoverEnter, QPointF(20, 20), QPointF(20, 20), QPointF(-1, -1))
    window.cursor_light.eventFilter(card, enter)
    assert wait_for(qapplication, lambda: light.strength > 0.95, 3) and light.point == QPointF(20, 20)
    leave = QHoverEvent(QEvent.Type.HoverLeave, QPointF(-1, -1), QPointF(-1, -1), QPointF(20, 20))
    window.cursor_light.eventFilter(card, leave)
    assert wait_for(qapplication, lambda: light.strength < 0.05, 3)


def test_a_press_leaves_a_ripple_that_cleans_up(qapplication):
    from PySide6.QtCore import QEvent, QPointF, Qt
    from PySide6.QtGui import QMouseEvent
    from PySide6.QtWidgets import QPushButton

    from ui.polish import Ripples, _Ripple

    ripples = Ripples(qapplication)
    button = QPushButton("Go")
    button.resize(120, 36)
    button.show()
    press = QMouseEvent(QEvent.Type.MouseButtonPress, QPointF(10, 10), QPointF(10, 10), Qt.MouseButton.LeftButton,
                        Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier)
    ripples.eventFilter(button, press)
    assert len(button.findChildren(_Ripple)) == 1
    assert wait_for(qapplication, lambda: not button.findChildren(_Ripple), 3)
    qapplication.removeEventFilter(ripples)
    button.close()


def test_copying_the_fingerprint_shows_a_toast_that_leaves(window, qapplication, tmp_path):
    from conftest import scan
    from ui.polish import Toast

    sample = tmp_path / "notes.txt"
    sample.write_text("Agenda.\n" * 50, encoding="utf-8")
    scan(qapplication, window, str(sample))
    window.result_panel._copy_fingerprint()
    toasts = window.findChildren(Toast)
    assert len(toasts) == 1 and "copied" in toasts[0].text().lower()
    assert wait_for(qapplication, lambda: not window.findChildren(Toast), 5)


def test_the_meter_fills_in_order_and_the_check_draws(qapplication):
    from ui.polish import SuccessMark
    from ui.widgets import LevelMeter

    meter = LevelMeter()
    meter.set_level(3, ["Low", "Some", "High"], "Unknown", "Warning level")
    meter.show()
    meter.reveal()
    assert meter._fill < 1.0
    assert wait_for(qapplication, lambda: meter._fill == 1.0, 3)
    mark = SuccessMark()
    mark.show()
    mark.play()
    assert mark.progress < 1.0
    assert wait_for(qapplication, lambda: mark.progress == 1.0, 3)


def test_reduced_motion_makes_every_touch_immediate(qapplication, monkeypatch):
    monkeypatch.setenv("CYBERSCAN_REDUCE_MOTION", "1")
    from ui.polish import SuccessMark
    from ui.widgets import LevelMeter

    meter = LevelMeter()
    meter.set_level(2, ["Low", "Some", "High"], "Unknown", "Warning level")
    meter.reveal()
    mark = SuccessMark()
    mark.play()
    assert meter._fill == 1.0 and mark.progress == 1.0


# --- the sonar chamber on the home screen ------------------------------------------------------


def test_the_chamber_leans_toward_the_pointer_then_rests(window, qapplication):
    window.show()
    settle(qapplication, 0.3)
    chamber = window.lens.chamber
    assert chamber.isVisible() and chamber.phase in {"drawing", "stopped"}
    base = chamber._base
    chamber.look(1.0, 0.0)
    assert chamber._fx.isActive()
    assert wait_for(qapplication, lambda: not chamber._fx.isActive(), 5)  # it settles, then stops working
    assert chamber.yaw > base[0] + 0.3


def test_the_chamber_pings_when_it_recognises_a_target(window, qapplication):
    from ui.file_kind import KINDS

    window.show()
    settle(qapplication, 0.3)
    chamber = window.lens.chamber
    window.lens.set_target("https://example.com/login")
    assert len(chamber._pings) == 1 and chamber.hue.name() == KINDS["url"].hue.lower()
    window.lens.set_target("https://example.com/other")  # the same kind again: no new ping
    assert len(chamber._pings) == 1
    assert wait_for(qapplication, lambda: not chamber._pings and not chamber._fx.isActive(), 5)


def test_the_chamber_makes_room_on_a_short_window(window, qapplication):
    window.show()
    window.lens.fit(700)
    assert not window.lens.chamber.isVisible()
    window.lens.fit(1000)
    assert window.lens.chamber.isVisible() and window.lens.chamber.height() == 280


def test_dragging_a_file_in_shows_rings_at_the_pointer(window, qapplication):
    from PySide6.QtCore import QPointF

    window.show()
    window.lens.set_armed(True)
    overlay = window.drop_overlay
    assert overlay.isVisible() and overlay._timer.isActive()
    overlay.follow(QPointF(100, 120))
    assert overlay.point == QPointF(100, 120)
    window.lens.set_armed(False)
    assert not overlay.isVisible() and not overlay._timer.isActive()  # nothing runs once the drag is over
