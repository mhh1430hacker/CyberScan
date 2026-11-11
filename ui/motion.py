"""Motion rules, in one place.

* Motion follows events: a click, a drop, a real stage report, a result.
  Nothing animates on a loop while the app is idle.
* Short and decelerating: 140 ms for feedback, 260 ms for a change of view,
  420 ms for the one emphasised moment (the verdict).
* Reduced motion (CYBERSCAN_REDUCE_MOTION=1 or Windows "Show animations"
  off) turns every transition into an immediate change.
"""
from __future__ import annotations

import ctypes
import os
import sys

from PySide6.QtCore import QAbstractAnimation, QEasingCurve, QPropertyAnimation, QTimer
from PySide6.QtWidgets import QGraphicsOpacityEffect, QWidget

FEEDBACK_MS = 140
VIEW_MS = 260
EMPHASIS_MS = 420
STAGGER_MS = 55


def prefers_reduced_motion() -> bool:
    override = os.environ.get("CYBERSCAN_REDUCE_MOTION", "").strip().lower()
    if override in {"1", "true", "yes"}:
        return True
    if override in {"0", "false", "no"}:
        return False
    if sys.platform == "win32":
        try:
            enabled = ctypes.c_bool(True)
            ok = ctypes.windll.user32.SystemParametersInfoW(0x1042, 0, ctypes.byref(enabled), 0)
            return bool(ok) and not enabled.value
        except (AttributeError, OSError):
            return False
    return False


def fade_in(widget: QWidget, duration: int = VIEW_MS, delay: int = 0) -> None:
    """Fade a widget in. The opacity effect is removed when done, so text
    renders crisply and no effect lingers on static content."""
    if prefers_reduced_motion():
        widget.setGraphicsEffect(None)
        return
    effect = QGraphicsOpacityEffect(widget)
    effect.setOpacity(0.0)
    widget.setGraphicsEffect(effect)
    animation = QPropertyAnimation(effect, b"opacity", widget)
    animation.setDuration(duration)
    animation.setStartValue(0.0)
    animation.setEndValue(1.0)
    animation.setEasingCurve(QEasingCurve.Type.OutCubic)

    def finish() -> None:
        if widget.graphicsEffect() is effect:
            widget.setGraphicsEffect(None)

    animation.finished.connect(finish)

    def start() -> None:
        if widget.graphicsEffect() is effect:
            animation.start(QAbstractAnimation.DeletionPolicy.DeleteWhenStopped)

    if delay:
        QTimer.singleShot(delay, start)
    else:
        start()
    # Safety net: never leave content invisible if the clock does not run.
    QTimer.singleShot(delay + duration + 120, finish)


def stagger(widgets: list[QWidget], duration: int = VIEW_MS) -> None:
    for index, widget in enumerate(widgets):
        fade_in(widget, duration, index * STAGGER_MS)
