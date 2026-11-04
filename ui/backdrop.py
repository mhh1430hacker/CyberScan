"""The window's living background: slow aurora light behind frosted panels.

Four soft light fields drift on long, unrelated loops, so the picture never
visibly repeats. One of them takes the current target's kind hue, so the
whole window leans toward the colour of what is being looked at.

Cost is kept small on purpose:
* the light is painted into an image at 1/6 of the window size and scaled up
  smoothly (soft light loses nothing at low resolution);
* it advances 10 times a second, and only while CyberScan is the active
  window and in use: not when another app has focus, the window is hidden or
  minimised, nobody has touched it for 10 seconds (it rests, and wakes on
  the next pointer move or key), reduced motion is on, or the user turns it off;
* turned off, it is one still frame.
"""
from __future__ import annotations

import math
import time

from PySide6.QtCore import QEvent, QPointF, QRectF, Qt, QTimer
from PySide6.QtGui import QColor, QImage, QLinearGradient, QPainter, QRadialGradient
from PySide6.QtWidgets import QWidget

from ui.motion import prefers_reduced_motion
from ui.theme import TOKENS, alpha, mix

SCALE = 6
FRAME_MS = 100  # 10 frames a second: the drift is slow, so this is enough
IDLE_SECONDS = 10.0  # every frame repaints the window above it, so it rests when nobody is there

# (colour, radius as share of the long side, x loop seconds, y loop seconds, phase)
_SCAN_FIELDS = [
    ("#1b5f5a", 0.55, 97.0, 71.0, 0.0),
    ("#26357a", 0.60, 83.0, 113.0, 1.7),
    ("#4a2a6a", 0.48, 127.0, 89.0, 3.1),
    (None, 0.45, 109.0, 79.0, 4.4),  # the kind hue
]

# Repair mode: the same slow light, in indigo and rose.
_REPAIR_FIELDS = [
    ("#3a2f8a", 0.55, 97.0, 71.0, 0.0),
    ("#5a2a6a", 0.60, 83.0, 113.0, 1.7),
    ("#26357a", 0.48, 127.0, 89.0, 3.1),
    (None, 0.45, 109.0, 79.0, 4.4),
]
PALETTES = {"scan": _SCAN_FIELDS, "repair": _REPAIR_FIELDS}


class Backdrop(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("root")
        self.setAttribute(Qt.WidgetAttribute.WA_OpaquePaintEvent)
        self._hue = QColor(TOKENS["accent"])
        self._target_hue = QColor(self._hue)
        self._enabled = True
        self._fields = PALETTES["scan"]
        self._start = time.monotonic()
        self._frozen_at = 0.0
        self._image: QImage | None = None
        self._timer = QTimer(self)
        self._timer.setInterval(FRAME_MS)
        self._timer.timeout.connect(self.update)
        self.frames = 0
        self._last_input = time.monotonic()
        self._resting = False

    # -- control -------------------------------------------------------------
    @property
    def animating(self) -> bool:
        return self._timer.isActive()

    def set_enabled(self, enabled: bool) -> None:
        self._enabled = enabled
        self._sync()
        self.update()

    def wake(self) -> None:
        """Someone is using the window (a pointer move, a key): drift again."""
        self._last_input = time.monotonic()
        if self._resting:
            self._resting = False
            self._sync()

    def set_palette(self, mode: str) -> None:
        self._fields = PALETTES.get(mode, PALETTES["scan"])
        self.update()

    def set_hue(self, color: str) -> None:
        self._target_hue = QColor(color)
        if not self.animating:
            self._hue = QColor(color)
            self.update()

    def _should_run(self) -> bool:
        window = self.window()
        return (
            self._enabled
            and not self._resting
            and not prefers_reduced_motion()
            and self.isVisible()
            and not window.isMinimized()
            and window.isActiveWindow()
        )

    def _sync(self) -> None:
        if self._should_run():
            if not self._timer.isActive():
                self._start = time.monotonic() - self._frozen_at
                self._timer.start()
        elif self._timer.isActive():
            self._frozen_at = time.monotonic() - self._start
            self._timer.stop()

    def showEvent(self, event) -> None:  # noqa: N802
        super().showEvent(event)
        self.window().installEventFilter(self)
        # Appearing counts as activity: building the window can itself take longer than the rest delay.
        self._last_input = time.monotonic()
        self._resting = False
        self._sync()

    def hideEvent(self, event) -> None:  # noqa: N802
        self._sync()
        super().hideEvent(event)

    def eventFilter(self, watched, event) -> bool:  # noqa: N802
        if watched is self.window() and event.type() in (
            QEvent.Type.WindowStateChange,
            QEvent.Type.Hide,
            QEvent.Type.Show,
            QEvent.Type.WindowActivate,
            QEvent.Type.WindowDeactivate,
        ):
            QTimer.singleShot(0, self._sync)
        return False

    def stop(self) -> None:
        self._enabled = False
        self._timer.stop()

    # -- painting --------------------------------------------------------------
    def _elapsed(self) -> float:
        return (time.monotonic() - self._start) if self._timer.isActive() else self._frozen_at

    def _render(self, width: int, height: int, now: float) -> QImage:
        if self._image is None or self._image.width() != width or self._image.height() != height:
            self._image = QImage(width, height, QImage.Format.Format_RGB32)
        image = self._image
        image.fill(QColor(TOKENS["bg"]))
        painter = QPainter(image)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setCompositionMode(QPainter.CompositionMode.CompositionMode_Plus)
        side = max(width, height)
        for color, radius_share, period_x, period_y, phase in self._fields:
            base = QColor(color) if color else self._hue
            x = width * (0.5 + 0.42 * math.sin(2 * math.pi * now / period_x + phase))
            # Light stays mostly in the upper half, like a hero glow.
            y = height * (0.22 + 0.22 * math.cos(2 * math.pi * now / period_y + phase * 0.7))
            radius = side * radius_share * (0.92 + 0.08 * math.sin(now / 13.0 + phase))
            glow = QRadialGradient(QPointF(x, y), radius)
            glow.setColorAt(0.0, alpha(base, 0.20 if color else 0.16))
            glow.setColorAt(0.55, alpha(base, 0.05))
            glow.setColorAt(1.0, alpha(base, 0.0))
            painter.fillRect(QRectF(0, 0, width, height), glow)
        painter.setCompositionMode(QPainter.CompositionMode.CompositionMode_SourceOver)
        vignette = QLinearGradient(0, 0, 0, height)
        vignette.setColorAt(0.0, alpha(TOKENS["bg"], 0.0))
        vignette.setColorAt(1.0, alpha(TOKENS["bg"], 0.85))
        painter.fillRect(QRectF(0, 0, width, height), vignette)
        painter.end()
        return image

    def paintEvent(self, event) -> None:  # noqa: N802
        now = self._elapsed()
        if self._hue != self._target_hue:
            self._hue = mix(self._hue, self._target_hue, 0.08)
            if abs(self._hue.red() - self._target_hue.red()) + abs(self._hue.green() - self._target_hue.green()) + abs(self._hue.blue() - self._target_hue.blue()) < 6:
                self._hue = QColor(self._target_hue)
        width = max(8, self.width() // SCALE)
        height = max(8, self.height() // SCALE)
        image = self._render(width, height, now)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
        painter.drawImage(QRectF(self.rect()), image)
        self.frames += 1
        if self._timer.isActive() and time.monotonic() - self._last_input > IDLE_SECONDS:
            self._resting = True
            QTimer.singleShot(0, self._sync)
