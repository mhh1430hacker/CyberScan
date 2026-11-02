"""The passage from a scan result into Repair: one cinematic moment.

Painted over the whole window, about two seconds, skippable with a click
or any key, and an immediate change under reduced motion:

1. the result recedes: it dims and drifts back, as if the camera pulls away;
2. a sonar wave leaves the "Repair this file" button: three rings, teal
   turning to the repair indigo as they travel, sparks riding the front;
   inside the wave the window is already the Repair screen;
3. a title card passes through the middle: the mark, "Repair mode", the
   file's name and the promise that only a copy is touched;
4. the overlay lifts, and the Repair screen's cube runs its own sonar on
   the file (started by the caller when ``finished`` fires).

Both pictures are real grabs of the window (before and after the switch),
so nothing on screen is a mock-up.
"""
from __future__ import annotations

import math
import random
import time

from PySide6.QtCore import QPointF, QRectF, Qt, QTimer, Signal
from PySide6.QtGui import QColor, QFont, QLinearGradient, QPainter, QPainterPath, QPen, QPixmap, QRadialGradient
from PySide6.QtWidgets import QWidget

from ui import brand
from ui.motion import prefers_reduced_motion
from ui.theme import MODE_ACCENTS, TOKENS

DURATION = 2.15
FRAME_MS = 16


def _ease_in_out(t: float) -> float:
    t = min(1.0, max(0.0, t))
    return 4 * t * t * t if t < 0.5 else 1 - (-2 * t + 2) ** 3 / 2


def _ease_out(t: float) -> float:
    t = min(1.0, max(0.0, t))
    return 1 - (1 - t) ** 3


def _window(t: float, start: float, end: float) -> float:
    """0 before ``start``, 1 after ``end``, eased in between."""
    if end <= start:
        return 1.0 if t >= end else 0.0
    return _ease_in_out((t - start) / (end - start))


def _mix(a: QColor, b: QColor, amount: float) -> QColor:
    amount = min(1.0, max(0.0, amount))
    return QColor(
        round(a.red() + (b.red() - a.red()) * amount),
        round(a.green() + (b.green() - a.green()) * amount),
        round(a.blue() + (b.blue() - a.blue()) * amount),
    )


class RepairTransition(QWidget):
    finished = Signal()

    def __init__(self, parent: QWidget, before: QPixmap, after: QPixmap, origin: QPointF, title: str, name: str,
                 promise: str, language: str = "en"):
        super().__init__(parent)
        self.before, self.after = before, after
        self.origin = origin
        self.title, self.name, self.promise, self.language = title, name, promise, language
        self.progress = 0.0
        self.done = False
        self._started = time.monotonic()
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self.teal = QColor(TOKENS["accent"])
        self.indigo = QColor(MODE_ACCENTS["repair"]["accent"])
        rng = random.Random(7)
        # Sparks riding the wave front: angle, distance behind the front, size, speed.
        self.sparks = [(rng.uniform(0, math.tau), rng.uniform(-18, 26), rng.uniform(1.2, 3.4), rng.uniform(0.85, 1.15)) for _ in range(140)]
        self.setAttribute(Qt.WidgetAttribute.WA_OpaquePaintEvent, True)
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.setGeometry(parent.rect())
        self.setAccessibleName(title)

    # -- control --------------------------------------------------------------------------
    def play(self) -> None:
        self.show()
        self.raise_()
        self.setFocus()
        if prefers_reduced_motion():
            self.finish()
            return
        self._started = time.monotonic()
        self._timer.start(FRAME_MS)

    def finish(self) -> None:
        if self.done:
            return
        self.done = True
        self._timer.stop()
        self.hide()
        self.finished.emit()
        self.deleteLater()

    def _tick(self) -> None:
        self.progress = min(1.0, (time.monotonic() - self._started) / DURATION)
        self.update()
        if self.progress >= 1.0:
            self.finish()

    def mousePressEvent(self, event) -> None:  # noqa: N802
        self.finish()

    def keyPressEvent(self, event) -> None:  # noqa: N802
        self.finish()

    # -- picture -------------------------------------------------------------------------
    def _reach(self) -> float:
        w, h, x, y = self.width(), self.height(), self.origin.x(), self.origin.y()
        return max(math.hypot(x - cx, y - cy) for cx in (0, w) for cy in (0, h)) + 40

    def paintEvent(self, event) -> None:  # noqa: N802
        t = self.progress
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
        rect = QRectF(self.rect())
        painter.fillRect(rect, QColor("#04050a"))

        # 1. The result pulls away: smaller, darker.
        recede = _window(t, 0.0, 0.55)
        scale = 1.0 - 0.06 * recede
        painter.save()
        painter.translate(self.origin)
        painter.scale(scale, scale)
        painter.translate(-self.origin)
        painter.drawPixmap(rect, self.before, QRectF(self.before.rect()))
        painter.restore()
        painter.fillRect(rect, QColor(4, 5, 10, int(170 * recede)))

        # 2. The wave: the Repair screen inside it, rings on its edge.
        reach = self._reach()
        front = reach * _ease_in_out((t - 0.10) / 0.62)
        if front > 0:
            inside = QPainterPath()
            inside.addEllipse(self.origin, front, front)
            painter.save()
            painter.setClipPath(inside)
            settle = _window(t, 0.25, 0.85)
            zoom = 1.06 - 0.06 * settle  # the new screen arrives from slightly close, then settles
            painter.translate(self.origin)
            painter.scale(zoom, zoom)
            painter.translate(-self.origin)
            painter.drawPixmap(rect, self.after, QRectF(self.after.rect()))
            painter.restore()
            # The inside glows faintly just behind the front.
            glow = QRadialGradient(self.origin, max(1.0, front))
            edge = QColor(self.indigo)
            edge.setAlpha(int(70 * (1 - _window(t, 0.7, 0.95))))
            clear = QColor(self.indigo)
            clear.setAlpha(0)
            glow.setColorAt(0.0, clear)
            glow.setColorAt(0.82, clear)
            glow.setColorAt(1.0, edge)
            painter.save()
            painter.setClipPath(inside)
            painter.fillRect(rect, glow)
            painter.restore()
        for index, lag in enumerate((0.0, 0.06, 0.12)):
            radius = reach * _ease_in_out((t - 0.10 - lag) / 0.62)
            if radius <= 0:
                continue
            fade = 1.0 - _window(t, 0.62 + lag, 0.86 + lag)
            if fade <= 0:
                continue
            color = _mix(self.teal, self.indigo, radius / reach)
            for width, alpha in ((14 - 4 * index, 40), (3 - 0.8 * index, 230)):
                stroke = QColor(color)
                stroke.setAlpha(int(alpha * fade * (1 - 0.25 * index)))
                painter.setPen(QPen(stroke, max(1.0, width)))
                painter.setBrush(Qt.BrushStyle.NoBrush)
                painter.drawEllipse(self.origin, radius, radius)
        if front > 0:
            spark_fade = 1.0 - _window(t, 0.55, 0.8)
            painter.setPen(Qt.PenStyle.NoPen)
            for angle, behind, size, speed in self.sparks:
                distance = front * speed - behind
                if distance <= 0:
                    continue
                spot = QPointF(self.origin.x() + math.cos(angle) * distance, self.origin.y() + math.sin(angle) * distance)
                if not rect.adjusted(-10, -10, 10, 10).contains(spot):
                    continue
                color = _mix(self.teal, QColor("#ffffff"), 0.35) if behind < 0 else _mix(self.indigo, QColor("#ffffff"), 0.4)
                color.setAlpha(int(220 * spark_fade))
                painter.setBrush(color)
                painter.drawEllipse(spot, size, size)

        # 3. The title card passes through.
        card_in, card_out = _window(t, 0.42, 0.6), _window(t, 0.82, 0.97)
        presence = card_in * (1 - card_out)
        if presence > 0.01:
            self._title_card(painter, rect, presence, t)

        # 4. The overlay lifts away at the very end.
        lift = _window(t, 0.9, 1.0)
        if lift > 0:
            painter.setOpacity(lift)
            painter.drawPixmap(rect, self.after, QRectF(self.after.rect()))
        painter.end()

    def _title_card(self, painter: QPainter, rect: QRectF, presence: float, t: float) -> None:
        painter.save()
        # The whole frame dims while the card passes; the band itself is nearly opaque, with soft edges.
        painter.fillRect(rect, QColor(4, 5, 10, int(120 * presence)))
        band = QRectF(0, rect.center().y() - 110, rect.width(), 220)
        shade = QLinearGradient(band.topLeft(), band.bottomLeft())
        for stop, alpha in ((0.0, 0.0), (0.12, 0.96), (0.88, 0.96), (1.0, 0.0)):
            shade.setColorAt(stop, QColor(4, 5, 10, int(255 * alpha * presence)))
        painter.fillRect(band.adjusted(0, -30, 0, 30), shade)
        line = QColor(self.indigo)
        line.setAlpha(int(200 * presence))
        sweep = _ease_out((t - 0.42) / 0.3)
        half = rect.width() * 0.5 * sweep
        painter.setPen(QPen(line, 1.2))
        for y in (band.top(), band.bottom()):
            painter.drawLine(QPointF(rect.center().x() - half, y), QPointF(rect.center().x() + half, y))
        painter.setOpacity(presence)
        mark = QRectF(0, 0, 64, 64)
        mark.moveCenter(QPointF(rect.center().x(), band.top() + 50))
        brand.paint_mark(painter, mark, MODE_ACCENTS["repair"]["accent"])
        rise = 14 * (1 - _ease_out((t - 0.42) / 0.25))
        title_font = QFont(brand.family(self.language), 30, QFont.Weight.DemiBold)
        title_font.setLetterSpacing(QFont.SpacingType.PercentageSpacing, 100 + 30 * (1 - sweep))
        painter.setFont(title_font)
        painter.setPen(QColor("#f1efff"))
        painter.drawText(QRectF(0, band.top() + 84 + rise, rect.width(), 50), Qt.AlignmentFlag.AlignCenter, self.title)
        painter.setFont(QFont("Segoe UI", 13))
        painter.setPen(QColor("#b9b2e6"))
        painter.drawText(QRectF(40, band.top() + 138 + rise, rect.width() - 80, 26), Qt.AlignmentFlag.AlignCenter,
                         painter.fontMetrics().elidedText(self.name, Qt.TextElideMode.ElideMiddle, int(rect.width() - 120)))
        painter.setPen(QColor("#8b84b8"))
        painter.drawText(QRectF(40, band.top() + 166 + rise, rect.width() - 80, 26), Qt.AlignmentFlag.AlignCenter, self.promise)
        painter.restore()
