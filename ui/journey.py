"""The scan journey: the target travels through the four real pipeline stages.

Everything that moves here is caused by a real event:

* ``start`` when the user starts a scan;
* ``set_stage_states`` when the scan worker reports a stage;
* ``conclude`` / ``fail`` / ``cancel`` when the worker finishes.

Between events, only two things move, and only while a stage is running: a
ring turns around the running station and a scan line sweeps the target tile.
Both say "working", at a fixed speed, and encode no progress or percentage.
A connector fills when the stage before it completes, never on a timer.

The conclusion depends on nothing but the verdict: the tile takes the
verdict's colour and symbol in one short movement, then ``concluded`` fires.
Hidden widgets and reduced motion skip straight to the end state.
"""
from __future__ import annotations

import time

from PySide6.QtCore import QEasingCurve, QPointF, QRectF, QSize, Qt, QTimer, QVariantAnimation, Signal
from PySide6.QtGui import QColor, QFont, QFontMetrics, QLinearGradient, QPainter, QPainterPath, QPen, QRadialGradient
from PySide6.QtWidgets import QSizePolicy, QWidget

from ui.file_kind import KINDS, FileKind
from ui.icons import glyph, icon_font
from ui.motion import EMPHASIS_MS, prefers_reduced_motion
from ui.theme import DISPLAY_FONT, TOKENS, alpha, mix

STAGE_COUNT = 4
STAGE_ICONS = ("search", "pulse", "layers", "globe")
_VALID_STATES = {"waiting", "running", "complete", "failed"}


class JourneyScene(QWidget):
    concluded = Signal()

    FRAME_MS = 33
    CONNECT_MS = 320

    def __init__(self, parent=None, *, reduced_motion: bool | None = None):
        super().__init__(parent)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.setFixedHeight(300)
        self.reduced_motion = prefers_reduced_motion() if reduced_motion is None else reduced_motion
        self.phase = "idle"
        self.kind: FileKind = KINDS["file"]
        self.target_name = ""
        self.target_type = ""
        self.stage_titles = ["Reading", "Patterns", "Structure", "Lookups"]
        self.stage_states = ["waiting"] * STAGE_COUNT
        self.verdict_symbol = ""
        self.verdict_color = QColor(TOKENS["neutral"])
        self.status_word = ""
        self._links = [0.0] * (STAGE_COUNT - 1)
        self._link_animations: list[QVariantAnimation | None] = [None] * (STAGE_COUNT - 1)
        self._morph = 0.0
        self._spin = 0.0
        self._sweep = 0.0
        self._last_tick = time.monotonic()
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._morph_animation = QVariantAnimation(self)
        self._morph_animation.setDuration(EMPHASIS_MS)
        self._morph_animation.setStartValue(0.0)
        self._morph_animation.setEndValue(1.0)
        self._morph_animation.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._morph_animation.valueChanged.connect(self._on_morph)
        self._morph_animation.finished.connect(self._finish_conclusion)
        self.setAccessibleName("Scan journey")
        self._describe()

    # -- public API (called from real scan events) -------------------------
    def set_stage_titles(self, titles: list[str]) -> None:
        self.stage_titles = list(titles)[:STAGE_COUNT]
        self.update()

    def start(self, name: str, kind: FileKind, type_line: str) -> None:
        self._stop_animations()
        self.target_name = name
        self.kind = kind
        self.target_type = type_line
        self.stage_states = ["waiting"] * STAGE_COUNT
        self._links = [0.0] * (STAGE_COUNT - 1)
        self._morph = 0.0
        self.verdict_symbol = ""
        self.status_word = ""
        self.phase = "analyzing"
        self._sync_timer()
        self._describe()
        self.update()

    def set_stage_states(self, states) -> None:
        if self.phase != "analyzing":
            return
        clean = [state if state in _VALID_STATES else "waiting" for state in list(states)[:STAGE_COUNT]]
        clean += ["waiting"] * (STAGE_COUNT - len(clean))
        for index in range(STAGE_COUNT - 1):
            if clean[index] == "complete" and self.stage_states[index] != "complete":
                self._fill_link(index)
        self.stage_states = clean
        self._sync_timer()
        self._describe()
        self.update()

    def conclude(self, symbol: str, color: str) -> None:
        for index in range(STAGE_COUNT - 1):
            self._fill_link(index, animate=False)
        self.stage_states = ["complete"] * STAGE_COUNT
        self.verdict_symbol = symbol
        self.verdict_color = QColor(color)
        self.phase = "concluding"
        self._timer.stop()
        if self.reduced_motion or not self.isVisible():
            self._morph = 1.0
            self._finish_conclusion()
            return
        self._morph_animation.stop()
        self._morph_animation.start()

    def fail(self, word: str) -> None:
        self._stop_animations()
        self.phase = "failed"
        self.status_word = word
        if "running" in self.stage_states:
            self.stage_states = ["failed" if state == "running" else state for state in self.stage_states]
        else:
            # The worker failed before reporting the next stage: mark that one.
            for index, state in enumerate(self.stage_states):
                if state == "waiting":
                    self.stage_states[index] = "failed"
                    break
        self._describe()
        self.update()

    def cancel(self, word: str) -> None:
        self._stop_animations()
        self.phase = "cancelled"
        self.status_word = word
        self.stage_states = ["waiting" if state == "running" else state for state in self.stage_states]
        self._describe()
        self.update()

    def reset(self) -> None:
        self._stop_animations()
        self.phase = "idle"
        self.stage_states = ["waiting"] * STAGE_COUNT
        self._links = [0.0] * (STAGE_COUNT - 1)
        self._morph = 0.0
        self.verdict_symbol = ""
        self.status_word = ""
        self._describe()
        self.update()

    def stop(self) -> None:
        self._stop_animations()

    @property
    def animating(self) -> bool:
        return (
            self._timer.isActive()
            or self._morph_animation.state() == QVariantAnimation.State.Running
            or any(a is not None and a.state() == QVariantAnimation.State.Running for a in self._link_animations)
        )

    # -- internals -----------------------------------------------------------
    def _stop_animations(self) -> None:
        self._timer.stop()
        self._morph_animation.stop()
        for index, animation in enumerate(self._link_animations):
            if animation is not None:
                animation.stop()
                self._links[index] = 1.0 if self._links[index] > 0 else 0.0

    def _fill_link(self, index: int, *, animate: bool = True) -> None:
        if self._links[index] >= 1.0:
            return
        if not animate or self.reduced_motion or not self.isVisible():
            self._links[index] = 1.0
            return
        animation = QVariantAnimation(self)
        animation.setDuration(self.CONNECT_MS)
        animation.setStartValue(self._links[index])
        animation.setEndValue(1.0)
        animation.setEasingCurve(QEasingCurve.Type.OutCubic)

        def advance(value, slot=index) -> None:
            self._links[slot] = float(value)
            self.update()

        animation.valueChanged.connect(advance)
        self._link_animations[index] = animation
        animation.start()

    def _on_morph(self, value) -> None:
        self._morph = float(value)
        self.update()

    def _finish_conclusion(self) -> None:
        if self.phase != "concluding":
            return
        self._morph = 1.0
        self.phase = "concluded"
        self._describe()
        self.update()
        self.concluded.emit()

    def _needs_timer(self) -> bool:
        return (
            not self.reduced_motion
            and self.isVisible()
            and self.phase == "analyzing"
            and "running" in self.stage_states
        )

    def _sync_timer(self) -> None:
        if self._needs_timer():
            if not self._timer.isActive():
                self._last_tick = time.monotonic()
                self._timer.start(self.FRAME_MS)
        else:
            self._timer.stop()

    def _tick(self) -> None:
        now = time.monotonic()
        dt = min(0.1, now - self._last_tick)
        self._last_tick = now
        self._spin = (self._spin + dt * 160.0) % 360.0
        self._sweep = (self._sweep + dt * 0.55) % 1.0
        if not self._needs_timer():
            self._timer.stop()
        self.update()

    def _describe(self) -> None:
        done = self.stage_states.count("complete")
        self.setAccessibleDescription(f"{self.phase}; {done}/{STAGE_COUNT}")

    def showEvent(self, event) -> None:  # noqa: N802
        super().showEvent(event)
        self._sync_timer()

    def hideEvent(self, event) -> None:  # noqa: N802
        self._timer.stop()
        if self.phase == "concluding":
            self._morph_animation.stop()
            self._finish_conclusion()
        super().hideEvent(event)

    def sizeHint(self) -> QSize:  # noqa: N802
        return QSize(760, 300)

    # -- painting --------------------------------------------------------------
    def _station_centers(self) -> list[QPointF]:
        margin = max(60.0, self.width() * 0.12)
        span = self.width() - margin * 2
        y = 214.0
        xs = [margin + span * index / (STAGE_COUNT - 1) for index in range(STAGE_COUNT)]
        if self.layoutDirection() == Qt.LayoutDirection.RightToLeft:
            xs.reverse()
        return [QPointF(x, y) for x in xs]

    def paintEvent(self, event) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setRenderHint(QPainter.RenderHint.TextAntialiasing)
        hue = QColor(self.kind.hue)
        centers = self._station_centers()
        self._paint_links(painter, centers, hue)
        for index, center in enumerate(centers):
            self._paint_station(painter, index, center, hue)
        self._paint_tile(painter, hue)

    def _paint_tile(self, painter: QPainter, hue: QColor) -> None:
        size = 96.0
        center = QPointF(self.width() / 2, 70)
        rect = QRectF(center.x() - size / 2, center.y() - size / 2, size, size)
        color = mix(hue, self.verdict_color, self._morph) if self.verdict_symbol else hue
        glow = QRadialGradient(center, size * 1.25)
        glow.setColorAt(0.0, alpha(color, 0.22 + 0.14 * self._morph))
        glow.setColorAt(1.0, alpha(color, 0.0))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(glow)
        painter.drawEllipse(center, size * 1.25, size * 1.25)
        radius = size * (0.28 + 0.22 * self._morph)  # rounded square -> circle
        gradient = QLinearGradient(rect.topLeft(), rect.bottomRight())
        gradient.setColorAt(0, mix(TOKENS["surface_2"], color, 0.30))
        gradient.setColorAt(1, mix(TOKENS["surface"], color, 0.10))
        painter.setBrush(gradient)
        painter.setPen(QPen(alpha(color, 0.75), 1.6))
        painter.drawRoundedRect(rect, radius, radius)
        if self.phase == "analyzing" and "running" in self.stage_states and not self.reduced_motion:
            path = QPainterPath()
            path.addRoundedRect(rect, radius, radius)
            painter.save()
            painter.setClipPath(path)
            y = rect.top() + rect.height() * self._sweep
            beam = QLinearGradient(0, y - 18, 0, y + 2)
            beam.setColorAt(0.0, alpha(color, 0.0))
            beam.setColorAt(1.0, alpha(color, 0.55))
            painter.fillRect(QRectF(rect.left(), y - 18, rect.width(), 20), beam)
            painter.restore()
        painter.setPen(color)
        if self.verdict_symbol and self._morph > 0.5:
            font = QFont(DISPLAY_FONT)
            font.setPixelSize(44)
            font.setWeight(QFont.Weight.Bold)
            painter.setFont(font)
            painter.drawText(rect, int(Qt.AlignmentFlag.AlignCenter), self.verdict_symbol)
        else:
            painter.setFont(icon_font(40))
            painter.drawText(rect, int(Qt.AlignmentFlag.AlignCenter), glyph(self.kind.icon))
        name_font = QFont(self.font())
        name_font.setPixelSize(15)
        name_font.setWeight(QFont.Weight.DemiBold)
        painter.setFont(name_font)
        painter.setPen(QColor(TOKENS["text"]))
        metrics = QFontMetrics(name_font)
        name = metrics.elidedText(self.target_name, Qt.TextElideMode.ElideMiddle, int(self.width() * 0.7))
        painter.drawText(QRectF(0, rect.bottom() + 10, self.width(), 22), int(Qt.AlignmentFlag.AlignHCenter), name)
        type_font = QFont(self.font())
        type_font.setPixelSize(12)
        painter.setFont(type_font)
        painter.setPen(QColor(TOKENS["text_mute"]))
        painter.drawText(
            QRectF(0, rect.bottom() + 32, self.width(), 18), int(Qt.AlignmentFlag.AlignHCenter), self.target_type
        )

    def _paint_links(self, painter: QPainter, centers: list[QPointF], hue: QColor) -> None:
        radius = 23.0
        for index in range(STAGE_COUNT - 1):
            start, end = centers[index], centers[index + 1]
            direction = 1 if end.x() > start.x() else -1
            a = QPointF(start.x() + direction * (radius + 6), start.y())
            b = QPointF(end.x() - direction * (radius + 6), end.y())
            painter.setPen(QPen(QColor(TOKENS["line_strong"]), 2, Qt.PenStyle.DashLine, Qt.PenCapStyle.RoundCap))
            painter.drawLine(a, b)
            fill = self._links[index]
            if fill > 0:
                tip = QPointF(a.x() + (b.x() - a.x()) * fill, a.y())
                painter.setPen(QPen(hue, 2.4, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
                painter.drawLine(a, tip)

    def _paint_station(self, painter: QPainter, index: int, center: QPointF, hue: QColor) -> None:
        state = self.stage_states[index]
        radius = 23.0
        danger = QColor(TOKENS["danger"])
        if state == "running":
            glow = QRadialGradient(center, radius * 2.2)
            glow.setColorAt(0.0, alpha(hue, 0.30))
            glow.setColorAt(1.0, alpha(hue, 0.0))
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(glow)
            painter.drawEllipse(center, radius * 2.2, radius * 2.2)
        fill = {
            "complete": mix(TOKENS["surface"], hue, 0.24),
            "failed": mix(TOKENS["surface"], danger, 0.20),
        }.get(state, QColor(TOKENS["surface_2"]))
        ring = {"complete": hue, "running": hue, "failed": danger}.get(state, QColor(TOKENS["line_strong"]))
        painter.setBrush(fill)
        painter.setPen(QPen(ring, 2 if state != "waiting" else 1.4))
        painter.drawEllipse(center, radius, radius)
        if state == "running" and not self.reduced_motion:
            arc = QRectF(center.x() - radius - 6, center.y() - radius - 6, (radius + 6) * 2, (radius + 6) * 2)
            painter.setPen(QPen(hue, 2.4, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawArc(arc, int(-self._spin * 16), 100 * 16)
        icon = {"complete": "check", "failed": "close"}.get(state, STAGE_ICONS[index])
        painter.setFont(icon_font(18))
        painter.setPen(ring if state != "waiting" else QColor(TOKENS["text_mute"]))
        painter.drawText(
            QRectF(center.x() - radius, center.y() - radius, radius * 2, radius * 2),
            int(Qt.AlignmentFlag.AlignCenter),
            glyph(icon),
        )
        font = QFont(self.font())
        font.setPixelSize(13)
        font.setWeight(QFont.Weight.DemiBold if state in {"running", "complete"} else QFont.Weight.Normal)
        painter.setFont(font)
        painter.setPen(QColor(TOKENS["text"] if state in {"running", "complete"} else TOKENS["text_mute"]))
        title = self.stage_titles[index] if index < len(self.stage_titles) else ""
        painter.drawText(
            QRectF(center.x() - 80, center.y() + radius + 10, 160, 20),
            int(Qt.AlignmentFlag.AlignHCenter),
            title,
        )
