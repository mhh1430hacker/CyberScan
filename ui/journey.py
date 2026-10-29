"""The scan journey: one scene where the target travels through the real stages.

Presentation only. Every state change in the scene is driven by an event from
the scan worker (stage running/complete/failed, result, failure, cancel):

* ``entering``  - the target card hands an abstract, decorative packet to the
  pipeline. The packet is a visual token, not a picture of the file's bytes.
* ``analyzing`` - the packet waits at the station of the stage the engine
  reports as running and moves on only when that stage reports complete. The
  ring around a running station turns at a fixed speed; it encodes no ratio.
* ``evidence``  - one marker per real finding (capped for drawing; the label
  always states the true count) leaves the last station, strongest first.
* ``concluded`` - the verdict node takes the verdict colour; the scene then
  settles into a compact recap of the stages.
* ``failed`` / ``cancelled`` - the run stops where it stopped.

Motion pauses while hidden and is skipped under reduced motion; every state
also has a complete static rendering.
"""
from __future__ import annotations

import math
import time
from dataclasses import dataclass

from PySide6.QtCore import QPointF, QRectF, QSize, Qt, QTimer, Signal
from PySide6.QtGui import (
    QColor,
    QFont,
    QFontMetrics,
    QLinearGradient,
    QPainter,
    QPainterPath,
    QPen,
    QRadialGradient,
)
from PySide6.QtWidgets import QSizePolicy, QWidget

from ui.design_system import TOKENS
from ui.home import ICON_FONT, glyph, icon_font_available, prefers_reduced_motion

STAGE_COUNT = 4
MAX_MARKERS = 12


@dataclass
class Marker:
    color: QColor
    symbol: str
    born: float


def _ease(t: float) -> float:
    t = max(0.0, min(1.0, t))
    return 1 - (1 - t) ** 3


class JourneyScene(QWidget):
    concluded = Signal()

    FULL_HEIGHT = 330
    COMPACT_HEIGHT = 150
    FRAME = 16
    ENTER_SECONDS = 0.75
    MARKER_GAP = 0.09
    CONCLUDE_DELAY = 0.45

    def __init__(self, parent=None, *, reduced_motion: bool | None = None):
        super().__init__(parent)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.setFixedHeight(self.FULL_HEIGHT)
        self.reduced_motion = prefers_reduced_motion() if reduced_motion is None else reduced_motion
        self.phase = "idle"
        self.stage_titles = ["Static evidence", "Entropy", "Projection", "Intelligence"]
        self.stage_states = ["waiting"] * STAGE_COUNT
        self.target_name = ""
        self.target_kind = "file"
        self.target_type = ""
        self.markers: list[Marker] = []
        self.finding_total = 0
        self.evidence_label = ""
        self.verdict_title = ""
        self.verdict_symbol = "?"
        self.verdict_color = QColor(TOKENS["text_mute"])
        self.status_word = ""
        self._verdict_ready = False
        self.compact = False
        self._height = float(self.FULL_HEIGHT)
        self._packet_x: float | None = None
        self._phase_started = time.monotonic()
        self._now = time.monotonic()
        self._spin = 0.0
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self.setAccessibleName("Analysis journey")

    # -- public API (called from real scan events) -----------------------
    def set_stage_titles(self, titles: list[str]) -> None:
        self.stage_titles = list(titles)[:STAGE_COUNT]
        self.update()

    def start(self, name: str, kind: str, type_label: str) -> None:
        self.phase = "entering"
        self.target_name = name
        self.target_kind = kind
        self.target_type = type_label
        self.stage_states = ["waiting"] * STAGE_COUNT
        self.markers = []
        self.finding_total = 0
        self.evidence_label = ""
        self.verdict_title = ""
        self.verdict_symbol = "?"
        self.verdict_color = QColor(TOKENS["text_mute"])
        self._packet_x = None
        self._verdict_ready = False
        self._set_compact(False, animate=False)
        if self.reduced_motion:
            self.phase = "analyzing"
        self._begin_phase()

    def set_stage_states(self, states) -> None:
        values = [s if s in {"waiting", "running", "complete", "failed"} else "waiting" for s in list(states)[:STAGE_COUNT]]
        self.stage_states = values + ["waiting"] * (STAGE_COUNT - len(values))
        if self.phase == "idle":
            self.phase = "analyzing"
        elif self.phase == "entering" and (self.reduced_motion or self._elapsed() >= self.ENTER_SECONDS):
            self.phase = "analyzing"
        self._describe()
        self._sync_timer()
        self.update()

    def show_evidence(self, markers: list[tuple[str, str]], total: int, label: str) -> None:
        """markers: (colour, symbol) per finding, strongest first; total is the real count."""
        self.stage_states = ["complete"] * STAGE_COUNT
        self.phase = "evidence"
        self.finding_total = int(total)
        self.evidence_label = label
        start = time.monotonic()
        self.markers = [
            Marker(QColor(color), symbol, start + index * self.MARKER_GAP)
            for index, (color, symbol) in enumerate(markers[:MAX_MARKERS])
        ]
        self._begin_phase()

    def conclude(self, title: str, symbol: str, color: str) -> None:
        self.verdict_title = title
        self.verdict_symbol = symbol
        self.verdict_color = QColor(color)
        self._verdict_ready = True
        if self.reduced_motion or not self.isVisible():
            self._finish_conclusion()
        elif self.phase != "evidence":
            # Markers (if any) settle first; the tick moves on from there.
            self.phase = "concluding"
            self._begin_phase()

    def fail(self, word: str) -> None:
        self.phase = "failed"
        self.status_word = word
        self.stage_states = ["failed" if s == "running" else s for s in self.stage_states]
        if "failed" not in self.stage_states:
            index = next((i for i, s in enumerate(self.stage_states) if s != "complete"), STAGE_COUNT - 1)
            self.stage_states[index] = "failed"
        self.verdict_color = QColor(TOKENS["danger"])
        self.verdict_symbol = "✕"
        self.verdict_title = word
        self._end_motion()

    def cancel(self, word: str) -> None:
        self.phase = "cancelled"
        self.status_word = word
        self.stage_states = ["waiting" if s == "running" else s for s in self.stage_states]
        self.verdict_color = QColor(TOKENS["text_mute"])
        self.verdict_symbol = "–"
        self.verdict_title = word
        self._end_motion()

    def reset(self) -> None:
        self.phase = "idle"
        self._end_motion()
        self._set_compact(False, animate=False)

    def stop(self) -> None:
        self._timer.stop()

    @property
    def animating(self) -> bool:
        return self._timer.isActive()

    # -- internals ---------------------------------------------------------
    def _elapsed(self) -> float:
        return time.monotonic() - self._phase_started

    def _begin_phase(self) -> None:
        self._phase_started = time.monotonic()
        self._describe()
        self._sync_timer()
        self.update()

    def _end_motion(self) -> None:
        self._describe()
        self._timer.stop()
        self.update()

    def _finish_conclusion(self) -> None:
        self.phase = "concluded"
        for marker in self.markers:
            marker.born = 0.0
        self._set_compact(True, animate=not self.reduced_motion)
        self._describe()
        self.update()
        self.concluded.emit()

    def _set_compact(self, compact: bool, *, animate: bool) -> None:
        self.compact = compact
        target = self.COMPACT_HEIGHT if compact else self.FULL_HEIGHT
        if not animate:
            self._height = float(target)
            self.setFixedHeight(target)
        self._sync_timer()

    def _describe(self) -> None:
        done = self.stage_states.count("complete")
        self.setAccessibleDescription(f"{self.phase}; {done} of {STAGE_COUNT} stages complete")

    def _needs_motion(self) -> bool:
        if self.reduced_motion or not self.isVisible():
            return False
        if self.phase in {"entering", "analyzing", "evidence", "concluding"}:
            return True
        target = self.COMPACT_HEIGHT if self.compact else self.FULL_HEIGHT
        return abs(self._height - target) > 0.5

    def _sync_timer(self) -> None:
        if self._needs_motion():
            if not self._timer.isActive():
                self._now = time.monotonic()
                self._timer.start(self.FRAME)
        else:
            self._timer.stop()
            target = self.COMPACT_HEIGHT if self.compact else self.FULL_HEIGHT
            if self._height != target:
                self._height = float(target)
                self.setFixedHeight(target)

    def _tick(self) -> None:
        now = time.monotonic()
        dt = min(0.1, now - self._now)
        self._now = now
        self._spin = (self._spin + dt * 90.0) % 360.0
        if self.phase == "entering" and self._elapsed() >= self.ENTER_SECONDS:
            self.phase = "analyzing"
        if self.phase == "evidence" and self._verdict_ready:
            last = self.markers[-1].born if self.markers else now
            if now >= last + 0.55:
                self.phase = "concluding"
                self._phase_started = now
        if self.phase == "concluding" and self._elapsed() >= self.CONCLUDE_DELAY:
            self._finish_conclusion()
        target = self.COMPACT_HEIGHT if self.compact else self.FULL_HEIGHT
        if abs(self._height - target) > 0.5:
            self._height += (target - self._height) * min(1.0, dt * 9.0)
            self.setFixedHeight(int(round(self._height)))
        if not self._needs_motion():
            self._sync_timer()
        self.update()

    def showEvent(self, event) -> None:  # noqa: N802
        super().showEvent(event)
        self._sync_timer()

    def hideEvent(self, event) -> None:  # noqa: N802
        self._timer.stop()
        super().hideEvent(event)

    # -- geometry ------------------------------------------------------------
    def _layout(self):
        w, h = float(self.width()), float(self.height())
        rtl = self.isRightToLeft()
        compact = self.compact or self._height < self.FULL_HEIGHT - 40
        pad = 46.0
        y = h * (0.5 if compact else 0.40)
        start = pad + (40 if compact else 70)
        end = w - pad - (40 if compact else 60)
        stations = [start + (end - start) * (i + 1) / (STAGE_COUNT + 1) for i in range(STAGE_COUNT)]
        source, verdict = start - (0 if compact else 10), end
        if rtl:
            mirror = lambda x: w - x  # noqa: E731
            stations = [mirror(x) for x in stations]
            source, verdict = mirror(source), mirror(verdict)
        return compact, y, source, stations, verdict

    # -- painting --------------------------------------------------------------
    def paintEvent(self, event) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setRenderHint(QPainter.RenderHint.TextAntialiasing)
        compact, y, source, stations, verdict_x = self._layout()
        accent = QColor(TOKENS["accent"])
        now = time.monotonic()

        # Conduit between nodes: solid where the run has passed, dashed ahead.
        nodes = [source, *stations, verdict_x]
        for index in range(len(nodes) - 1):
            a, b = nodes[index], nodes[index + 1]
            passed = index == 0 and self.phase != "idle" or (
                index > 0 and self.stage_states[index - 1] == "complete"
            )
            if index == STAGE_COUNT and self.phase not in {"concluding", "concluded", "evidence"}:
                passed = False
            if passed:
                gradient = QLinearGradient(QPointF(a, y), QPointF(b, y))
                faded = QColor(accent)
                faded.setAlpha(110)
                gradient.setColorAt(0.0, faded)
                gradient.setColorAt(1.0, accent)
                painter.setPen(QPen(gradient, 2.2))
            else:
                painter.setPen(QPen(QColor(TOKENS["line_strong"]), 1.4, Qt.PenStyle.DashLine))
            inset = 30 if index == 0 else 22
            direction = 1 if b > a else -1
            painter.drawLine(QPointF(a + direction * inset, y), QPointF(b - direction * 24, y))

        self._paint_source(painter, source, y, compact)
        for index, x in enumerate(stations):
            self._paint_station(painter, index, x, y, compact)
        self._paint_verdict(painter, verdict_x, y, compact)
        self._paint_packet(painter, source, stations, y, compact)
        if not compact:
            self._paint_markers(painter, stations[-1], verdict_x, y, now)

    def _font(self, px: float, weight=QFont.Weight.Normal, family: str | None = None) -> QFont:
        font = QFont(self.font())
        if family:
            font.setFamily(family)
        font.setPixelSize(int(px))
        font.setWeight(weight)
        return font

    def _paint_source(self, painter: QPainter, x: float, y: float, compact: bool) -> None:
        scale = 0.62 if compact else 1.0
        w, h = 58 * scale, 70 * scale
        rect = QRectF(x - w / 2, y - h / 2, w, h)
        fold = 14 * scale
        path = QPainterPath()
        path.moveTo(rect.left() + 8, rect.top())
        path.lineTo(rect.right() - fold, rect.top())
        path.lineTo(rect.right(), rect.top() + fold)
        path.lineTo(rect.right(), rect.bottom() - 8)
        path.quadTo(rect.right(), rect.bottom(), rect.right() - 8, rect.bottom())
        path.lineTo(rect.left() + 8, rect.bottom())
        path.quadTo(rect.left(), rect.bottom(), rect.left(), rect.bottom() - 8)
        path.lineTo(rect.left(), rect.top() + 8)
        path.quadTo(rect.left(), rect.top(), rect.left() + 8, rect.top())
        body = QLinearGradient(rect.topLeft(), rect.bottomRight())
        body.setColorAt(0.0, QColor(TOKENS["surface_3"]))
        body.setColorAt(1.0, QColor(TOKENS["surface_2"]))
        painter.setPen(QPen(QColor(TOKENS["line_strong"]), 1.2))
        painter.setBrush(body)
        painter.drawPath(path)
        painter.setPen(QPen(QColor(TOKENS["line_strong"]), 1.0))
        painter.drawLine(QPointF(rect.right() - fold, rect.top()), QPointF(rect.right() - fold, rect.top() + fold))
        painter.drawLine(QPointF(rect.right() - fold, rect.top() + fold), QPointF(rect.right(), rect.top() + fold))

        painter.setPen(QColor(TOKENS["accent"]))
        painter.setFont(self._font(24 * scale, family=ICON_FONT if icon_font_available() else None))
        painter.drawText(rect.adjusted(0, 6 * scale, 0, 0), int(Qt.AlignmentFlag.AlignCenter), glyph(self.target_kind))
        if compact or not self.target_name:
            return
        name_font = self._font(13, QFont.Weight.DemiBold)
        metrics = QFontMetrics(name_font)
        name = metrics.elidedText(self.target_name, Qt.TextElideMode.ElideMiddle, 150)
        painter.setFont(name_font)
        painter.setPen(QColor(TOKENS["text"]))
        painter.drawText(QRectF(x - 80, rect.bottom() + 10, 160, 20), int(Qt.AlignmentFlag.AlignCenter), name)
        painter.setFont(self._font(11.5))
        painter.setPen(QColor(TOKENS["text_mute"]))
        painter.drawText(QRectF(x - 80, rect.bottom() + 30, 160, 18), int(Qt.AlignmentFlag.AlignCenter), self.target_type)

    def _hexagon(self, center: QPointF, radius: float) -> QPainterPath:
        path = QPainterPath()
        for index in range(6):
            angle = math.radians(-90 + index * 60)
            point = QPointF(center.x() + radius * math.cos(angle), center.y() + radius * math.sin(angle))
            path.moveTo(point) if index == 0 else path.lineTo(point)
        path.closeSubpath()
        return path

    def _paint_station(self, painter: QPainter, index: int, x: float, y: float, compact: bool) -> None:
        state = self.stage_states[index]
        radius = 15 if compact else 22
        center = QPointF(x, y)
        hexagon = self._hexagon(center, radius)
        accent = QColor(TOKENS["accent"])
        if state == "complete":
            fill, edge, mark, ink = QColor(TOKENS["accent_wash"]), accent, "✓", accent
        elif state == "failed":
            fill, edge, mark, ink = QColor("#2a1214"), QColor(TOKENS["danger"]), "✕", QColor(TOKENS["danger"])
        elif state == "running":
            fill, edge, mark, ink = QColor(TOKENS["surface_2"]), accent, "", accent
        else:
            fill, edge, mark, ink = QColor(TOKENS["surface"]), QColor(TOKENS["line_strong"]), "", QColor(TOKENS["text_mute"])
        if state in {"complete", "running"} and not compact:
            halo = QRadialGradient(center, radius * 2.2)
            soft = QColor(accent)
            soft.setAlpha(40)
            halo.setColorAt(0.0, soft)
            halo.setColorAt(1.0, QColor(0, 0, 0, 0))
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(halo)
            painter.drawEllipse(center, radius * 2.2, radius * 2.2)
        painter.setPen(QPen(edge, 1.6))
        painter.setBrush(fill)
        painter.drawPath(hexagon)
        if state == "running":
            ring = QRectF(x - radius - 8, y - radius - 8, (radius + 8) * 2, (radius + 8) * 2)
            pen = QPen(accent, 2.0, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap)
            painter.setPen(pen)
            painter.setBrush(Qt.BrushStyle.NoBrush)
            start = 0.0 if self.reduced_motion else self._spin
            painter.drawArc(ring, int(-start * 16), int(-70 * 16))
            painter.drawArc(ring, int((-start - 180) * 16), int(-70 * 16))
        if mark:
            painter.setPen(ink)
            painter.setFont(self._font(13 if compact else 16, QFont.Weight.Bold))
            painter.drawText(QRectF(x - radius, y - radius, radius * 2, radius * 2), int(Qt.AlignmentFlag.AlignCenter), mark)
        else:
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(ink)
            painter.drawEllipse(center, 2.6, 2.6)
        title = self.stage_titles[index] if index < len(self.stage_titles) else ""
        painter.setFont(self._font(11 if compact else 12.5, QFont.Weight.DemiBold if state == "running" else QFont.Weight.Normal))
        painter.setPen(QColor(TOKENS["text"] if state in {"running", "complete"} else TOKENS["text_mute"]))
        offset = radius + (10 if compact else 16)
        painter.drawText(QRectF(x - 70, y + offset, 140, 18), int(Qt.AlignmentFlag.AlignCenter), title)

    def _paint_verdict(self, painter: QPainter, x: float, y: float, compact: bool) -> None:
        radius = 20 if compact else 30
        center = QPointF(x, y)
        reached = self.phase in {"concluded", "failed", "cancelled"}
        color = self.verdict_color if reached else QColor(TOKENS["line_strong"])
        if reached and self.phase == "concluded":
            glow = QRadialGradient(center, radius * 2.4)
            soft = QColor(color)
            soft.setAlpha(60)
            glow.setColorAt(0.0, soft)
            glow.setColorAt(1.0, QColor(0, 0, 0, 0))
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(glow)
            painter.drawEllipse(center, radius * 2.4, radius * 2.4)
        fill = QColor(color)
        fill.setAlpha(46 if reached else 0)
        painter.setPen(QPen(color, 2.0 if reached else 1.4, Qt.PenStyle.SolidLine if reached else Qt.PenStyle.DashLine))
        painter.setBrush(fill if reached else QColor(TOKENS["surface"]))
        painter.drawEllipse(center, radius, radius)
        painter.setPen(color if reached else QColor(TOKENS["text_mute"]))
        painter.setFont(self._font(16 if compact else 22, QFont.Weight.Bold))
        painter.drawText(QRectF(x - radius, y - radius, radius * 2, radius * 2), int(Qt.AlignmentFlag.AlignCenter), self.verdict_symbol if reached else "?")
        if reached and self.verdict_title:
            painter.setFont(self._font(12 if compact else 14, QFont.Weight.Bold))
            painter.setPen(color)
            painter.drawText(QRectF(x - 90, y + radius + (8 if compact else 12), 180, 20), int(Qt.AlignmentFlag.AlignCenter), self.verdict_title)

    def _packet_target(self, source: float, stations: list[float]) -> float | None:
        if self.phase in {"idle", "concluded", "concluding"}:
            return None
        if self.phase == "entering":
            progress = _ease(self._elapsed() / self.ENTER_SECONDS) if not self.reduced_motion else 1.0
            return source + (stations[0] - source) * progress
        if self.phase in {"failed", "cancelled"}:
            stopped = next((i for i, s in enumerate(self.stage_states) if s in {"failed", "waiting"}), STAGE_COUNT - 1)
            return stations[stopped]
        if self.phase == "evidence":
            return stations[-1]
        running = next((i for i, s in enumerate(self.stage_states) if s == "running"), None)
        if running is None:
            done = [i for i, s in enumerate(self.stage_states) if s == "complete"]
            running = min(done[-1] + 1, STAGE_COUNT - 1) if done else 0
        return stations[running]

    def _paint_packet(self, painter: QPainter, source: float, stations: list[float], y: float, compact: bool) -> None:
        target = self._packet_target(source, stations)
        if target is None or compact:
            self._packet_x = None
            return
        if self._packet_x is None or self.reduced_motion or self.phase == "entering":
            self._packet_x = target
        else:
            self._packet_x += (target - self._packet_x) * 0.18
        x = self._packet_x
        # Three offset layers: an abstract token for "the target under analysis".
        accent = QColor(TOKENS["accent"])
        bob = 0.0 if self.reduced_motion else math.sin(self._spin * math.pi / 90) * 2.0
        lift = 44 if self.phase != "entering" else 40
        for layer in range(3):
            offset = (2 - layer) * 5
            color = QColor(accent)
            color.setAlpha(70 + layer * 70)
            path = QPainterPath()
            cx, cy = x + offset - 5, y - lift - offset + bob
            path.moveTo(cx, cy - 9)
            path.lineTo(cx + 13, cy)
            path.lineTo(cx, cy + 9)
            path.lineTo(cx - 13, cy)
            path.closeSubpath()
            painter.setPen(QPen(color, 1.3))
            fill = QColor(color)
            fill.setAlpha(28 + layer * 18)
            painter.setBrush(fill)
            painter.drawPath(path)
        tether = QColor(accent)
        tether.setAlpha(90)
        painter.setPen(QPen(tether, 1.0, Qt.PenStyle.DotLine))
        painter.drawLine(QPointF(x, y - lift + 12 + bob), QPointF(x, y - 24))

    def _paint_markers(self, painter: QPainter, from_x: float, verdict_x: float, y: float, now: float) -> None:
        if self.phase not in {"evidence", "concluding", "concluded"}:
            return
        row_y = y + 92
        count = len(self.markers)
        spacing = 30.0
        width = spacing * max(0, count - 1)
        left = (from_x + verdict_x) / 2 - width / 2
        if self.isRightToLeft():
            positions = [left + width - i * spacing for i in range(count)]
        else:
            positions = [left + i * spacing for i in range(count)]
        for marker, target_x in zip(self.markers, positions):
            t = 1.0 if self.reduced_motion or marker.born == 0.0 else _ease((now - marker.born) / 0.5)
            if t <= 0:
                continue
            px = from_x + (target_x - from_x) * t
            py = y + (row_y - y) * t
            color = QColor(marker.color)
            color.setAlpha(int(255 * min(1.0, t * 1.4)))
            painter.setPen(QPen(color, 1.4))
            fill = QColor(color)
            fill.setAlpha(int(50 * t))
            painter.setBrush(fill)
            painter.drawEllipse(QPointF(px, py), 11, 11)
            painter.setFont(self._font(11, QFont.Weight.Bold))
            painter.drawText(QRectF(px - 11, py - 11, 22, 22), int(Qt.AlignmentFlag.AlignCenter), marker.symbol)
        painter.setFont(self._font(13, QFont.Weight.DemiBold))
        painter.setPen(QColor(TOKENS["text_dim"]))
        painter.drawText(
            QRectF((from_x + verdict_x) / 2 - 200, row_y + 18, 400, 22),
            int(Qt.AlignmentFlag.AlignCenter),
            self.evidence_label,
        )

    def sizeHint(self) -> QSize:  # noqa: N802
        return QSize(860, self.FULL_HEIGHT)
