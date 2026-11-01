"""Sonar cube: the file as a glass cube, scanned, then echo-mapped from inside.

The sequence follows the scan:

1. ``start``: an empty glass cube draws itself in the target's hue.
2. While the engine works, an emitter circles the cube and its beams sweep a
   scanning plane through it, along one axis after another. This loops for as
   long as the real scan runs, so the picture never stops or jumps while
   waiting, and it shows nothing it does not know yet: the cube stays empty.
3. ``reveal``: once the real result exists, sonar pings expand from the
   centre and every slice of the file (``ui.structure``) appears as the
   wavefront passes it, like an echo mapping a cave. Walls (sharp changes in
   the content) answer brightest; uniform stretches stay a faint mist.
4. The regions the engine located glow in their severity colour, rings pulse
   around them and callouts name their byte ranges; then ``finished`` fires.

On the result screen the cube is explored by hand: drag to turn it, scroll
to zoom, hover a point to read its byte range and value. Nothing moves on
its own there. Reduced motion and hidden widgets skip straight to the end.
"""
from __future__ import annotations

import math
import time

import numpy as np
from PySide6.QtCore import QPointF, QRectF, QSize, Qt, QTimer, Signal
from PySide6.QtGui import (
    QBrush, QColor, QFontMetricsF, QImage, QLinearGradient, QPainter, QPen, QPolygonF, QRadialGradient,
)
from PySide6.QtWidgets import QSizePolicy, QToolTip, QWidget

from ui.motion import prefers_reduced_motion
from ui.structure import SEVERITY_RANK, Structure
from ui.theme import TOKENS, alpha, mix, ui_font

FRAME_MS = 33
DRAW_SECONDS = 0.9
SWEEP_SECONDS = 1.5  # one pass of the scanning plane along one axis
ECHO_SECONDS = 2.2
FLAG_SECONDS = 1.8
DISTANCE = 2.7  # camera distance, in cube sides
MAX_CALLOUTS = 4
SEVERITY_COLORS = {1: TOKENS["info"], 2: TOKENS["warn"], 3: TOKENS["danger"]}
_EDGES = [
    (0, 1), (1, 3), (3, 2), (2, 0),
    (4, 5), (5, 7), (7, 6), (6, 4),
    (0, 4), (1, 5), (2, 6), (3, 7),
]
_CORNERS = np.array([[x, y, z] for x in (-0.5, 0.5) for y in (-0.5, 0.5) for z in (-0.5, 0.5)], dtype=np.float32)
# Corner indices are x*4 + y*2 + z; each face is a closed loop of four.
_FACES = [(0, 1, 3, 2), (4, 5, 7, 6), (0, 1, 5, 4), (2, 3, 7, 6), (0, 2, 6, 4), (1, 3, 7, 5)]


def _ease(t: float) -> float:
    return 1.0 - (1.0 - t) ** 3


def _ease_in_out(t: float) -> float:
    return t * t * (3.0 - 2.0 * t)


def _rgb(color) -> np.ndarray:
    color = QColor(color)
    return np.array([color.redF(), color.greenF(), color.blueF()], dtype=np.float32)


def _severity_color(region) -> QColor:
    return QColor(SEVERITY_COLORS[SEVERITY_RANK.get(region.severity, 2)])


def _plane(axis: int, position: float) -> np.ndarray:
    """The square cross-section of the cube at ``position`` along ``axis``."""
    points = []
    for u, v in ((-0.5, -0.5), (0.5, -0.5), (0.5, 0.5), (-0.5, 0.5)):
        point = [u, v]
        point.insert(axis, position)
        points.append(point)
    return np.array(points, dtype=np.float32)


def _circle(radius: float, plane: str, steps: int = 72) -> np.ndarray:
    angle = np.linspace(0.0, 2.0 * math.pi, steps + 1)
    a, b = radius * np.cos(angle), radius * np.sin(angle)
    zero = np.zeros_like(a)
    columns = {"xz": (a, zero, b), "xy": (a, b, zero)}[plane]
    return np.stack(columns, axis=1).astype(np.float32)


class SonarCube(QWidget):
    finished = Signal()
    cellHovered = Signal(int)

    def __init__(self, parent=None, *, interactive: bool = False, reduced_motion: bool | None = None, height: int = 380):
        super().__init__(parent)
        self.interactive = interactive
        self.reduced_motion = prefers_reduced_motion() if reduced_motion is None else reduced_motion
        self.phase = "idle"
        self.hue = QColor(TOKENS["accent"])
        self.structure: Structure | None = None
        self.describe = None  # callable(cell index) -> tooltip text
        self.label_for = None  # callable(Region) -> callout text
        self.highlighted: set[int] = set()
        self.failed = False
        self._hold = False  # after drawing, stay still instead of scanning
        self.yaw = -0.62
        self.pitch = -0.42
        self.zoom = 1.0
        self._phase_started = time.monotonic()
        self._last = time.monotonic()
        self._drag: QPointF | None = None
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self.setMouseTracking(interactive)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.setFixedHeight(height)
        self.setAccessibleName("File structure")

    # -- sequence (driven by real events) ---------------------------------------
    def start(self, hue: str) -> None:
        self.hue = QColor(hue)
        self.structure = None
        self.highlighted = set()
        self.failed = False
        self._hold = False
        self._set_phase("scanning" if self.reduced_motion else "drawing")

    def reveal(self, structure: Structure | None) -> None:
        self.structure = structure
        if self.reduced_motion or not self.isVisible():
            self._finish()
            return
        self._set_phase("echo")

    def fail(self) -> None:
        self.failed = True
        self._set_phase("stopped")

    def halt(self) -> None:
        """Stop where it is (the scan was cancelled); nothing is revealed."""
        self.failed = False
        self._set_phase("stopped")

    def skip(self) -> None:
        if self.phase in {"echo", "flag"}:
            self._finish()

    def show_structure(self, structure: Structure | None, hue: str) -> None:
        """Static, explorable view (result screen)."""
        self.hue = QColor(hue)
        self.structure = structure
        self.failed = False
        self._set_phase("explore")

    def show_empty(self, hue: str) -> None:
        """The glass cube alone: drawn once, then still."""
        self.hue = QColor(hue)
        self.structure = None
        self.failed = False
        self._hold = True
        self._set_phase("stopped" if self.reduced_motion else "drawing")

    def reset(self) -> None:
        self.structure = None
        self.highlighted = set()
        self.failed = False
        self._set_phase("idle")

    def stop(self) -> None:
        self._timer.stop()

    def highlight(self, cells) -> None:
        self.highlighted = set(int(c) for c in cells)
        self.update()

    @property
    def animating(self) -> bool:
        return self._timer.isActive()

    # -- internals ----------------------------------------------------------------
    def _set_phase(self, phase: str) -> None:
        self.phase = phase
        self._phase_started = time.monotonic()
        self._sync_timer()
        self.update()

    def _elapsed(self) -> float:
        return time.monotonic() - self._phase_started

    def _needs_timer(self) -> bool:
        return (
            not self.reduced_motion
            and self.isVisible()
            and self.phase in {"drawing", "scanning", "echo", "flag"}
        )

    def _sync_timer(self) -> None:
        if self._needs_timer():
            if not self._timer.isActive():
                self._last = time.monotonic()
                self._timer.start(FRAME_MS)
        else:
            self._timer.stop()

    def _finish(self) -> None:
        self.phase = "explore"
        self._timer.stop()
        self.update()
        self.finished.emit()

    def _tick(self) -> None:
        now = time.monotonic()
        dt = min(0.1, now - self._last)
        self._last = now
        if self.phase in {"drawing", "scanning", "echo", "flag"}:
            self.yaw += dt * 0.22
        elapsed = self._elapsed()
        if self.phase == "drawing" and elapsed >= DRAW_SECONDS:
            self._set_phase("stopped" if self._hold else "scanning")
        elif self.phase == "echo" and elapsed >= ECHO_SECONDS:
            if self.structure is not None and bool((self.structure.flags > 0).any()):
                self._set_phase("flag")
            else:
                self._finish()
        elif self.phase == "flag" and elapsed >= FLAG_SECONDS:
            self._finish()
        self.update()

    def showEvent(self, event) -> None:  # noqa: N802
        super().showEvent(event)
        self._sync_timer()

    def hideEvent(self, event) -> None:  # noqa: N802
        self._timer.stop()
        if self.phase in {"echo", "flag"}:
            self._finish()
        super().hideEvent(event)

    def sizeHint(self) -> QSize:  # noqa: N802
        return QSize(640, 380)

    # -- projection -------------------------------------------------------------------
    def _scale(self) -> float:
        return min(self.width(), self.height()) * 0.52 * self.zoom

    def _project(self, points: np.ndarray) -> np.ndarray:
        """(n, 3) cube points -> (n, 3) screen x, y and depth (larger is farther)."""
        cy, sy = math.cos(self.yaw), math.sin(self.yaw)
        cp, sp = math.cos(self.pitch), math.sin(self.pitch)
        x = points[:, 0] * cy + points[:, 2] * sy
        z = -points[:, 0] * sy + points[:, 2] * cy
        y = points[:, 1] * cp - z * sp
        z = points[:, 1] * sp + z * cp
        factor = DISTANCE / (DISTANCE + z)
        scale = self._scale()
        screen_x = self.width() / 2 + x * factor * scale
        screen_y = self.height() / 2 + y * factor * scale
        return np.stack([screen_x, screen_y, z], axis=1)

    # -- painting -------------------------------------------------------------------------
    def paintEvent(self, event) -> None:  # noqa: N802
        if self.phase == "idle":
            return
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        elapsed = self._elapsed()
        hue = QColor(TOKENS["danger"]) if self.failed else self.hue
        draw = _ease(min(1.0, elapsed / DRAW_SECONDS)) if self.phase == "drawing" else 1.0
        corners = self._project(_CORNERS * (0.82 + 0.18 * draw))
        self._paint_stage(painter, corners, hue, draw)
        self._paint_edges(painter, corners, hue, draw, front=False)
        if self.phase in {"drawing", "scanning"}:
            self._paint_scan(painter, hue, elapsed)
        elif self.structure is not None and self.phase != "stopped":
            self._paint_points(painter, hue, elapsed)
        self._paint_edges(painter, corners, hue, draw, front=True)
        if self.structure is not None and self.phase in {"flag", "explore"}:
            self._paint_callouts(painter, elapsed)

    def _paint_stage(self, painter: QPainter, corners: np.ndarray, hue: QColor, draw: float) -> None:
        """Ambient light, a soft shadow under the cube, and its glass faces."""
        center = QPointF(self.width() / 2, self.height() / 2)
        glow = QRadialGradient(center, min(self.width(), self.height()) * 0.62)
        glow.setColorAt(0.0, alpha(hue, 0.11 * draw))
        glow.setColorAt(0.55, alpha(hue, 0.03 * draw))
        glow.setColorAt(1.0, alpha(hue, 0.0))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(glow)
        painter.drawRect(self.rect())
        floor = self._project(np.array([[0.0, 0.78, 0.0]], dtype=np.float32))[0]
        shadow_center = QPointF(floor[0], floor[1])
        span = self._scale() * 0.62
        shadow = QRadialGradient(shadow_center, span)
        shadow.setColorAt(0.0, alpha(hue, 0.16 * draw))
        shadow.setColorAt(1.0, alpha(hue, 0.0))
        painter.save()
        painter.translate(shadow_center)
        painter.scale(1.0, 0.18)
        painter.translate(-shadow_center)
        painter.setBrush(shadow)
        painter.drawEllipse(shadow_center, span, span)
        painter.restore()
        # Glass: back faces darker, front faces catch a little light.
        for face in sorted(_FACES, key=lambda f: -float(corners[list(f), 2].mean())):
            depth = float(corners[list(face), 2].mean())
            polygon = QPolygonF([QPointF(corners[i, 0], corners[i, 1]) for i in face])
            painter.setBrush(alpha(hue, (0.018 if depth > 0 else 0.035) * draw))
            painter.drawPolygon(polygon)

    def _paint_edges(self, painter: QPainter, corners: np.ndarray, hue: QColor, draw: float, *, front: bool) -> None:
        """Back edges under the content, front edges over it, each with a soft glow."""
        for a, b in _EDGES:
            depth = (corners[a, 2] + corners[b, 2]) / 2
            if (depth <= 0) != front:
                continue
            strength = max(0.16, min(0.95, 0.5 - depth * 0.9)) * draw
            start = QPointF(corners[a, 0], corners[a, 1])
            end = QPointF(corners[a, 0] + (corners[b, 0] - corners[a, 0]) * draw, corners[a, 1] + (corners[b, 1] - corners[a, 1]) * draw)
            painter.setPen(QPen(alpha(hue, strength * 0.16), 5.0, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
            painter.drawLine(start, end)
            painter.setPen(QPen(alpha(mix(hue, "#ffffff", 0.25), strength), 1.2))
            painter.drawLine(start, end)
        painter.setPen(Qt.PenStyle.NoPen)
        for corner in corners:
            if (corner[2] <= 0) != front:
                continue
            point = QPointF(corner[0], corner[1])
            painter.setBrush(alpha(hue, 0.22 * draw))
            painter.drawEllipse(point, 5.0, 5.0)
            painter.setBrush(alpha(mix(hue, "#ffffff", 0.5), 0.95 * draw))
            painter.drawEllipse(point, 1.8, 1.8)

    def _paint_scan(self, painter: QPainter, hue: QColor, elapsed: float) -> None:
        """Beams from an emitter outside the cube sweep a plane through it."""
        if self.phase == "drawing":
            return
        cycle = elapsed / SWEEP_SECONDS
        axis = int(cycle) % 3
        progress = cycle % 1.0
        sweep = -0.5 + _ease_in_out(progress)
        light = math.sin(math.pi * progress) ** 0.6  # fade in and out at the faces
        angle = elapsed * 0.8
        emitter = self._project(np.array([[1.5 * math.cos(angle), -0.55, 1.5 * math.sin(angle)]], dtype=np.float32))[0]
        origin = QPointF(emitter[0], emitter[1])
        # The trail of the plane, then the plane itself.
        for lag, strength in ((0.10, 0.25), (0.05, 0.45), (0.0, 1.0)):
            position = -0.5 + _ease_in_out(max(0.0, progress - lag))
            trail = self._project(_plane(axis, position))
            painter.setPen(QPen(alpha(hue, 0.85 * strength * light), 1.3 if lag == 0 else 1.0))
            painter.setBrush(alpha(hue, 0.10 * strength * light))
            painter.drawPolygon(QPolygonF([QPointF(p[0], p[1]) for p in trail]))
        plane = self._project(_plane(axis, sweep))
        painter.setPen(QPen(alpha(hue, 0.16 * light), 1))
        for step in (0.2, 0.4, 0.6, 0.8):
            for a, b, c, d in ((0, 1, 3, 2), (0, 3, 1, 2)):
                p = plane[a] + (plane[b] - plane[a]) * step
                q = plane[c] + (plane[d] - plane[c]) * step
                painter.drawLine(QPointF(p[0], p[1]), QPointF(q[0], q[1]))
        # Beam fan: from the emitter to a grid of points on the plane.
        for u in (0.15, 0.5, 0.85):
            top = plane[0] + (plane[1] - plane[0]) * u
            bottom = plane[3] + (plane[2] - plane[3]) * u
            for v in (0.15, 0.5, 0.85):
                target = top + (bottom - top) * v
                end = QPointF(target[0], target[1])
                beam = QLinearGradient(origin, end)
                beam.setColorAt(0.0, alpha(hue, 0.55 * light))
                beam.setColorAt(1.0, alpha(hue, 0.08 * light))
                painter.setPen(QPen(QBrush(beam), 1.0))
                painter.drawLine(origin, end)
                painter.setPen(Qt.PenStyle.NoPen)
                painter.setBrush(alpha(mix(hue, "#ffffff", 0.6), 0.75 * light))
                painter.drawEllipse(end, 1.6, 1.6)
        # Where the plane meets the cube's edges, the glass lights up.
        painter.setPen(Qt.PenStyle.NoPen)
        for point in plane:
            spot = QPointF(point[0], point[1])
            halo = QRadialGradient(spot, 12.0)
            halo.setColorAt(0.0, alpha(mix(hue, "#ffffff", 0.5), 0.8 * light))
            halo.setColorAt(1.0, alpha(hue, 0.0))
            painter.setBrush(halo)
            painter.drawEllipse(spot, 12.0, 12.0)
        halo = QRadialGradient(origin, 16.0)
        halo.setColorAt(0.0, alpha(mix(hue, "#ffffff", 0.6), 0.95))
        halo.setColorAt(0.4, alpha(hue, 0.45))
        halo.setColorAt(1.0, alpha(hue, 0.0))
        painter.setBrush(halo)
        painter.drawEllipse(origin, 16.0, 16.0)

    def _paint_points(self, painter: QPainter, hue: QColor, elapsed: float) -> None:
        structure = self.structure
        points = self._project(structure.positions)
        distance = np.linalg.norm(structure.positions, axis=1) / 0.87  # 0 at centre, 1 at corners
        if self.phase == "echo":
            radius = min(1.05, elapsed / (ECHO_SECONDS * 0.82))
            visible = distance <= radius
            front = visible & (distance > radius - 0.09)
            # Points settle from the flash of the wavefront to their own light.
            settle = np.clip((radius - distance) / 0.35, 0.0, 1.0)
        else:
            visible = np.ones(structure.count, dtype=bool)
            front = np.zeros(structure.count, dtype=bool)
            settle = np.ones(structure.count, dtype=np.float32)
        level = structure.entropy / 8.0
        walls = structure.walls if structure.walls is not None else np.zeros(structure.count, dtype=np.float32)
        nearness = np.clip(0.55 - points[:, 2], 0.0, 1.0)
        white = np.array([0.95, 0.97, 1.0], dtype=np.float32)
        # Terrain: walls (sharp changes) answer the sonar brightest; dense,
        # random content glows softly; quiet content is a faint mist.
        tint = np.clip(0.75 * walls + 0.3 * level ** 1.5, 0.0, 1.0)[:, None]
        colors = _rgb(hue) * (1.0 - tint) + white * tint
        weights = (0.05 + 0.32 * level ** 1.6 + 1.05 * walls ** 0.85) * (0.4 + 0.6 * nearness)
        weights = weights * (0.35 + 0.65 * settle)
        weights = np.where(visible, weights, 0.0)
        weights = np.where(front, 1.5, weights)
        colors[front] = white
        glow_colors = np.zeros((0, 3), dtype=np.float32)
        glow_points = np.zeros((0, 2), dtype=np.float32)
        glow_weights = np.zeros(0, dtype=np.float32)
        if self.phase in {"flag", "explore"} and bool((structure.flags > 0).any()):
            pulse = 1.0
            if self.phase == "flag":
                pulse = 0.55 + 0.45 * math.sin(elapsed * 7.0) ** 2
            flagged = visible & (structure.flags > 0)
            ranks = structure.flags[flagged]
            palette = {rank: _rgb(color) for rank, color in SEVERITY_COLORS.items()}
            if ranks.size:
                glow_colors = np.stack([palette[int(r)] for r in ranks])
                colors[flagged] = glow_colors * 0.55 + white * 0.45
            glow_points = points[flagged, :2]
            glow_weights = np.full(ranks.size, 0.95 * pulse, dtype=np.float32)
            weights = np.where(flagged, 1.5, weights)
        if self.highlighted:
            chosen = np.array([i for i in self.highlighted if 0 <= i < structure.count], dtype=np.int64)
            if chosen.size:
                colors[chosen] = white
                weights[chosen] = 2.4
        image, area = _splat(self.width(), self.height(), self.devicePixelRatioF(), points[:, :2], colors, weights, glow_points, glow_colors, glow_weights)
        if not image.isNull():
            painter.drawImage(area, image)
        if self.phase == "echo":
            self._paint_pings(painter, hue, elapsed)
        else:
            self._paint_rings(painter, points, elapsed)

    def _paint_pings(self, painter: QPainter, hue: QColor, elapsed: float) -> None:
        """The sonar wavefront: a sphere growing from the centre, with two echoes behind it."""
        center = self._project(np.zeros((1, 3), dtype=np.float32))[0]
        painter.setBrush(Qt.BrushStyle.NoBrush)
        for lag, strength in ((0.0, 1.0), (0.16, 0.5), (0.32, 0.25)):
            radius = elapsed / (ECHO_SECONDS * 0.82) - lag
            if radius <= 0.0 or radius > 1.05:
                continue
            world = radius * 0.87
            fade = strength * (1.0 - radius / 1.05) ** 0.7
            ring = self._project(_circle(world, "xz"))
            painter.setPen(QPen(alpha(mix(hue, "#ffffff", 0.35), 0.7 * fade), 1.3))
            painter.drawPolyline(QPolygonF([QPointF(p[0], p[1]) for p in ring]))
            ring = self._project(_circle(world, "xy"))
            painter.setPen(QPen(alpha(hue, 0.35 * fade), 1.0))
            painter.drawPolyline(QPolygonF([QPointF(p[0], p[1]) for p in ring]))
            silhouette = world * self._scale() * DISTANCE / (DISTANCE + center[2])
            painter.setPen(QPen(alpha(hue, 0.22 * fade), 6.0))
            painter.drawEllipse(QPointF(center[0], center[1]), silhouette, silhouette)

    def _paint_rings(self, painter: QPainter, points: np.ndarray, elapsed: float) -> None:
        """Rings around each located region: pulsing while flagged, still afterwards."""
        painter.setBrush(Qt.BrushStyle.NoBrush)
        for index, region in enumerate(self.structure.regions[:MAX_CALLOUTS]):
            if not region.cells:
                continue
            color = _severity_color(region)
            spot = points[list(region.cells), :2].mean(axis=0)
            center = QPointF(spot[0], spot[1])
            if self.phase == "flag":
                for offset in (0.0, 0.5):
                    progress = ((elapsed - index * 0.18) / 0.9 + offset) % 1.0
                    painter.setPen(QPen(alpha(color, 0.75 * (1.0 - progress)), 1.4))
                    painter.drawEllipse(center, 6.0 + 26.0 * progress, 6.0 + 26.0 * progress)
            else:
                painter.setPen(QPen(alpha(color, 0.6), 1.2))
                painter.drawEllipse(center, 11.0, 11.0)

    def _paint_callouts(self, painter: QPainter, elapsed: float) -> None:
        """A label beside the cube for each located region, with a leader to its place."""
        regions = [r for r in self.structure.regions[:MAX_CALLOUTS] if r.cells]
        if not regions:
            return
        points = self._project(self.structure.positions)
        corners = self._project(_CORNERS)
        left_edge, right_edge = float(corners[:, 0].min()), float(corners[:, 0].max())
        font = ui_font(11.5, 500)  # follows the reader's text size
        painter.setFont(font)
        metrics = QFontMetricsF(font)
        sides: dict[bool, list] = {True: [], False: []}
        for index, region in enumerate(regions):
            spot = points[list(region.cells), :2].mean(axis=0)
            sides[bool(spot[0] >= self.width() / 2)].append((index, region, spot))
        for right, items in sides.items():
            items.sort(key=lambda item: item[2][1])
            gap = 30.0
            top = self.height() / 2 - gap * (len(items) - 1) / 2
            for slot, (index, region, spot) in enumerate(items):
                appear = 1.0 if self.phase == "explore" else _ease(min(1.0, max(0.0, (elapsed - 0.15 - index * 0.2) / 0.35)))
                if appear <= 0.0:
                    continue
                color = _severity_color(region)
                text = self.label_for(region) if self.label_for else f"0x{region.offset_start:X} – 0x{region.offset_end:X}"
                width, height = metrics.horizontalAdvance(text) + 26.0, 22.0
                y = top + slot * gap
                if right:
                    x = min(self.width() - width - 6.0, right_edge + 28.0)
                    anchor = QPointF(x, y)
                else:
                    x = max(6.0, left_edge - 28.0 - width)
                    anchor = QPointF(x + width, y)
                start = QPointF(spot[0], spot[1])
                elbow = QPointF(anchor.x() + (-14.0 if right else 14.0), y)
                painter.setPen(QPen(alpha(color, 0.7 * appear), 1.0))
                painter.setBrush(Qt.BrushStyle.NoBrush)
                painter.drawLine(start, start + (elbow - start) * appear)
                if appear < 1.0:
                    continue
                painter.drawLine(elbow, anchor)
                box = QRectF(x, y - height / 2, width, height)
                painter.setPen(QPen(alpha(color, 0.55), 1.0))
                painter.setBrush(QColor(12, 13, 15, 225))
                painter.drawRoundedRect(box, 6.0, 6.0)
                painter.setPen(Qt.PenStyle.NoPen)
                painter.setBrush(color)
                painter.drawEllipse(QPointF(box.left() + 11.0, box.center().y()), 3.0, 3.0)
                painter.setPen(QColor(TOKENS["text"]))
                painter.drawText(box.adjusted(19.0, 0, -6.0, 0), int(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft), text)

    # -- exploring ---------------------------------------------------------------------------
    def mousePressEvent(self, event) -> None:  # noqa: N802
        if self.phase in {"echo", "flag"}:
            self.skip()
            return
        if self.interactive and event.button() == Qt.MouseButton.LeftButton:
            self._drag = event.position()
            self.setCursor(Qt.CursorShape.ClosedHandCursor)

    def mouseReleaseEvent(self, event) -> None:  # noqa: N802
        self._drag = None
        if self.interactive:
            self.setCursor(Qt.CursorShape.OpenHandCursor)

    def mouseMoveEvent(self, event) -> None:  # noqa: N802
        if not self.interactive:
            return
        position = event.position()
        if self._drag is not None:
            delta = position - self._drag
            self._drag = position
            self.yaw += delta.x() * 0.01
            self.pitch = max(-1.4, min(1.4, self.pitch + delta.y() * 0.01))
            self.update()
            return
        index = self.cell_at(position)
        if index is not None:
            self.cellHovered.emit(index)
            if self.describe is not None:
                QToolTip.showText(event.globalPosition().toPoint(), self.describe(index), self)
        else:
            QToolTip.hideText()

    def wheelEvent(self, event) -> None:  # noqa: N802
        if not self.interactive:
            return
        self.zoom = max(0.6, min(2.4, self.zoom * (1.0 + event.angleDelta().y() / 1200.0)))
        self.update()

    def enterEvent(self, event) -> None:  # noqa: N802
        if self.interactive:
            self.setCursor(Qt.CursorShape.OpenHandCursor)
        super().enterEvent(event)

    def cell_at(self, position: QPointF) -> int | None:
        if self.structure is None:
            return None
        # Project afresh: the pointer can arrive before the first paint.
        points = self._project(self.structure.positions)
        distances = (points[:, 0] - position.x()) ** 2 + (points[:, 1] - position.y()) ** 2
        # Prefer the nearest point in front when several overlap.
        candidates = np.nonzero(distances <= 49.0)[0]
        if candidates.size == 0:
            return None
        return int(candidates[np.argmin(points[candidates, 2])])


def _kernel(radius: int, sigma: float) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    span = np.arange(-radius, radius + 1)
    dx, dy = np.meshgrid(span, span)
    weight = np.exp(-(dx ** 2 + dy ** 2) / (2 * sigma ** 2))
    return dx.ravel(), dy.ravel(), (weight / weight.max()).ravel().astype(np.float32)


_CORE = _kernel(2, 0.75)
_HALO = _kernel(6, 2.6)


def _accumulate(buffer: np.ndarray, width: int, height: int, xy: np.ndarray, colors: np.ndarray, weights: np.ndarray, kernel) -> None:
    if xy.shape[0] == 0:
        return
    dx, dy, kw = kernel
    x = np.rint(xy[:, 0]).astype(np.int64)[:, None] + dx[None, :]
    y = np.rint(xy[:, 1]).astype(np.int64)[:, None] + dy[None, :]
    inside = (x >= 0) & (x < width) & (y >= 0) & (y < height)
    index = (y * width + x)[inside]
    strength = (weights[:, None] * kw[None, :])[inside]
    owner = np.broadcast_to(np.arange(xy.shape[0])[:, None], inside.shape)[inside]
    for channel in range(3):
        buffer[channel] += np.bincount(index, weights=strength * colors[owner, channel], minlength=width * height)


def _splat(width: int, height: int, ratio: float, xy: np.ndarray, colors: np.ndarray, weights: np.ndarray,
           glow_xy: np.ndarray, glow_colors: np.ndarray, glow_weights: np.ndarray) -> tuple[QImage, QRectF]:
    """Additive light: every slice adds a small gaussian spot, flagged slices a halo.

    Only the rectangle around the points is computed (the cube, not the widget).
    """
    ratio = max(1.0, float(ratio))
    live = weights > 0.001
    if not live.any():
        return QImage(), QRectF()
    margin = 8
    left = max(0, int(np.floor(xy[live, 0].min())) - margin)
    top = max(0, int(np.floor(xy[live, 1].min())) - margin)
    right = min(width, int(np.ceil(xy[live, 0].max())) + margin)
    bottom = min(height, int(np.ceil(xy[live, 1].max())) + margin)
    if right <= left or bottom <= top:
        return QImage(), QRectF()
    origin = np.array([left, top], dtype=np.float32)
    w, h = max(1, int((right - left) * ratio)), max(1, int((bottom - top) * ratio))
    buffer = np.zeros((3, w * h), dtype=np.float64)
    _accumulate(buffer, w, h, (xy[live] - origin) * ratio, colors[live], weights[live], _CORE)
    if glow_xy.shape[0]:
        _accumulate(buffer, w, h, (glow_xy - origin) * ratio, glow_colors, glow_weights * 0.22, _HALO)
    light = 1.0 - np.exp(-buffer * 1.4)
    rgb = (np.clip(light, 0.0, 1.0) * 255.0).astype(np.uint8)
    rgba = np.empty((h, w, 4), dtype=np.uint8)
    rgba[..., 0] = rgb[0].reshape(h, w)
    rgba[..., 1] = rgb[1].reshape(h, w)
    rgba[..., 2] = rgb[2].reshape(h, w)
    rgba[..., 3] = rgb.max(axis=0).reshape(h, w)
    image = QImage(rgba.data, w, h, 4 * w, QImage.Format.Format_RGBA8888_Premultiplied).copy()
    return image, QRectF(left, top, right - left, bottom - top)
