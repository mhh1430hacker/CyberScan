"""The file as a galaxy: its own, unique, made from its real bytes.

Every slice of the file (``ui.structure``) becomes a star:

* **distance from the core is position in the file**: the header sits at
  the heart, the last bytes at the rim;
* **colour and spread are the slice's measured density** (entropy): quiet
  text and padding are faint blue stars held tight to their arm, structured
  data and code burn white, compressed or encrypted data glows gold and
  drifts into a diffuse cloud;
* **walls** (sharp changes in content) are the bright stars;
* **red supernovas** are exactly the regions the scan located, with their
  byte ranges on hover;
* **the shape** (number of arms, their twist, the turn of the core) comes
  from the file's SHA-256, so no two different files share a galaxy and the
  same file always gives the same one.

Nothing is invented: every star is a measured slice; only the dust between
stars is drawn around them for depth, and it carries their colour.

The galaxy turns like a real one: the core faster than the rim (three bands,
pre-rendered once, each turned at its own speed). It opens with a big bang
from the core, then keeps turning while it is on screen; drag to orbit and
tilt, scroll to zoom. Reduced motion shows it still. ``render_wallpaper``
paints it at any size for a desktop background.
"""
from __future__ import annotations

import hashlib
import math
import random
import time
from dataclasses import dataclass

import numpy as np
from PySide6.QtCore import QPointF, QRectF, QSize, Qt, QTimer, Signal
from PySide6.QtGui import QColor, QFont, QImage, QPainter, QPen, QRadialGradient
from PySide6.QtWidgets import QSizePolicy, QToolTip, QWidget

from ui.motion import prefers_reduced_motion
from ui.theme import TOKENS

BANDS = ((0.0, 0.33, 1.0), (0.33, 0.66, 0.62), (0.66, 9.0, 0.38))  # (inner, outer, relative speed)
TURN_SECONDS = 160.0  # one turn of the core
BANG_SECONDS = 2.4
FRAME_MS = 33
SUPERNOVA = {1: TOKENS["info"], 2: TOKENS["warn"], 3: TOKENS["danger"]}
# Star colour by density: cool blue (quiet) -> white (structured) -> gold (scrambled).
_COOL = np.array([0.36, 0.52, 1.00], dtype=np.float32)
_WHITE = np.array([0.93, 0.96, 1.00], dtype=np.float32)
_GOLD = np.array([1.00, 0.76, 0.38], dtype=np.float32)


@dataclass
class Galaxy:
    positions: np.ndarray  # (n, 2) face-on, radius 0 .. 1
    radius: np.ndarray  # (n,)
    colors: np.ndarray  # (n, 3)
    weights: np.ndarray  # (n,)
    dust: np.ndarray  # (m, 2)
    dust_colors: np.ndarray  # (m, 3)
    dust_weights: np.ndarray  # (m,)
    dust_radius: np.ndarray  # (m,)
    offsets: np.ndarray  # (n, 2) byte range of each star
    entropy: np.ndarray  # (n,)
    flags: np.ndarray  # (n,) 0 or severity rank
    arms: int
    twist: float
    core_hue: QColor
    sha256: str


def _star_colors(level: np.ndarray) -> np.ndarray:
    level = level[:, None]
    low = np.clip(level / 0.55, 0.0, 1.0)
    high = np.clip((level - 0.72) / 0.28, 0.0, 1.0)
    return (_COOL * (1 - low) + _WHITE * low) * (1 - high) + _GOLD * high


def build_galaxy(structure, sha256: str | None = None) -> Galaxy:
    """Lay the file's measured slices out as a spiral galaxy."""
    digest = bytes.fromhex(sha256) if sha256 and len(sha256) == 64 else hashlib.sha256(structure.offsets.tobytes()).digest()
    arms = 2 + digest[0] % 4
    twist = 2.0 + digest[1] / 255.0 * 2.8
    turn = digest[2] / 255.0 * math.tau
    rng = np.random.default_rng(int.from_bytes(digest[3:11], "little"))
    n = structure.count
    order = np.arange(n, dtype=np.float32)
    fraction = (order + 0.5) / max(1, n)
    radius = 0.05 + 0.95 * fraction ** 0.78
    arm = (np.arange(n) % arms).astype(np.float32)
    level = np.clip(structure.entropy / 8.0, 0.0, 1.0).astype(np.float32)
    walls = (structure.walls if structure.walls is not None else np.zeros(n)).astype(np.float32)
    # Logarithmic spiral; dense content strays further from its arm.
    angle = turn + arm * (math.tau / arms) + twist * np.log(radius / 0.05 + 1.0)
    spread = 0.03 + 0.16 * level ** 2
    angle = angle + rng.normal(0.0, 1.0, n).astype(np.float32) * spread
    jitter_r = np.clip(radius * (1.0 + rng.normal(0.0, 0.02 + 0.04 * level, n).astype(np.float32)), 0.02, 0.985)
    positions = np.stack([np.cos(angle) * jitter_r, np.sin(angle) * jitter_r], axis=1).astype(np.float32)
    colors = _star_colors(level)
    weights = (0.16 + 0.34 * level + 1.1 * walls ** 0.9) * (1.1 - 0.4 * radius)
    flags = structure.flags.astype(np.int64)
    # Dust: each star's own colour, scattered around it.
    per = 4
    dust = np.repeat(positions, per, axis=0) + rng.normal(0.0, 1.0, (n * per, 2)).astype(np.float32) * (
        0.006 + 0.018 * np.repeat(level, per)[:, None])
    dust_colors = np.repeat(colors, per, axis=0) * 0.7 + np.array([0.42, 0.30, 0.75], dtype=np.float32) * 0.3
    dust_weights = np.repeat(0.035 + 0.05 * level, per).astype(np.float32)
    hue = QColor.fromHsvF((0.08 + digest[12] / 255.0 * 0.12) % 1.0, 0.45, 1.0)
    return Galaxy(positions, np.linalg.norm(positions, axis=1), colors.astype(np.float32), weights.astype(np.float32),
                  dust.astype(np.float32), dust_colors.astype(np.float32), dust_weights, np.linalg.norm(dust, axis=1),
                  structure.offsets, structure.entropy, flags, arms, twist, hue, digest.hex())


# -- rendering ---------------------------------------------------------------------------------


def _kernel(radius: int, sigma: float):
    span = np.arange(-radius, radius + 1)
    dx, dy = np.meshgrid(span, span)
    weight = np.exp(-(dx ** 2 + dy ** 2) / (2 * sigma ** 2))
    return dx.ravel(), dy.ravel(), (weight / weight.max()).ravel().astype(np.float32)


def _accumulate(buffer, side, xy, colors, weights, kernel) -> None:
    if xy.shape[0] == 0:
        return
    dx, dy, kw = kernel
    x = np.rint(xy[:, 0]).astype(np.int64)[:, None] + dx[None, :]
    y = np.rint(xy[:, 1]).astype(np.int64)[:, None] + dy[None, :]
    inside = (x >= 0) & (x < side) & (y >= 0) & (y < side)
    index = (y * side + x)[inside]
    strength = (weights[:, None] * kw[None, :])[inside]
    owner = np.broadcast_to(np.arange(xy.shape[0])[:, None], inside.shape)[inside]
    for channel in range(3):
        buffer[channel] += np.bincount(index, weights=strength * colors[owner, channel], minlength=side * side)


def _band_image(galaxy: Galaxy, side: int, inner: float, outer: float) -> QImage:
    """One ring of the galaxy, face-on, as additive light (premultiplied RGBA)."""
    half = side / 2
    scale = half * 0.96
    buffer = np.zeros((3, side * side), dtype=np.float64)
    pick = (galaxy.dust_radius >= inner) & (galaxy.dust_radius < outer)
    soft = max(2, round(side / 420))
    _accumulate(buffer, side, galaxy.dust[pick] * scale + half, galaxy.dust_colors[pick], galaxy.dust_weights[pick],
                _kernel(soft * 2, soft * 1.0))
    pick = (galaxy.radius >= inner) & (galaxy.radius < outer)
    sharp = max(1, round(side / 700))
    _accumulate(buffer, side, galaxy.positions[pick] * scale + half, galaxy.colors[pick], galaxy.weights[pick],
                _kernel(sharp * 2, sharp * 0.8))
    _accumulate(buffer, side, galaxy.positions[pick] * scale + half, galaxy.colors[pick], galaxy.weights[pick] * 0.10,
                _kernel(sharp * 4, sharp * 2.0))
    light = 1.0 - np.exp(-buffer * 0.9)
    rgb = (np.clip(light, 0.0, 1.0) * 255.0).astype(np.uint8)
    rgba = np.empty((side, side, 4), dtype=np.uint8)
    for channel in range(3):
        rgba[..., channel] = rgb[channel].reshape(side, side)
    rgba[..., 3] = rgb.max(axis=0).reshape(side, side)
    return QImage(rgba.data, side, side, 4 * side, QImage.Format.Format_RGBA8888_Premultiplied).copy()


def _starfield(width: int, height: int, seed: int) -> QImage:
    image = QImage(max(1, width), max(1, height), QImage.Format.Format_ARGB32_Premultiplied)
    image.fill(Qt.GlobalColor.transparent)
    painter = QPainter(image)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    rng = random.Random(seed)
    painter.setPen(Qt.PenStyle.NoPen)
    for _ in range(int(width * height / 2600)):
        level = rng.random() ** 3
        painter.setBrush(QColor(200, 214, 255, int(30 + 150 * level)))
        size = 0.4 + 1.1 * level
        painter.drawEllipse(QPointF(rng.random() * width, rng.random() * height), size, size)
    painter.end()
    return image


class GalaxyPainter:
    """Paints a galaxy at a given moment; shared by the live view and the wallpaper."""

    def __init__(self, galaxy: Galaxy):
        self.galaxy = galaxy
        self._bands: list[QImage] = []
        self._side = 0
        self._stars: QImage | None = None
        self._stars_size = QSize()
        rng = random.Random(galaxy.sha256)
        bright = np.argsort(-galaxy.weights)[: min(70, len(galaxy.weights))]
        self.twinkles = [(int(i), rng.uniform(1.2, 3.4), rng.uniform(0, math.tau)) for i in bright]

    def prepare(self, side: int) -> None:
        side = max(64, int(side))
        if side != self._side:
            self._side = side
            self._bands = [_band_image(self.galaxy, side, inner, outer) for inner, outer, _speed in BANDS]

    def angles(self, elapsed: float, offset: float) -> list[float]:
        spin = math.tau * elapsed / TURN_SECONDS
        return [offset + spin * speed for _inner, _outer, speed in BANDS]

    def band_of(self, radius: np.ndarray) -> np.ndarray:
        band = np.zeros(radius.shape, dtype=np.int64)
        band[radius >= BANDS[1][0] + 0.02] = 1
        band[radius >= BANDS[2][0] + 0.02] = 2
        return band

    def screen(self, center: QPointF, size: float, tilt: float, angles: list[float], positions: np.ndarray) -> np.ndarray:
        """Face-on positions -> screen points, each turned with its band."""
        radius = np.linalg.norm(positions, axis=1)
        band = self.band_of(radius)
        theta = np.array(angles, dtype=np.float32)[band]
        c, s = np.cos(theta), np.sin(theta)
        x = positions[:, 0] * c - positions[:, 1] * s
        y = positions[:, 0] * s + positions[:, 1] * c
        half = size / 2 * 0.96
        return np.stack([center.x() + x * half, center.y() + y * half * tilt], axis=1)

    def paint(self, painter: QPainter, rect: QRectF, *, elapsed: float, offset: float = 0.0, tilt: float = 0.58,
              zoom: float = 1.0, bang: float = 1.0, pulse_time: float | None = None, highlight: int | None = None) -> np.ndarray:
        """Draw the galaxy; returns the screen positions of its stars (for hovering)."""
        galaxy = self.galaxy
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
        if self._stars is None or self._stars_size != rect.size().toSize():
            self._stars_size = rect.size().toSize()
            self._stars = _starfield(self._stars_size.width(), self._stars_size.height(), int(galaxy.sha256[:8], 16))
        sky = QRadialGradient(rect.center(), max(rect.width(), rect.height()) * 0.75)
        sky.setColorAt(0.0, QColor("#0b0a18"))
        sky.setColorAt(0.6, QColor("#05060c"))
        sky.setColorAt(1.0, QColor("#020205"))
        painter.fillRect(rect, sky)
        painter.drawImage(rect.topLeft(), self._stars)
        center = rect.center()
        size = min(rect.width() * 0.92, rect.height() / max(0.35, tilt) * 0.84) * zoom
        size = min(size, max(rect.width(), rect.height()) * 1.6 * zoom)
        angles = self.angles(elapsed, offset)
        # The disc's faint haze and the core's light, under everything.
        painter.save()
        painter.translate(center)
        painter.scale(1.0, tilt)
        painter.setPen(Qt.PenStyle.NoPen)
        for reach, stops in (
            (size * 0.50, ((0.0, 0.10), (0.6, 0.035), (1.0, 0.0))),  # the disc
            (size * 0.20, ((0.0, 0.55), (0.3, 0.18), (1.0, 0.0))),  # the bulge
        ):
            light = QRadialGradient(QPointF(0, 0), reach)
            for position, strength in stops:
                color = QColor(galaxy.core_hue)
                color.setAlphaF(strength * bang)
                light.setColorAt(position, color)
            painter.setBrush(light)
            painter.drawEllipse(QPointF(0, 0), reach, reach)
        painter.restore()
        # The three bands, each turned at its own speed; the bang grows them from the core outward.
        painter.setCompositionMode(QPainter.CompositionMode.CompositionMode_Plus)
        for index, image in enumerate(self._bands):
            grow = min(1.0, max(0.0, (bang - index * 0.18) / 0.64))
            if grow <= 0:
                continue
            grow = 1 - (1 - grow) ** 3
            painter.save()
            painter.translate(center)
            painter.scale(grow, grow * tilt)
            painter.rotate(math.degrees(angles[index] + (1 - grow) * 1.6))
            painter.setOpacity(grow)
            painter.drawImage(QRectF(-size / 2, -size / 2, size, size), image)
            painter.restore()
        painter.setOpacity(1.0)
        painter.setCompositionMode(QPainter.CompositionMode.CompositionMode_SourceOver)
        points = self.screen(center, size, tilt, angles, galaxy.positions)
        if bang >= 1.0:
            self._paint_twinkles(painter, points, elapsed)
            self._paint_supernovas(painter, points, size, pulse_time if pulse_time is not None else elapsed)
        # The heart: a small, hot, white core over the arms.
        heart = QRadialGradient(center, size * 0.05)
        heart.setColorAt(0.0, QColor(255, 250, 238, int(235 * bang)))
        heart.setColorAt(0.35, QColor(255, 228, 180, int(120 * bang)))
        heart.setColorAt(1.0, QColor(255, 220, 170, 0))
        painter.save()
        painter.translate(center)
        painter.scale(1.0, tilt)
        painter.translate(-center)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(heart)
        painter.drawEllipse(center, size * 0.05, size * 0.05)
        painter.restore()
        if highlight is not None and 0 <= highlight < len(points):
            spot = QPointF(*points[highlight])
            painter.setPen(QPen(QColor(255, 255, 255, 220), 1.2))
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawEllipse(spot, 7, 7)
        return points

    def _paint_twinkles(self, painter: QPainter, points: np.ndarray, elapsed: float) -> None:
        painter.setPen(Qt.PenStyle.NoPen)
        for index, speed, phase in self.twinkles:
            level = 0.5 + 0.5 * math.sin(elapsed * speed + phase)
            if level < 0.55:
                continue
            spot = QPointF(*points[index])
            color = QColor.fromRgbF(*[float(c) for c in self.galaxy.colors[index]])
            color.setAlphaF(0.85 * (level - 0.55) / 0.45)
            painter.setBrush(color)
            painter.drawEllipse(spot, 1.6, 1.6)
            painter.setPen(QPen(color, 0.8))
            arm = 4.0 + 5.0 * level
            painter.drawLine(spot - QPointF(arm, 0), spot + QPointF(arm, 0))
            painter.drawLine(spot - QPointF(0, arm), spot + QPointF(0, arm))
            painter.setPen(Qt.PenStyle.NoPen)

    def supernovas(self) -> list[int]:
        """One star per flagged region run (the brightest slice of each run)."""
        flags = self.galaxy.flags
        chosen, index = [], 0
        while index < len(flags):
            if flags[index] > 0:
                end = index
                while end + 1 < len(flags) and flags[end + 1] > 0:
                    end += 1
                chosen.append(index + int(np.argmax(self.galaxy.weights[index:end + 1])))
                index = end + 1
            else:
                index += 1
        return chosen[:12]

    def _paint_supernovas(self, painter: QPainter, points: np.ndarray, size: float, elapsed: float) -> None:
        for number, index in enumerate(self.supernovas()):
            spot = QPointF(*points[index])
            color = QColor(SUPERNOVA.get(int(self.galaxy.flags[index]), TOKENS["danger"]))
            beat = 0.5 + 0.5 * math.sin(elapsed * 2.4 + number)
            reach = size * (0.016 + 0.008 * beat)
            halo = QRadialGradient(spot, reach)
            inner = QColor(color)
            inner.setAlphaF(0.75)
            outer = QColor(color)
            outer.setAlphaF(0.0)
            halo.setColorAt(0.0, QColor(255, 255, 255, 235))
            halo.setColorAt(0.12, inner)
            halo.setColorAt(1.0, outer)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(halo)
            painter.drawEllipse(spot, reach, reach)
            spike = QColor(color)
            spike.setAlphaF(0.55 + 0.35 * beat)
            painter.setPen(QPen(spike, 1.0))
            arm = reach * 1.9
            painter.drawLine(spot - QPointF(arm, 0), spot + QPointF(arm, 0))
            painter.drawLine(spot - QPointF(0, arm * 0.8), spot + QPointF(0, arm * 0.8))
            ring = QColor(color)
            ring.setAlphaF(0.5 * (1 - beat))
            painter.setPen(QPen(ring, 1.2))
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawEllipse(spot, reach * (1.2 + beat), reach * (1.2 + beat))


def render_wallpaper(galaxy: Galaxy, width: int, height: int, title: str, subtitle: str, family: str = "Space Grotesk") -> QImage:
    """The galaxy as a still picture (a desktop wallpaper), with a quiet caption."""
    image = QImage(width, height, QImage.Format.Format_ARGB32_Premultiplied)
    image.fill(QColor("#020205"))
    painter = QPainter(image)
    artist = GalaxyPainter(galaxy)
    artist.prepare(int(min(width, height / 0.58) * 0.92))
    artist.paint(painter, QRectF(0, 0, width, height), elapsed=18.0, tilt=0.58)
    margin = width * 0.03
    painter.setPen(QColor(236, 240, 248, 230))
    painter.setFont(QFont(family, max(12, int(height * 0.024)), QFont.Weight.DemiBold))
    painter.drawText(QRectF(margin, height - margin - height * 0.075, width - 2 * margin, height * 0.04), int(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter), title)
    painter.setPen(QColor(150, 160, 185, 200))
    painter.setFont(QFont("Consolas", max(9, int(height * 0.011))))
    painter.drawText(QRectF(margin, height - margin - height * 0.032, width - 2 * margin, height * 0.03), int(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter), subtitle)
    painter.end()
    return image


class GalaxyView(QWidget):
    """The galaxy, live: a big bang, then a slow turn. Drag to orbit and tilt, scroll to zoom."""

    starHovered = Signal(int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.artist: GalaxyPainter | None = None
        self.describe = None  # callable(star index) -> tooltip text
        self.offset = 0.0
        self.tilt = 0.58
        self.zoom = 1.0
        self.hovered: int | None = None
        self._points = np.zeros((0, 2), dtype=np.float32)
        self._born = time.monotonic()
        self._drag: QPointF | None = None
        self._timer = QTimer(self)
        self._timer.timeout.connect(self.update)
        self.setMouseTracking(True)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.setCursor(Qt.CursorShape.OpenHandCursor)

    def set_galaxy(self, galaxy: Galaxy) -> None:
        self.set_galaxy_painter(GalaxyPainter(galaxy))

    def set_galaxy_painter(self, artist: GalaxyPainter) -> None:
        """Show a galaxy (already formed, or formed on first paint); the big bang starts now."""
        self.artist = artist
        self._born = time.monotonic()
        self._sync()
        self.update()

    def elapsed(self) -> float:
        return BANG_SECONDS + 20.0 if prefers_reduced_motion() else time.monotonic() - self._born

    def bang(self) -> float:
        return min(1.0, self.elapsed() / BANG_SECONDS)

    def _sync(self) -> None:
        live = self.isVisible() and self.artist is not None and not prefers_reduced_motion()
        if live and not self._timer.isActive():
            self._timer.start(FRAME_MS)
        elif not live:
            self._timer.stop()

    def showEvent(self, event) -> None:  # noqa: N802
        super().showEvent(event)
        self._sync()

    def hideEvent(self, event) -> None:  # noqa: N802
        self._timer.stop()
        super().hideEvent(event)

    def paintEvent(self, event) -> None:  # noqa: N802
        painter = QPainter(self)
        if self.artist is None:
            painter.fillRect(self.rect(), QColor("#020205"))
            return
        rect = QRectF(self.rect())
        self.artist.prepare(int(min(rect.width(), rect.height() / 0.5) * self.devicePixelRatioF() * 0.92))
        elapsed = self.elapsed()
        # The bang starts fast and slows into the galaxy's own turn.
        swirl = -2.2 * (1 - self.bang()) ** 2
        self._points = self.artist.paint(painter, rect, elapsed=elapsed, offset=self.offset + swirl, tilt=self.tilt,
                                         zoom=self.zoom, bang=self.bang(), highlight=self.hovered)

    def mousePressEvent(self, event) -> None:  # noqa: N802
        if event.button() == Qt.MouseButton.LeftButton:
            self._drag = event.position()
            self.setCursor(Qt.CursorShape.ClosedHandCursor)

    def mouseReleaseEvent(self, event) -> None:  # noqa: N802
        self._drag = None
        self.setCursor(Qt.CursorShape.OpenHandCursor)

    def mouseMoveEvent(self, event) -> None:  # noqa: N802
        position = event.position()
        if self._drag is not None:
            delta = position - self._drag
            self._drag = position
            self.offset += delta.x() * 0.006
            self.tilt = max(0.18, min(1.0, self.tilt - delta.y() * 0.003))
            self.update()
            return
        if self._points.shape[0] == 0:
            return
        distance = (self._points[:, 0] - position.x()) ** 2 + (self._points[:, 1] - position.y()) ** 2
        nearest = int(np.argmin(distance))
        hovered = nearest if distance[nearest] <= 81.0 else None
        if hovered != self.hovered:
            self.hovered = hovered
            self.update()
        if hovered is not None:
            self.starHovered.emit(hovered)
            if self.describe is not None:
                QToolTip.showText(event.globalPosition().toPoint(), self.describe(hovered), self)
        else:
            QToolTip.hideText()

    def wheelEvent(self, event) -> None:  # noqa: N802
        self.zoom = max(0.5, min(3.0, self.zoom * (1.0 + event.angleDelta().y() / 1200.0)))
        self.update()
