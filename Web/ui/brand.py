"""The CyberScan identity: the sonar cube mark and the name in each language.

The mark is the product's own picture: a file drawn as a cube, with the one
point the sonar found inside it (a white dot and its echo rings). It is
painted here, so the rail, the window icon and the .ico file are the same
drawing at every size; below 24 px the faint inner lines and rings are left
out because they would only blur.

The name follows the interface language: "CyberScan" set in Space Grotesk,
"المسبار السيبراني" in Reem Kufi (both OFL, bundled in ui/fonts).
"""
from __future__ import annotations

import struct
from pathlib import Path

from PySide6.QtCore import QByteArray, QBuffer, QIODevice, QPointF, QRectF, QSize, Qt
from PySide6.QtGui import QColor, QIcon, QPainter, QPainterPath, QPen, QPixmap
from PySide6.QtWidgets import QSizePolicy, QWidget

NAMES = {"en": "CyberScan", "ar": "المسبار السيبراني"}
FAMILIES = {"en": "Space Grotesk", "ar": "Reem Kufi"}
TEAL = "#5EE0D0"
TEAL_ON_LIGHT = "#0F6E56"
TILE = "#0B0C0E"

# The drawing in a 64 x 64 box (same geometry as the logo study).
_HEX = [(32, 8), (52.8, 20), (52.8, 44), (32, 56), (11.2, 44), (11.2, 20)]
_FOUND = (41.0, 39.0)


def name(language: str) -> str:
    return NAMES.get(language, NAMES["en"])


def family(language: str) -> str:
    return FAMILIES.get(language, FAMILIES["en"])


def paint_mark(painter: QPainter, rect: QRectF, color: str = TEAL, dot: str = "#ffffff") -> None:
    """Draw the mark scaled into ``rect`` (kept square, centred)."""
    side = min(rect.width(), rect.height())
    scale = side / 64.0
    origin = QPointF(rect.center().x() - side / 2, rect.center().y() - side / 2)
    detailed = side >= 24

    def at(x: float, y: float) -> QPointF:
        return QPointF(origin.x() + x * scale, origin.y() + y * scale)

    painter.save()
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    hexagon = QPainterPath(at(*_HEX[0]))
    for point in _HEX[1:]:
        hexagon.lineTo(at(*point))
    hexagon.closeSubpath()
    stroke = QColor(color)
    # Thicker strokes when small, so the outline survives at 16 px.
    width = max(1.4, (3.2 if detailed else 4.6) * scale)
    painter.setBrush(Qt.BrushStyle.NoBrush)
    if detailed:
        faint = QColor(stroke)
        faint.setAlphaF(0.45)
        painter.setPen(QPen(faint, max(1.0, 2.0 * scale), Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
        painter.drawLine(at(11.2, 20), at(32, 32))
        painter.drawLine(at(52.8, 20), at(32, 32))
        painter.drawLine(at(32, 32), at(32, 56))
        painter.setClipPath(hexagon)
        for radius, opacity, line in ((7.5, 0.85, 1.8), (13.0, 0.4, 1.6)):
            ring = QColor(stroke)
            ring.setAlphaF(opacity)
            painter.setPen(QPen(ring, max(1.0, line * scale)))
            painter.drawEllipse(at(*_FOUND), radius * scale, radius * scale)
        painter.setClipping(False)
    painter.setPen(QPen(stroke, width, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
    painter.drawPath(hexagon)
    painter.setPen(Qt.PenStyle.NoPen)
    painter.setBrush(QColor(dot))
    radius = (3.4 if detailed else 4.6) * scale
    painter.drawEllipse(at(*_FOUND), radius, radius)
    painter.restore()


def app_pixmap(size: int) -> QPixmap:
    """The app icon: the mark on a dark rounded tile."""
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setPen(Qt.PenStyle.NoPen)
    painter.setBrush(QColor(TILE))
    painter.drawRoundedRect(QRectF(0, 0, size, size), size * 0.22, size * 0.22)
    inset = size * (0.14 if size >= 32 else 0.06)
    paint_mark(painter, QRectF(inset, inset, size - 2 * inset, size - 2 * inset))
    painter.end()
    return pixmap


ICON_SIZES = (16, 20, 24, 32, 40, 48, 64, 128, 256)


def app_icon() -> QIcon:
    icon = QIcon()
    for size in ICON_SIZES:
        icon.addPixmap(app_pixmap(size))
    return icon


def write_ico(path: Path) -> Path:
    """A multi-size Windows .ico (PNG entries), for the executable and shortcuts."""
    images = []
    for size in ICON_SIZES:
        data = QByteArray()
        buffer = QBuffer(data)
        buffer.open(QIODevice.OpenModeFlag.WriteOnly)
        app_pixmap(size).save(buffer, "PNG")
        images.append((size, bytes(data)))
    header = struct.pack("<HHH", 0, 1, len(images))
    offset = 6 + 16 * len(images)
    entries, blobs = b"", b""
    for size, blob in images:
        entries += struct.pack("<BBBBHHII", size % 256, size % 256, 0, 0, 1, 32, len(blob), offset)
        offset += len(blob)
        blobs += blob
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(header + entries + blobs)
    return path


class SonarMark(QWidget):
    """The mark, painted at any size (used in the rail next to the name)."""

    def __init__(self, size: int = 36, parent=None):
        super().__init__(parent)
        self.setFixedSize(size, size)
        self.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        self.setAccessibleName("CyberScan")

    def sizeHint(self) -> QSize:  # noqa: N802
        return self.size()

    def paintEvent(self, event) -> None:  # noqa: N802
        painter = QPainter(self)
        paint_mark(painter, QRectF(self.rect()))
