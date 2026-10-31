"""Icons: Segoe Fluent Icons when installed, plain symbols otherwise.

Code points were checked by rendering them, not taken from memory.
"""
from __future__ import annotations

import tempfile
from functools import lru_cache
from pathlib import Path

from PySide6.QtCore import QRectF, Qt
from PySide6.QtGui import QColor, QFont, QFontDatabase, QIcon, QPainter, QPixmap

ICON_FONT = "Segoe Fluent Icons"
ICONS = {
    "program": ("", "▣"),
    "script": ("", "›"),
    "document": ("", "▤"),
    "archive": ("", "▦"),
    "media": ("", "◩"),
    "textfile": ("", "≡"),
    "file": ("", "▢"),
    "link": ("", "⧉"),
    "tag": ("", "#"),
    "search": ("", "⌕"),
    "pulse": ("", "∿"),
    "layers": ("", "◇"),
    "globe": ("", "◍"),
    "settings": ("", "⚙"),
    "info": ("", "ⓘ"),
    "history": ("", "◴"),
    "shield": ("", "◈"),
    "close": ("", "✕"),
    "check": ("", "✓"),
    "warning": ("", "!"),
    "error": ("", "!"),
    "back": ("", "←"),
    "more": ("", "…"),
    "copy": ("", "⧉"),
    "delete": ("", "✕"),
    "save": ("", "↓"),
    "open": ("", "↗"),
    "folder": ("", "▥"),
    "language": ("", "A"),
    "lock": ("", "◉"),
    "eye": ("", "◉"),
    "drop": ("", "↓"),
    "spark": ("", "✦"),
    "key": ("", "⚿"),
}


@lru_cache(maxsize=1)
def icon_font_available() -> bool:
    return ICON_FONT in QFontDatabase.families()


def glyph(name: str) -> str:
    fluent, fallback = ICONS.get(name, ("", "●"))
    return fluent if icon_font_available() and fluent else fallback


def icon_font(pixels: float) -> QFont:
    font = QFont(ICON_FONT if icon_font_available() else "Segoe UI Symbol")
    font.setPixelSize(max(1, round(pixels)))
    return font


def glyph_pixmap(name: str, color: str | QColor, size: int = 18) -> QPixmap:
    ratio = 2.0
    pixmap = QPixmap(int(size * ratio), int(size * ratio))
    pixmap.setDevicePixelRatio(ratio)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setRenderHint(QPainter.RenderHint.TextAntialiasing)
    painter.setFont(icon_font(size * 0.86))
    painter.setPen(QColor(color))
    painter.drawText(QRectF(0, 0, size, size), int(Qt.AlignmentFlag.AlignCenter), glyph(name))
    painter.end()
    return pixmap


def glyph_icon(name: str, color: str, size: int = 18) -> QIcon:
    return QIcon(glyph_pixmap(name, color, size))


def glyph_file(name: str, color: str, size: int = 14) -> str:
    """A glyph rendered to a cached PNG, for stylesheet ``image:`` rules."""
    folder = Path(tempfile.gettempdir()) / "cyberscan-ui"
    folder.mkdir(exist_ok=True)
    path = folder / f"{name}-{color.lstrip('#')}-{size}.png"
    if not path.is_file():
        glyph_pixmap(name, color, size).save(str(path))
    return path.as_posix()
