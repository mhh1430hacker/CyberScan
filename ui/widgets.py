"""Small painted building blocks shared by every screen.

All of them are presentation only. Painted widgets carry an accessible name
and description in the interface language, mirror themselves in RTL, and
animate only when their value changes (never on an idle loop).
"""
from __future__ import annotations

from PySide6.QtCore import (
    QEasingCurve,
    QEvent,
    QPoint,
    QPointF,
    QRect,
    QRectF,
    QSize,
    Qt,
    QVariantAnimation,
)
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
from PySide6.QtWidgets import QFrame, QLabel, QLayout, QSizePolicy, QWidget

from ui.file_kind import FileKind, KINDS
from ui.icons import glyph, icon_font
from ui.motion import EMPHASIS_MS, VIEW_MS, prefers_reduced_motion
from ui.theme import TOKENS, alpha, mix, tone_color, ui_font


class ElidedLabel(QLabel):
    """One line that shortens with an ellipsis instead of widening its parent."""

    def __init__(self, text: str = "", parent=None, *, mode=Qt.TextElideMode.ElideRight, file_name: bool = False):
        super().__init__(parent)
        self._full = ""
        self._mode = mode
        self._file_name = file_name  # shorten without ever hiding the extension (ui.names)
        self.setMinimumWidth(24)
        self.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        self.setText(text)

    def setText(self, text: str) -> None:  # noqa: N802
        self._full = text or ""
        self.setToolTip(self._full if len(self._full) > 24 else "")
        self._elide()

    def full_text(self) -> str:
        return self._full

    def _elide(self) -> None:
        width = max(10, self.contentsRect().width())
        metrics = QFontMetrics(self.font())
        if self._file_name:
            from ui.names import elide_to_width

            super().setText(elide_to_width(self._full, width, metrics.horizontalAdvance))
        else:
            super().setText(metrics.elidedText(self._full, self._mode, width))

    def resizeEvent(self, event) -> None:  # noqa: N802
        super().resizeEvent(event)
        self._elide()

    def sizeHint(self) -> QSize:  # noqa: N802
        hint = super().sizeHint()
        return QSize(min(hint.width(), 240), hint.height())

    def minimumSizeHint(self) -> QSize:  # noqa: N802
        return QSize(24, super().minimumSizeHint().height())


class FlowLayout(QLayout):
    """Buttons in a row that wraps to the next line instead of widening the page."""

    def __init__(self, parent=None, spacing: int = 10):
        super().__init__(parent)
        self._items = []
        self._spacing = spacing
        self.setContentsMargins(0, 0, 0, 0)

    def addItem(self, item) -> None:  # noqa: N802
        self._items.append(item)

    def count(self) -> int:
        return len(self._items)

    def itemAt(self, index):  # noqa: N802
        return self._items[index] if 0 <= index < len(self._items) else None

    def takeAt(self, index):  # noqa: N802
        return self._items.pop(index) if 0 <= index < len(self._items) else None

    def expandingDirections(self):  # noqa: N802
        return Qt.Orientation(0)

    def hasHeightForWidth(self) -> bool:  # noqa: N802
        return True

    def heightForWidth(self, width: int) -> int:  # noqa: N802
        return self._arrange(QRect(0, 0, width, 0), apply=False)

    def setGeometry(self, rect) -> None:  # noqa: N802
        super().setGeometry(rect)
        self._arrange(rect, apply=True)

    def sizeHint(self) -> QSize:  # noqa: N802
        return self.minimumSize()

    def minimumSize(self) -> QSize:  # noqa: N802
        size = QSize()
        for item in self._items:
            size = size.expandedTo(item.minimumSize())
        return size

    def _arrange(self, rect: QRect, *, apply: bool) -> int:
        rtl = self.parentWidget() is not None and self.parentWidget().layoutDirection() == Qt.LayoutDirection.RightToLeft
        x, y, line = 0, rect.y(), 0
        rows: list[list[tuple]] = [[]]
        for item in self._items:
            if item.widget() is not None and item.widget().isHidden():
                continue
            hint = item.sizeHint()
            if x and x + hint.width() > rect.width():
                y += line + self._spacing
                x, line = 0, 0
                rows.append([])
            rows[-1].append((item, x, y, hint))
            x += hint.width() + self._spacing
            line = max(line, hint.height())
        if apply:
            for row in rows:
                for item, ix, iy, hint in row:
                    left = rect.right() - ix - hint.width() + 1 if rtl else rect.x() + ix
                    item.setGeometry(QRect(QPoint(left, iy), hint))
        return y + line - rect.y()


def card(object_name: str = "card") -> QFrame:
    frame = QFrame()
    frame.setObjectName(object_name)
    return frame


def label(text: str = "", role: str = "", *, wrap: bool = False) -> QLabel:
    widget = QLabel(text)
    if role:
        widget.setObjectName(role)
    widget.setWordWrap(wrap)
    return widget


class Pill(QLabel):
    """A short tone-coloured tag: symbol plus word, never colour alone."""

    def __init__(self, text: str = "", tone: str = "neutral", parent=None):
        super().__init__(parent)
        self.set_pill(text, tone)

    def set_pill(self, text: str, tone: str) -> None:
        color = QColor(tone_color(tone))
        self.setText(text)
        self.setStyleSheet(
            f"QLabel {{ color: {color.name()}; background: {alpha(color, 0.10).name(QColor.NameFormat.HexArgb)};"
            f" border: 1px solid {alpha(color, 0.30).name(QColor.NameFormat.HexArgb)}; border-radius: 10px;"
            " padding: 2px 9px; font-size: 12px; font-weight: 600; }"
        )


class KindTile(QWidget):
    """The target's kind: a rounded tile in its hue with its icon."""

    def __init__(self, size: int = 48, parent=None):
        super().__init__(parent)
        self._kind = KINDS["file"]
        self._color = QColor(self._kind.hue)
        self._tween = QVariantAnimation(self)
        self._tween.setDuration(VIEW_MS)
        self._tween.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._tween.valueChanged.connect(self._on_color)
        self.setFixedSize(size, size)

    def kind(self) -> FileKind:
        return self._kind

    def set_kind(self, kind: FileKind, *, animate: bool = True) -> None:
        self._kind = kind
        self.setAccessibleName(kind.label)
        target = QColor(kind.hue)
        if animate and self.isVisible() and not prefers_reduced_motion():
            self._tween.stop()
            self._tween.setStartValue(self._color)
            self._tween.setEndValue(target)
            self._tween.start()
        else:
            self._color = target
            self.update()

    def _on_color(self, value) -> None:
        self._color = QColor(value)
        self.update()

    def paintEvent(self, event) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        rect = QRectF(self.rect()).adjusted(1, 1, -1, -1)
        radius = rect.width() * 0.28
        gradient = QLinearGradient(rect.topLeft(), rect.bottomRight())
        gradient.setColorAt(0, alpha(self._color, 0.26))
        gradient.setColorAt(1, alpha(self._color, 0.08))
        painter.setBrush(gradient)
        painter.setPen(QPen(alpha(self._color, 0.55), 1.2))
        painter.drawRoundedRect(rect, radius, radius)
        painter.setFont(icon_font(rect.width() * 0.46))
        painter.setPen(self._color)
        painter.drawText(rect, int(Qt.AlignmentFlag.AlignCenter), glyph(self._kind.icon))


class Medallion(QWidget):
    """The verdict mark: a glowing ring with the verdict's symbol.

    ``reveal()`` grows it in once (the single emphasised moment of a scan).
    """

    def __init__(self, size: int = 120, parent=None):
        super().__init__(parent)
        self.setFixedSize(size, size)
        self._symbol = "?"
        self._color = QColor(TOKENS["neutral"])
        self._progress = 1.0
        self._animation = QVariantAnimation(self)
        self._animation.setDuration(EMPHASIS_MS)
        self._animation.setStartValue(0.0)
        self._animation.setEndValue(1.0)
        self._animation.setEasingCurve(QEasingCurve.Type.OutBack)
        self._animation.valueChanged.connect(self._on_progress)
        self._pulse = 1.0  # a halo leaves the ring once, on reveal
        self._pulse_animation = QVariantAnimation(self)
        self._pulse_animation.setDuration(1100)
        self._pulse_animation.setStartValue(0.0)
        self._pulse_animation.setEndValue(1.0)
        self._pulse_animation.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._pulse_animation.valueChanged.connect(self._on_pulse)

    def _on_pulse(self, value) -> None:
        self._pulse = float(value)
        self.update()

    def set_verdict(self, symbol: str, color: str, name: str) -> None:
        self._symbol = symbol
        self._color = QColor(color)
        self.setAccessibleName(name)
        self.update()

    def reveal(self) -> None:
        if prefers_reduced_motion():
            self._progress = 1.0
            self.update()
            return
        self._animation.stop()
        self._on_progress(0.0)
        self._animation.start()
        self._pulse_animation.stop()
        self._on_pulse(0.0)
        self._pulse_animation.start()

    def _on_progress(self, value) -> None:
        self._progress = float(value)
        self.update()

    def paintEvent(self, event) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        side = min(self.width(), self.height())
        center = QPointF(self.width() / 2, self.height() / 2)
        scale = 0.80 + 0.20 * max(0.0, self._progress)
        ring = side / 2 * 0.70 * scale
        glow = QRadialGradient(center, ring * 1.45)
        glow.setColorAt(0.0, alpha(self._color, 0.22))
        glow.setColorAt(1.0, alpha(self._color, 0.0))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(glow)
        painter.drawEllipse(center, ring * 1.45, ring * 1.45)
        painter.setBrush(mix(TOKENS["surface"], self._color, 0.12))
        painter.setPen(QPen(alpha(self._color, 0.95), 1.6))
        painter.drawEllipse(center, ring, ring)
        painter.setPen(QPen(alpha(self._color, 0.25), 1))
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawEllipse(center, ring * 1.22, ring * 1.22)
        if 0.0 < self._pulse < 1.0:
            halo = ring * (1.0 + 0.42 * self._pulse)
            painter.setPen(QPen(alpha(self._color, 0.55 * (1.0 - self._pulse)), 2.0 * (1.0 - self._pulse) + 0.6))
            painter.drawEllipse(center, halo, halo)
        painter.setFont(ui_font(ring * 0.82, 600))
        painter.setPen(self._color)
        painter.drawText(QRectF(center.x() - ring, center.y() - ring, ring * 2, ring * 2), int(Qt.AlignmentFlag.AlignCenter), self._symbol)


class LevelMeter(QWidget):
    """Three steps: low, some, high. ``level`` None draws an unknown state."""

    LABELS = ("Low", "Some", "High")
    COLORS = (TOKENS["ok"], TOKENS["warn"], TOKENS["danger"])

    def __init__(self, parent=None):
        super().__init__(parent)
        self.level: int | None = None
        self._labels = list(self.LABELS)
        self._unknown = "Unknown"
        self._fill = 1.0
        self._fill_animation = QVariantAnimation(self)
        self._fill_animation.setDuration(EMPHASIS_MS + 260)
        self._fill_animation.setStartValue(0.0)
        self._fill_animation.setEndValue(1.0)
        self._fill_animation.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._fill_animation.valueChanged.connect(self._on_fill)
        self.setMinimumSize(240, 54)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

    def set_level(self, level: int | None, labels: list[str], unknown: str, name: str) -> None:
        self.level = level
        self._labels = labels
        self._unknown = unknown
        self.setAccessibleName(name)
        self.setAccessibleDescription(labels[level - 1] if level else unknown)
        self.update()

    def _on_fill(self, value) -> None:
        self._fill = float(value)
        self.update()

    def reveal(self) -> None:
        """Fill the active bars in order, once."""
        if prefers_reduced_motion() or not self.level:
            self._on_fill(1.0)
            return
        self._fill_animation.stop()
        self._on_fill(0.0)  # the first frame starts empty, not full
        self._fill_animation.start()

    def sizeHint(self) -> QSize:  # noqa: N802
        return QSize(360, 54)

    def paintEvent(self, event) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        rtl = self.layoutDirection() == Qt.LayoutDirection.RightToLeft
        gap = 6.0
        width = (self.width() - gap * 2) / 3
        painter.setFont(ui_font(12, 500))
        for index in range(3):
            slot = 2 - index if rtl else index
            x = slot * (width + gap)
            bar = QRectF(x, 8, width, 5)
            active = self.level is not None and index < self.level
            color = QColor(self.COLORS[self.level - 1]) if active and self.level else QColor(TOKENS["line_strong"])
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor(TOKENS["line_strong"]))
            painter.drawRoundedRect(bar, 2.5, 2.5)
            if active:
                share = min(1.0, max(0.0, self._fill * self.level - index))
                if share > 0:
                    filled = QRectF(bar.right() - bar.width() * share if rtl else bar.left(), bar.top(), bar.width() * share, bar.height())
                    painter.setBrush(color)
                    painter.drawRoundedRect(filled, 2.5, 2.5)
            current = self.level is not None and index == self.level - 1
            painter.setPen(QColor(TOKENS["text"] if current else TOKENS["text_mute"]))
            painter.drawText(
                QRectF(x, 22, width, 24),
                int(Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop),
                self._labels[index],
            )


class PlaceBars(QWidget):
    """Horizontal bars: where the findings were, with their real counts."""

    ROW = 30

    def __init__(self, parent=None):
        super().__init__(parent)
        self.rows: list[tuple[str, int, str]] = []
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

    def set_rows(self, rows: list[tuple[str, int, str]], name: str) -> None:
        self.rows = list(rows)
        self.setAccessibleName(name)
        self.setAccessibleDescription("; ".join(f"{label}: {count}" for label, count, _tone in rows))
        self.setFixedHeight(max(1, len(self.rows)) * self.ROW)
        self.update()

    def paintEvent(self, event) -> None:  # noqa: N802
        if not self.rows:
            return
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        rtl = self.layoutDirection() == Qt.LayoutDirection.RightToLeft
        peak = max(count for _label, count, _tone in self.rows) or 1
        label_width = min(220.0, self.width() * 0.45)
        count_width = 34.0
        track = self.width() - label_width - count_width - 16
        font = QFont(self.font())
        font.setPixelSize(13)
        painter.setFont(font)
        for index, (text, count, tone) in enumerate(self.rows):
            y = index * self.ROW
            if rtl:
                label_rect = QRectF(self.width() - label_width, y, label_width, self.ROW)
                bar_left = count_width + 8
                count_rect = QRectF(0, y, count_width, self.ROW)
                text_flags = Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
                count_flags = Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter
            else:
                label_rect = QRectF(0, y, label_width, self.ROW)
                bar_left = label_width + 8
                count_rect = QRectF(self.width() - count_width, y, count_width, self.ROW)
                text_flags = Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter
                count_flags = Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
            painter.setPen(QColor(TOKENS["text_dim"]))
            elided = QFontMetrics(font).elidedText(text, Qt.TextElideMode.ElideRight, int(label_width - 6))
            painter.drawText(label_rect, int(text_flags), elided)
            track_rect = QRectF(bar_left, y + self.ROW / 2 - 4, track, 8)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor(TOKENS["surface_3"]))
            painter.drawRoundedRect(track_rect, 4, 4)
            fill = track * count / peak
            fill_rect = (
                QRectF(track_rect.right() - fill, track_rect.top(), fill, 8)
                if rtl
                else QRectF(track_rect.left(), track_rect.top(), fill, 8)
            )
            painter.setBrush(QColor(tone_color(tone)))
            painter.drawRoundedRect(fill_rect, 4, 4)
            painter.setPen(QColor(TOKENS["text"]))
            painter.drawText(count_rect, int(count_flags), str(count))


class Ambient(QWidget):
    """A soft glow in the current kind's hue, painted behind a stage.

    It changes only when the hue changes (a short colour tween); it never
    animates on its own.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self._color = QColor(TOKENS["accent"])
        self._strength = 0.10
        self._tween = QVariantAnimation(self)
        self._tween.setDuration(EMPHASIS_MS)
        self._tween.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._tween.valueChanged.connect(self._on_color)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        if parent is not None:
            # Always cover the whole parent, whatever resizes it.
            parent.installEventFilter(self)
            self.setGeometry(parent.rect())
            self.lower()

    def eventFilter(self, watched, event) -> bool:  # noqa: N802
        if watched is self.parentWidget() and event.type() in (QEvent.Type.Resize, QEvent.Type.Show):
            self.setGeometry(watched.rect())
            self.lower()
        return False

    def hue(self) -> QColor:
        return QColor(self._color)

    def set_hue(self, color: str, strength: float = 0.10) -> None:
        self._strength = strength
        target = QColor(color)
        if self.isVisible() and not prefers_reduced_motion():
            self._tween.stop()
            self._tween.setStartValue(self._color)
            self._tween.setEndValue(target)
            self._tween.start()
        else:
            self._color = target
            self.update()

    def _on_color(self, value) -> None:
        self._color = QColor(value)
        self.update()

    def paintEvent(self, event) -> None:  # noqa: N802
        """Glass panel: a faint white layer, a hairline edge, and a thin
        signal line along the top in the current hue."""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        rect = QRectF(self.rect()).adjusted(0.5, 0.5, -0.5, -0.5)
        radius = 16.0
        path = QPainterPath()
        path.addRoundedRect(rect, radius, radius)
        painter.setClipPath(path)
        painter.fillRect(rect, QColor(16, 17, 19, 205))
        painter.fillRect(rect, QColor(255, 255, 255, 7))
        rtl = self.layoutDirection() == Qt.LayoutDirection.RightToLeft
        anchor = QPointF(rect.width() * (0.15 if rtl else 0.85), 0.0)
        glow = QRadialGradient(anchor, max(rect.width(), rect.height()) * 0.6)
        glow.setColorAt(0.0, alpha(self._color, self._strength * 0.9))
        glow.setColorAt(1.0, alpha(self._color, 0.0))
        painter.fillRect(rect, glow)
        line = QLinearGradient(rect.left(), 0, rect.right(), 0)
        line.setColorAt(0.0, alpha(self._color, 0.0))
        line.setColorAt(0.85 if not rtl else 0.15, alpha(self._color, 0.9))
        line.setColorAt(1.0, alpha(self._color, 0.0))
        painter.fillRect(QRectF(rect.left() + radius, rect.top(), rect.width() - 2 * radius, 1.2), line)
        painter.setClipping(False)
        painter.setPen(QPen(QColor(255, 255, 255, 20), 1))
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawRoundedRect(rect, radius, radius)
