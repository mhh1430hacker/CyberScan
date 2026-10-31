"""The side rail: your scans, and nothing else.

Each saved scan is a card: the target's kind tile in its hue, its name, when
it ran and its verdict as a symbol and a word. Cards are grouped by day.
Clicking one opens that scan's result; right-click (or the context-menu key)
offers the saved report, export and removal.

The rail shows what the app already saved; it never re-scans anything. The
verdict on a card is the same coverage-aware verdict the result screen shows
(the window reads it from the saved report), so a scan that did not finish
is never listed as low risk.
"""
from __future__ import annotations

from dataclasses import dataclass

from PySide6.QtCore import QEasingCurve, QPoint, QRectF, QSize, Qt, QVariantAnimation, Signal
from PySide6.QtGui import QColor, QFont, QFontMetrics, QLinearGradient, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import (
    QAbstractButton,
    QFrame,
    QHBoxLayout,
    QLineEdit,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from ui.copy import count_phrase, tr
from ui.file_kind import FileKind
from ui.icons import glyph, glyph_pixmap, icon_font
from ui.motion import prefers_reduced_motion
from ui.theme import TOKENS, alpha, mix, tone_color, ui_font
from ui.widgets import label

GROUPS = ("Today", "Yesterday", "This week", "Earlier")


@dataclass(frozen=True)
class RailItem:
    record_id: str
    name: str
    kind: FileKind
    when: str
    group: str
    verdict_key: str
    verdict_word: str
    symbol: str
    tone: str
    search_text: str


class BrandMark(QWidget):
    def __init__(self, size: int = 36, parent=None):
        super().__init__(parent)
        self.setFixedSize(size, size)

    def paintEvent(self, event) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        side = float(self.width())
        gradient = QLinearGradient(0, 0, side, side)
        gradient.setColorAt(0.0, QColor("#1f5c55"))
        gradient.setColorAt(1.0, QColor("#0e1d26"))
        painter.setBrush(gradient)
        painter.setPen(QPen(QColor("#3b8277"), 1))
        painter.drawRoundedRect(QRectF(0.5, 0.5, side - 1, side - 1), side * 0.3, side * 0.3)
        s = side / 42.0
        shield = QPainterPath()
        shield.moveTo(21 * s, 8 * s)
        shield.lineTo(31 * s, 12 * s)
        shield.lineTo(30 * s, 23 * s)
        shield.cubicTo(29 * s, 29 * s, 25 * s, 32 * s, 21 * s, 34 * s)
        shield.cubicTo(17 * s, 32 * s, 13 * s, 29 * s, 12 * s, 23 * s)
        shield.lineTo(11 * s, 12 * s)
        shield.closeSubpath()
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.setPen(QPen(QColor(TOKENS["accent"]), 1.8 * s, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
        painter.drawPath(shield)
        painter.drawEllipse(QRectF(18 * s, 17 * s, 6 * s, 6 * s))


class MixBar(QWidget):
    """How many saved scans have each verdict, as one thin stacked bar."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.segments: list[tuple[int, str]] = []
        self.setFixedHeight(6)

    def set_segments(self, segments: list[tuple[int, str]], description: str) -> None:
        self.segments = [(count, color) for count, color in segments if count > 0]
        self.setAccessibleDescription(description)
        self.update()

    def paintEvent(self, event) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        rect = QRectF(self.rect())
        clip = QPainterPath()
        clip.addRoundedRect(rect, 3, 3)
        painter.setClipPath(clip)
        painter.fillRect(rect, QColor(TOKENS["surface_3"]))
        total = sum(count for count, _color in self.segments)
        if not total:
            return
        rtl = self.layoutDirection() == Qt.LayoutDirection.RightToLeft
        x = rect.right() if rtl else rect.left()
        for count, color in self.segments:
            width = rect.width() * count / total
            segment = QRectF(x - width if rtl else x, rect.top(), width, rect.height())
            painter.fillRect(segment.adjusted(0, 0, -1 if not rtl else 0, 0), QColor(color))
            x = x - width if rtl else x + width


class HistoryCard(QAbstractButton):
    menuRequested = Signal(str, QPoint)

    HEIGHT = 40

    def __init__(self, item: RailItem, parent=None):
        super().__init__(parent)
        self.item = item
        self.setCheckable(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.setFixedHeight(self.HEIGHT)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.setAccessibleName(f"{item.verdict_word}: {item.name}, {item.when}")
        self.setToolTip(f"{item.name} — {item.symbol} {item.verdict_word} · {item.when}")
        self._hover = False
        self._flash = 0.0
        self._flash_animation = QVariantAnimation(self)
        self._flash_animation.setDuration(1600)
        self._flash_animation.setStartValue(1.0)
        self._flash_animation.setEndValue(0.0)
        self._flash_animation.setEasingCurve(QEasingCurve.Type.InCubic)
        self._flash_animation.valueChanged.connect(self._on_flash)

    def flash(self) -> None:
        """Mark a newly added scan once, so the eye finds where it went."""
        if prefers_reduced_motion():
            return
        self._flash_animation.start()

    def _on_flash(self, value) -> None:
        self._flash = float(value)
        self.update()

    def sizeHint(self) -> QSize:  # noqa: N802
        return QSize(260, self.HEIGHT)

    def enterEvent(self, event) -> None:  # noqa: N802
        self._hover = True
        self.update()
        super().enterEvent(event)

    def leaveEvent(self, event) -> None:  # noqa: N802
        self._hover = False
        self.update()
        super().leaveEvent(event)

    def contextMenuEvent(self, event) -> None:  # noqa: N802
        self.menuRequested.emit(self.item.record_id, event.globalPos())

    def paintEvent(self, event) -> None:  # noqa: N802
        """One line, Linear-style: kind icon, name, time, verdict mark."""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setRenderHint(QPainter.RenderHint.TextAntialiasing)
        rtl = self.layoutDirection() == Qt.LayoutDirection.RightToLeft
        rect = QRectF(self.rect()).adjusted(2, 2, -2, -2)
        verdict = QColor(tone_color(self.item.tone))
        hue = QColor(self.item.kind.hue)
        if self.isChecked():
            painter.setBrush(QColor(255, 255, 255, 16))
        elif self._hover:
            painter.setBrush(QColor(255, 255, 255, 9))
        else:
            painter.setBrush(Qt.BrushStyle.NoBrush)
        if self._flash > 0:
            painter.setBrush(alpha(hue, 0.22 * self._flash))
        painter.setPen(QPen(QColor(TOKENS["accent"]), 1.5) if self.hasFocus() else Qt.PenStyle.NoPen)
        painter.drawRoundedRect(rect, 7, 7)
        if self.isChecked():
            bar = QRectF(rect.right() - 2.5, rect.top() + 9, 2.5, rect.height() - 18) if rtl else QRectF(rect.left(), rect.top() + 9, 2.5, rect.height() - 18)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(verdict)
            painter.drawRoundedRect(bar, 1.2, 1.2)

        icon = QRectF(rect.right() - 30, rect.top(), 22, rect.height()) if rtl else QRectF(rect.left() + 10, rect.top(), 22, rect.height())
        painter.setFont(icon_font(15))
        painter.setPen(hue)
        painter.drawText(icon, int(Qt.AlignmentFlag.AlignCenter), glyph(self.item.kind.icon))

        meta_font = ui_font(11.5)
        metrics = QFontMetrics(meta_font)
        mark = self.item.symbol
        mark_width = 14.0
        when_width = min(118.0, metrics.horizontalAdvance(self.item.when) + 4.0)
        if rtl:
            mark_rect = QRectF(rect.left() + 8, rect.top(), mark_width, rect.height())
            when_rect = QRectF(mark_rect.right() + 6, rect.top(), when_width, rect.height())
            name_rect = QRectF(when_rect.right() + 8, rect.top(), icon.left() - when_rect.right() - 14, rect.height())
        else:
            mark_rect = QRectF(rect.right() - 8 - mark_width, rect.top(), mark_width, rect.height())
            when_rect = QRectF(mark_rect.left() - 6 - when_width, rect.top(), when_width, rect.height())
            name_rect = QRectF(icon.right() + 8, rect.top(), when_rect.left() - icon.right() - 14, rect.height())
        name_font = ui_font(13.5, 500)
        painter.setFont(name_font)
        painter.setPen(QColor(TOKENS["text"] if self.isChecked() else TOKENS["text_dim"]))
        name = QFontMetrics(name_font).elidedText(self.item.name, Qt.TextElideMode.ElideMiddle, int(max(10.0, name_rect.width())))
        align = Qt.AlignmentFlag.AlignRight if rtl else Qt.AlignmentFlag.AlignLeft
        painter.drawText(name_rect, int(align | Qt.AlignmentFlag.AlignVCenter), name)
        painter.setFont(meta_font)
        painter.setPen(QColor(TOKENS["text_mute"]))
        painter.drawText(when_rect, int(Qt.AlignmentFlag.AlignCenter), metrics.elidedText(self.item.when, Qt.TextElideMode.ElideRight, int(when_width)))
        painter.setFont(ui_font(12, 600))
        painter.setPen(verdict)
        painter.drawText(mark_rect, int(Qt.AlignmentFlag.AlignCenter), mark)


class EmptyArt(QWidget):
    """Concentric rings: the place where scans will gather."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(110)

    def paintEvent(self, event) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        center = QRectF(self.rect()).center()
        for index, radius in enumerate((46, 32, 18)):
            painter.setPen(QPen(alpha(TOKENS["accent"], 0.18 + index * 0.16), 1.2))
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawEllipse(center, radius, radius)
        painter.setFont(icon_font(18))
        painter.setPen(QColor(TOKENS["accent"]))
        painter.drawText(QRectF(center.x() - 12, center.y() - 12, 24, 24), int(Qt.AlignmentFlag.AlignCenter), glyph("history"))


class HistoryRail(QFrame):
    recordActivated = Signal(str)
    menuRequested = Signal(str, QPoint)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("rail")
        self.language = "en"
        self.items: list[RailItem] = []
        self.cards: list[HistoryCard] = []
        self.selected_id: str | None = None
        self.setStyleSheet(
            f"QFrame#rail {{ background: {TOKENS['glass_rail']}; border: 0; }}"
            f"QFrame#rail[rtl=\"false\"] {{ border-right: 1px solid {TOKENS['line']}; }}"
            f"QFrame#rail[rtl=\"true\"] {{ border-left: 1px solid {TOKENS['line']}; }}"
        )
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 20, 16, 14)
        layout.setSpacing(12)

        brand = QHBoxLayout()
        brand.setSpacing(10)
        brand.addWidget(BrandMark(36))
        names = QVBoxLayout()
        names.setSpacing(0)
        self.brand = label("CYBERSCAN", "brand")
        self.tagline = label("", "brandTag")
        names.addWidget(self.brand)
        names.addWidget(self.tagline)
        brand.addLayout(names, 1)
        layout.addLayout(brand)
        layout.addSpacing(8)

        head = QHBoxLayout()
        self.title = label("", "title")
        self.count = label("", "mute")
        head.addWidget(self.title)
        head.addStretch(1)
        head.addWidget(self.count, 0, Qt.AlignmentFlag.AlignBottom)
        layout.addLayout(head)
        self.mix = MixBar()
        layout.addWidget(self.mix)
        self.search = QLineEdit()
        self.search.setObjectName("search")
        self.search.setClearButtonEnabled(True)
        self.search.textChanged.connect(lambda _text: self._rebuild())
        layout.addWidget(self.search)

        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setFrameShape(QFrame.Shape.NoFrame)
        self.scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.scroll.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.list_host = QWidget()
        self.list_layout = QVBoxLayout(self.list_host)
        self.list_layout.setContentsMargins(0, 0, 0, 0)
        self.list_layout.setSpacing(2)
        self.scroll.setWidget(self.list_host)
        layout.addWidget(self.scroll, 1)

        self.empty = QWidget()
        empty = QVBoxLayout(self.empty)
        empty.setContentsMargins(4, 24, 4, 24)
        empty.setSpacing(8)
        empty.addWidget(EmptyArt())
        self.empty_title = label("", "section")
        self.empty_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.empty_body = label("", "mute", wrap=True)
        self.empty_body.setAlignment(Qt.AlignmentFlag.AlignCenter)
        empty.addWidget(self.empty_title)
        empty.addWidget(self.empty_body)
        empty.addStretch(1)
        layout.addWidget(self.empty, 1)

        footer = QHBoxLayout()
        footer.setSpacing(6)
        self.footer_icon = label("")
        self.footer_icon.setPixmap(glyph_pixmap("lock", TOKENS["text_mute"], 13))
        self.footer = label("", "mute")
        footer.addWidget(self.footer_icon)
        footer.addWidget(self.footer, 1)
        layout.addLayout(footer)

    def retranslate(self, language: str) -> None:
        self.language = language
        self.setProperty("rtl", language == "ar")
        self.style().unpolish(self)
        self.style().polish(self)
        self.tagline.setText(tr("LOCAL SECURITY LAB", language))
        self.title.setText(tr("Your scans", language))
        self.search.setPlaceholderText(tr("Search your scans", language))
        self.footer.setText(tr("Kept on this device only", language))
        self._rebuild()

    def set_items(self, items: list[RailItem], mix: list[tuple[int, str]]) -> None:
        self.items = list(items)
        self.mix.set_segments(mix, count_phrase("scan", len(items), self.language))
        self._rebuild()

    def select(self, record_id: str | None) -> None:
        self.selected_id = record_id
        for card_widget in self.cards:
            card_widget.setChecked(card_widget.item.record_id == record_id)

    def flash(self, record_id: str) -> None:
        for card_widget in self.cards:
            if card_widget.item.record_id == record_id:
                card_widget.flash()
                self.scroll.ensureWidgetVisible(card_widget)

    def card_for(self, record_id: str) -> HistoryCard | None:
        return next((c for c in self.cards if c.item.record_id == record_id), None)

    def _rebuild(self) -> None:
        while self.list_layout.count():
            entry = self.list_layout.takeAt(0)
            widget = entry.widget()
            if widget is not None:
                widget.setParent(None)
                widget.deleteLater()
        self.cards = []
        query = self.search.text().strip().casefold()
        shown = [item for item in self.items if not query or query in item.search_text]
        self.count.setText(count_phrase("scan", len(self.items), self.language) if self.items else "")
        for group in GROUPS:
            members = [item for item in shown if item.group == group]
            if not members:
                continue
            heading = label(tr(group, self.language), "eyebrow")
            heading.setContentsMargins(6, 10, 6, 4)
            self.list_layout.addWidget(heading)
            for item in members:
                card_widget = HistoryCard(item)
                card_widget.setChecked(item.record_id == self.selected_id)
                card_widget.clicked.connect(lambda _checked=False, rid=item.record_id: self.recordActivated.emit(rid))
                card_widget.menuRequested.connect(self.menuRequested)
                self.list_layout.addWidget(card_widget)
                self.cards.append(card_widget)
        self.list_layout.addStretch(1)
        has_items = bool(self.items)
        self.scroll.setVisible(bool(shown))
        self.empty.setVisible(not shown)
        self.mix.setVisible(has_items)
        self.search.setVisible(has_items)
        if has_items and not shown:
            self.empty_title.setText(tr("No scan matches your search", self.language))
            self.empty_body.setText("")
        else:
            self.empty_title.setText(tr("No scans yet", self.language))
            self.empty_body.setText(tr("Every scan you run appears here, so you can come back to it.", self.language))
