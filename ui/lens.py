"""The ready state: one place to give CyberScan something to scan.

A large drop well, one field and one button. The input kind is detected from
what is typed or dropped (``ui.file_kind.detect_mode``), so there is no mode
to choose first. As soon as the input names something, a preview shows its
kind and the whole lens takes that kind's hue; the button says what it will
scan. Validation messages appear under the field and clear on the next edit.

The lens never runs a scan: it emits ``submitted`` / ``browseRequested`` /
``fileDropped`` and the window decides.
"""
from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QRectF, QSize, Qt, QTimer, Signal
from PySide6.QtGui import QColor, QFont, QPainter, QPen
from PySide6.QtWidgets import QHBoxLayout, QLineEdit, QPushButton, QSizePolicy, QVBoxLayout, QWidget

from ui.copy import tr
from ui.file_kind import KINDS, detect_mode, display_name, kind_for_target
from ui.icons import glyph, glyph_icon, icon_font
from ui.plain_language import format_size, isolate
from ui.theme import TOKENS, alpha
from ui.widgets import Ambient, ElidedLabel, KindTile, label


class DropWell(QWidget):
    """The painted drop target. It changes only when a drag enters or leaves."""

    clicked = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.armed = False
        self.hue = QColor(TOKENS["accent"])
        self.title = ""
        self.hint = ""
        self.setMinimumHeight(150)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFocusPolicy(Qt.FocusPolicy.NoFocus)

    def set_text(self, title: str, hint: str) -> None:
        self.title, self.hint = title, hint
        self.setAccessibleName(title)
        self.update()

    def set_armed(self, armed: bool) -> None:
        self.armed = armed
        self.update()

    def set_hue(self, color: QColor) -> None:
        self.hue = QColor(color)
        self.update()

    def sizeHint(self) -> QSize:  # noqa: N802
        return QSize(600, 150)

    def mouseReleaseEvent(self, event) -> None:  # noqa: N802
        if event.button() == Qt.MouseButton.LeftButton and self.rect().contains(event.position().toPoint()):
            self.clicked.emit()
        super().mouseReleaseEvent(event)

    def paintEvent(self, event) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        rect = QRectF(self.rect()).adjusted(1.5, 1.5, -1.5, -1.5)
        hue = self.hue
        painter.setBrush(alpha(hue, 0.12 if self.armed else 0.04))
        pen = QPen(alpha(hue, 0.95 if self.armed else 0.45), 2 if self.armed else 1.4)
        if not self.armed:
            pen.setStyle(Qt.PenStyle.CustomDashLine)
            pen.setDashPattern([5, 4])
        painter.setPen(pen)
        painter.drawRoundedRect(rect, 18, 18)
        center_y = rect.center().y()
        painter.setFont(icon_font(30))
        painter.setPen(hue)
        painter.drawText(QRectF(rect.left(), center_y - 52, rect.width(), 40), int(Qt.AlignmentFlag.AlignCenter), glyph("drop"))
        font = QFont(self.font())
        font.setPixelSize(17)
        font.setWeight(QFont.Weight.DemiBold)
        painter.setFont(font)
        painter.setPen(QColor(TOKENS["text"]))
        painter.drawText(QRectF(rect.left(), center_y - 8, rect.width(), 26), int(Qt.AlignmentFlag.AlignCenter), self.title)
        font.setPixelSize(13)
        font.setWeight(QFont.Weight.Normal)
        painter.setFont(font)
        painter.setPen(QColor(TOKENS["text_mute"]))
        painter.drawText(QRectF(rect.left() + 12, center_y + 20, rect.width() - 24, 22), int(Qt.AlignmentFlag.AlignCenter), self.hint)


class Lens(QWidget):
    submitted = Signal(str)
    browseRequested = Signal()
    fileDropped = Signal(str)
    kindChanged = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.language = "en"
        self.mode = "File"
        self.kind = KINDS["file"]
        self.setAcceptDrops(True)
        self.ambient = Ambient(self)
        self.ambient.lower()

        outer = QVBoxLayout(self)
        outer.setContentsMargins(40, 36, 40, 30)
        outer.setSpacing(16)
        self.title = label("", "display", wrap=True)
        self.lead = label("", "lead", wrap=True)
        outer.addWidget(self.title)
        outer.addWidget(self.lead)
        outer.addSpacing(6)

        self.well = DropWell()
        self.well.clicked.connect(self.browseRequested)
        self.choose_button = QPushButton()
        self.choose_button.setObjectName("ghost")
        self.choose_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.choose_button.clicked.connect(self.browseRequested)
        outer.addWidget(self.well)

        row = QHBoxLayout()
        row.setSpacing(10)
        self.field = QLineEdit()
        self.field.setObjectName("target")
        self.field.setClearButtonEnabled(True)
        self.field.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
        self.field.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.field.textChanged.connect(self._edited)
        self.field.returnPressed.connect(self._submit)
        self.scan_button = QPushButton()
        self.scan_button.setObjectName("primary")
        self.scan_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.scan_button.clicked.connect(self._submit)
        row.addWidget(self.field, 1)
        row.addWidget(self.choose_button)
        row.addWidget(self.scan_button)
        outer.addLayout(row)

        self.preview = QWidget()
        preview_row = QHBoxLayout(self.preview)
        preview_row.setContentsMargins(4, 2, 4, 2)
        preview_row.setSpacing(12)
        self.preview_tile = KindTile(40)
        preview_row.addWidget(self.preview_tile)
        preview_text = QVBoxLayout()
        preview_text.setSpacing(0)
        self.preview_name = ElidedLabel(mode=Qt.TextElideMode.ElideMiddle)
        self.preview_name.setObjectName("section")
        self.preview_meta = label("", "mute")
        preview_text.addWidget(self.preview_name)
        preview_text.addWidget(self.preview_meta)
        preview_row.addLayout(preview_text, 1)
        self.preview.setVisible(False)
        outer.addWidget(self.preview)

        self.error = label("", "error", wrap=True)
        self.error.setVisible(False)
        outer.addWidget(self.error)
        outer.addStretch(1)

        footer = QHBoxLayout()
        footer.setSpacing(8)
        self.lock_icon = label("")
        self.lock_icon.setFixedSize(16, 16)
        footer.addWidget(self.lock_icon, 0, Qt.AlignmentFlag.AlignVCenter)
        self.promise = label("", "mute", wrap=True)
        footer.addWidget(self.promise, 1)
        self.shortcuts = label("", "mute")
        footer.addWidget(self.shortcuts, 0, Qt.AlignmentFlag.AlignVCenter)
        outer.addLayout(footer)
        self.notice = label("", "mute", wrap=True)
        self.notice.setVisible(False)
        outer.addWidget(self.notice)

        self._preview_timer = QTimer(self)
        self._preview_timer.setSingleShot(True)
        self._preview_timer.setInterval(120)
        self._preview_timer.timeout.connect(self._refresh_preview)
        self._apply_hue(animate=False)

    # -- text -----------------------------------------------------------------
    def retranslate(self, language: str) -> None:
        self.language = language
        t = lambda text: tr(text, language)  # noqa: E731
        self.title.setText(t("Inspect before you trust."))
        self.lead.setText(t("Drop a file here, or paste a link, a hash or any text."))
        self.set_armed(self.well.armed)
        self.choose_button.setText(t("Choose a file"))
        self.choose_button.setIcon(glyph_icon("folder", TOKENS["text_dim"], 16))
        self.field.setPlaceholderText(t("Paste a path, a link, a hash or text…"))
        edge = Qt.AlignmentFlag.AlignRight if language == "ar" else Qt.AlignmentFlag.AlignLeft
        for widget in (self.preview_name, self.preview_meta):
            widget.setAlignment(edge | Qt.AlignmentFlag.AlignAbsolute | Qt.AlignmentFlag.AlignVCenter)
        self.promise.setText(t("Files are read, never opened or run."))
        self.lock_icon.setPixmap(self._lock_pixmap())
        # Latin key names inside Arabic: keep them as isolated LTR runs.
        hint = t("Enter to scan · Ctrl+O to choose a file")
        self.shortcuts.setText(_isolate_latin(hint) if language == "ar" else hint)
        self._refresh_preview()

    @staticmethod
    def _lock_pixmap():
        from ui.icons import glyph_pixmap

        return glyph_pixmap("lock", TOKENS["text_mute"], 14)

    def set_notice(self, text: str) -> None:
        self.notice.setText(text)
        self.notice.setVisible(bool(text))

    # -- state ----------------------------------------------------------------
    def text(self) -> str:
        return self.field.text().strip().strip('"')

    def set_target(self, text: str) -> None:
        self.field.setText(text)
        self._refresh_preview()

    def show_error(self, message: str) -> None:
        self.error.setText(message)
        self.error.setVisible(True)
        self.field.setProperty("invalid", True)
        self._repolish(self.field)
        self.field.setFocus()

    def clear_error(self) -> None:
        if self.error.isVisible() or self.field.property("invalid"):
            self.error.setVisible(False)
            self.field.setProperty("invalid", False)
            self._repolish(self.field)

    def set_armed(self, armed: bool) -> None:
        self.well.set_armed(armed)
        t = lambda text: tr(text, self.language)  # noqa: E731
        self.well.set_text(t("Let go to scan it") if armed else t("Drop a file here"), "" if armed else t("or click to choose one"))

    def set_enabled_for_scan(self, enabled: bool) -> None:
        for widget in (self.field, self.scan_button, self.choose_button, self.well):
            widget.setEnabled(enabled)

    # -- internals -------------------------------------------------------------
    @staticmethod
    def _repolish(widget: QWidget) -> None:
        widget.style().unpolish(widget)
        widget.style().polish(widget)

    def _edited(self, _text: str) -> None:
        self.clear_error()
        self._preview_timer.start()

    def _submit(self) -> None:
        self._refresh_preview()
        self.submitted.emit(self.text())

    def _refresh_preview(self) -> None:
        value = self.text()
        self.mode = detect_mode(value)
        t = lambda text: tr(text, self.language)  # noqa: E731
        if not value:
            self.kind = KINDS["file"]
            self.preview.setVisible(False)
            self.scan_button.setText(t("Scan"))
        else:
            self.kind = kind_for_target(value, self.mode)
            self.preview_tile.set_kind(self.kind)
            self.preview_name.setText(display_name(value, self.mode))
            meta = tr("Will be scanned as: {kind}", self.language).format(kind=t(self.kind.label))
            if self.mode == "File":
                try:
                    meta += " · " + isolate(format_size(Path(value).stat().st_size), self.language)
                except OSError:
                    pass
            self.preview_meta.setText(meta)
            self.preview.setVisible(True)
            kind_word = t(self.kind.label)
            self.scan_button.setText(t("Scan this {kind}").format(kind=kind_word.lower() if self.language == "en" else kind_word))
        self._apply_hue()
        self.kindChanged.emit(self.kind.key)

    def _apply_hue(self, animate: bool = True) -> None:
        hue = self.kind.hue if self.text() else TOKENS["accent"]
        if animate:
            self.ambient.set_hue(hue, 0.12)
        else:
            self.ambient._color = QColor(hue)
        self.well.set_hue(QColor(hue))

    def resizeEvent(self, event) -> None:  # noqa: N802
        super().resizeEvent(event)
        self.ambient.setGeometry(self.rect())

    def dragEnterEvent(self, event) -> None:  # noqa: N802
        if event.mimeData().hasUrls() or event.mimeData().hasText():
            self.set_armed(True)
            event.acceptProposedAction()
        else:
            event.ignore()

    def dragLeaveEvent(self, event) -> None:  # noqa: N802
        self.set_armed(False)
        super().dragLeaveEvent(event)

    def dropEvent(self, event) -> None:  # noqa: N802
        self.set_armed(False)
        mime = event.mimeData()
        paths = [url.toLocalFile() for url in mime.urls() if url.isLocalFile()] if mime.hasUrls() else []
        if paths:
            self.fileDropped.emit(paths[0])
            event.acceptProposedAction()
        elif mime.hasText():
            self.set_target(mime.text().strip())
            event.acceptProposedAction()
        else:
            event.ignore()


def _isolate_latin(text: str) -> str:
    """Wrap Latin runs (key names) in FSI/PDI so they keep their order in RTL."""
    import re

    return re.sub(r"([A-Za-z][A-Za-z0-9+]*(?:\+[A-Za-z0-9]+)*)", "⁨\\1⁩", text)
