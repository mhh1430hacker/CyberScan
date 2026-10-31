"""The ready state: a command bar, like Spotlight or Raycast.

One centred field takes anything: a path, a link, a hash or text. Its kind
is detected as you type (``ui.file_kind.detect_mode``); a chip inside the
bar names it in its hue, and the button says what it will scan. Keyboard
hints are drawn as key caps. A file can be dropped anywhere in the window
(the window shows ``DropOverlay``); validation messages appear under the bar
and clear on the next edit.

The lens never runs a scan: it emits ``submitted`` / ``browseRequested`` /
``fileDropped`` and the window decides.
"""
from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QEvent, QRectF, Qt, QTimer, Signal
from PySide6.QtGui import QColor, QPainter, QPen
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLineEdit, QPushButton, QSizePolicy, QVBoxLayout, QWidget

from ui.copy import tr
from ui.file_kind import KINDS, detect_mode, display_name, kind_for_target
from ui.icons import glyph, glyph_icon, glyph_pixmap, icon_font
from ui.plain_language import format_size, isolate
from ui.theme import TOKENS, alpha, ui_font
from ui.widgets import ElidedLabel, KindTile, label


def keycap(text: str) -> QWidget:
    cap = label(text, "key")
    cap.setAlignment(Qt.AlignmentFlag.AlignCenter)
    cap.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
    return cap


class DropOverlay(QWidget):
    """Shown over the whole stage while a file is dragged over the window."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.text = ""
        self.hint = ""
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        self.hide()

    def set_text(self, text: str, hint: str) -> None:
        self.text, self.hint = text, hint
        self.update()

    def paintEvent(self, event) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.fillRect(self.rect(), QColor(5, 6, 7, 205))
        frame = QRectF(self.rect()).adjusted(28, 28, -28, -28)
        pen = QPen(alpha(TOKENS["accent"], 0.85), 1.5)
        pen.setStyle(Qt.PenStyle.CustomDashLine)
        pen.setDashPattern([6, 5])
        painter.setPen(pen)
        painter.setBrush(alpha(TOKENS["accent"], 0.04))
        painter.drawRoundedRect(frame, 20, 20)
        center = frame.center()
        painter.setFont(icon_font(40))
        painter.setPen(QColor(TOKENS["accent"]))
        painter.drawText(QRectF(frame.left(), center.y() - 70, frame.width(), 50), int(Qt.AlignmentFlag.AlignCenter), glyph("drop"))
        painter.setFont(ui_font(26, 600, -0.4))
        painter.setPen(QColor(TOKENS["text"]))
        painter.drawText(QRectF(frame.left(), center.y() - 10, frame.width(), 36), int(Qt.AlignmentFlag.AlignCenter), self.text)
        painter.setFont(ui_font(14))
        painter.setPen(QColor(TOKENS["text_mute"]))
        painter.drawText(QRectF(frame.left(), center.y() + 32, frame.width(), 24), int(Qt.AlignmentFlag.AlignCenter), self.hint)


class Lens(QWidget):
    submitted = Signal(str)
    browseRequested = Signal()
    fileDropped = Signal(str)
    kindChanged = Signal(str)
    armedChanged = Signal(bool)

    WIDTH = 720

    def __init__(self, parent=None):
        super().__init__(parent)
        self.language = "en"
        self.mode = "File"
        self.kind = KINDS["file"]
        self.armed = False
        self.setAcceptDrops(True)

        outer = QHBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addStretch(1)
        column_host = QWidget()
        column_host.setMaximumWidth(self.WIDTH)
        column_host.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        column = QVBoxLayout(column_host)
        column.setContentsMargins(8, 24, 8, 24)
        column.setSpacing(0)
        outer.addWidget(column_host, 100)
        outer.addStretch(1)

        self.privacy = label("", "chip")
        column.addWidget(self.privacy, 0, Qt.AlignmentFlag.AlignHCenter)
        column.addSpacing(22)
        self.title = label("", "display", wrap=True)
        self.title.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        column.addWidget(self.title)
        column.addSpacing(10)
        self.lead = label("", "lead", wrap=True)
        self.lead.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        column.addWidget(self.lead)
        column.addSpacing(30)

        # The command bar ------------------------------------------------------
        self.bar = QFrame()
        self.bar.setObjectName("command")
        bar = QHBoxLayout(self.bar)
        bar.setContentsMargins(16, 8, 8, 8)
        bar.setSpacing(10)
        self.search_icon = label("")
        self.search_icon.setPixmap(glyph_pixmap("search", TOKENS["text_mute"], 18))
        bar.addWidget(self.search_icon)
        self.field = QLineEdit()
        self.field.setObjectName("target")
        self.field.setClearButtonEnabled(True)
        self.field.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
        self.field.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.field.textChanged.connect(self._edited)
        self.field.returnPressed.connect(self._submit)
        self.field.installEventFilter(self)
        bar.addWidget(self.field, 1)
        self.kind_chip = QWidget()
        chip = QHBoxLayout(self.kind_chip)
        chip.setContentsMargins(8, 3, 10, 3)
        chip.setSpacing(6)
        self.kind_tile = KindTile(20)
        self.kind_label = label("", "mute")
        chip.addWidget(self.kind_tile)
        chip.addWidget(self.kind_label)
        self.kind_chip.setVisible(False)
        bar.addWidget(self.kind_chip)
        self.enter_cap = keycap("↵")
        bar.addWidget(self.enter_cap)
        self.scan_button = QPushButton()
        self.scan_button.setObjectName("primary")
        self.scan_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.scan_button.clicked.connect(self._submit)
        bar.addWidget(self.scan_button)
        column.addWidget(self.bar)
        column.addSpacing(10)

        self.error = label("", "error", wrap=True)
        self.error.setVisible(False)
        column.addWidget(self.error)

        # Preview of what will be scanned ------------------------------------------
        self.preview = QFrame()
        self.preview.setObjectName("card")
        preview_row = QHBoxLayout(self.preview)
        preview_row.setContentsMargins(14, 10, 14, 10)
        preview_row.setSpacing(12)
        self.preview_tile = KindTile(36)
        preview_row.addWidget(self.preview_tile)
        preview_text = QVBoxLayout()
        preview_text.setSpacing(1)
        self.preview_name = ElidedLabel(mode=Qt.TextElideMode.ElideMiddle)
        self.preview_name.setObjectName("section")
        self.preview_meta = label("", "mute")
        preview_text.addWidget(self.preview_name)
        preview_text.addWidget(self.preview_meta)
        preview_row.addLayout(preview_text, 1)
        self.preview.setVisible(False)
        column.addWidget(self.preview)
        column.addSpacing(16)

        # Hints as key caps ------------------------------------------------------------
        hints = QHBoxLayout()
        hints.setSpacing(6)
        hints.addStretch(1)
        self.choose_button = QPushButton()
        self.choose_button.setObjectName("ghost")
        self.choose_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.choose_button.clicked.connect(self.browseRequested)
        hints.addWidget(self.choose_button)
        hints.addWidget(keycap("Ctrl"))
        hints.addWidget(keycap("O"))
        hints.addSpacing(14)
        self.drop_hint = label("", "mute")
        hints.addWidget(self.drop_hint)
        hints.addStretch(1)
        column.addLayout(hints)
        column.addSpacing(12)

        self.notice = label("", "mute", wrap=True)
        self.notice.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        self.notice.setVisible(False)
        column.addWidget(self.notice)

        self._preview_timer = QTimer(self)
        self._preview_timer.setSingleShot(True)
        self._preview_timer.setInterval(120)
        self._preview_timer.timeout.connect(self._refresh_preview)

    # -- text -----------------------------------------------------------------
    def retranslate(self, language: str) -> None:
        self.language = language
        t = lambda text: tr(text, language)  # noqa: E731
        self.privacy.setText("●  " + t("Local · read-only · nothing leaves this device"))
        self.title.setText(t("Inspect before you trust."))
        self.lead.setText(t("Paste a path, a link, a hash or any text, or drop a file anywhere."))
        self.choose_button.setText(t("Choose a file"))
        self.choose_button.setIcon(glyph_icon("folder", TOKENS["text_dim"], 15))
        self.drop_hint.setText(t("or drop a file anywhere"))
        self.field.setPlaceholderText(t("Paste a path, a link, a hash or text…"))
        edge = Qt.AlignmentFlag.AlignRight if language == "ar" else Qt.AlignmentFlag.AlignLeft
        for widget in (self.preview_name, self.preview_meta):
            widget.setAlignment(edge | Qt.AlignmentFlag.AlignAbsolute | Qt.AlignmentFlag.AlignVCenter)
        self._refresh_preview()

    def overlay_text(self) -> tuple[str, str]:
        return tr("Drop to scan", self.language), tr("Files are read, never opened or run.", self.language)

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
        for widget in (self.field, self.bar):
            widget.setProperty("invalid", True)
            self._repolish(widget)
        self.field.setFocus()

    def clear_error(self) -> None:
        if self.error.isVisible() or self.field.property("invalid"):
            self.error.setVisible(False)
            for widget in (self.field, self.bar):
                widget.setProperty("invalid", False)
                self._repolish(widget)

    def set_armed(self, armed: bool) -> None:
        if armed != self.armed:
            self.armed = armed
            self.armedChanged.emit(armed)

    # -- internals -------------------------------------------------------------
    @staticmethod
    def _repolish(widget: QWidget) -> None:
        widget.style().unpolish(widget)
        widget.style().polish(widget)

    def eventFilter(self, watched, event) -> bool:  # noqa: N802
        if watched is self.field and event.type() in (QEvent.Type.FocusIn, QEvent.Type.FocusOut):
            self.bar.setProperty("focused", event.type() == QEvent.Type.FocusIn)
            self._repolish(self.bar)
        return False

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
            self.kind_chip.setVisible(False)
            self.scan_button.setText(t("Scan"))
        else:
            self.kind = kind_for_target(value, self.mode)
            kind_word = t(self.kind.label)
            self.kind_tile.set_kind(self.kind)
            self.kind_label.setText(kind_word)
            self.kind_chip.setVisible(True)
            self.preview_tile.set_kind(self.kind)
            self.preview_name.setText(display_name(value, self.mode))
            meta = tr("Will be scanned as: {kind}", self.language).format(kind=kind_word)
            if self.mode == "File":
                try:
                    meta += " · " + isolate(format_size(Path(value).stat().st_size), self.language)
                except OSError:
                    pass
            self.preview_meta.setText(meta)
            self.preview.setVisible(self.mode == "File")
            self.scan_button.setText(t("Scan this {kind}").format(kind=kind_word.lower() if self.language == "en" else kind_word))
        self.kindChanged.emit(self.kind.key)

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
