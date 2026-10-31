"""Settings, about and the session log, in one sheet that slides over the stage.

The sheet only collects choices and shows them; the window validates,
persists and applies them.
"""
from __future__ import annotations

from PySide6.QtCore import QEasingCurve, QPropertyAnimation, QRect, Qt, Signal
from PySide6.QtGui import QColor, QPainter
from PySide6.QtWidgets import (
    QCheckBox,
    QFrame,
    QHBoxLayout,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from ui.copy import tr
from ui.icons import glyph_icon
from ui.motion import VIEW_MS, prefers_reduced_motion
from ui.theme import TOKENS
from ui.widgets import Pill, card, label

ENGINE_OPTIONS = (
    ("entropy_analysis", "Content randomness (entropy)"),
    ("heuristic_rules", "Warning-sign rules (heuristics)"),
    ("ml_analysis", "Learning model (structural classifier)"),
)


class Scrim(QWidget):
    clicked = Signal()

    def paintEvent(self, event) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.fillRect(self.rect(), QColor(3, 6, 10, 150))

    def mousePressEvent(self, event) -> None:  # noqa: N802
        self.clicked.emit()


class SettingsSheet(QFrame):
    closeRequested = Signal()
    saveRequested = Signal()
    browseRequested = Signal()
    languageRequested = Signal()
    changed = Signal()

    WIDTH = 460

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("sheet")
        self.setStyleSheet(
            f"QFrame#sheet {{ background: {TOKENS['surface']}; border: 1px solid {TOKENS['line_strong']}; border-radius: 0; }}"
        )
        self.language = "en"
        self._animation: QPropertyAnimation | None = None
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        head = QHBoxLayout()
        head.setContentsMargins(24, 20, 16, 12)
        self.title = label("", "title")
        head.addWidget(self.title, 1)
        self.close_button = QPushButton()
        self.close_button.setObjectName("icon")
        self.close_button.setIcon(glyph_icon("close", TOKENS["text_dim"], 16))
        self.close_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.close_button.clicked.connect(self.closeRequested)
        head.addWidget(self.close_button)
        outer.addLayout(head)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        body = QWidget()
        layout = QVBoxLayout(body)
        layout.setContentsMargins(24, 4, 24, 24)
        layout.setSpacing(14)
        scroll.setWidget(body)
        outer.addWidget(scroll, 1)

        self.checks: dict[str, QCheckBox] = {}

        def section() -> tuple[QFrame, QVBoxLayout]:
            frame = card("cardQuiet")
            box = QVBoxLayout(frame)
            box.setContentsMargins(18, 16, 18, 16)
            box.setSpacing(8)
            layout.addWidget(frame)
            return frame, box

        _frame, engines = section()
        self.engines_title = label("", "section")
        self.engines_note = label("", "mute", wrap=True)
        engines.addWidget(self.engines_title)
        engines.addWidget(self.engines_note)
        for key, _text in ENGINE_OPTIONS:
            box = QCheckBox()
            box.stateChanged.connect(lambda _state: self.changed.emit())
            self.checks[key] = box
            engines.addWidget(box)

        _frame, online = section()
        self.checks["osint_enabled"] = QCheckBox()
        self.checks["osint_enabled"].stateChanged.connect(lambda _state: self.changed.emit())
        self.online_note = label("", "mute", wrap=True)
        self.keys_note = label("", "mute", wrap=True)
        online.addWidget(self.checks["osint_enabled"])
        online.addWidget(self.online_note)
        online.addWidget(self.keys_note)

        _frame, downloads = section()
        self.downloads_title = label("", "section")
        self.checks["monitoring_enabled"] = QCheckBox()
        self.checks["monitoring_enabled"].stateChanged.connect(lambda _state: self.changed.emit())
        self.downloads_note = label("", "mute", wrap=True)
        self.folder_caption = label("", "body")
        folder_row = QHBoxLayout()
        self.folder = QLineEdit()
        self.folder.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
        self.folder.textChanged.connect(lambda _text: self.changed.emit())
        self.browse_button = QPushButton()
        self.browse_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.browse_button.clicked.connect(self.browseRequested)
        folder_row.addWidget(self.folder, 1)
        folder_row.addWidget(self.browse_button)
        for widget in (self.downloads_title, self.checks["monitoring_enabled"], self.downloads_note, self.folder_caption):
            downloads.addWidget(widget)
        downloads.addLayout(folder_row)

        _frame, display = section()
        self.display_title = label("", "section")
        self.checks["large_text"] = QCheckBox()
        self.checks["large_text"].stateChanged.connect(lambda _state: self.changed.emit())
        language_row = QHBoxLayout()
        self.language_caption = label("", "body")
        self.language_button = QPushButton()
        self.language_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.language_button.setIcon(glyph_icon("language", TOKENS["text_dim"], 16))
        self.language_button.clicked.connect(self.languageRequested)
        language_row.addWidget(self.language_caption, 1)
        language_row.addWidget(self.language_button)
        display.addWidget(self.display_title)
        display.addWidget(self.checks["large_text"])
        display.addLayout(language_row)

        save_row = QHBoxLayout()
        self.saved_pill = Pill()
        self.save_button = QPushButton()
        self.save_button.setObjectName("primary")
        self.save_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.save_button.clicked.connect(self.saveRequested)
        save_row.addWidget(self.saved_pill, 0, Qt.AlignmentFlag.AlignVCenter)
        save_row.addStretch(1)
        save_row.addWidget(self.save_button)
        layout.addLayout(save_row)

        _frame, log = section()
        self.log_title = label("", "section")
        self.log_view = QPlainTextEdit()
        self.log_view.setObjectName("mono")
        self.log_view.setReadOnly(True)
        self.log_view.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
        self.log_view.setFixedHeight(150)
        log.addWidget(self.log_title)
        log.addWidget(self.log_view)

        _frame, about = section()
        self.about_title = label("", "section")
        self.about_body = label("", "body", wrap=True)
        self.credits = label("", "mute")
        about.addWidget(self.about_title)
        about.addWidget(self.about_body)
        about.addWidget(self.credits)
        layout.addStretch(1)
        self.hide()

    def retranslate(self, language: str) -> None:
        self.language = language
        t = lambda text: tr(text, language)  # noqa: E731
        self.title.setText(t("Settings"))
        self.close_button.setToolTip(t("Close"))
        self.close_button.setAccessibleName(t("Close"))
        self.engines_title.setText(t("What to check"))
        self.engines_note.setText(t("Disabling a check reduces coverage. Every result says which checks ran."))
        for key, text in ENGINE_OPTIONS:
            self.checks[key].setText(t(text))
        self.checks["osint_enabled"].setText(t("Online lookups (off by default)"))
        self.online_note.setText(t("Sends supported links, domains, IPs or a file's SHA-256 to public services. File contents are never uploaded. A miss is not proof of safety."))
        self.keys_note.setText(t("Keys are read from URLHAUS_API_KEY, OTX_API_KEY and THREATFOX_API_KEY."))
        self.downloads_title.setText(t("Downloads"))
        self.checks["monitoring_enabled"].setText(t("Scan new downloads automatically"))
        self.downloads_note.setText(t("New files are scanned after they stop changing. Nothing is moved or deleted."))
        self.folder_caption.setText(t("Watched folder"))
        self.browse_button.setText(t("Browse…"))
        self.display_title.setText(t("Display"))
        self.checks["large_text"].setText(t("Larger text and controls"))
        self.language_caption.setText(t("Language"))
        self.language_button.setText("English" if language == "ar" else "العربية")
        self.language_button.setAccessibleName(t("Switch to English") if language == "ar" else t("Switch to Arabic"))
        self.save_button.setText(t("Save settings"))
        self.log_title.setText(t("Session log"))
        self.about_title.setText(t("About CyberScan"))
        self.about_body.setText(t("CyberScan is a defensive research prototype. It reads files, links and indicators without running them. Its findings are leads for review, not proof of malware, and its scores are not probabilities. It never repairs, deletes or quarantines anything."))
        self.credits.setText(t("Developed by m6no5 and Ainex"))

    def set_saved(self, saved: bool) -> None:
        self.saved_pill.set_pill(
            tr("Saved", self.language) if saved else tr("Unsaved changes", self.language),
            "ok" if saved else "warn",
        )
        self.save_button.setEnabled(not saved)

    # -- sliding ------------------------------------------------------------------
    def _geometry(self, host_rect: QRect, open_: bool) -> QRect:
        width = min(self.WIDTH, host_rect.width() - 24)
        rtl = self.layoutDirection() == Qt.LayoutDirection.RightToLeft
        if rtl:
            x = host_rect.left() if open_ else host_rect.left() - width
        else:
            x = host_rect.right() - width + 1 if open_ else host_rect.right() + 1
        return QRect(x, host_rect.top(), width, host_rect.height())

    def place(self, host_rect: QRect) -> None:
        if self.isVisible() and (self._animation is None or self._animation.state() != QPropertyAnimation.State.Running):
            self.setGeometry(self._geometry(host_rect, True))

    def slide(self, host_rect: QRect, open_: bool) -> None:
        if self._animation is not None:
            self._animation.stop()
        start = self._geometry(host_rect, not open_)
        end = self._geometry(host_rect, open_)
        if open_:
            self.setGeometry(start)
            self.show()
            self.raise_()
        if prefers_reduced_motion() or not self.window().isVisible():
            self.setGeometry(end)
            self.setVisible(open_)
            return
        animation = QPropertyAnimation(self, b"geometry", self)
        animation.setDuration(VIEW_MS)
        animation.setStartValue(self.geometry() if not open_ else start)
        animation.setEndValue(end)
        animation.setEasingCurve(QEasingCurve.Type.OutCubic if open_ else QEasingCurve.Type.InCubic)
        if not open_:
            animation.finished.connect(self.hide)
        self._animation = animation
        animation.start()
