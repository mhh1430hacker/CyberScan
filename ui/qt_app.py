"""CyberScan main window.

Layout: the history rail on the reading-start side, and one stage that shows
one thing at a time: the lens (ready), the journey (scanning) or the result
(three reading levels). Settings slide over the stage.

The scan pipeline, the verdict and the risk score come from the engine
unchanged (``ui.scan_service`` -> ``ui.result_view``). This window decides
only what is shown, in which words and in which order.
"""
from __future__ import annotations

import json
import queue
import shutil
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from PySide6.QtCore import Qt, QThread, QTimer, QUrl, Signal
from PySide6.QtGui import QDesktopServices, QFont, QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QApplication,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from config import DATA_DIR, DEFAULT_SETTINGS, REPORT_DIR, ensure_directories
from core.models import Finding, ScanResult
from monitoring.downloads_monitor import DownloadMonitor
from reports.exporter import export_report
from ui import plain_language
from ui.copy import tr
from ui.file_kind import KINDS, FileKind, detect_mode, display_name, kind_for_target
from ui.history_rail import GROUPS, HistoryRail, RailItem
from ui.icons import glyph_icon
from ui.journey import JourneyScene
from ui.lens import Lens
from ui.motion import fade_in
from ui.persistence import LocalUiStore
from ui.result_tiers import ResultPanel, advanced_texts
from ui.result_view import ResultView, build_result_view
from ui.scan_service import ScanService
from ui.settings_sheet import Scrim, SettingsSheet
from ui.theme import TOKENS, stylesheet, tone_color
from ui.widgets import Ambient, Pill, label

STAGE_TITLES = ("Reading", "Patterns", "Structure", "Lookups")
STAGE_CAPTIONS = (
    "Reading what you gave us…",
    "Looking for unusual patterns…",
    "Mapping how it's built…",
    "Finishing the last checks…",
)
RAIL_WORDS = {"high": "High risk", "review": "Needs review", "low": "Nothing found", "inconclusive": "Not sure"}
RAIL_SYMBOLS = {"high": "▲", "review": "◆", "low": "●", "inconclusive": "?"}
RAIL_TONES = {"high": "danger", "review": "warn", "low": "ok", "inconclusive": "neutral"}
CLASSIFICATION_KEYS = {"SUSPICIOUS": "high", "REVIEW": "review", "NO_INDICATORS_OBSERVED": "low"}
CONTENT_MAX_WIDTH = 1000


class ScanWorker(QThread):
    progress = Signal(int, str, str)
    completed = Signal(object)
    failed = Signal(str)

    def __init__(self, candidate: str, mode: str, settings: dict[str, Any]) -> None:
        super().__init__()
        self.candidate = candidate
        self.mode = mode
        self.settings = settings

    def run(self) -> None:
        try:
            payload = ScanService().analyze(
                self.candidate,
                self.mode,
                self.settings,
                self.progress.emit,
            )
            self.completed.emit(payload)
        except Exception as exc:
            self.failed.emit(f"{type(exc).__name__}: {exc}")


def plain_failure(message: str) -> str:
    """One plain sentence for an engine failure; the raw text is kept separately."""
    lowered = message.casefold()
    if "exceeds the configured limit" in lowered:
        return "The file is bigger than the size limit in your settings."
    if "deadline" in lowered or "timeout" in lowered:
        return "The scan took longer than the time limit in your settings."
    if lowered.startswith(("permissionerror", "oserror", "filenotfounderror", "isadirectoryerror")):
        return "The file couldn't be read. It may be open in another program, or you may not have permission."
    return "Something unexpected went wrong inside the scanner."


class CyberScanApp(QMainWindow):
    monitor_file_detected = Signal(str)

    def __init__(self) -> None:
        super().__init__()
        ensure_directories()
        screen = QApplication.primaryScreen()
        available = screen.availableGeometry() if screen else None
        width = min(1460, available.width() - 48) if available else 1320
        height = min(960, available.height() - 64) if available else 860
        self.resize(max(1040, width), max(680, height))
        self.setMinimumSize(880, 600)
        self.setAcceptDrops(True)

        self.ui_store = LocalUiStore(DATA_DIR / "ui_settings.json", DATA_DIR / "scan_history.json")
        self.startup_warnings: list[str] = []
        try:
            persisted = self.ui_store.load_settings({**DEFAULT_SETTINGS, "ui_language": "en"})
        except ValueError as exc:
            persisted = {**DEFAULT_SETTINGS, "ui_language": "en"}
            self.startup_warnings.append(str(exc))
        language = persisted.pop("ui_language", "en")
        self.language = language if language in {"en", "ar"} else "en"
        self.settings = {key: persisted[key] for key in DEFAULT_SETTINGS if key in persisted}
        try:
            self.scan_history = self.ui_store.load_history()
        except ValueError as exc:
            self.scan_history = []
            self.startup_warnings.append(str(exc))

        self.audit_log: list[str] = []
        self.last_payload: tuple[Any, ...] | None = None
        self.worker: ScanWorker | None = None
        self._abandoned_workers: list[ScanWorker] = []
        self.pending_monitor_scans: queue.Queue[str] = queue.Queue()
        self.view = "lens"
        self.target = ""
        self.mode = "File"
        self.kind: FileKind = KINDS["file"]
        self._stage_states = ["waiting"] * 4
        self._scan_started = 0.0
        self._pending_reveal = False
        self._current: dict[str, Any] | None = None
        self._failure: tuple[str, str] | None = None  # (kind, raw message)
        self._verdict_cache: dict[str, str] = {}
        self._text_scale: tuple[float, str] | None = None
        self._monitor = DownloadMonitor(self.settings["monitoring_directory"], callback=self.monitor_file_detected.emit)
        self.monitor_file_detected.connect(self._queue_monitored_file)

        self._build()
        self._install_shortcuts()
        self._apply_text_scale()
        self._append_log("CyberScan started. Static analysis only; targets are never executed.")
        self.retranslate()
        self._show_view("lens", animate=False)
        if self.settings.get("monitoring_enabled"):
            self._monitor.start()
            self._append_log("Downloads monitoring enabled.")
        self._refresh_notice()
        QTimer.singleShot(0, self._apply_layout_mode)

    # ===================================================================== build
    def _build(self) -> None:
        root = QWidget()
        root.setObjectName("root")
        shell = QHBoxLayout(root)
        shell.setContentsMargins(0, 0, 0, 0)
        shell.setSpacing(0)
        self.rail = HistoryRail()
        self.rail.setFixedWidth(300)
        self.rail.recordActivated.connect(self.open_record)
        self.rail.menuRequested.connect(self._record_menu)
        shell.addWidget(self.rail)

        self.main = QWidget()
        self.main.setObjectName("main")
        main = QVBoxLayout(self.main)
        main.setContentsMargins(0, 0, 0, 0)
        main.setSpacing(0)
        topbar = QFrame()
        topbar.setObjectName("topbar")
        bar = QHBoxLayout(topbar)
        bar.setContentsMargins(24, 14, 20, 6)
        bar.setSpacing(8)
        self.rail_button = self._icon_button("history", self._toggle_rail)
        bar.addWidget(self.rail_button)
        self.status_pill = Pill()
        bar.addWidget(self.status_pill)
        bar.addStretch(1)
        self.language_button = QPushButton()
        self.language_button.setObjectName("ghost")
        self.language_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.language_button.setIcon(glyph_icon("language", TOKENS["text_dim"], 16))
        self.language_button.clicked.connect(self.toggle_language)
        bar.addWidget(self.language_button)
        self.settings_button = self._icon_button("settings", self.open_settings)
        bar.addWidget(self.settings_button)
        main.addWidget(topbar)

        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setFrameShape(QFrame.Shape.NoFrame)
        self.scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.scroll.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        stage = QWidget()
        stage.setObjectName("stage")
        centered = QHBoxLayout(stage)
        centered.setContentsMargins(24, 10, 24, 32)
        centered.addStretch(1)
        self.column = QWidget()
        self.column.setMaximumWidth(CONTENT_MAX_WIDTH)
        self.column.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        column = QVBoxLayout(self.column)
        column.setContentsMargins(0, 0, 0, 0)
        column.setSpacing(0)
        self.column_layout = column
        column.addStretch(0)  # top: grows to centre the lens and the journey
        centered.addWidget(self.column, 100)
        centered.addStretch(1)
        self.scroll.setWidget(stage)
        main.addWidget(self.scroll, 1)
        shell.addWidget(self.main, 1)
        self.setCentralWidget(root)

        # -- the three views ---------------------------------------------------
        self.lens = Lens()
        self.lens.setMinimumHeight(520)
        self.lens.submitted.connect(self.run_scan)
        self.lens.browseRequested.connect(self.select_file)
        self.lens.fileDropped.connect(self._file_dropped)
        column.addWidget(self.lens)

        self.journey_view = QWidget()
        self.journey_ambient = Ambient(self.journey_view)
        journey = QVBoxLayout(self.journey_view)
        journey.setContentsMargins(32, 26, 32, 26)
        journey.setSpacing(10)
        head = QHBoxLayout()
        self.journey_title = label("", "eyebrow")
        head.addWidget(self.journey_title, 1)
        self.journey_promise = label("", "mute")
        head.addWidget(self.journey_promise)
        journey.addLayout(head)
        self.journey = JourneyScene()
        self.journey.concluded.connect(self._journey_concluded)
        journey.addWidget(self.journey)
        self.journey_caption = label("", "lead")
        self.journey_caption.setAlignment(Qt.AlignmentFlag.AlignCenter)
        journey.addWidget(self.journey_caption)
        self.outcome = QWidget()
        outcome = QVBoxLayout(self.outcome)
        outcome.setContentsMargins(0, 8, 0, 0)
        outcome.setSpacing(6)
        self.outcome_title = label("", "title", wrap=True)
        self.outcome_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.outcome_body = label("", "body", wrap=True)
        self.outcome_body.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.outcome_note = label("", "mute", wrap=True)
        self.outcome_note.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.technical_button = QPushButton()
        self.technical_button.setObjectName("link")
        self.technical_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.technical_button.clicked.connect(self._toggle_technical)
        self.technical_text = label("", "mono", wrap=True)
        self.technical_text.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
        self.technical_text.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.technical_text.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.technical_text.setVisible(False)
        for widget in (self.outcome_title, self.outcome_body, self.outcome_note):
            outcome.addWidget(widget)
        outcome.addWidget(self.technical_button, 0, Qt.AlignmentFlag.AlignHCenter)
        outcome.addWidget(self.technical_text)
        self.outcome.setVisible(False)
        journey.addWidget(self.outcome)
        journey.addStretch(1)
        actions = QHBoxLayout()
        actions.addStretch(1)
        self.stop_button = QPushButton()
        self.stop_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.stop_button.clicked.connect(self.cancel_scan)
        self.retry_button = QPushButton()
        self.retry_button.setObjectName("primary")
        self.retry_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.retry_button.clicked.connect(self._retry)
        self.other_button = QPushButton()
        self.other_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.other_button.clicked.connect(self.new_scan)
        for button in (self.stop_button, self.retry_button, self.other_button):
            actions.addWidget(button)
        actions.addStretch(1)
        journey.addLayout(actions)
        column.addWidget(self.journey_view)

        self.result_panel = ResultPanel()
        self.result_panel.newScanRequested.connect(self.new_scan)
        self.result_panel.exportRequested.connect(self.export_current_report)
        self.result_panel.detailsToggled.connect(lambda opened: opened and self._scroll_to(self.result_panel.details))
        self.result_panel.advancedToggled.connect(lambda opened: opened and self._scroll_to(self.result_panel.advanced))
        column.addWidget(self.result_panel)
        column.addStretch(1)

        # -- settings sheet over the stage -------------------------------------
        self.scrim = Scrim(self.main)
        self.scrim.hide()
        self.scrim.clicked.connect(self.close_settings)
        self.sheet = SettingsSheet(self.main)
        self.sheet.closeRequested.connect(self.close_settings)
        self.sheet.saveRequested.connect(self.apply_settings)
        self.sheet.browseRequested.connect(self.select_monitor_directory)
        self.sheet.languageRequested.connect(self.toggle_language)
        self.sheet.changed.connect(self._settings_dirty)

    def _icon_button(self, icon: str, callback) -> QPushButton:
        button = QPushButton()
        button.setObjectName("icon")
        button.setIcon(glyph_icon(icon, TOKENS["text_dim"], 18))
        button.setCursor(Qt.CursorShape.PointingHandCursor)
        button.clicked.connect(callback)
        return button

    def _install_shortcuts(self) -> None:
        self.shortcuts: list[QShortcut] = []
        for sequence, callback in (
            ("Ctrl+O", self.select_file),
            ("Ctrl+L", self._focus_input),
            ("Ctrl+Return", self.run_scan),
            ("Ctrl+Enter", self.run_scan),
            ("Ctrl+N", self.new_scan),
            ("Ctrl+F", self._focus_search),
            ("Ctrl+,", self.open_settings),
            ("Escape", self.close_settings),
        ):
            shortcut = QShortcut(QKeySequence(sequence), self)
            shortcut.activated.connect(callback)
            self.shortcuts.append(shortcut)

    # ============================================================== language
    def t(self, text: str) -> str:
        return tr(text, self.language)

    def retranslate(self) -> None:
        rtl = self.language == "ar"
        self.setLayoutDirection(Qt.LayoutDirection.RightToLeft if rtl else Qt.LayoutDirection.LeftToRight)
        self.setWindowTitle(self.t("CyberScan · Local threat analysis"))
        self.language_button.setText("English" if rtl else "العربية")
        self.language_button.setAccessibleName(self.t("Switch to English") if rtl else self.t("Switch to Arabic"))
        self.settings_button.setToolTip(self.t("Settings"))
        self.settings_button.setAccessibleName(self.t("Settings"))
        self.rail_button.setToolTip(self.t("Open your scans"))
        self.rail_button.setAccessibleName(self.t("Open your scans"))
        self.rail.retranslate(self.language)
        self.lens.retranslate(self.language)
        self.sheet.retranslate(self.language)
        self.result_panel.retranslate(self.language)
        self.journey.set_stage_titles([self.t(title) for title in STAGE_TITLES])
        self.journey.setAccessibleName(self.t("Scanning {name}").format(name=display_name(self.target, self.mode)))
        self.journey_promise.setText(self.t("Read only · never run"))
        self.stop_button.setText(self.t("Stop"))
        self.retry_button.setText(self.t("Try again"))
        self.other_button.setText(self.t("Scan something else"))
        self._refresh_rail()
        self._refresh_status()
        self._refresh_journey_text()
        self._refresh_notice()
        self._settings_saved_state()
        if self._current is not None:
            self._render_current(reveal=False)

    def toggle_language(self) -> None:
        self.language = "ar" if self.language == "en" else "en"
        self._apply_text_scale()
        self.retranslate()
        try:
            self.ui_store.save_settings({**self.settings, "ui_language": self.language})
        except (OSError, TypeError, ValueError) as exc:
            self._append_log(f"Language preference was not saved: {exc}")

    # ================================================================ views
    def _show_view(self, name: str, *, animate: bool = True) -> None:
        self.view = name
        widgets = {"lens": self.lens, "journey": self.journey_view, "result": self.result_panel}
        for key, widget in widgets.items():
            widget.setVisible(key == name)
        # The lens and the journey sit in the middle of the stage; a result
        # starts at the top and grows downward as levels open.
        centred = name in {"lens", "journey"}
        self.column_layout.setStretch(0, 1 if centred else 0)
        self.column_layout.setStretch(self.column_layout.count() - 1, 1)
        if animate:
            fade_in(widgets[name])
        self.scroll.verticalScrollBar().setValue(0)
        self._refresh_status()

    def _refresh_status(self) -> None:
        if self.view == "journey" and self.journey.phase == "analyzing":
            text, tone = "Scanning", "info"
        elif self.view == "journey" and self.journey.phase == "failed":
            text, tone = "Stopped", "danger"
        elif self.view == "journey" and self.journey.phase == "cancelled":
            text, tone = "Cancelled", "warn"
        elif self.view == "result" and self._current is not None:
            text, tone = "Done", "ok"
        else:
            text, tone = "Ready", "accent"
        self.status_pill.set_pill(f"● {self.t(text)}", tone)
        self.status_pill.setAccessibleName(self.t(text))

    def _scroll_to(self, widget: QWidget) -> None:
        QTimer.singleShot(60, lambda: self.scroll.ensureWidgetVisible(widget, 0, 40))

    # ============================================================ scanning
    def _focus_input(self) -> None:
        if self.worker is None:
            self.new_scan()
        self.lens.field.setFocus()
        self.lens.field.selectAll()

    def _focus_search(self) -> None:
        self.rail.show()
        self.rail.search.setFocus()

    def select_file(self) -> None:
        if self.worker is not None:
            return
        path, _filter = QFileDialog.getOpenFileName(self, self.t("Choose a file"))
        if path:
            self._file_dropped(path)

    def _file_dropped(self, path: str) -> None:
        if self.worker is not None:
            return
        self._show_view("lens", animate=self.view != "lens")
        self.lens.set_target(path)
        self.lens.scan_button.setFocus()

    def run_scan(self, text: str | None = None) -> None:
        if self.worker is not None and self.worker.isRunning():
            return
        if self.view != "lens":
            return
        value = (text if isinstance(text, str) else self.lens.text()).strip().strip('"')
        if not value:
            self.lens.show_error(self.t("Add something to scan first."))
            return
        mode = detect_mode(value)
        if mode == "File":
            try:
                resolved = Path(value).expanduser().resolve(strict=True)
            except (OSError, RuntimeError):
                resolved = None
            if resolved is None or not resolved.is_file():
                self.lens.show_error(self.t("That file doesn't exist. Check the path, or choose the file again."))
                return
            value = str(resolved)
        elif mode == "URL":
            parsed = urlsplit(value)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                self.lens.show_error(self.t("A link must start with http:// or https:// and include a site name."))
                return
        self._start(value, mode)

    def _start(self, target: str, mode: str) -> None:
        self.target, self.mode = target, mode
        self.kind = kind_for_target(target, mode)
        self._stage_states = ["waiting"] * 4
        self._failure = None
        self._pending_reveal = False
        self._current = None
        self.journey_ambient.set_hue(self.kind.hue, 0.12)
        self.journey.start(display_name(target, mode), self.kind, self._type_line(target, mode))
        self.outcome.setVisible(False)
        self.technical_text.setVisible(False)
        self.stop_button.setVisible(True)
        self.retry_button.setVisible(False)
        self.other_button.setVisible(False)
        self._show_view("journey")
        self._refresh_journey_text()
        self._append_log(f"Analysis started in {mode} mode: {target}")
        self._scan_started = time.perf_counter()
        self.worker = ScanWorker(target, mode, self.settings.copy())
        self.worker.progress.connect(self._update_stage)
        self.worker.completed.connect(self._scan_completed)
        self.worker.failed.connect(self._scan_failed)
        self.worker.start()
        self._refresh_status()
        self.stop_button.setFocus()

    def _type_line(self, target: str, mode: str) -> str:
        kind = self.t(kind_for_target(target, mode).label)
        if mode == "File":
            try:
                return f"{kind} · {plain_language.isolate(plain_language.format_size(Path(target).stat().st_size), self.language)}"
            except OSError:
                return kind
        if mode == "URL":
            return f"{kind} · {urlsplit(target).hostname or ''}"
        return kind

    def _refresh_journey_text(self) -> None:
        name = display_name(self.target, self.mode)
        word = {"failed": "Stopped", "cancelled": "Cancelled"}.get(self.journey.phase, "Scanning")
        self.journey_title.setText(self.t(word).upper() if self.language == "en" else self.t(word))
        if self.journey.phase == "analyzing":
            running = next((i for i, s in enumerate(self._stage_states) if s == "running"), None)
            index = running if running is not None else min(3, self._stage_states.count("complete"))
            self.journey_caption.setText(self.t(STAGE_CAPTIONS[index]))
        else:
            self.journey_caption.setText("")
        self.journey_caption.setVisible(bool(self.journey_caption.text()))
        if self._failure is not None:
            kind, raw = self._failure
            if kind == "failed":
                self.outcome_title.setText(self.t("The scan couldn't finish"))
                self.outcome_body.setText(self.t(plain_failure(raw)))
                self.outcome_note.setText(self.t("Nothing was concluded about this target."))
            else:
                self.outcome_title.setText(self.t("Scan stopped"))
                self.outcome_body.setText(self.t("You stopped the scan. Its result will be thrown away and not saved."))
                self.outcome_note.setText(self.t("The part already running finishes quietly in the background."))
            self.technical_button.setText(self.t("Technical message"))
            self.technical_button.setVisible(kind == "failed")
            self.technical_text.setText(raw)
        self.journey.setAccessibleName(self.t("Scanning {name}").format(name=name))

    def _from_stale_worker(self) -> bool:
        sender = self.sender()
        return isinstance(sender, ScanWorker) and sender is not self.worker

    def _update_stage(self, index: int, state: str, detail: str) -> None:
        if self._from_stale_worker() or not 0 <= index < 4:
            return
        self._stage_states[index] = state
        self.journey.set_stage_states(self._stage_states)
        self._refresh_journey_text()
        self._append_log(f"Stage {index + 1} {state}: {detail}")

    def _scan_completed(self, payload: tuple[Any, ...]) -> None:
        if self._from_stale_worker():
            return
        self.worker = None
        elapsed = time.perf_counter() - self._scan_started
        self.last_payload = payload
        result, nextgen, vector, prediction, intelligence, _raw = payload
        view = build_result_view(result, nextgen)
        self._append_log(f"Analysis complete: {result.classification} · risk index {result.combined_score}/100")
        record_id = None
        save_error = None
        try:
            record_id = self._record_scan_history(result, view)
        except (OSError, ValueError, TypeError) as exc:
            save_error = str(exc)
            self._append_log(f"Unable to save scan history: {type(exc).__name__}: {exc}")
        self._current = {
            "result": result,
            "view": view,
            "nextgen": nextgen,
            "prediction": prediction,
            "intelligence": intelligence,
            "kind": self.kind,
            "elapsed": elapsed,
            "origin_when": None,
            "record_id": record_id,
            "save_error": save_error,
        }
        self._pending_reveal = True
        self.stop_button.setVisible(False)
        self.journey.conclude(view.verdict.symbol, tone_color(view.verdict.tone))
        if record_id is not None:
            self.rail.select(record_id)
            self.rail.flash(record_id)
        self._start_next_monitor_scan()

    def _journey_concluded(self) -> None:
        if not self._pending_reveal:
            return
        self._pending_reveal = False
        self._render_current(reveal=True)
        self._show_view("result")
        self.result_panel.why_button.setFocus()

    def _render_current(self, *, reveal: bool) -> None:
        current = self._current
        if current is None:
            return
        view: ResultView = current["view"]
        kind: FileKind = current["kind"]
        summary = plain_language.summary(view, kind, current["elapsed"], self.language)
        details = plain_language.details(view, kind, self.language)
        texts = advanced_texts(current["result"], current["nextgen"] or {}, current["prediction"] or {}, current["intelligence"] or {})
        entropy = ((current["nextgen"] or {}).get("entropy_topography") or {}).get("trajectory", ())
        origin = ""
        if current["origin_when"]:
            origin = self.t("From your scans · {when}").format(when=current["origin_when"])
        elif current["save_error"]:
            origin = self.t("The result is shown, but it wasn't added to your scans.")
        was_open = (self.result_panel.details.isVisibleTo(self.result_panel), self.result_panel.advanced.isVisibleTo(self.result_panel))
        self.result_panel.show_result(summary, details, kind, texts, tuple(entropy), origin, reveal=reveal)
        if not reveal:
            # A language switch keeps the reader where they were.
            if was_open[0]:
                self.result_panel.details.setVisible(True)
            if was_open[1]:
                self.result_panel.advanced.setVisible(True)
            self.result_panel._sync_buttons()

    def _scan_failed(self, message: str) -> None:
        if self._from_stale_worker():
            return
        self.worker = None
        self._failure = ("failed", message)
        self.journey.fail(self.t("Stopped"))
        self.stop_button.setVisible(False)
        self.retry_button.setVisible(True)
        self.other_button.setVisible(True)
        self.outcome.setVisible(True)
        fade_in(self.outcome)
        self._refresh_journey_text()
        self._refresh_status()
        self._append_log(f"Analysis failed: {message}")
        self.retry_button.setFocus()
        self._start_next_monitor_scan()

    def cancel_scan(self) -> None:
        """Stop following the running scan and discard its result.

        The engine cannot be interrupted inside a stage; the read already in
        progress finishes in the background within its configured deadline,
        and its result is ignored and never saved.
        """
        worker = self.worker
        if worker is None or not worker.isRunning():
            return
        for signal, slot in ((worker.progress, self._update_stage), (worker.completed, self._scan_completed), (worker.failed, self._scan_failed)):
            try:
                signal.disconnect(slot)
            except (RuntimeError, TypeError):
                pass
        self._abandoned_workers.append(worker)
        worker.finished.connect(self._forget_abandoned_workers)
        self.worker = None
        self._failure = ("cancelled", "")
        self.journey.cancel(self.t("Cancelled"))
        self.stop_button.setVisible(False)
        self.retry_button.setVisible(False)
        self.other_button.setVisible(True)
        self.outcome.setVisible(True)
        fade_in(self.outcome)
        self._refresh_journey_text()
        self._refresh_status()
        self._append_log("Analysis cancelled by the user; its result will be discarded.")
        self.other_button.setFocus()
        self._start_next_monitor_scan()

    def _forget_abandoned_workers(self) -> None:
        for worker in list(self._abandoned_workers):
            if not worker.isRunning():
                self._abandoned_workers.remove(worker)
                worker.deleteLater()

    def _toggle_technical(self) -> None:
        self.technical_text.setVisible(not self.technical_text.isVisible())

    def _retry(self) -> None:
        if self.worker is None and self.target:
            self._start(self.target, self.mode)

    def new_scan(self) -> None:
        if self.worker is not None and self.worker.isRunning():
            return
        self.journey.reset()
        self._current = None
        self._failure = None
        self.rail.select(None)
        self._show_view("lens", animate=self.view != "lens")
        self.lens.field.setFocus()
        self.lens.field.selectAll()

    # ============================================================== history
    def _record_scan_history(self, result, view: ResultView) -> str:
        history_dir = Path(REPORT_DIR) / "history"
        history_dir.mkdir(parents=True, exist_ok=True)
        record_id = uuid.uuid4().hex
        report_path = history_dir / f"scan_{record_id}.json"
        export_report(result, report_path, "json")
        record = {
            "id": record_id,
            "timestamp": datetime.now().astimezone().isoformat(timespec="seconds"),
            "target": str(result.target),
            "classification": result.classification,
            "score": result.combined_score,
            "sha256": result.feature_summary.get("sha256", ""),
            "report_path": str(report_path.resolve()),
        }
        candidate = [*self.scan_history, record]
        updated = candidate[-200:]
        try:
            self.ui_store.save_history(updated)
        except (OSError, TypeError, ValueError):
            report_path.unlink(missing_ok=True)
            raise
        self.scan_history = updated
        self._verdict_cache[record_id] = view.verdict.key
        for expired in candidate[:-200]:
            try:
                self._validated_history_report(expired).unlink()
            except (OSError, ValueError) as exc:
                self._append_log(f"Unable to remove expired history report: {exc}")
        self._refresh_rail()
        return record_id

    def refresh_history(self, *_args) -> None:
        self._refresh_rail()

    def _record_verdict(self, record: dict[str, Any]) -> str:
        """The coverage-aware verdict for a saved scan, read from its report.

        Falls back to the saved classification only when the report cannot be
        read; that fallback cannot see engine coverage.
        """
        record_id = str(record.get("id", ""))
        if record_id in self._verdict_cache:
            return self._verdict_cache[record_id]
        try:
            payload = json.loads(self._validated_history_report(record).read_text(encoding="utf-8"))
            key = build_result_view(self._result_from_report(payload)).verdict.key
        except (OSError, ValueError, TypeError, KeyError):
            key = CLASSIFICATION_KEYS.get(str(record.get("classification", "")), "inconclusive")
        self._verdict_cache[record_id] = key
        return key

    @staticmethod
    def _record_mode(target: str) -> str:
        if target.startswith(("http://", "https://")):
            return "URL"
        if Path(target).is_absolute():
            return "File"
        return "Indicator / text"

    def _record_when(self, record: dict[str, Any]) -> tuple[str, str]:
        try:
            moment = datetime.fromisoformat(str(record.get("timestamp", "")))
        except ValueError:
            return "", "Earlier"
        now = datetime.now(moment.tzinfo)
        days = (now.date() - moment.date()).days
        clock = moment.strftime("%H:%M")
        if days <= 0:
            return self.t("Today {time}").format(time=clock), "Today"
        if days == 1:
            return self.t("Yesterday {time}").format(time=clock), "Yesterday"
        stamp = moment.strftime("%Y-%m-%d %H:%M")
        return stamp, "This week" if days < 7 else "Earlier"

    def _refresh_rail(self) -> None:
        items = []
        counts = {key: 0 for key in RAIL_WORDS}
        for record in reversed(self.scan_history):
            target = str(record.get("target", ""))
            mode = self._record_mode(target)
            key = self._record_verdict(record)
            counts[key] = counts.get(key, 0) + 1
            when, group = self._record_when(record)
            name = display_name(target, mode)
            items.append(
                RailItem(
                    record_id=str(record.get("id", "")),
                    name=name,
                    kind=kind_for_target(target, mode),
                    when=when,
                    group=group if group in GROUPS else "Earlier",
                    verdict_key=key,
                    verdict_word=self.t(RAIL_WORDS[key]),
                    symbol=RAIL_SYMBOLS[key],
                    tone=RAIL_TONES[key],
                    search_text=" ".join((target, name, str(record.get("sha256", "")), self.t(RAIL_WORDS[key]), RAIL_WORDS[key])).casefold(),
                )
            )
        mix = [(counts[key], tone_color(RAIL_TONES[key])) for key in ("high", "review", "low", "inconclusive")]
        self.rail.set_items(items, mix)
        if self._current is not None:
            self.rail.select(self._current.get("record_id"))

    def _record(self, record_id: str) -> dict[str, Any] | None:
        return next((r for r in self.scan_history if r.get("id") == record_id), None)

    def open_record(self, record_id: str) -> None:
        if self.worker is not None and self.worker.isRunning():
            self.rail.select(self._current.get("record_id") if self._current else None)
            return
        record = self._record(record_id)
        if record is None:
            return
        try:
            payload = json.loads(self._validated_history_report(record).read_text(encoding="utf-8"))
            result = self._result_from_report(payload)
        except (OSError, ValueError, TypeError, KeyError) as exc:
            QMessageBox.critical(self, self.t("Report unavailable"), str(exc))
            return
        target = str(record.get("target", ""))
        mode = self._record_mode(target)
        view = build_result_view(result, result.nextgen_analysis or {})
        when, _group = self._record_when(record)
        self.target, self.mode = target, mode
        self._current = {
            "result": result,
            "view": view,
            "nextgen": result.nextgen_analysis or {},
            "prediction": result.structural_prediction or {},
            "intelligence": result.osint_summary or {},
            "kind": kind_for_target(target, mode),
            "elapsed": None,
            "origin_when": when or "—",
            "record_id": record_id,
            "save_error": None,
        }
        self.last_payload = (result, result.nextgen_analysis or {}, (), result.structural_prediction or {}, result.osint_summary or {}, b"")
        self.rail.select(record_id)
        self._render_current(reveal=True)
        self._show_view("result")

    def _record_menu(self, record_id: str, position) -> None:
        menu = QMenu(self)
        menu.addAction(glyph_icon("open", TOKENS["text_dim"], 16), self.t("Open the saved report"), lambda: self.open_history_report(record_id))
        menu.addAction(glyph_icon("save", TOKENS["text_dim"], 16), self.t("Export the report…"), lambda: self.export_history_report(record_id))
        menu.addSeparator()
        menu.addAction(glyph_icon("delete", TOKENS["danger"], 16), self.t("Remove from your scans"), lambda: self.remove_history_record(record_id))
        menu.exec(position)

    def _validated_history_report(self, record: dict[str, Any]) -> Path:
        directory = (Path(REPORT_DIR) / "history").resolve()
        report_path = Path(record["report_path"]).resolve()
        if report_path.parent != directory or not report_path.is_file():
            raise ValueError(self.t("The saved report is missing or outside the local history folder."))
        return report_path

    def open_history_report(self, record_id: str) -> None:
        record = self._record(record_id)
        if record is None:
            return
        try:
            path = self._validated_history_report(record)
        except (OSError, ValueError) as exc:
            QMessageBox.critical(self, self.t("Report unavailable"), str(exc))
            return
        if not QDesktopServices.openUrl(QUrl.fromLocalFile(str(path))):
            QMessageBox.critical(self, self.t("Report unavailable"), self.t("The report couldn't be opened."))

    def export_history_report(self, record_id: str) -> None:
        record = self._record(record_id)
        if record is None:
            return
        try:
            source = self._validated_history_report(record)
        except (OSError, ValueError) as exc:
            QMessageBox.critical(self, self.t("Report unavailable"), str(exc))
            return
        destination, _filter = QFileDialog.getSaveFileName(
            self, self.t("Export report"), f"{Path(record['target']).name or 'scan-report'}.json", "JSON (*.json);;Text report (*.txt)"
        )
        if not destination:
            return
        try:
            if Path(destination).suffix.casefold() == ".txt":
                result = self._result_from_report(json.loads(source.read_text(encoding="utf-8")))
                export_report(result, destination, "txt")
            else:
                shutil.copy2(source, destination)
        except (OSError, TypeError, ValueError, KeyError) as exc:
            QMessageBox.critical(self, self.t("Export failed"), str(exc))
            return
        QMessageBox.information(self, self.t("Export complete"), destination)

    def remove_history_record(self, record_id: str) -> None:
        record = self._record(record_id)
        if record is None:
            return
        answer = QMessageBox.question(
            self,
            self.t("Remove scan"),
            self.t("Remove this scan from your list and delete its saved report? The scanned file itself is not touched."),
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        updated = [entry for entry in self.scan_history if entry["id"] != record_id]
        try:
            self.ui_store.save_history(updated)
        except (OSError, TypeError, ValueError) as exc:
            QMessageBox.critical(self, self.t("Your scans couldn't be saved"), str(exc))
            return
        self.scan_history = updated
        self._verdict_cache.pop(record_id, None)
        try:
            self._validated_history_report(record).unlink()
        except (OSError, ValueError) as exc:
            self._append_log(f"History entry removed but report cleanup failed: {exc}")
        if self._current is not None and self._current.get("record_id") == record_id:
            self._current["record_id"] = None
        self._refresh_rail()

    @staticmethod
    def _result_from_report(payload: dict[str, Any]) -> ScanResult:
        if not isinstance(payload, dict):
            raise ValueError("The saved report must contain a JSON object.")
        evidence = [
            Finding(
                category=str(item.get("category", "unknown")),
                severity=str(item.get("severity", "unknown")),
                evidence=str(item.get("evidence", "")),
                explanation=str(item.get("explanation", "")),
                contribution=int(item.get("contribution", 0)),
            )
            for item in payload.get("evidence", [])
            if isinstance(item, dict)
        ]
        return ScanResult(
            target=str(payload.get("target", "")),
            heuristic_score=int(payload.get("heuristic_score", 0)),
            ml_risk_score=payload.get("ml_risk_score"),
            combined_score=int(payload.get("combined_score", 0)),
            classification=str(payload.get("classification", "UNKNOWN")),
            evidence=evidence,
            feature_summary=payload.get("feature_summary", {}),
            model_status=str(payload.get("model_status", "")),
            limitations=str(payload.get("limitations", "")),
            summary=str(payload.get("summary", "")),
            yara_matches=payload.get("yara_matches", []),
            engine_status=payload.get("engine_status", {}),
            nextgen_analysis=payload.get("nextgen_analysis", {}),
            pe_analysis=payload.get("pe_analysis", {}),
            mitre_techniques=payload.get("mitre_techniques", []),
            osint_summary=payload.get("osint_summary", {}),
            structural_prediction=payload.get("structural_prediction", {}),
        )

    def export_current_report(self) -> None:
        if self._current is None:
            return
        result = self._current["result"]
        destination, selected_filter = QFileDialog.getSaveFileName(
            self, self.t("Export report"), f"{Path(result.target).name or 'cyberscan-report'}.txt", "Text report (*.txt);;JSON (*.json)"
        )
        if not destination:
            return
        output_format = "json" if Path(destination).suffix.casefold() == ".json" or "JSON" in selected_filter else "txt"
        try:
            export_report(result, destination, output_format)
        except (OSError, ValueError, TypeError) as exc:
            QMessageBox.critical(self, self.t("Export failed"), str(exc))
            return
        QMessageBox.information(self, self.t("Export complete"), destination)

    # ============================================================= settings
    def open_settings(self) -> None:
        if self.sheet.isVisible():
            return
        for key, box in self.sheet.checks.items():
            box.blockSignals(True)
            box.setChecked(bool(self.settings.get(key, False)))
            box.blockSignals(False)
        self.sheet.folder.blockSignals(True)
        self.sheet.folder.setText(str(self.settings.get("monitoring_directory", "")))
        self.sheet.folder.blockSignals(False)
        self.sheet.log_view.setPlainText("\n".join(self.audit_log[-400:]))
        self._settings_saved_state()
        self.scrim.setGeometry(self.main.rect())
        self.scrim.show()
        self.scrim.raise_()
        self.sheet.slide(self.main.rect(), True)
        self.sheet.close_button.setFocus()

    def close_settings(self) -> None:
        if not self.sheet.isVisible():
            return
        self.scrim.hide()
        self.sheet.slide(self.main.rect(), False)
        self.settings_button.setFocus()

    def _pending_settings(self) -> dict[str, Any]:
        pending = dict(self.settings)
        for key, box in self.sheet.checks.items():
            pending[key] = box.isChecked()
        pending["monitoring_directory"] = self.sheet.folder.text().strip()
        return pending

    def _settings_saved_state(self) -> None:
        self.sheet.set_saved(self._pending_settings() == self.settings)

    def _settings_dirty(self) -> None:
        self._settings_saved_state()

    def apply_settings(self) -> None:
        updated = self._pending_settings()
        directory = updated["monitoring_directory"]
        if not directory or (updated.get("monitoring_enabled") and not Path(directory).expanduser().is_dir()):
            QMessageBox.warning(self, self.t("Settings couldn't be saved"), self.t("Choose a folder that exists."))
            return
        updated["monitoring_directory"] = str(Path(directory).expanduser())
        try:
            self.ui_store.save_settings({**updated, "ui_language": self.language})
        except (OSError, TypeError, ValueError) as exc:
            QMessageBox.critical(self, self.t("Settings couldn't be saved"), str(exc))
            return
        self.settings = updated
        self._apply_text_scale()
        if self.settings["monitoring_enabled"]:
            if self._monitor.directory != Path(self.settings["monitoring_directory"]) or not self._monitor_running():
                self._monitor.stop()
                self._monitor = DownloadMonitor(self.settings["monitoring_directory"], callback=self.monitor_file_detected.emit)
            self._monitor.start()
            self._append_log("Downloads monitoring enabled.")
        else:
            self._monitor.stop()
            self._append_log("Downloads monitoring disabled.")
        self._settings_saved_state()
        self._refresh_notice()

    def select_monitor_directory(self) -> None:
        directory = QFileDialog.getExistingDirectory(self, self.t("Choose downloads folder"), self.sheet.folder.text())
        if directory:
            self.sheet.folder.setText(directory)

    def _monitor_running(self) -> bool:
        thread = getattr(self._monitor, "_thread", None)
        return bool(thread and thread.is_alive())

    def _refresh_notice(self) -> None:
        lines = []
        if self.settings.get("osint_enabled"):
            lines.append(self.t("Online lookups are on: links, domains and file fingerprints may be sent to public services."))
        if self._monitor_running():
            lines.append(self.t("Watching {folder} for new downloads.").format(folder=self.settings.get("monitoring_directory", "")))
        if self.startup_warnings:
            lines.append(self.t("Local data warning") + ": " + " ".join(self.startup_warnings))
        self.lens.set_notice("\n".join(lines))

    def _apply_text_scale(self) -> None:
        scale = 1.18 if self.settings.get("large_text") else 1.0
        if (scale, self.language) == self._text_scale:
            return
        self._text_scale = (scale, self.language)
        self.setStyleSheet(stylesheet(scale, self.language))
        font = QFont(self.font())
        font.setPixelSize(round(14 * scale))
        self.setFont(font)

    def _queue_monitored_file(self, path: str) -> None:
        self.pending_monitor_scans.put(path)
        self._append_log(f"[Monitoring] Stable download detected: {path}")
        self._start_next_monitor_scan()

    def _start_next_monitor_scan(self) -> None:
        if self.worker is not None and self.worker.isRunning():
            return
        try:
            path = self.pending_monitor_scans.get_nowait()
        except queue.Empty:
            return
        if not Path(path).is_file():
            self._append_log(f"[Monitoring] File no longer available; skipped: {path}")
            QTimer.singleShot(0, self._start_next_monitor_scan)
            return
        self._append_log(f"[Monitoring] Starting static analysis: {path}")
        self._start(str(Path(path).resolve()), "File")

    def _append_log(self, message: str) -> None:
        line = f"{datetime.now().astimezone().strftime('%H:%M:%S')}  {message}"
        self.audit_log.append(line)
        if self.sheet.isVisible():
            self.sheet.log_view.appendPlainText(line)

    # =============================================================== layout
    def _toggle_rail(self) -> None:
        self.rail.setVisible(not self.rail.isVisible())

    def _apply_layout_mode(self) -> None:
        width = self.width()
        narrow = width < 1040
        self.rail.setFixedWidth(300 if width >= 1280 else 268)
        if narrow != getattr(self, "_narrow", None):
            self._narrow = narrow
            self.rail.setVisible(not narrow)
        self.rail_button.setVisible(narrow)
        self.scrim.setGeometry(self.main.rect())
        self.sheet.place(self.main.rect())

    def resizeEvent(self, event) -> None:  # noqa: N802
        super().resizeEvent(event)
        self._apply_layout_mode()

    def dragEnterEvent(self, event) -> None:  # noqa: N802
        if self.worker is None and event.mimeData().hasUrls():
            self.lens.set_armed(True)
            event.acceptProposedAction()
        else:
            event.ignore()

    def dragLeaveEvent(self, event) -> None:  # noqa: N802
        self.lens.set_armed(False)
        super().dragLeaveEvent(event)

    def dropEvent(self, event) -> None:  # noqa: N802
        self.lens.set_armed(False)
        paths = [url.toLocalFile() for url in event.mimeData().urls() if url.isLocalFile()]
        if paths and self.worker is None:
            self._file_dropped(paths[0])
            event.acceptProposedAction()
        else:
            event.ignore()

    def closeEvent(self, event) -> None:  # noqa: N802
        busy = (self.worker is not None and self.worker.isRunning()) or any(w.isRunning() for w in self._abandoned_workers)
        if busy:
            event.ignore()
            QMessageBox.information(self, self.t("Analysis in progress"), self.t("Wait for the current scan to finish, then close CyberScan."))
            return
        if self._monitor:
            self._monitor.stop()
        self.journey.stop()
        event.accept()


def main() -> None:
    app = QApplication.instance() or QApplication([])
    app.setApplicationName("CyberScan")
    app.setOrganizationName("CyberScan")
    app.setStyle("Fusion")
    window = CyberScanApp()
    window.show()
    app.exec()
