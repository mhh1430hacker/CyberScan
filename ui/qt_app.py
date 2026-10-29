from __future__ import annotations

import json
import os
import queue
import shutil
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from PySide6.QtCore import (
    QSize,
    QEasingCurve,
    QEvent,
    QObject,
    QParallelAnimationGroup,
    QPropertyAnimation,
    QRect,
    Qt,
    QThread,
    QTimer,
    QUrl,
    Signal,
)
from PySide6.QtGui import QAction, QColor, QDesktopServices, QFont, QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFrame,
    QGraphicsOpacityEffect,
    QGridLayout,
    QBoxLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QStackedWidget,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from config import DATA_DIR, DEFAULT_SETTINGS, REPORT_DIR, ensure_directories
from core.models import Finding, ScanResult
from monitoring.downloads_monitor import DownloadMonitor
from reports.exporter import export_report
from ui.persistence import LocalUiStore
from ui.design_system import (
    TOKENS,
    CategoryBars,
    Chip,
    CollapsibleSection,
    EmptyState,
    FindingCard,
    Hairline,
    IconRailButton,
    MeterBar,
    MetaRow,
    PrimaryButton,
    SectionHeader,
    SeverityDot,
    StageTrack,
    StatTile,
    VerdictBadge,
    mono_font,
    severity_color,
    tone_color,
)
from ui.home import (
    FactRow,
    HeroPanel,
    ModeSegment,
    RecentActivity,
    ScanCore,
    glyph_icon,
    glyph_pixmap,
)
from ui.qt_widgets import AnimatedBackground, BrandMark, RiskGauge, SignalCanvas, Surface
from ui.scan_service import ScanService
from ui.result_view import (
    CATEGORY_LABELS,
    COVERAGE_LABELS,
    COVERAGE_TONES,
    ENGINE_LABELS,
    SEVERITY_LABELS,
    SEVERITY_RANK,
    SEVERITY_TONES,
    ResultView,
    build_result_view,
)
from ui.translations import translate_exact, translate_text

APP_STYLE = """
/* =====================================================================
   CyberScan design system (NOR). Tokens mirror ui/design_system.TOKENS.
   bg #070b12 · surface #0b1220 · line #1a2637
   text #e8eef8 / #9bacbf / #6b7d92 · accent #5ee0d0
   ===================================================================== */

QMainWindow { background: #070b12; }
QWidget {
    color: #e8eef8;
    font-family: "Segoe UI", "Noto Sans Arabic", "Tahoma";
    font-size: 14px;
}
QLabel { font-family: "Segoe UI", "Noto Sans Arabic", "Tahoma"; }
QWidget#root, QWidget#content, QWidget#page, QStackedWidget,
QStackedWidget > QWidget, QScrollArea, QScrollArea::viewport {
    background: transparent;
    border: 0;
}

/* ---------- canvas: painted, very low contrast, no grid ---------- */
#animatedBackground { background: transparent; }

QToolTip {
    background: #0f1826; color: #e8eef8;
    border: 1px solid #26364b; padding: 6px 9px;
}

/* ---------- navigation rail ---------- */
QFrame#sidebar {
    background: #080d16;
    border: 0;
    border-right: 1px solid #131e2c;
}
QFrame#sidebar[rtl="true"] {
    border-right: 0;
    border-left: 1px solid #131e2c;
}
QLabel#brandName {
    color: #f2f7ff; font-size: 14px; font-weight: 800;
    letter-spacing: 2.2px;
}
QLabel#brandTagline {
    color: #5ee0d0; font-size: 9px; font-weight: 700;
    letter-spacing: 1.6px;
}
QLabel#eyebrow {
    color: #6b7d92; font-size: 10px; font-weight: 700;
    letter-spacing: 1.4px; text-transform: uppercase;
}
QPushButton#railButton {
    background: transparent;
    border: 1px solid transparent;
    border-radius: 9px;
    color: #9bacbf;
    text-align: left;
    padding: 0 12px;
    font-size: 13.5px;
    font-weight: 600;
    min-height: 44px;
}
QPushButton#railButton:hover {
    background: #0f1826; color: #e8eef8;
}
QPushButton#railButton:pressed { background: #131e2c; }
QPushButton#railButton:checked {
    background: #0e2527;
    border: 1px solid #1f4a47;
    color: #dffbf6;
}
QPushButton#railButton:focus {
    border: 1px solid #5ee0d0;
}
QPushButton#sidebarPrimary {
    background: #5ee0d0; color: #04110f;
    border: 1px solid #5ee0d0; border-radius: 9px;
    font-size: 13px; font-weight: 800;
    min-height: 40px; padding: 0 14px;
}
QPushButton#sidebarPrimary:hover { background: #74f0e1; border-color: #74f0e1; }
QPushButton#sidebarPrimary:pressed { background: #46c6b7; }
QPushButton#sidebarPrimary:focus { border: 2px solid #dffbf6; }

QLabel#engineCard {
    background: #0b1220;
    border: 1px solid #131e2c;
    border-radius: 10px;
    padding: 10px 11px;
    color: #9bacbf;
    font-size: 11.5px;
}

QListWidget#sidebarHistory {
    background: transparent; border: 0;
    outline: 0;
}
QListWidget#sidebarHistory::item {
    color: #9bacbf; padding: 7px 8px;
    border-radius: 7px; border: 1px solid transparent;
}
QListWidget#sidebarHistory::item:hover { background: #0f1826; color: #e8eef8; }
QListWidget#sidebarHistory::item:selected {
    background: #0e2527; color: #dffbf6; border: 1px solid #1f4a47;
}

/* ---------- page header ---------- */
QFrame#topbar { background: transparent; border: 0; }
QLabel#breadcrumb { color: #6b7d92; font-size: 12px; }
QLabel#pageTitle { color: #f2f7ff; font-size: 28px; font-weight: 750; }
QLabel#pageSubtitle { color: #9bacbf; font-size: 13.5px; }
QLabel#statusPill {
    background: #0b1220; color: #9bacbf;
    border: 1px solid #1a2637; border-radius: 999px;
    padding: 5px 12px; font-size: 10.5px;
    font-weight: 700; letter-spacing: 1.1px;
}
QLabel#statusPill[tone="busy"] {
    background: #0e2527; color: #5ee0d0; border-color: #1f4a47;
}
QLabel#statusPill[tone="ok"], QLabel#statusPill[tone="ready"] {
    background: #0c1e14; color: #4ade80; border-color: #1d4a2c;
}
QLabel#statusPill[tone="warn"] {
    background: #241b0b; color: #f5b544; border-color: #55401a;
}
QLabel#statusPill[tone="danger"] {
    background: #240f10; color: #f0645f; border-color: #55211f;
}

/* ---------- surfaces ---------- */
QFrame#surface {
    background: #0b1220;
    border: 1px solid #1a2637;
    border-radius: 12px;
}
QFrame#surfaceQuiet {
    background: #0b1220;
    border: 1px solid #131e2c;
    border-radius: 12px;
}
QFrame#composer {
    background: #0d1523;
    border: 1px solid #26364b;
    border-radius: 14px;
}
QFrame#composer[armed="true"] {
    border: 1px solid #2f8f87;
    background: #0e1a22;
}
QFrame#metric {
    background: #0d1523;
    border: 1px solid #131e2c;
    border-radius: 10px;
}

/* ---------- typography helpers ---------- */
QLabel#heroTitle {
    color: #f2f7ff; font-size: 30px; font-weight: 800;
    letter-spacing: -0.4px;
}
QLabel#sectionTitle {
    color: #e8eef8; font-size: 14px; font-weight: 700;
    letter-spacing: 0.2px;
}
QLabel#sectionCaption { color: #6b7d92; font-size: 12.5px; }
QLabel#muted { color: #9bacbf; font-size: 13.5px; }
QLabel#subtle { color: #6b7d92; font-size: 12.5px; }
QLabel#metricValue {
    color: #f2f7ff; font-size: 24px; font-weight: 750;
}
QLabel#metricLabel {
    color: #6b7d92; font-size: 10.5px; font-weight: 700;
    letter-spacing: 1.1px;
}
QLabel#mono {
    font-family: "Cascadia Mono", "Consolas", "Courier New";
    color: #9bacbf; font-size: 11.5px;
}
QLabel#metaLabel { color: #6b7d92; font-size: 12px; }
QLabel#metaValue { color: #e8eef8; font-size: 12px; font-weight: 600; }
QLabel#metaValueMono {
    font-family: "Cascadia Mono", "Consolas", "Courier New";
    color: #dffbf6; font-size: 11.5px;
}
QLabel#emptyMark {
    color: #2f8f87; font-size: 20px; font-weight: 700;
}
QLabel#emptyTitle { color: #e8eef8; font-size: 13.5px; font-weight: 700; }
QLabel#emptyBody { color: #6b7d92; font-size: 12px; }

QLabel#chip {
    border-radius: 999px;
    padding: 3px 10px;
    font-size: 10.5px;
    font-weight: 700;
    letter-spacing: 0.4px;
    background: #0f1826;
    color: #9bacbf;
    border: 1px solid #1a2637;
}
QLabel#chip[tone="accent"] {
    background: #0e2527; color: #5ee0d0; border-color: #1f4a47;
}
QLabel#chip[tone="ok"] {
    background: #0c1e14; color: #4ade80; border-color: #1d4a2c;
}
QLabel#chip[tone="warn"] {
    background: #241b0b; color: #f5b544; border-color: #55401a;
}
QLabel#chip[tone="danger"] {
    background: #240f10; color: #f0645f; border-color: #55211f;
}
QLabel#chip[tone="info"] {
    background: #0d1726; color: #6fa8ff; border-color: #1f3555;
}

/* ---------- buttons ---------- */
QPushButton {
    background: #131e2c;
    color: #e8eef8;
    border: 1px solid #26364b;
    border-radius: 8px;
    padding: 0 14px;
    min-height: 34px;
    min-width: 96px;
    font-size: 13.5px;
    font-weight: 600;
}
QPushButton:hover { background: #19273a; border-color: #33475f; }
QPushButton:pressed { background: #0f1826; }
QPushButton:focus { border: 1px solid #5ee0d0; }
QPushButton:disabled {
    background: #0d1523; color: #4d5c70; border-color: #172232;
}

QPushButton#primary {
    background: #5ee0d0;
    color: #04110f;
    border: 1px solid #5ee0d0;
    font-weight: 800;
    font-size: 14px;
    min-height: 42px;
    min-width: 188px;
    padding: 0 22px;
    border-radius: 9px;
}
QPushButton#primary:hover { background: #74f0e1; border-color: #74f0e1; }
QPushButton#primary:pressed { background: #46c6b7; }
QPushButton#primary:focus { border: 2px solid #dffbf6; }
QPushButton#primary:disabled {
    background: #10252a; color: #4f8079; border-color: #1b3a3d;
}

QPushButton#secondary {
    background: transparent; color: #e8eef8;
    border: 1px solid #26364b;
}
QPushButton#secondary:hover { background: #131e2c; border-color: #33475f; }

QPushButton#quiet {
    background: transparent; color: #9bacbf;
    border: 1px solid transparent; font-weight: 600;
}
QPushButton#quiet:hover {
    background: #0f1826; color: #e8eef8; border-color: #1a2637;
}
QPushButton#quiet:focus { border: 1px solid #5ee0d0; }

QPushButton#nav, QPushButton#tabChip {
    background: transparent; color: #9bacbf;
    border: 1px solid transparent; border-radius: 8px;
    font-size: 12px; min-height: 30px; padding: 0 12px;
}
QPushButton#nav:hover, QPushButton#tabChip:hover {
    background: #0f1826; color: #e8eef8;
}
QPushButton#nav[selected="true"], QPushButton#tabChip[selected="true"] {
    background: #0e2527; color: #dffbf6; border-color: #1f4a47;
}
QPushButton#nav:focus, QPushButton#tabChip:focus {
    border: 1px solid #5ee0d0;
}

QPushButton#modeChip {
    background: #0d1523; color: #9bacbf;
    border: 1px solid #1a2637; border-radius: 999px;
    min-height: 28px; padding: 0 13px;
    font-size: 11.5px; font-weight: 600;
}
QPushButton#modeChip:hover { border-color: #33475f; color: #e8eef8; }
QPushButton#modeChip[selected="true"] {
    background: #0e2527; color: #dffbf6; border-color: #2f8f87;
}

/* ---------- inputs ---------- */
QLineEdit, QComboBox, QSpinBox, QPlainTextEdit, QTextEdit {
    background: #0a111c;
    border: 1px solid #1a2637;
    border-radius: 8px;
    color: #e8eef8;
    padding: 7px 10px;
    min-height: 20px;
    selection-background-color: #2f8f87;
    selection-color: #04110f;
}
QLineEdit:hover, QComboBox:hover, QSpinBox:hover { border-color: #26364b; }
QLineEdit:focus, QComboBox:focus, QSpinBox:focus,
QPlainTextEdit:focus, QTextEdit:focus {
    border: 1px solid #5ee0d0;
    background: #0b131f;
}
QLineEdit:disabled, QComboBox:disabled, QSpinBox:disabled {
    color: #4d5c70; background: #0d1523;
}
QLineEdit#targetEntry {
    font-size: 15px;
    padding: 12px 14px;
    border-radius: 10px;
    background: #0a111c;
    border: 1px solid #1a2637;
}
QLineEdit#targetEntry:focus {
    border: 1px solid #2f8f87;
    background: #0b131f;
}
QComboBox::drop-down { border: 0; width: 22px; }
QComboBox QAbstractItemView {
    background: #0f1826; border: 1px solid #26364b;
    selection-background-color: #0e2527; selection-color: #dffbf6;
    outline: 0;
}
QPlainTextEdit#logView, QTextBrowser#reportView {
    font-family: "Cascadia Mono", "Consolas", "Courier New";
    font-size: 11.5px;
    background: #080e17;
    border: 1px solid #131e2c;
    border-radius: 10px;
    padding: 8px;
}

QCheckBox { color: #c8d4e3; spacing: 9px; font-size: 12.5px; }
QCheckBox::indicator {
    width: 16px; height: 16px;
    border: 1px solid #33475f; border-radius: 4px;
    background: #0a111c;
}
QCheckBox::indicator:hover { border-color: #5ee0d0; }
QCheckBox::indicator:checked {
    background: #5ee0d0; border-color: #5ee0d0;
}
QCheckBox:focus { color: #e8eef8; }
QCheckBox:disabled { color: #4d5c70; }

/* ---------- tabs / lists / tables ---------- */
QTabWidget::pane {
    border: 1px solid #1a2637; border-radius: 10px;
    background: #0b1220; top: -1px;
}
QTabBar::tab {
    background: transparent; color: #6b7d92;
    padding: 7px 14px; margin-right: 4px;
    border: 0; border-bottom: 2px solid transparent;
    font-size: 12px; font-weight: 600;
}
QTabBar::tab:hover { color: #e8eef8; }
QTabBar::tab:selected {
    color: #dffbf6; border-bottom: 2px solid #5ee0d0;
}
QTabBar::tab:focus { color: #e8eef8; }

QListWidget, QTreeWidget, QTableWidget {
    background: #0b1220;
    border: 1px solid #1a2637;
    border-radius: 10px;
    outline: 0;
}
QListWidget::item, QTreeWidget::item { padding: 6px 4px; color: #c8d4e3; }
QListWidget::item:hover, QTreeWidget::item:hover { background: #0f1826; }
QListWidget::item:selected, QTreeWidget::item:selected {
    background: #0e2527; color: #dffbf6;
}
QHeaderView::section {
    background: #0d1523; color: #6b7d92;
    border: 0; border-bottom: 1px solid #1a2637;
    padding: 8px; font-size: 11px; font-weight: 700;
}
QTableWidget::item { padding: 6px; }

QScrollBar:vertical {
    background: transparent; width: 10px; margin: 2px;
}
QScrollBar::handle:vertical {
    background: #26364b; border-radius: 4px; min-height: 28px;
}
QScrollBar::handle:vertical:hover { background: #33475f; }
QScrollBar:horizontal {
    background: transparent; height: 10px; margin: 2px;
}
QScrollBar::handle:horizontal {
    background: #26364b; border-radius: 4px; min-width: 28px;
}
QScrollBar::add-line, QScrollBar::sub-line { height: 0; width: 0; }
QScrollBar::add-page, QScrollBar::sub-page { background: transparent; }

QProgressBar {
    background: #0f1826; border: 0; border-radius: 3px;
    height: 6px; text-align: center; color: transparent;
}
QProgressBar::chunk { background: #5ee0d0; border-radius: 3px; }

/* ---------- status banner ---------- */
QFrame#statusBanner {
    background: #0b1220;
    border: 1px solid #1a2637;
    border-radius: 10px;
}
QFrame#statusBanner[tone="busy"] {
    background: #0c1a1e; border-color: #1f4a47;
}
QFrame#statusBanner[tone="ok"], QFrame#statusBanner[tone="success"] {
    background: #0b1a12; border-color: #1d4a2c;
}
QFrame#statusBanner[tone="warning"] {
    background: #1c1509; border-color: #4b3a18;
}
QFrame#statusBanner[tone="error"] {
    background: #1c0d0e; border-color: #4b2020;
}
QLabel#bannerTitle { color: #f2f7ff; font-size: 13px; font-weight: 700; }
QLabel#bannerDetail { color: #9bacbf; font-size: 12px; }

/* ---------- results screen ---------- */
QFrame#findingCard {
    background: #0f1826; border: 1px solid #1a2637; border-radius: 10px;
}
QLabel#cardTitle { color: #e8eef8; font-size: 13px; font-weight: 650; }
QFrame#resultColumn {
    background: #0b1220; border: 1px solid #131e2c; border-radius: 12px;
}
QPushButton#sectionToggle {
    background: transparent; color: #e8eef8;
    border: 1px solid #1a2637; border-radius: 9px;
    padding: 9px 12px; text-align: left; font-weight: 650;
}
QPushButton#sectionToggle:hover { background: #0f1826; }
QPushButton#sectionToggle:checked { background: #0f1826; border-color: #26364b; }
QPushButton#sectionToggle:focus { border: 1px solid #5ee0d0; }

/* ---------- main screen ---------- */
QLabel#heroTitle {
    color: #f2f7ff;
    font-family: "Segoe UI Variable Display", "Segoe UI", "Dubai", "Noto Sans Arabic";
    font-size: 36px; font-weight: 700;
}
QLabel#heroBody { color: #9bacbf; font-size: 15px; }
QLabel#heroFact { color: #b9c7d6; font-size: 13px; }
QFrame#composer {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #0e1726, stop:1 #0b1220);
    border: 1px solid #1f2d40;
    border-radius: 16px;
}
QFrame#composer[armed="true"] {
    border: 1px dashed #5ee0d0;
    background: #0d1c22;
}
QFrame#composer QPushButton#modeChip {
    min-height: 34px; padding: 0 15px; font-size: 13px;
}
QFrame#composer QPushButton#secondary { min-height: 44px; padding: 0 16px; }
QFrame#composer QLineEdit#targetEntry { min-height: 44px; font-size: 15px; }
QFrame#activityPanel {
    background: #0b1220; border: 1px solid #131e2c; border-radius: 16px;
}
QPushButton#activityRow {
    background: #0d1523; border: 1px solid #131e2c; border-radius: 11px;
    text-align: left; padding: 0; min-height: 62px;
}
QPushButton#activityRow:hover { background: #111c2c; border-color: #26364b; }
QPushButton#activityRow:focus { border: 1px solid #5ee0d0; }
QLabel#activityName { color: #e8eef8; font-size: 14px; font-weight: 600; }
QLabel#activityScore {
    color: #9bacbf; font-family: "Cascadia Mono", "Consolas"; font-size: 13px;
}
QPushButton#railButton:checked {
    background: #0d1f23; color: #e9fbf8;
    border: 1px solid transparent; border-left: 3px solid #5ee0d0;
}
QPushButton#railButton[rtl="true"]:checked {
    border-left: 1px solid transparent; border-right: 3px solid #5ee0d0;
}
QPushButton#railButton { min-height: 40px; }

/* ---------- dialogs ---------- */
QMessageBox, QDialog { background: #0b1220; }
QMessageBox QLabel { color: #e8eef8; }
"""

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


STATUS_TONES = {
    "ready": ("#4ade80", "#0c1e14"),
    "busy": ("#5ee0d0", "#0e2527"),
    "warning": ("#f5b544", "#241b0b"),
    "error": ("#f0645f", "#240f10"),
    "ok": ("#4ade80", "#0c1e14"),
    "success": ("#4ade80", "#0c1e14"),
}

_CHIP_TONE_FOR_SEVERITY = {
    "high": "danger",
    "critical": "danger",
    "medium": "warn",
    "low": "info",
    "info": "neutral",
}


_STATUS_TONE = {
    "error": "error",
    "failed": "error",
    "danger": "error",
    "busy": "busy",
    "warning": "warning",
    "warn": "warning",
    "ok": "success",
    "success": "success",
    "complete": "success",
    "ready": "ready",
}


def apply_tone(widget: QWidget, tone: str) -> None:
    """Apply a semantic tone and repolish so the stylesheet reacts.

    Status pills and the banner use the status vocabulary; chips use the
    severity vocabulary. One helper serves both so they can never drift.
    """
    if widget.objectName() in {"statusPill", "statusBanner"}:
        resolved = _STATUS_TONE.get(tone, "neutral")
    else:
        resolved = _CHIP_TONE_FOR_SEVERITY.get(tone, "neutral")
    widget.setProperty("tone", resolved)
    style = widget.style()
    style.unpolish(widget)
    style.polish(widget)
    widget.update()


class StatusBanner(QFrame):
    """Compact, honest status strip used above the analysis composer."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("statusBanner")
        self.setProperty("tone", "ready")
        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(12)
        self.dot = QLabel("●")
        self.dot.setStyleSheet("font-size:12px;color:#77ead7")
        self.dot.setAlignment(
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop
        )
        self.dot.setFixedWidth(12)
        self.dot.setContentsMargins(0, 3, 0, 0)
        layout.addWidget(self.dot, 0, Qt.AlignmentFlag.AlignTop)
        copy = QVBoxLayout()
        copy.setSpacing(1)
        self.title = QLabel("")
        self.title.setObjectName("statusTitle")
        self.detail = QLabel("")
        self.detail.setObjectName("statusDetail")
        self.detail.setWordWrap(True)
        copy.addWidget(self.title)
        copy.addWidget(self.detail)
        layout.addLayout(copy, 1)

    def set_state(self, tone: str, title: str, detail: str) -> None:
        normalized = "success" if tone in {"ok", "ready", "success"} else tone
        apply_tone(self, tone if tone in STATUS_TONES else "ready")
        color = STATUS_TONES.get(tone, STATUS_TONES["ready"])[0]
        self.dot.setStyleSheet(f"font-size:12px;color:{color}")
        self.title.setText(title)
        self.detail.setText(detail)
        self.setVisible(tone != "ready")
        self.setProperty("tone", normalized)
        style = self.style()
        style.unpolish(self)
        style.polish(self)


class EmptyState(QFrame):
    """Placeholder shown in result panes before any scan has produced data."""

    def __init__(self, title: str, body: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("emptyState")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 22, 20, 22)
        layout.setSpacing(6)
        self._title_source = title
        self._body_source = body
        self.title_label = QLabel(title)
        self.title_label.setObjectName("emptyTitle")
        self.title_label.setWordWrap(True)
        self.body_label = QLabel(body)
        self.body_label.setObjectName("emptyBody")
        self.body_label.setWordWrap(True)
        layout.addStretch(1)
        layout.addWidget(self.title_label, 0, Qt.AlignmentFlag.AlignHCenter)
        layout.addWidget(self.body_label, 0, Qt.AlignmentFlag.AlignHCenter)
        layout.addStretch(1)

    def retranslate(self, translate) -> None:
        self.title_label.setText(translate(self._title_source))
        self.body_label.setText(translate(self._body_source))


class CyberScanApp(QMainWindow):
    monitor_file_detected = Signal(str)

    STAGE_TITLES = (
        "Static evidence",
        "Entropy & structure",
        "4096-D projection",
        "Intelligence",
    )

    NAV_ITEMS = (
        ("New analysis", "analysis", "\u25b8"),
        ("Scan history", "history", "\u25f4"),
        ("YARA & PE", "yara", "\u25a3"),
        ("MITRE ATT&CK", "mitre", "\u2263"),
        ("Structural model", "model", "\u25c7"),
        ("Audit timeline", "logs", "\u2261"),
        ("Settings", "settings", "\u2699"),
        ("About", "about", "\u24d8"),
    )

    def __init__(self) -> None:
        super().__init__()
        ensure_directories()
        self.setWindowTitle("CyberScan · Local threat analysis")
        screen = QApplication.primaryScreen()
        available = screen.availableGeometry() if screen else None
        width = min(1460, available.width() - 48) if available else 1320
        height = min(960, available.height() - 64) if available else 860
        self.resize(max(1040, width), max(660, height))
        self.setMinimumSize(880, 600)
        self.setAcceptDrops(True)
        self.setStyleSheet(APP_STYLE)
        base_point_size = self.font().pointSizeF()
        self._base_font_size = base_point_size if base_point_size > 0 else 9.0
        self._large_text_applied: bool | None = None

        self.ui_store = LocalUiStore(
            DATA_DIR / "ui_settings.json",
            DATA_DIR / "scan_history.json",
        )
        self.startup_warnings: list[str] = []
        try:
            persisted = self.ui_store.load_settings(
                {**DEFAULT_SETTINGS, "ui_language": "en"}
            )
        except ValueError as exc:
            persisted = {**DEFAULT_SETTINGS, "ui_language": "en"}
            self.startup_warnings.append(str(exc))
        language = persisted.pop("ui_language", "en")
        self.language = language if language in {"en", "ar"} else "en"
        self.settings = {
            key: persisted[key] for key in DEFAULT_SETTINGS if key in persisted
        }
        try:
            self.scan_history = self.ui_store.load_history()
        except ValueError as exc:
            self.scan_history = []
            self.startup_warnings.append(str(exc))
        self.audit_log: list[str] = [
            "[System] CyberScan initialized. Static analysis active."
        ]
        self.last_payload: tuple[Any, ...] | None = None
        self.worker: ScanWorker | None = None
        self.pending_monitor_scans: queue.Queue[str] = queue.Queue()
        self.current_page = "analysis"
        self._text_bindings: list[tuple[QLabel | QPushButton, str]] = []
        self._nav_buttons: dict[str, QPushButton] = {}
        self._monitor = DownloadMonitor(
            self.settings["monitoring_directory"],
            callback=self.monitor_file_detected.emit,
        )
        self.monitor_file_detected.connect(self._queue_monitored_file)

        self.setLayoutDirection(
            Qt.LayoutDirection.RightToLeft
            if self.language == "ar"
            else Qt.LayoutDirection.LeftToRight
        )
        self._page_effect = QGraphicsOpacityEffect(self)
        self._page_effect.setOpacity(1.0)
        self._page_animation = QPropertyAnimation(self._page_effect, b"opacity", self)
        self._page_animation.setDuration(180)
        self._page_animation.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._build_shell()
        self.pages.setGraphicsEffect(self._page_effect)
        self.risk_gauge.language = self.language
        self._apply_text_scale()
        self._settings_snapshot = dict(self.settings)
        self.refresh_history()
        self.refresh_workspace_status()
        self._refresh_detection_summary()
        self._sync_nav_state("analysis")
        self._install_shortcuts()
        self._workspace_timer = QTimer(self)
        self._workspace_timer.timeout.connect(self.refresh_workspace_status)
        self._workspace_timer.start(5000)
        if self.settings.get("monitoring_enabled"):
            self._monitor.start()
            self._append_log("Downloads monitoring enabled.")
        self._show_page("analysis")
        self.status_banner.set_state(
            "ready",
            self.tr("Ready for a new target"),
            self.tr("Choose a file, paste a URL, or enter an indicator, then start the analysis."),
        )
        QTimer.singleShot(0, self._apply_layout_mode)
        if self.startup_warnings:
            self.status_banner.set_state(
                "warning",
                self.tr("Local data warning"),
                "\n\n".join(self.startup_warnings),
            )

    def tr(self, text: str) -> str:
        return translate_text(text, self.language)

    def _label(self, text: str, object_name: str = "") -> QLabel:
        label = QLabel(self.tr(text))
        if object_name:
            label.setObjectName(object_name)
        if text:
            self._text_bindings.append((label, text))
        return label

    def _button(
        self,
        text: str,
        callback=None,
        *,
        primary: bool = False,
        quiet: bool = False,
    ) -> QPushButton:
        button = QPushButton(self.tr(text))
        button.setCursor(Qt.CursorShape.PointingHandCursor)
        if primary:
            button.setObjectName("primary")
        elif quiet:
            button.setObjectName("quiet")
        if callback:
            button.clicked.connect(callback)
        self._text_bindings.append((button, text))
        return button

    @staticmethod
    def _spacer() -> QWidget:
        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        return spacer

    def _build_shell(self) -> None:
        root = AnimatedBackground()
        root.setObjectName("root")
        shell = QHBoxLayout(root)
        shell.setContentsMargins(0, 0, 0, 0)
        shell.setSpacing(0)

        self.sidebar = QFrame()
        self.sidebar.setObjectName("sidebar")
        self.sidebar.setMinimumWidth(232)
        self.sidebar.setMaximumWidth(232)
        rail = QVBoxLayout(self.sidebar)
        rail.setContentsMargins(14, 22, 14, 16)
        rail.setSpacing(2)

        brand = QHBoxLayout()
        brand.setSpacing(10)
        brand_mark = BrandMark()
        brand.addWidget(brand_mark, 0, Qt.AlignmentFlag.AlignVCenter)
        brand_copy = QVBoxLayout()
        brand_copy.setSpacing(0)
        brand_name = QLabel("CYBERSCAN")
        brand_name.setObjectName("brandName")
        brand_copy.addWidget(brand_name)
        brand_tagline = QLabel(self.tr("LOCAL SECURITY LAB"))
        brand_tagline.setObjectName("brandTagline")
        self._text_bindings.append((brand_tagline, "LOCAL SECURITY LAB"))
        brand_copy.addWidget(brand_tagline)
        brand.addLayout(brand_copy)
        brand.addStretch(1)
        rail.addLayout(brand)
        rail.addSpacing(20)

        self.sidebar_primary = self._button(
            "New analysis", self._show_analysis, primary=False
        )
        self.sidebar_primary.setObjectName("railButton")
        self.sidebar_primary.setIcon(glyph_icon("analysis"))
        self.sidebar_primary.setIconSize(QSize(18, 18))
        self.sidebar_primary.setCheckable(True)
        self.sidebar_primary.setMinimumHeight(44)
        self.sidebar_primary.setProperty("navKey", "analysis")
        self.sidebar_primary.setToolTip(self.tr("Start a new scan (Ctrl+1)"))
        self.sidebar_primary.setMinimumHeight(40)
        rail.addWidget(self.sidebar_primary)

        groups = {"history": "Analyze", "yara": "Evidence", "logs": "System"}
        self._rail_groups: list[tuple[QLabel, str]] = []
        for label, page, icon in self.NAV_ITEMS[1:]:
            if page in groups:
                rail.addSpacing(14)
                group = QLabel(translate_exact(groups[page], self.language))
                group.setObjectName("eyebrow")
                self._rail_groups.append((group, groups[page]))
                rail.addWidget(group)
                rail.addSpacing(3)
            button = IconRailButton(f"{icon}", self.tr(label), icon=glyph_icon(page))
            button.setToolTip(self.tr(f"Open {label}"))
            button.clicked.connect(
                lambda checked=False, key=page: self._show_page(key)
            )
            self._nav_buttons[page] = button
            rail.addWidget(button)

        self.sidebar_history = QListWidget()
        self.sidebar_history.setObjectName("sidebarHistory")
        self.sidebar_history.setMaximumHeight(150)
        self.sidebar_history.setFrameShape(QFrame.Shape.NoFrame)
        self.sidebar_history.itemActivated.connect(self._open_history_item)
        self.sidebar_history.itemClicked.connect(self._open_history_item)
        # Kept for compatibility; recent scans now live on the main screen.
        self.sidebar_history.setVisible(False)
        rail.addWidget(self.sidebar_history)
        self.sidebar_recent_empty = QLabel(self.tr("No scans yet."))
        self.sidebar_recent_empty.setVisible(False)

        rail.addStretch(1)

        self.sidebar_workspace_label = self._label(
            "Local analysis · targets are read, never executed"
        )
        self.sidebar_workspace_label.setObjectName("engineCard")
        self.sidebar_workspace_label.setWordWrap(True)
        rail.addWidget(self.sidebar_workspace_label)
        rail.addSpacing(8)

        language_row = QHBoxLayout()
        language_row.setSpacing(6)
        lang_caption = self._label("Language", "subtle")
        self._rail_groups.append((lang_caption, "Language"))
        language_row.addWidget(lang_caption)
        language_row.addStretch(1)
        self.language_button = self._button(
            "العربية" if self.language == "en" else "English",
            self.toggle_language,
            quiet=True,
        )
        self.language_button.setObjectName("quiet")
        self.language_button.setIcon(glyph_icon("globe", TOKENS["text_dim"], TOKENS["text_dim"], 16))
        language_row.addWidget(self.language_button)
        rail.addLayout(language_row)
        shell.addWidget(self.sidebar)

        content = QWidget()
        content.setObjectName("content")
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(24, 12, 28, 20)
        content_layout.setSpacing(14)
        topbar = QFrame()
        topbar.setObjectName("topbar")
        top_layout = QHBoxLayout(topbar)
        top_layout.setContentsMargins(2, 16, 2, 10)
        top_layout.setSpacing(14)

        heading = QVBoxLayout()
        heading.setSpacing(3)
        self.breadcrumb = self._label("Workspace", "breadcrumb")
        self.breadcrumb.setVisible(False)
        heading.addWidget(self.breadcrumb)
        self.page_title = QLabel(self.tr("New analysis"))
        self.page_title.setObjectName("pageTitle")
        heading.addWidget(self.page_title)
        self.page_subtitle = QLabel("")
        self.page_subtitle.setObjectName("pageSubtitle")
        self.page_subtitle.setWordWrap(True)
        heading.addWidget(self.page_subtitle)
        top_layout.addLayout(heading, 1)

        self.connection_status = QLabel("READY")
        self.connection_status.setObjectName("statusPill")
        self.connection_status.setProperty("tone", "ok")
        self.connection_status.setToolTip(
            self.tr("The local analysis engines are idle and ready for a new target.")
        )
        top_layout.addWidget(
            self.connection_status, 0, Qt.AlignmentFlag.AlignVCenter
        )
        content_layout.addWidget(topbar)

        self.pages = QStackedWidget()
        self.pages.addWidget(self._build_analysis_page())
        self.pages.addWidget(self._build_history_page())
        self.pages.addWidget(self._build_yara_page())
        self.pages.addWidget(self._build_mitre_page())
        self.pages.addWidget(self._build_model_page())
        self.pages.addWidget(self._build_logs_page())
        self.pages.addWidget(self._build_settings_page())
        self.pages.addWidget(self._build_about_page())
        self.page_indices = {
            name: index
            for index, name in enumerate(
                ("analysis", "history", "yara", "mitre", "model", "logs", "settings", "about")
            )
        }
        content_layout.addWidget(self.pages, 1)
        shell.addWidget(content, 1)
        self.setCentralWidget(root)
        self._sync_directional_styles()

    def _sync_directional_styles(self) -> None:
        is_rtl = self.language == "ar"
        self.sidebar.setProperty("rtl", is_rtl)
        self.sidebar.style().unpolish(self.sidebar)
        self.sidebar.style().polish(self.sidebar)
        for button in (*self._nav_buttons.values(), self.sidebar_primary):
            button.setProperty("rtl", is_rtl)
            button.style().unpolish(button)
            button.style().polish(button)
        labels = {page: label for label, page, _icon in self.NAV_ITEMS}
        for page, button in self._nav_buttons.items():
            if hasattr(button, "set_label"):
                button.set_label(self.tr(labels.get(page, page)))

    def _scroll_page(self) -> tuple[QScrollArea, QWidget, QVBoxLayout]:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.viewport().setStyleSheet("background: transparent;")
        page = QWidget()
        page.setObjectName("page")
        page.setAutoFillBackground(False)
        layout = QVBoxLayout(page)
        layout.setContentsMargins(2, 20, 4, 28)
        layout.setSpacing(19)
        scroll.setWidget(page)
        return scroll, page, layout

    def _build_analysis_page(self) -> QWidget:
        scroll, page, layout = self._scroll_page()
        layout.setContentsMargins(2, 8, 4, 28)

        # ---- hero: identity, location, and state the app can prove -------
        self.hero = HeroPanel()
        self.hero.setMaximumWidth(1180)
        hero_layout = QHBoxLayout(self.hero)
        hero_layout.setContentsMargins(32, 28, 26, 28)
        hero_layout.setSpacing(28)
        hero_copy = QVBoxLayout()
        hero_copy.setSpacing(10)
        hero_copy.addStretch(1)
        self.hero_state = Chip(self.tr("PRIVATE BY DEFAULT"), "accent")
        self._text_bindings.append((self.hero_state, "PRIVATE BY DEFAULT"))
        hero_copy.addWidget(self.hero_state, 0, Qt.AlignmentFlag.AlignLeft)
        self.hero_title = QLabel("")
        self.hero_title.setObjectName("heroTitle")
        self.hero_title.setWordWrap(True)
        hero_copy.addWidget(self.hero_title)
        self.hero_body = QLabel("")
        self.hero_body.setObjectName("heroBody")
        self.hero_body.setWordWrap(True)
        hero_copy.addWidget(self.hero_body)
        hero_copy.addSpacing(6)
        self.fact_engines = FactRow("engines")
        self.fact_engines.set_text("", "accent")
        self.detection_summary = self.fact_engines.text
        self.fact_lookups = FactRow("globe")
        self.fact_monitor = FactRow("monitor")
        for fact in (self.fact_engines, self.fact_lookups, self.fact_monitor):
            hero_copy.addWidget(fact)
        hero_copy.addStretch(1)
        hero_layout.addLayout(hero_copy, 1)
        self.scan_core = ScanCore()
        hero_layout.addWidget(self.scan_core, 0, Qt.AlignmentFlag.AlignVCenter)
        layout.addWidget(self.hero)

        # ---- action dock: the one thing to do on this screen -------------
        composer = QFrame()
        composer.setObjectName("composer")
        composer.setMaximumWidth(1180)
        composer.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        self._composer = composer
        composer_layout = QVBoxLayout(composer)
        composer_layout.setContentsMargins(22, 18, 22, 18)
        composer_layout.setSpacing(14)

        self.mode_values = ("File", "URL", "Indicator / text")
        modes_row = QHBoxLayout()
        modes_row.setSpacing(10)
        self.mode_segment = ModeSegment(self.mode_values)
        self.mode_segment.modeSelected.connect(self._choose_mode_without_dialog)
        modes_row.addWidget(self.mode_segment, 1)
        self.shortcut_hint = QLabel("")
        self.shortcut_hint.setObjectName("subtle")
        modes_row.addWidget(self.shortcut_hint, 0, Qt.AlignmentFlag.AlignVCenter)
        composer_layout.addLayout(modes_row)
        # The combo box stays the single source of the selected mode; the
        # segmented control above is its visible face.
        self.input_mode = QComboBox()
        for mode in self.mode_values:
            self.input_mode.addItem(self.tr(mode), mode)
        self.input_mode.currentIndexChanged.connect(self._mode_changed)
        self.input_mode.setVisible(False)
        composer_layout.addWidget(self.input_mode)

        entry_row = QHBoxLayout()
        entry_row.setSpacing(10)
        self.target_entry = QLineEdit()
        self.target_entry.setObjectName("targetEntry")
        self.target_entry.setPlaceholderText(
            self.tr("Paste a file path, URL, hash, or suspicious text…")
        )
        self.target_entry.setClearButtonEnabled(True)
        self.target_entry.setAcceptDrops(True)
        self.target_entry.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
        self.target_entry.setToolTip(
            self.tr("Paste a target, or drag a file here. Enter starts the analysis.")
        )
        self.target_entry.returnPressed.connect(self.run_scan)
        self.target_entry.installEventFilter(self)
        entry_row.addWidget(self.target_entry, 1)
        self.browse_button = self._button("Choose file…", self.select_file)
        self.browse_button.setObjectName("secondary")
        self.browse_button.setIcon(glyph_icon("folder", TOKENS["text"], TOKENS["text"], 16))
        self.browse_button.setToolTip(
            self.tr("Pick a local file with the system file dialog (Ctrl+O)")
        )
        entry_row.addWidget(self.browse_button)
        self.analyze_button = PrimaryButton(self.tr("Analyze target"))
        self.analyze_button.clicked.connect(self.run_scan)
        self._text_bindings.append((self.analyze_button, "Analyze target"))
        self.analyze_button.setToolTip(self.tr("Start the static analysis (Ctrl+Enter)"))
        entry_row.addWidget(self.analyze_button)
        composer_layout.addLayout(entry_row)

        hint_row = QHBoxLayout()
        hint_row.setSpacing(8)
        self.drop_icon = QLabel()
        self.drop_icon.setPixmap(glyph_pixmap("drop", TOKENS["text_mute"], 14))
        self.drop_icon.setFixedSize(16, 16)
        hint_row.addWidget(self.drop_icon, 0, Qt.AlignmentFlag.AlignVCenter)
        self.selected_file_label = QLabel("")
        self.selected_file_label.setObjectName("subtle")
        self.selected_file_label.setWordWrap(True)
        hint_row.addWidget(self.selected_file_label, 1)
        composer_layout.addLayout(hint_row)
        layout.addWidget(composer)

        self.status_banner = StatusBanner()
        self.status_banner.setMaximumWidth(1180)
        self.status_banner.set_state(
            "ready",
            self.tr("Ready for a new target"),
            self.tr("Choose a file, paste a URL, or enter an indicator, then start the analysis."),
        )
        layout.addWidget(self.status_banner)

        # ---- live analysis: real stages ---------------------------------
        lab_panel = QFrame()
        lab_panel.setObjectName("surfaceQuiet")
        lab_panel.setMaximumWidth(1180)
        lab_panel.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        lab_layout = QVBoxLayout(lab_panel)
        lab_layout.setContentsMargins(16, 14, 16, 14)
        lab_layout.setSpacing(8)
        lab_header = SectionHeader(
            self.tr("Analysis pipeline"), self.tr("Waiting for a target")
        )
        lab_header.caption.setObjectName("sectionCaption")
        self.lab_caption = lab_header.caption
        lab_layout.addWidget(lab_header)

        self.stage_labels: list[tuple[QLabel, QProgressBar, QLabel]] = []
        self.stage_cards: list[QFrame] = []
        self.stage_track = StageTrack(
            [
                self.tr("Static evidence"),
                self.tr("Entropy"),
                self.tr("Projection"),
                self.tr("Intelligence"),
            ]
        )
        self.stage_track.setFixedHeight(34)
        lab_layout.addWidget(self.stage_track)
        self.stage_row = QGridLayout()
        self.stage_row.setHorizontalSpacing(1)
        self.stage_row.setVerticalSpacing(1)
        self._stage_columns = 1
        for index, key in enumerate(
            ("Static evidence", "Entropy & structure", "4096-D projection", "Intelligence")
        ):
            stage = QFrame()
            stage.setObjectName("metric")
            stage_layout = QVBoxLayout(stage)
            stage_layout.setContentsMargins(10, 8, 10, 8)
            title = self._label(f"0{index + 1}  {key}", "muted")
            title.setWordWrap(True)
            title.setVisible(False)
            status = self._label("Waiting", "subtle")
            status.setWordWrap(True)
            bar = QProgressBar()
            bar.setRange(0, 100)
            bar.setValue(0)
            stage_layout.addWidget(title)
            stage_layout.addWidget(bar)
            stage_layout.addWidget(status)
            self.stage_cards.append(stage)
            self.stage_row.addWidget(stage, index, 0)
            self.stage_labels.append((title, bar, status))
        lab_layout.addLayout(self.stage_row)
        for stage in self.stage_cards:
            stage.setVisible(False)
            stage.setFixedHeight(0)
        self.stage_row.setContentsMargins(0, 0, 0, 0)
        lab_layout.addWidget(self.stage_track)
        layout.addWidget(lab_panel)
        self._pipeline_panel = lab_panel
        lab_panel.setVisible(False)

        self.signal_canvas = SignalCanvas()
        self.signal_canvas.setVisible(False)
        # Keep the canvas timer running: it is the single source of the live
        # activity signal, and hiding the widget means it never repaints.
        self.signal_canvas._timer.start(50)

        # ---- results: verdict first ------------------------------------
        # Texts built here are re-applied in _apply_results_static_text() on
        # every render, so a language switch updates them too.
        self._results_static: list[tuple[Any, str]] = []
        self.results_panel = QFrame()
        self.results_panel.setObjectName("surface")
        result_layout = QVBoxLayout(self.results_panel)
        result_layout.setContentsMargins(18, 16, 18, 16)
        result_layout.setSpacing(14)

        # 1. Verdict + risk index: readable in one glance.
        verdict_row = QHBoxLayout()
        verdict_row.setSpacing(18)
        verdict_copy = QVBoxLayout()
        verdict_copy.setSpacing(6)
        self.verdict_badge = VerdictBadge()
        self.verdict_badge.setMinimumHeight(96)
        verdict_copy.addWidget(self.verdict_badge)
        self.verdict_label = self._label("Analysis result", "verdict")
        self.verdict_label.setVisible(False)
        verdict_copy.addWidget(self.verdict_label)
        self.target_result_label = self._label("", "mono")
        self.target_result_label.setWordWrap(True)
        self.target_result_label.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
        self.target_result_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        verdict_copy.addWidget(self.target_result_label)
        self.verdict_summary = self._label("", "muted")
        self.verdict_summary.setWordWrap(True)
        self.verdict_summary.setVisible(False)
        verdict_copy.addWidget(self.verdict_summary)
        self.completeness_chip = QLabel("")
        self.completeness_chip.setObjectName("chip")
        self.completeness_chip.setVisible(False)
        verdict_copy.addWidget(self.completeness_chip, 0, Qt.AlignmentFlag.AlignLeft)
        self.limitations_label = self._label("", "subtle")
        self.limitations_label.setWordWrap(True)
        verdict_copy.addWidget(self.limitations_label)
        verdict_copy.addStretch(1)
        verdict_row.addLayout(verdict_copy, 1)

        gauge_col = QVBoxLayout()
        gauge_col.setSpacing(4)
        self.risk_gauge = RiskGauge()
        gauge_col.addWidget(self.risk_gauge, 0, Qt.AlignmentFlag.AlignHCenter)
        self.risk_unavailable = QLabel("")
        self.risk_unavailable.setObjectName("subtle")
        self.risk_unavailable.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.risk_unavailable.setWordWrap(True)
        self.risk_unavailable.setMinimumWidth(168)
        self.risk_unavailable.setVisible(False)
        self._results_static.append((self.risk_unavailable, "Risk index not available"))
        gauge_col.addWidget(self.risk_unavailable)
        self.risk_caption = self._label("", "subtle")
        self.risk_caption.setAlignment(Qt.AlignmentFlag.AlignCenter)
        gauge_col.addWidget(self.risk_caption)
        self.risk_note = self._label("Risk index · not a malware probability", "subtle")
        self.risk_note.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.risk_note.setWordWrap(True)
        self.risk_note.setMaximumWidth(220)
        gauge_col.addWidget(self.risk_note)
        gauge_col.addStretch(1)
        verdict_row.addLayout(gauge_col, 0)
        result_layout.addLayout(verdict_row)

        # 2. Quick summary: real counts only.
        stats_row = QHBoxLayout()
        stats_row.setSpacing(8)
        self.stat_tiles: dict[str, StatTile] = {}
        for key, caption in (
            ("findings", "Findings"),
            ("severity", "Highest severity"),
            ("mitre", "ATT&CK techniques"),
            ("coverage", "Engines that ran"),
        ):
            tile = StatTile()
            self._results_static.append((tile.caption, caption))
            self.stat_tiles[key] = tile
            stats_row.addWidget(tile, 1)
        result_layout.addLayout(stats_row)

        # 3. Evidence cards | category chart + coverage (stacks when narrow).
        self.results_columns = QBoxLayout(QBoxLayout.Direction.LeftToRight)
        self.results_columns.setSpacing(12)

        evidence_column = QFrame()
        evidence_column.setObjectName("resultColumn")
        evidence_layout = QVBoxLayout(evidence_column)
        evidence_layout.setContentsMargins(14, 12, 14, 14)
        evidence_layout.setSpacing(9)
        self.evidence_header = SectionHeader("", "")
        self._results_static.append((self.evidence_header.title, "Key evidence"))
        self._results_static.append((self.evidence_header.caption, "Strongest first"))
        evidence_layout.addWidget(self.evidence_header)
        self.finding_cards_layout = QVBoxLayout()
        self.finding_cards_layout.setSpacing(8)
        evidence_layout.addLayout(self.finding_cards_layout)
        self.finding_cards: list[FindingCard] = []
        self.no_findings_state = QWidget()
        empty_layout = QVBoxLayout(self.no_findings_state)
        empty_layout.setContentsMargins(8, 18, 8, 18)
        empty_layout.setSpacing(6)
        for object_name, source in (
            ("emptyTitle", "No indicators observed"),
            (
                "emptyBody",
                "The engines that ran reported no evidence for this target. That is not proof of safety.",
            ),
        ):
            text = QLabel("")
            text.setObjectName(object_name)
            text.setWordWrap(True)
            text.setAlignment(Qt.AlignmentFlag.AlignCenter)
            empty_layout.addWidget(text)
            self._results_static.append((text, source))
        evidence_layout.addWidget(self.no_findings_state)
        self.findings_overflow_button = QPushButton("")
        self.findings_overflow_button.setObjectName("quiet")
        self.findings_overflow_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.findings_overflow_button.clicked.connect(self._show_all_findings)
        self.findings_overflow_button.setVisible(False)
        evidence_layout.addWidget(self.findings_overflow_button, 0, Qt.AlignmentFlag.AlignLeft)
        evidence_layout.addStretch(1)
        self.results_columns.addWidget(evidence_column, 3)

        side_column = QFrame()
        side_column.setObjectName("resultColumn")
        side_layout = QVBoxLayout(side_column)
        side_layout.setContentsMargins(14, 12, 14, 14)
        side_layout.setSpacing(10)
        self.category_header = SectionHeader("", "")
        self._results_static.append((self.category_header.title, "Indicators by category"))
        self._results_static.append((self.category_header.caption, "Number of findings"))
        side_layout.addWidget(self.category_header)
        self.category_bars = CategoryBars()
        side_layout.addWidget(self.category_bars)
        self.category_unavailable = QLabel("")
        self.category_unavailable.setObjectName("subtle")
        self.category_unavailable.setWordWrap(True)
        self._results_static.append(
            (self.category_unavailable, "Not available: there are no findings to group.")
        )
        side_layout.addWidget(self.category_unavailable)
        side_layout.addWidget(Hairline())
        self.coverage_header = SectionHeader("", "")
        self._results_static.append((self.coverage_header.title, "Scan coverage"))
        side_layout.addWidget(self.coverage_header)
        self.coverage_layout = QVBoxLayout()
        self.coverage_layout.setSpacing(6)
        side_layout.addLayout(self.coverage_layout)
        self.coverage_unavailable = QLabel("")
        self.coverage_unavailable.setObjectName("subtle")
        self.coverage_unavailable.setWordWrap(True)
        self._results_static.append(
            (self.coverage_unavailable, "Not available: the engine reported no coverage data.")
        )
        side_layout.addWidget(self.coverage_unavailable)
        side_layout.addStretch(1)
        self.results_columns.addWidget(side_column, 2)
        result_layout.addLayout(self.results_columns)

        # 4. File details (collapsed; nothing is removed, only deferred).
        self.file_section = CollapsibleSection()
        self._results_static.append((self.file_section.set_title, "File details"))
        self.file_rows: dict[str, MetaRow] = {}
        for key, caption in (
            ("target", "Target"),
            ("type", "Content type"),
            ("size", "Size"),
            ("sha256", "SHA-256"),
            ("entropy", "Mean entropy"),
            ("pe", "PE status"),
            ("yara", "YARA matches"),
            ("model", "Model status"),
        ):
            raw_value = key in {"target", "sha256", "pe"}
            row = MetaRow(caption, "-", mono=raw_value)
            row.value.setWordWrap(True)
            row.layout().setStretch(2, 3)
            if raw_value:
                # Paths, hashes and engine identifiers stay left-to-right.
                row.value.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
            self._results_static.append((row.label, caption))
            self.file_rows[key] = row
            self.file_section.body_layout.addWidget(row)
        result_layout.addWidget(self.file_section)

        # 5. Technical details: the existing metric strip and detail tabs.
        self.technical_section = CollapsibleSection()
        self._results_static.append((self.technical_section.set_title, "Technical details"))
        self.technical_section.toggled.connect(self._sync_details_button)
        self.result_metrics = QHBoxLayout()
        self.result_metrics.setSpacing(8)
        self.technical_section.body_layout.addLayout(self.result_metrics)
        self.detail_tabs = QTabWidget()
        self.detail_tabs.setMinimumHeight(320)
        self.detail_tabs.addTab(self._build_result_overview(), self.tr("Evidence"))
        self.detail_tabs.addTab(self._build_structure_detail(), self.tr("Structure"))
        self.detail_tabs.addTab(self._build_detections_detail(), self.tr("Findings"))
        self.detail_tabs.addTab(self._build_engine_detail(), self.tr("Engines"))
        self.detail_tabs.addTab(self._build_intel_detail(), self.tr("Intelligence"))
        self.detail_tabs.addTab(self._build_report_detail(), self.tr("Report"))
        self.technical_section.body_layout.addWidget(self.detail_tabs)
        result_layout.addWidget(self.technical_section)

        # 6. Actions backed by existing functions.
        result_actions = QHBoxLayout()
        result_actions.setSpacing(8)
        self.details_button = QPushButton("")
        self.details_button.setObjectName("secondary")
        self.details_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.details_button.clicked.connect(self._toggle_technical_details)
        result_actions.addWidget(self.details_button)
        result_actions.addStretch(1)
        self.export_button = self._button("Export report", self.export_current_report)
        self.export_button.setObjectName("secondary")
        self.export_button.setToolTip(self.tr("Save this result as a text or JSON report"))
        self.export_button.setEnabled(False)
        result_actions.addWidget(self.export_button)
        self.new_scan_button = QPushButton("")
        self.new_scan_button.setObjectName("secondary")
        self.new_scan_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.new_scan_button.clicked.connect(self._return_to_scan)
        self._results_static.append((self.new_scan_button, "New scan"))
        result_actions.addWidget(self.new_scan_button)
        result_layout.addLayout(result_actions)
        layout.addWidget(self.results_panel)
        self.results_panel.setMaximumWidth(1180)
        self.results_panel.hide()
        self._results_effect = QGraphicsOpacityEffect(self.results_panel)
        self._results_effect.setOpacity(1.0)
        self.results_panel.setGraphicsEffect(self._results_effect)
        self._results_animation: QParallelAnimationGroup | None = None
        self._results_view: ResultView | None = None
        self._apply_results_static_text()

        # ---- recent activity: saved scans, newest first -----------------
        self.recent_activity = RecentActivity()
        self.recent_activity.setMaximumWidth(1180)
        self.recent_activity.recordActivated.connect(self._open_history_record)
        self.recent_activity.viewAllRequested.connect(lambda: self._show_page("history"))
        layout.addWidget(self.recent_activity)
        layout.addStretch(1)
        return scroll

    def _build_workspace_metrics(self) -> None:
        labels = (
            ("Scans in history", "0"),
            ("Structural model", "Checking…"),
            ("Downloads monitor", "Off"),
            ("Local reports", "0"),
        )
        for key, value in labels:
            card = QFrame()
            card.setObjectName("metric")
            card_layout = QVBoxLayout(card)
            card_layout.setContentsMargins(12, 10, 12, 10)
            card_layout.addWidget(self._label(key, "muted"))
            metric = self._label(value, "metricValue")
            card_layout.addWidget(metric)
            self._workspace_metric_widgets[key] = metric
            self.workspace_metrics.addWidget(card)

    def _build_result_overview(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(13, 13, 13, 13)
        self.evidence_summary = QPlainTextEdit()
        self.evidence_summary.setReadOnly(True)
        self.evidence_summary.setMinimumHeight(160)
        self.evidence_summary.setPlaceholderText(self.tr("Evidence will appear here after analysis."))
        layout.addWidget(self.evidence_summary)
        self.story_label = self._label("", "muted")
        self.story_label.setWordWrap(True)
        layout.addWidget(self.story_label)
        return page

    def _build_structure_detail(self) -> QWidget:
        scroll, page, layout = self._scroll_page()
        self.structure_metrics = QHBoxLayout()
        layout.addLayout(self.structure_metrics)
        entropy_surface = Surface()
        entropy_layout = QVBoxLayout(entropy_surface)
        entropy_layout.addWidget(self._label("Measured entropy profile", "sectionTitle"))
        self.entropy_canvas = SignalCanvas()
        entropy_layout.addWidget(self.entropy_canvas)
        layout.addWidget(entropy_surface)
        vector_surface = Surface()
        vector_layout = QVBoxLayout(vector_surface)
        vector_layout.addWidget(self._label("4096-D structural fingerprint", "sectionTitle"))
        self.embedding_canvas = SignalCanvas()
        vector_layout.addWidget(self.embedding_canvas)
        self.embedding_caption = self._label(
            "Deterministic structural representation · not a lossless reconstruction",
            "muted",
        )
        vector_layout.addWidget(self.embedding_caption)
        layout.addWidget(vector_surface)
        return scroll

    def _build_detections_detail(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(13, 13, 13, 13)
        self.findings_empty = EmptyState(
            "No findings recorded yet",
            "Run an analysis to list each observed indicator with its severity and explanation.",
        )
        layout.addWidget(self.findings_empty)
        self.findings_list = QListWidget()
        self.findings_list.hide()
        layout.addWidget(self.findings_list)
        return page

    def _build_engine_detail(self) -> QWidget:
        tabs = QTabWidget()
        self.engine_texts: dict[str, QPlainTextEdit] = {}
        for name in ("YARA", "PE", "Structural model", "MITRE ATT&CK"):
            pane = QPlainTextEdit()
            pane.setReadOnly(True)
            pane.setPlaceholderText(self.tr("Run an analysis to populate this view."))
            tabs.addTab(pane, self.tr(name))
            self.engine_texts[name] = pane
        return tabs

    def _build_intel_detail(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(13, 13, 13, 13)
        self.intel_summary = self._label(
            "Public intelligence is optional and disabled until you enable it in Settings.",
            "muted",
        )
        self.intel_summary.setWordWrap(True)
        layout.addWidget(self.intel_summary)
        self.intel_text = QPlainTextEdit()
        self.intel_text.setReadOnly(True)
        layout.addWidget(self.intel_text)
        return page

    def _build_report_detail(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(13, 13, 13, 13)
        self.report_text = QPlainTextEdit()
        self.report_text.setReadOnly(True)
        self.report_text.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        layout.addWidget(self.report_text)
        return page

    def _build_history_page(self) -> QWidget:
        page = QWidget()
        page.setObjectName("page")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 22, 0, 20)
        layout.addWidget(self._label("Scan history", "pageTitle"))
        layout.addWidget(
            self._label(
                "History and generated reports stay on this computer. Removing a record never deletes the scanned target.",
                "muted",
            )
        )
        self.history_filter = QLineEdit()
        self.history_filter.setPlaceholderText(self.tr("Search by file, hash, result…"))
        self.history_filter.textChanged.connect(self.refresh_history)
        layout.addWidget(self.history_filter)
        self.history_list = QListWidget()
        self.history_list.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.history_list.currentItemChanged.connect(self._select_history_record)
        self.history_empty = EmptyState(
            "No saved scans yet",
            "Completed analyses appear here with their risk index and a local JSON report. "
            "Choose a record to open or export it.",
        )
        layout.addWidget(self.history_empty, 1)
        layout.addWidget(self.history_list, 1)
        self.history_details = QPlainTextEdit()
        self.history_details.setReadOnly(True)
        self.history_details.setMaximumHeight(145)
        layout.addWidget(self.history_details)
        actions = QHBoxLayout()
        actions.addStretch(1)
        self.history_open_button = self._button("Open report", self.open_history_report)
        self.history_open_button.setToolTip(
            self.tr("Open the saved JSON report of the selected scan")
        )
        actions.addWidget(self.history_open_button)
        self.history_export_button = self._button("Export selected", self.export_history_report)
        self.history_export_button.setToolTip(
            self.tr("Save the selected report as text or JSON")
        )
        actions.addWidget(self.history_export_button)
        self.history_remove_button = self._button(
            "Remove from history", self.remove_history_record
        )
        self.history_remove_button.setToolTip(
            self.tr("Remove the saved record and its report; the scanned file is kept")
        )
        actions.addWidget(self.history_remove_button)
        for button in (
            self.history_open_button,
            self.history_export_button,
            self.history_remove_button,
        ):
            button.setEnabled(False)
        layout.addLayout(actions)
        return page

    def _build_yara_page(self) -> QWidget:
        page = QWidget()
        page.setObjectName("page")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 22, 0, 20)
        layout.addWidget(self._label("YARA & PE inspection", "pageTitle"))
        layout.addWidget(self._label("Read-only matching and executable metadata from the latest analysis.", "muted"))
        self.yara_page_text = QPlainTextEdit()
        self.yara_page_text.setReadOnly(True)
        self.yara_page_text.setPlaceholderText(self.tr("Run a file analysis to inspect YARA matches."))
        layout.addWidget(self.yara_page_text, 1)
        self.pe_page_text = QPlainTextEdit()
        self.pe_page_text.setReadOnly(True)
        self.pe_page_text.setPlaceholderText(self.tr("Portable Executable details appear when applicable."))
        layout.addWidget(self.pe_page_text, 1)
        return page

    def _build_mitre_page(self) -> QWidget:
        page = QWidget()
        page.setObjectName("page")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 22, 0, 20)
        layout.addWidget(self._label("MITRE ATT&CK mapping", "pageTitle"))
        layout.addWidget(
            self._label(
                "Technique mapping is derived from observed indicators and is not proof of adversary activity.",
                "muted",
            )
        )
        self.mitre_list = QListWidget()
        self.mitre_empty = EmptyState(
            "No techniques mapped yet",
            "MITRE ATT&CK techniques are mapped from observed indicators after an analysis. "
            "A mapping is a lead for review, not proof of adversary activity.",
        )
        layout.addWidget(self.mitre_empty, 1)
        layout.addWidget(self.mitre_list, 1)
        return page

    def _build_model_page(self) -> QWidget:
        page = QWidget()
        page.setObjectName("page")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 22, 0, 20)
        layout.addWidget(self._label("Structural classifier", "pageTitle"))
        layout.addWidget(
            self._label(
                "Supervised three-class Random Forest over a deterministic 4096-D representation. Scores are not calibrated probabilities.",
                "muted",
            )
        )
        self.model_page_text = QPlainTextEdit()
        self.model_page_text.setReadOnly(True)
        layout.addWidget(self.model_page_text, 1)
        return page

    def _build_logs_page(self) -> QWidget:
        page = QWidget()
        page.setObjectName("page")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 22, 0, 20)
        heading = QHBoxLayout()
        heading.addWidget(self._label("Audit timeline", "pageTitle"))
        heading.addStretch(1)
        heading.addWidget(self._button("Clear view", self.clear_logs, quiet=True))
        layout.addLayout(heading)
        layout.addWidget(self._label("Timestamped local events from the current session.", "muted"))
        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        layout.addWidget(self.log_view, 1)
        return page

    def _build_settings_page(self) -> QWidget:
        scroll, page, layout = self._scroll_page()
        layout.setContentsMargins(2, 22, 4, 20)
        heading = QHBoxLayout()
        heading.addWidget(self._label("Analysis settings", "pageTitle"))
        heading.addStretch(1)
        self.settings_saved_chip = QLabel(self.tr("Saved"))
        self.settings_saved_chip.setObjectName("chip")
        apply_tone(self.settings_saved_chip, "low")
        heading.addWidget(self.settings_saved_chip, 0, Qt.AlignmentFlag.AlignTop)
        layout.addLayout(heading)
        layout.addWidget(
            self._label("Choose what the local analyzer can inspect or share.", "muted")
        )
        self.setting_checks: dict[str, QCheckBox] = {}

        def add_section(
            title: str,
            description: str,
            options: tuple[tuple[str, str, str], ...],
        ) -> None:
            surface = Surface()
            section_layout = QVBoxLayout(surface)
            section_layout.setContentsMargins(18, 16, 18, 16)
            section_layout.setSpacing(4)
            section_layout.addWidget(self._label(title, "sectionTitle"))
            note = self._label(description, "muted")
            note.setWordWrap(True)
            section_layout.addWidget(note)
            section_layout.addSpacing(6)
            for key, label, help_text in options:
                check = QCheckBox(self.tr(label))
                check.setChecked(bool(self.settings.get(key, False)))
                check.setToolTip(self.tr(help_text))
                check.stateChanged.connect(self._settings_dirty)
                self.setting_checks[key] = check
                section_layout.addWidget(check)
            layout.addWidget(surface)

        add_section(
            "Detection",
            "Static engines used by each analysis. Disabling an engine reduces coverage "
            "and is reported in the engine status of every result.",
            (
                ("entropy_analysis", "Entropy analysis", "Measure byte entropy and its transitions"),
                ("heuristic_rules", "Heuristic rules", "Apply the static indicator and URL/text rules"),
                (
                    "ml_analysis",
                    "Structural classifier analysis",
                    "Compute the 4096-D representation and use a trained model if present",
                ),
            ),
        )
        add_section(
            "Monitoring",
            "Optional. Watches a folder and analyzes new files after they stop changing. "
            "Files are analyzed only; nothing is moved, quarantined, or deleted.",
            (("monitoring_enabled", "Downloads monitoring", "Scan new files in the folder below"),),
        )
        folder_row = QHBoxLayout()
        folder_row.addWidget(self._label("Watched folder"))
        self.monitor_directory = QLineEdit(self.settings["monitoring_directory"])
        self.monitor_directory.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
        self.monitor_directory.setToolTip(
            self.tr("The local folder watched when downloads monitoring is enabled")
        )
        self.monitor_directory.textChanged.connect(self._settings_dirty)
        folder_row.addWidget(self.monitor_directory, 1)
        browse_folder = self._button("Browse…", self.select_monitor_directory)
        browse_folder.setToolTip(self.tr("Choose the folder to monitor"))
        folder_row.addWidget(browse_folder)
        layout.addLayout(folder_row)

        add_section(
            "Network",
            "Public intelligence is off by default. Enabling it sends supported URLs, "
            "domains, IPs, or the SHA-256 hash of a tested file to public services. "
            "Local file contents are not uploaded. A feed miss is not proof of safety.",
            (
                (
                    "osint_enabled",
                    "Send indicators to public OSINT feeds",
                    "Allow non-blocking lookups against optional public feeds",
                ),
            ),
        )
        api_note = self._label(
            "Feed credentials come from the environment: URLHAUS_API_KEY, "
            "OTX_API_KEY, and optionally THREATFOX_API_KEY.",
            "muted",
        )
        api_note.setWordWrap(True)
        layout.addWidget(api_note)

        add_section(
            "Accessibility",
            "Interface-only preferences. They do not affect analysis behavior.",
            (
                (
                    "large_text",
                    "Larger text and controls",
                    "Increase interface font size and control height",
                ),
            ),
        )
        self.settings_engine_summary = self._label("", "muted")
        self.settings_engine_summary.setWordWrap(True)
        layout.addWidget(self.settings_engine_summary)
        self.apply_settings_button = self._button(
            "Apply settings", self.apply_settings, primary=True
        )
        self.apply_settings_button.setEnabled(False)
        self.apply_settings_button.setToolTip(
            self.tr("Save and apply the settings changed above")
        )
        layout.addWidget(self.apply_settings_button)
        layout.addStretch(1)
        return scroll

    def _build_about_page(self) -> QWidget:
        page = QWidget()
        page.setObjectName("page")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 22, 0, 20)
        layout.addWidget(self._label("About CyberScan", "pageTitle"))
        layout.addWidget(self._label("Defensive research prototype · local static analysis", "eyebrow"))
        about = QPlainTextEdit()
        about.setReadOnly(True)
        about.setPlainText(
            self.tr(
                "CyberScan is a defensive cybersecurity research prototype. It analyzes files, URLs, and indicators without executing targets. "
                "Its evidence and model scores are investigative aids, not proof of malware or calibrated probabilities. "
                "The 4096-D projection is deterministic and non-lossless. Packed or encrypted content may hide semantics. "
                "There is no automatic repair, deletion, or quarantine action. "
                "Public intelligence is optional and disabled by default."
            )
            + "\n\n"
            + self.tr("Developed by m6no5 and Ainex")
        )
        layout.addWidget(about, 1)
        return page

    def _show_analysis(self) -> None:
        self._show_page("analysis")
        self.target_entry.setFocus()

    PAGE_COPY = {
        "analysis": (
            "New analysis",
            "Inspect a file, URL or indicator with the local engines. Nothing is executed.",
        ),
        "history": (
            "Scan history",
            "Every analysis stored on this machine, newest first.",
        ),
        "yara": ("YARA & PE", "Signature rules and portable-executable structure."),
        "mitre": ("MITRE ATT&CK", "Techniques mapped from observed evidence."),
        "model": ("Structural model", "Status and output of the trained classifier."),
        "logs": ("Audit timeline", "Ordered record of what this session did."),
        "settings": ("Settings", "Choose which engines run and how they behave."),
        "about": ("About", "What this build can and cannot do."),
    }

    def _breadcrumb_for(self, name: str) -> str:
        """Current page name, in the active language."""
        labels = {page: label for label, page, _icon in self.NAV_ITEMS}
        return self.tr(labels.get(name, "New analysis"))

    def _show_page(self, name: str) -> None:
        self.current_page = name
        self.pages.setCurrentIndex(self.page_indices[name])
        title, subtitle = self.PAGE_COPY.get(name, ("New analysis", ""))
        self.page_title.setText(self.tr(title))
        self.page_subtitle.setText(self.tr(subtitle))
        # The main screen's hero carries its own title.
        self.page_title.setVisible(name != "analysis")
        self.page_subtitle.setVisible(name != "analysis")
        self.breadcrumb.setText(self._breadcrumb_for(name))
        self._sync_nav_state(name)
        self._animate_page_entry()

    def _sync_nav_state(self, name: str) -> None:
        for page, button in self._nav_buttons.items():
            button.setProperty("selected", page == name)
            button.setChecked(page == name)
            button.style().unpolish(button)
            button.style().polish(button)
        self.sidebar_primary.setProperty("selected", name == "analysis")
        self.sidebar_primary.setChecked(name == "analysis")
        self.sidebar_primary.style().unpolish(self.sidebar_primary)
        self.sidebar_primary.style().polish(self.sidebar_primary)

    def _animate_page_entry(self) -> None:
        """Short, non-blocking fade so page changes read as a transition."""
        self._page_animation.stop()
        self._page_effect.setOpacity(0.0)
        self._page_animation.setStartValue(0.0)
        self._page_animation.setEndValue(1.0)
        self._page_animation.start()
        # Safety net: if the animation clock never runs (headless/offscreen
        # backends, or animations disabled), the page must still be visible.
        QTimer.singleShot(260, lambda: self._page_effect.setOpacity(1.0))

    def _install_shortcuts(self) -> None:
        shortcuts = (
            ("Ctrl+O", self.select_file),
            ("Ctrl+L", self._focus_input),
            ("Ctrl+Return", self.run_scan),
            ("Ctrl+Enter", self.run_scan),
            ("Ctrl+1", self._show_analysis),
        )
        self.shortcuts: list[QShortcut] = []
        for sequence, callback in shortcuts:
            shortcut = QShortcut(QKeySequence(sequence), self)
            shortcut.activated.connect(callback)
            self.shortcuts.append(shortcut)
        for label, page, _icon in self.NAV_ITEMS[1:]:
            del label
            if page in self.page_indices:
                action = QAction(self)
                action.setShortcut(QKeySequence(f"Ctrl+{self.page_indices[page] + 1}"))
                action.triggered.connect(lambda key=page: self._show_page(key))
                self.addAction(action)

    def _focus_input(self) -> None:
        self._show_analysis()
        self.target_entry.setFocus()

    def _choose_mode(self, mode: str) -> None:
        index = self.mode_values.index(mode)
        self.input_mode.setCurrentIndex(index)
        self._show_analysis()
        if mode == "File" and not self.target_entry.text().strip():
            self.select_file()
        else:
            self.target_entry.setFocus()

    def _mode_changed(self, index: int) -> None:
        mode = self.input_mode.itemData(index)
        self.mode_segment.set_mode(mode)
        self.browse_button.setVisible(mode == "File")
        if mode != "File" and self.target_entry.text().strip() == getattr(
            self, "selected_path", None
        ):
            self.target_entry.clear()
            self.selected_path = None
            self.selected_file_label.setText(
                self.tr("Static analysis only · the target is never executed")
            )
        if mode == "File":
            self.target_entry.setPlaceholderText(
                self.tr("Paste a file path or choose a local file…")
            )
        elif mode == "URL":
            self.target_entry.setPlaceholderText(
                self.tr("Paste a complete http:// or https:// URL…")
            )
        else:
            self.target_entry.setPlaceholderText(
                self.tr("Paste a hash, domain, IP, or suspicious text…")
            )

    def select_file(self) -> None:
        path, _selected_filter = QFileDialog.getOpenFileName(
            self,
            self.tr("Choose a file"),
        )
        if not path:
            return
        self._choose_mode_without_dialog("File")
        self.selected_path = path
        self.target_entry.setText(path)
        self.selected_file_label.setText(path)
        self.selected_file_label.setProperty("hint", False)

    def _choose_mode_without_dialog(self, mode: str) -> None:
        self.input_mode.blockSignals(True)
        self.input_mode.setCurrentIndex(self.mode_values.index(mode))
        self.input_mode.blockSignals(False)
        self._mode_changed(self.input_mode.currentIndex())

    def eventFilter(self, watched: QObject, event: QEvent) -> bool:
        if watched is self.target_entry and event.type() == QEvent.Type.DragEnter:
            mime = event.mimeData()
            if mime.hasUrls() or mime.hasText():
                event.acceptProposedAction()
                return True
        if watched is self.target_entry and event.type() == QEvent.Type.Drop:
            mime = event.mimeData()
            if mime.hasUrls():
                local_paths = [url.toLocalFile() for url in mime.urls() if url.isLocalFile()]
                if local_paths and Path(local_paths[0]).is_file():
                    self._choose_mode_without_dialog("File")
                    self.selected_path = local_paths[0]
                    self.target_entry.setText(local_paths[0])
                    self.selected_file_label.setText(local_paths[0])
                    event.acceptProposedAction()
                    return True
            if mime.hasText():
                self._choose_mode_without_dialog("Indicator / text")
                self.target_entry.setText(mime.text().strip())
                event.acceptProposedAction()
                return True
        return super().eventFilter(watched, event)

    def dragEnterEvent(self, event) -> None:
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            event.ignore()

    def dropEvent(self, event) -> None:
        local_paths = [
            url.toLocalFile()
            for url in event.mimeData().urls()
            if url.isLocalFile()
        ]
        if local_paths and Path(local_paths[0]).is_file():
            self._choose_mode_without_dialog("File")
            self.selected_path = local_paths[0]
            self.target_entry.setText(local_paths[0])
            self.selected_file_label.setText(local_paths[0])
            self._show_analysis()
            event.acceptProposedAction()
        else:
            event.ignore()

    def run_scan(self) -> None:
        if self.worker and self.worker.isRunning():
            return
        target = self.target_entry.text().strip()
        mode = self.input_mode.currentData()
        if not target:
            self._show_input_problem(
                self.tr("Add a target first"),
                self.tr("Paste a file path, URL, hash, or text indicator, or choose a file."),
            )
            self.target_entry.setFocus()
            return
        if mode == "File":
            selected = getattr(self, "selected_path", None)
            candidate_path = Path(selected or target)
            try:
                resolved = candidate_path.resolve(strict=True)
            except OSError:
                resolved = None
            if resolved is None or not resolved.is_file():
                self._show_input_problem(
                    self.tr("File not found"),
                    self.tr("Choose a readable file that exists."),
                )
                self.select_file()
                return
            target = str(resolved)
        elif mode == "URL":
            parsed = urlsplit(target)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                self._show_input_problem(
                    self.tr("Invalid URL"),
                    self.tr("Enter a complete http:// or https:// URL."),
                )
                return
        self._show_analysis()
        self.results_panel.hide()
        self._pipeline_panel.setVisible(True)
        self.scan_core.begin()
        self.mode_segment.setEnabled(False)
        self.export_button.setEnabled(False)
        self.analyze_button.setEnabled(False)
        self.analyze_button.setText(self.tr("Analyzing…"))
        self.input_mode.setEnabled(False)
        self.browse_button.setEnabled(False)
        self._set_engine_pill("busy", "●  ANALYSIS IN PROGRESS")
        self.status_banner.set_state(
            "busy",
            self.tr("Analysis running"),
            self.tr("Static analysis only · the target is never executed."),
        )
        self.lab_caption.setText(self.tr("Following observed signals"))
        self.signal_canvas.set_scanning(True)
        for title, bar, status in self.stage_labels:
            bar.setRange(0, 100)
            bar.setValue(0)
            status.setText(self.tr("Waiting"))
        self.stage_labels[0][1].setRange(0, 0)
        self.stage_labels[0][2].setText(self.tr("Reading static evidence"))
        self._append_log(f"Analysis started in {mode} mode: {target}")
        self.worker = ScanWorker(target, mode, self.settings.copy())
        self.worker.progress.connect(self._update_stage)
        self.worker.completed.connect(self._scan_completed)
        self.worker.failed.connect(self._scan_failed)
        self.worker.start()

    def _set_engine_pill(self, tone: str, text: str) -> None:
        apply_tone(self.connection_status, tone)
        self.connection_status.setText(self.tr(text))

    def _show_input_problem(self, title: str, detail: str) -> None:
        self.status_banner.set_state("warning", title, detail)

    def _restore_input_controls(self) -> None:
        self.analyze_button.setEnabled(True)
        self.analyze_button.setText(self.tr("Analyze target"))
        self.input_mode.setEnabled(True)
        self.mode_segment.setEnabled(True)
        self.browse_button.setEnabled(True)
        self.signal_canvas.set_scanning(False)

    def _update_stage(self, index: int, state: str, detail: str) -> None:
        if not 0 <= index < len(self.stage_labels):
            return
        _title, progress, status = self.stage_labels[index]
        stage_title = self.STAGE_TITLES[index]
        track = getattr(self, "stage_track", None)
        if track is not None:
            states = [track.state_of(i) for i in range(len(self.stage_labels))]
            states[index] = state
            track.set_states(states)
            self.scan_core.set_stage_states(states)
        if state == "running":
            progress.setRange(0, 0)
            status.setText(self.tr(detail))
            self.lab_caption.setText(self.tr(detail))
            self.status_banner.set_state(
                "busy", self.tr(f"Analysis running · {stage_title}"), self.tr(detail)
            )
        else:
            progress.setRange(0, 100)
            progress.setValue(100 if state == "complete" else 0)
            status.setText(self.tr(detail))
            self.lab_caption.setText(self.tr(detail))

    def _scan_completed(self, payload: tuple[Any, ...]) -> None:
        self.worker = None
        self.last_payload = payload
        result, nextgen, vector, prediction, intelligence, raw_data = payload
        self._append_log(
            f"Analysis complete: {result.classification} · risk index {result.combined_score}/100"
        )
        self._set_engine_pill("success", "●  ANALYSIS COMPLETE")
        self._restore_input_controls()
        self._render_result(*payload)
        self.scan_core.finish(tone_color(self._results_view.verdict.tone))
        try:
            self._record_scan_history(result)
        except (OSError, ValueError, TypeError) as exc:
            self._append_log(f"Unable to save scan history: {type(exc).__name__}: {exc}")
            self.status_banner.set_state(
                "warning",
                self.tr("Result shown, but history was not saved"),
                str(exc),
            )
        self.refresh_workspace_status()
        self._start_next_monitor_scan()

    def _scan_failed(self, message: str) -> None:
        self.worker = None
        self._set_engine_pill("error", "●  ANALYSIS FAILED")
        self._restore_input_controls()
        self.scan_core.fail()
        self.export_button.setEnabled(False)
        for _title, bar, status in self.stage_labels:
            if bar.minimum() == 0 and bar.maximum() == 0:
                bar.setRange(0, 100)
                bar.setValue(0)
                status.setText(self.tr("Unable to complete"))
        self._append_log(f"Analysis failed: {message}")
        self.lab_caption.setText(self.tr("Analysis stopped · review the error"))
        self.status_banner.set_state(
            "error",
            self.tr("Analysis incomplete · nothing was concluded about this target"),
            message,
        )
        QMessageBox.critical(self, self.tr("Analysis failed"), message)
        self._start_next_monitor_scan()

    def _render_result(self, result, nextgen, vector, prediction, intelligence, raw_data) -> None:
        view = build_result_view(result, nextgen)
        self._results_view = view
        was_hidden = self.results_panel.isHidden()
        self.results_panel.show()
        if was_hidden:
            self._animate_results_entry()
        self._reveal_results()
        self.export_button.setEnabled(True)
        verdict, _color = self._verdict(result)
        self.verdict_label.setText(self.tr(verdict))
        self._render_result_screen(view)
        self.target_result_label.setText(result.target)
        self.verdict_summary.setText(
            self._summary_for(result, raw_data)
        )
        self._update_completeness_chip(result, prediction, intelligence)
        self.limitations_label.setText(self.tr(result.limitations or ""))
        self._update_result_status_banner(result)
        self._clear_layout(self.result_metrics)
        file_size = result.feature_summary.get("file_size", len(raw_data))
        metrics = (
            ("Risk index", f"{result.combined_score}/100"),
            ("File size", self._format_size(int(file_size))),
            ("Mean entropy", f"{nextgen['entropy_topography']['mean_entropy']:.2f}/8"),
            ("CFG complexity", str(nextgen["cfg_topology"]["cyclomatic_complexity"])),
        )
        for label, value in metrics:
            card = QFrame()
            card.setObjectName("metric")
            card_layout = QVBoxLayout(card)
            card_layout.setContentsMargins(12, 9, 12, 9)
            card_layout.addWidget(self._label(label, "muted"))
            value_label = QLabel(value)
            value_label.setObjectName("metricValue")
            card_layout.addWidget(value_label)
            self.result_metrics.addWidget(card)
        evidence_text = "\n\n".join(
            f"[{item.severity.upper()}] {item.evidence}\n{item.explanation}"
            for item in result.evidence
        ) or self.tr("No direct static evidence recorded.")
        position = result.feature_summary.get("position_aware_evidence", {})
        position_lines = [self.tr("Position-aware evidence (measured only):")]
        for boundary in position.get("entropy_boundaries", [])[:6]:
            region_hash = boundary.get("region_sha256")
            hash_detail = (
                f" · SHA-256 {region_hash[:16]}"
                if isinstance(region_hash, str)
                else ""
            )
            position_lines.append(
                f"{self.tr('Entropy boundary')} "
                f"0x{boundary['offset_start']:X}-0x{boundary['offset_end']:X} · "
                f"ΔH {boundary['entropy_delta_bits_per_byte']:+.3f} · "
                f"{boundary['severity'].upper()}{hash_detail}"
            )
        for section in position.get("pe_sections", []):
            start = section.get("file_offset_start")
            end = section.get("file_offset_end")
            if start is not None and end is not None:
                rva = section.get("rva_start")
                rva_label = f" · RVA 0x{rva:X}" if isinstance(rva, int) else ""
                position_lines.append(
                    f"{self.tr('PE section')} {section['name']} "
                    f"0x{start:X}-0x{end:X}{rva_label}"
                )
                if len(position_lines) >= 16:
                    break
        if len(position_lines) == 1:
            position_lines.append(self.tr("No mapped byte ranges."))
        evidence_text = f"{evidence_text}\n\n" + "\n".join(position_lines)
        self.evidence_summary.setPlainText(evidence_text)
        self.story_label.setText("\n".join(nextgen["forensic_storyboard"]))
        self.findings_list.clear()
        for finding in result.evidence:
            item = QListWidgetItem(
                f"{finding.severity.upper()}  ·  {finding.evidence}\n{finding.explanation}"
            )
            item.setToolTip(f"{finding.category} · contribution {finding.contribution}")
            if finding.severity.casefold() in {"critical", "high"}:
                item.setForeground(Qt.GlobalColor.red)
            elif finding.severity.casefold() == "medium":
                item.setForeground(Qt.GlobalColor.yellow)
            self.findings_list.addItem(item)
        has_findings = self.findings_list.count() > 0
        self.findings_empty.setVisible(not has_findings)
        self.findings_list.setVisible(has_findings)
        entropy = nextgen["entropy_topography"]
        self.entropy_canvas.set_data(entropy=entropy.get("trajectory", ()))
        self.signal_canvas.set_data(entropy=entropy.get("trajectory", ()))
        self.embedding_canvas.set_data(vector=vector)
        self.embedding_caption.setText(
            f"4096 dimensions · classifier {prediction.get('status', 'untrained')} · "
            "class scores are uncalibrated"
        )
        self._render_engine_details(result, nextgen, prediction, intelligence)
        self.detail_tabs.setCurrentIndex(0)
        self._normalize_child_fonts(1.18 if self.settings.get("large_text") else 1.0)

    def _animate_results_entry(self) -> None:
        """Fade and lift the results panel without blocking the UI thread."""
        self._results_animation = QParallelAnimationGroup(self.results_panel)
        opacity = QPropertyAnimation(self._results_effect, b"opacity", self.results_panel)
        opacity.setDuration(260)
        opacity.setStartValue(0.0)
        opacity.setEndValue(1.0)
        opacity.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._results_animation.addAnimation(opacity)
        current = self.results_panel.geometry()
        slide = QPropertyAnimation(self.results_panel, b"geometry", self.results_panel)
        slide.setDuration(260)
        slide.setStartValue(current.adjusted(0, 18, 0, 18))
        slide.setEndValue(current)
        slide.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._results_animation.addAnimation(slide)
        self._results_animation.finished.connect(self._finish_results_entry)
        self._results_animation.start()

    def _finish_results_entry(self) -> None:
        self._results_effect.setOpacity(1.0)

    def _reveal_results(self) -> None:
        """Bring the verdict into view: the result is the point of the scan."""
        pipeline = getattr(self, "_pipeline_panel", None)
        if pipeline is not None:
            pipeline.setVisible(False)
        if not self.signal_canvas._timer.isActive() and self.signal_canvas.isVisible():
            self.signal_canvas._timer.start(50)
        scanning = bool(self.worker and self.worker.isRunning())
        if scanning and not self.signal_canvas._timer.isActive():
            self.signal_canvas._timer.start(50)
        page = self.results_panel.parentWidget()
        scroll = None
        while page is not None and scroll is None:
            page = page.parentWidget()
            if isinstance(page, QScrollArea):
                scroll = page
        if scroll is None or page is None:
            return

        def scroll_to_verdict() -> None:
            target = self.results_panel.mapTo(
                scroll.widget(), self.results_panel.rect().topLeft()
            )
            scroll.verticalScrollBar().setValue(max(0, target.y() - 12))

        QTimer.singleShot(0, scroll_to_verdict)

    def _update_completeness_chip(self, result, prediction, intelligence) -> None:
        """Say honestly which evidence sources contributed to this result.

        Uses the same coverage states as the coverage panel. Engines switched
        off in Settings are a user choice, not missing coverage.
        """
        view = getattr(self, "_results_view", None) or build_result_view(result)
        incomplete = sorted(e.name for e in view.coverage if e.state in {"failed", "partial"})
        unavailable = sorted(e.name for e in view.coverage if e.state == "unavailable")
        if incomplete:
            self.completeness_chip.setText(self.tr("Partial coverage: ") + ", ".join(incomplete))
            apply_tone(self.completeness_chip, "medium")
        elif unavailable:
            self.completeness_chip.setText(
                self._tx("Some engines unavailable: ")
                + ", ".join(self._tx(ENGINE_LABELS.get(name, name)) for name in unavailable)
            )
            apply_tone(self.completeness_chip, "medium")
        else:
            self.completeness_chip.setText(self._tx("All enabled engines ran"))
            apply_tone(self.completeness_chip, "low")
        self.completeness_chip.setVisible(True)

    def _update_result_status_banner(self, result) -> None:
        view = getattr(self, "_results_view", None)
        if view is not None and view.verdict.key == "inconclusive":
            self.status_banner.set_state(
                "warning",
                self._tx(view.verdict.title),
                self._tx(view.verdict.detail),
            )
            return
        if result.classification == "SUSPICIOUS":
            self.status_banner.set_state(
                "error",
                self.tr("Indicators found · manual review recommended"),
                self.tr("The risk index is an explainable indicator, not a malware probability."),
            )
        elif result.classification == "REVIEW":
            self.status_banner.set_state(
                "warning",
                self.tr("Weak indicators observed · review the evidence"),
                self.tr("The risk index is an explainable indicator, not a malware probability."),
            )
        else:
            self.status_banner.set_state(
                "success",
                self.tr("Analysis complete · no indicators observed"),
                self.tr(
                    "This does not prove the target is safe. Static analysis has limits."
                ),
            )

    # ---- main screen --------------------------------------------------------

    def _monitor_running(self) -> bool:
        thread = getattr(self._monitor, "_thread", None)
        return bool(thread and thread.is_alive())

    @staticmethod
    def _history_display_name(target: str) -> str:
        path = Path(target)
        name = path.name if path.is_absolute() and path.name else target
        return name if len(name) <= 64 else name[:61] + "…"

    def _home_when(self, moment: datetime | None, target: str) -> str:
        if target.startswith(("http://", "https://")):
            kind = self._tx("URL")
        elif Path(target).is_absolute():
            kind = self._tx("File")
        else:
            kind = self._tx("Indicator")
        if moment is None:
            return kind
        now = datetime.now(moment.tzinfo)
        days = (now.date() - moment.date()).days
        clock = moment.strftime("%H:%M")
        if days == 0:
            when = self._tx("Today {time}").format(time=clock)
        elif days == 1:
            when = self._tx("Yesterday {time}").format(time=clock)
        else:
            when = moment.strftime("%Y-%m-%d %H:%M")
        return f"{kind} · {when}"

    def _refresh_home(self) -> None:
        """Main-screen text and facts, read from settings and saved history only."""
        if not hasattr(self, "recent_activity"):
            return
        tx = self._tx
        for group, source in self._rail_groups:
            group.setText(tx(source))
        self.hero_title.setText(tx("Inspect before you trust."))
        self.hero_body.setText(
            tx("Check a file, link or indicator with local static engines. Targets are read, never executed.")
        )
        if self.settings.get("osint_enabled"):
            self.fact_lookups.set_text(
                tx("Public lookups on · supported indicators may be sent to public services"), "warn"
            )
        else:
            self.fact_lookups.set_text(tx("Public lookups off · nothing is sent from this device"))
        if self._monitor_running():
            self.fact_monitor.set_text(
                tx("Downloads monitor on · {folder}").format(
                    folder=self.settings.get("monitoring_directory", "")
                ),
                "ok",
            )
        else:
            self.fact_monitor.set_text(tx("Downloads monitor off"))
        self.shortcut_hint.setText(tx("Enter to analyze · Ctrl+O to choose a file"))
        placeholders = {
            "File": "Paste a file path or choose a local file…",
            "URL": "Paste a complete http:// or https:// URL…",
        }
        self.target_entry.setPlaceholderText(
            self.tr(
                placeholders.get(
                    self.input_mode.currentData(),
                    "Paste a hash, domain, IP, or suspicious text…",
                )
            )
        )
        if self.connection_status.text() in {"READY", translate_exact("READY", "ar")}:
            self.connection_status.setText(tx("READY"))
        if not self.selected_file_label.text() or self.selected_file_label.property("hint"):
            self.selected_file_label.setText(tx("Drag a file onto this window, or paste its path."))
            self.selected_file_label.setProperty("hint", True)
        self.mode_segment.set_labels(tx)
        self.mode_segment.set_mode(self.input_mode.currentData())
        self.recent_activity.set_records(
            self.scan_history, tx, self._history_display_name, self._home_when
        )
        self._normalize_child_fonts(1.18 if self.settings.get("large_text") else 1.0)

    def _open_history_record(self, record_id: str) -> None:
        self._show_page("history")
        for index in range(self.history_list.count()):
            candidate = self.history_list.item(index)
            if candidate.data(Qt.ItemDataRole.UserRole) == record_id:
                self.history_list.setCurrentItem(candidate)
                break

    # ---- results screen ---------------------------------------------------

    def _tx(self, text: str) -> str:
        """Exact-match translation for results-screen text (no substring substitution)."""
        return translate_exact(text, self.language)

    def _apply_results_static_text(self) -> None:
        for target, source in self._results_static:
            text = self._tx(source)
            if isinstance(target, QWidget):
                target.setText(text)
            else:
                target(text)
        self._sync_details_button()

    def _severity_text(self, severity: str) -> str:
        symbol, label = SEVERITY_LABELS.get(severity, SEVERITY_LABELS["unknown"])
        return f"{symbol} {self._tx(label)}"

    @staticmethod
    def _clear_layout(layout) -> None:
        while layout.count():
            item = layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.setParent(None)
                widget.deleteLater()

    def _render_result_screen(self, view: ResultView) -> None:
        """Draw the verdict-first results from the presentation model only."""
        self._apply_results_static_text()
        verdict = view.verdict
        color = tone_color(verdict.tone)
        self.verdict_badge.set_verdict(
            f"{verdict.symbol}  {self._tx(verdict.title)}", self._tx(verdict.detail), color
        )
        self.verdict_badge.setAccessibleName(self._tx(verdict.title))

        has_score = view.score is not None
        self.risk_gauge.setVisible(has_score)
        self.risk_unavailable.setVisible(not has_score)
        self.risk_note.setVisible(has_score)
        if has_score:
            self.risk_gauge.set_color(color)
            self.risk_gauge.animate_to(view.score)
            self.risk_caption.setText(f"{view.score}/100")
        else:
            self.risk_caption.setText("")

        findings = view.findings
        notable = sum(
            1 for item in findings if SEVERITY_RANK[item.severity] >= SEVERITY_RANK["medium"]
        )
        self.stat_tiles["findings"].set_value(
            str(len(findings)),
            self._tx("{count} at medium or higher").format(count=notable) if notable else "",
        )
        if view.highest_severity:
            self.stat_tiles["severity"].set_value(
                self._severity_text(view.highest_severity),
                color=tone_color(SEVERITY_TONES[view.highest_severity]),
            )
        else:
            self.stat_tiles["severity"].set_value(self._tx("None"))
        self.stat_tiles["mitre"].set_value(str(view.mitre_count))
        if view.coverage:
            states = [engine.state for engine in view.coverage]
            not_applicable = states.count("not_applicable")
            switched_off = states.count("disabled")
            notes = []
            if not_applicable:
                notes.append(self._tx("{count} not applicable").format(count=not_applicable))
            if switched_off:
                notes.append(self._tx("{count} off").format(count=switched_off))
            self.stat_tiles["coverage"].set_value(
                self._tx("{ran} of {total}").format(
                    ran=view.engines_ran,
                    total=len(states) - not_applicable - switched_off,
                ),
                " · ".join(notes),
            )
        else:
            self.stat_tiles["coverage"].set_value(self._tx("Not available"))

        self._clear_layout(self.finding_cards_layout)
        self.finding_cards = []
        shown = findings[:5]
        for item in shown:
            card = FindingCard()
            card.set_finding(
                self._severity_text(item.severity),
                SEVERITY_TONES[item.severity],
                self._tx(CATEGORY_LABELS.get(item.category, item.category)),
                item.title,
                item.explanation,
                self._tx("Weight {value}/100").format(value=item.contribution)
                if item.contribution > 0
                else "",
            )
            self.finding_cards_layout.addWidget(card)
            self.finding_cards.append(card)
        self.no_findings_state.setVisible(not findings)
        overflow = len(findings) > len(shown)
        self.findings_overflow_button.setVisible(overflow)
        if overflow:
            self.findings_overflow_button.setText(
                self._tx("View all {count} findings").format(count=len(findings))
            )

        rows = [
            (
                self._tx(CATEGORY_LABELS.get(entry.category, entry.category)),
                entry.count,
                tone_color(SEVERITY_TONES[entry.top_severity]),
            )
            for entry in view.categories
        ]
        self.category_bars.set_rows(rows)
        self.category_bars.setVisible(bool(rows))
        self.category_unavailable.setVisible(not rows)

        self._clear_layout(self.coverage_layout)
        self.coverage_chips: dict[str, Chip] = {}
        for engine in view.coverage:
            row = QWidget()
            row_layout = QHBoxLayout(row)
            row_layout.setContentsMargins(0, 0, 0, 0)
            row_layout.setSpacing(8)
            name = QLabel(self._tx(ENGINE_LABELS.get(engine.name, engine.name)))
            name.setObjectName("muted")
            symbol, label = COVERAGE_LABELS[engine.state]
            chip = Chip(f"{symbol} {self._tx(label)}", COVERAGE_TONES[engine.state])
            # The raw engine status is shown unchanged as the tooltip.
            row.setToolTip(engine.status)
            row_layout.addWidget(name)
            row_layout.addStretch(1)
            row_layout.addWidget(chip)
            self.coverage_layout.addWidget(row)
            self.coverage_chips[engine.name] = chip
        self.coverage_unavailable.setVisible(not view.coverage)

        unavailable = self._tx("Not available")
        profiles = {"binary-content": "Binary content", "text-content": "Text content"}
        self.file_rows["target"].set_value(view.target or unavailable)
        self.file_rows["type"].set_value(
            self._tx(profiles[view.input_profile])
            if view.input_profile in profiles
            else (view.input_profile or unavailable)
        )
        self.file_rows["size"].set_value(
            self._format_size(view.file_size) if view.file_size is not None else unavailable
        )
        self.file_rows["sha256"].set_value(view.sha256 or unavailable)
        self.file_rows["entropy"].set_value(
            self._tx("{value} / 8 bits per byte").format(value=f"{view.mean_entropy:.2f}")
            if view.mean_entropy is not None
            else unavailable
        )
        self.file_rows["pe"].set_value(view.pe_status or unavailable)
        self.file_rows["yara"].set_value(str(view.yara_count))
        self.file_rows["model"].set_value(view.model_status or unavailable)

    def _sync_details_button(self, *_args) -> None:
        expanded = self.technical_section.is_expanded()
        self.details_button.setText(
            self._tx("Hide technical details" if expanded else "Show technical details")
        )

    def _scroll_area_for(self, widget: QWidget) -> QScrollArea | None:
        parent = widget.parentWidget()
        while parent is not None and not isinstance(parent, QScrollArea):
            parent = parent.parentWidget()
        return parent

    def _scroll_into_view(self, widget: QWidget, *, top: bool = False) -> None:
        scroll = self._scroll_area_for(widget)
        if scroll is None:
            return
        if top:
            QTimer.singleShot(0, lambda: scroll.verticalScrollBar().setValue(0))
        else:
            QTimer.singleShot(0, lambda: scroll.ensureWidgetVisible(widget, 0, 24))

    def _toggle_technical_details(self) -> None:
        expand = not self.technical_section.is_expanded()
        self.technical_section.set_expanded(expand)
        if expand:
            self._scroll_into_view(self.technical_section)

    def _show_all_findings(self) -> None:
        self.technical_section.set_expanded(True)
        self.detail_tabs.setCurrentIndex(2)
        self._scroll_into_view(self.technical_section)

    def _return_to_scan(self) -> None:
        self._show_analysis()
        self.target_entry.selectAll()
        self._scroll_into_view(self._composer, top=True)

    @staticmethod
    def _format_size(size: int) -> str:
        if size >= 1024 * 1024:
            return f"{size / (1024 * 1024):.1f} MiB"
        if size >= 1024:
            return f"{size / 1024:.1f} KiB"
        return f"{size} B"

    def _verdict(self, result) -> tuple[str, str]:
        if result.classification == "SUSPICIOUS":
            return "HIGH RISK", "#f0645f"
        if result.classification == "REVIEW":
            return "NEEDS REVIEW", "#f5b544"
        return "NO INDICATORS OBSERVED", "#5ee0d0"

    def _summary_for(self, result, raw_data: bytes) -> str:
        if b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" in raw_data:
            return self.tr("EICAR is a harmless test marker; it is not malware.")
        if result.evidence:
            strongest = sorted(
                result.evidence,
                key=lambda finding: finding.contribution,
                reverse=True,
            )[:2]
            return self.tr("Main evidence: ") + "; ".join(
                finding.evidence for finding in strongest
            )
        return self.tr(
            "No indicators were observed. This does not prove that the target is safe."
        )

    def _render_engine_details(self, result, nextgen, prediction, intelligence) -> None:
        yara_lines = [
            f"YARA status: {result.engine_status.get('YARA', 'unknown')}",
            f"YARA matches: {len(result.yara_matches)}",
        ]
        yara_lines.extend(
            f"- {match.get('rule_name', 'unnamed')}: {match.get('description', 'No description')}"
            for match in result.yara_matches
        )
        if not result.yara_matches:
            yara_lines.append("No configured YARA rule matched this target.")
        pe = result.pe_analysis or {}
        pe_lines = [
            f"PE status: {pe.get('status', 'not_run')}",
            f"Is PE: {bool(pe.get('is_pe', False))}",
            f"PE sections: {pe.get('section_count', 'not available')}",
            f"Imported APIs: {pe.get('import_count', 'not available')}",
        ]
        if pe.get("error"):
            pe_lines.append(f"Detail: {pe['error']}")
        pe_lines.extend(str(item) for item in pe.get("findings", []))
        classifier_lines = [
            "Model: supervised three-class Random Forest",
            "Embedding: deterministic 4096-D structural representation",
            f"Training state: {prediction.get('status', 'untrained')}",
            f"Predicted class: {prediction.get('label') or 'not available'}",
            f"Uncalibrated class scores: {prediction.get('class_scores') or 'not available'}",
            f"Uncalibrated infection score: {prediction.get('infection_score')}",
            "Automated repair: not available; scores never authorize file changes",
            result.model_status,
            "The projection is not lossless; scores are not probabilities. No automatic repair or modification is performed.",
        ]
        mitre_lines = [
            f"{item.get('id', 'N/A')}: {item.get('name', 'Unknown')}"
            for item in result.mitre_techniques
        ] or ["No mapped techniques."]
        self.yara_page_text.setPlainText("\n".join(yara_lines))
        self.pe_page_text.setPlainText("\n".join(pe_lines))
        self.engine_texts["YARA"].setPlainText("\n".join(yara_lines))
        self.engine_texts["PE"].setPlainText("\n".join(pe_lines))
        self.engine_texts["Structural model"].setPlainText("\n".join(classifier_lines))
        self.engine_texts["MITRE ATT&CK"].setPlainText("\n".join(mitre_lines))
        self.model_page_text.setPlainText("\n".join(classifier_lines))
        self.mitre_list.clear()
        for technique in result.mitre_techniques:
            self.mitre_list.addItem(
                f"{technique.get('id', 'N/A')} · {technique.get('name', 'Unknown')}\n"
                f"Evidence: {', '.join(technique.get('evidence', []))}"
            )
        if not result.mitre_techniques:
            self.mitre_list.addItem(self.tr("No mapped techniques detected in this scan."))
        self.mitre_empty.setVisible(not result.mitre_techniques)
        self.mitre_list.setVisible(bool(result.mitre_techniques))
        feed_lines = [
            f"Status: {intelligence.get('status', 'unknown')}",
            f"Indicator type: {intelligence.get('indicator_type') or 'not applicable'}",
            f"Elapsed: {intelligence.get('elapsed_ms', 0):.1f} ms",
            f"Matches: {len(intelligence.get('matches', []))}",
            "A feed miss is not proof of safety. Feed matches are correlations, not proof of malware.",
        ]
        for name, feed in intelligence.get("feeds", {}).items():
            feed_lines.append(
                f"\n{name}: {feed.get('status', 'unknown')} · "
                f"{feed.get('match_count', 0)} match(es)"
            )
            for record in feed.get("records", [])[:4]:
                feed_lines.append(f"  - {record}")
        self.intel_text.setPlainText("\n".join(feed_lines))
        self.intel_summary.setText(
            self.tr("OSINT disabled. No indicators were sent to external services.")
            if intelligence.get("status") == "disabled"
            else f"{intelligence.get('status', 'unknown')} · "
            f"{self.tr('indicator ')}{intelligence.get('indicator_type') or 'unsupported'}"
        )
        self.report_text.setPlainText(self.tr(result.as_text()))
        self._populate_detail_tabs()

    def _populate_detail_tabs(self) -> None:
        tabs = (
            "Evidence",
            "Structure",
            "Findings",
            "Engines",
            "Intelligence",
            "Report",
        )
        for index, title in enumerate(tabs):
            self.detail_tabs.setTabText(index, self.tr(title))
        for name, pane in self.engine_texts.items():
            index = ("YARA", "PE", "Structural model", "MITRE ATT&CK").index(name)
            self.detail_tabs.widget(3).setTabText(index, self.tr(name))

    def _record_scan_history(self, result) -> None:
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
        candidate_history = [*self.scan_history, record]
        updated = candidate_history[-200:]
        try:
            self.ui_store.save_history(updated)
        except (OSError, TypeError, ValueError):
            report_path.unlink(missing_ok=True)
            raise
        self.scan_history = updated
        for expired in candidate_history[:-200]:
            try:
                self._validated_history_report(expired).unlink()
            except (OSError, ValueError) as exc:
                self._append_log(f"Unable to remove expired history report: {exc}")
        self.refresh_history()

    def refresh_history(self, _query: str | None = None) -> None:
        query = (
            self.history_filter.text().casefold()
            if hasattr(self, "history_filter")
            else ""
        )
        if hasattr(self, "history_list"):
            self.history_list.clear()
        self.sidebar_history.clear()
        for record in reversed(self.scan_history):
            target = str(record.get("target", ""))
            shown = Path(target).name if Path(target).is_absolute() else target
            searchable = " ".join(
                (
                    target,
                    str(record.get("classification", "")),
                    str(record.get("sha256", "")),
                )
            ).casefold()
            if query and query not in searchable:
                continue
            timestamp = str(record.get("timestamp", ""))[:16].replace("T", " ")
            label = (
                f"{shown}\n{record.get('classification', 'UNKNOWN')} · "
                f"{record.get('score', 0)}/100 · {timestamp}"
            )
            history_item = QListWidgetItem(label)
            history_item.setData(Qt.ItemDataRole.UserRole, record["id"])
            color = self._history_color(str(record.get("classification", "")))
            history_item.setForeground(color)
            self.sidebar_history.addItem(history_item.clone())
            if hasattr(self, "history_list"):
                self.history_list.addItem(history_item)
        if hasattr(self, "history_empty"):
            has_records = self.history_list.count() > 0
            has_any = bool(self.scan_history)
            self.history_empty.setVisible(not has_records)
            self.history_list.setVisible(has_records)
            if not has_records and has_any:
                self.history_empty.title_label.setText(self.tr("No scan matches this search"))
                self.history_empty.body_label.setText(
                    self.tr("Clear the search field to see all saved scans.")
                )
            elif not has_records:
                self.history_empty.retranslate(self.tr)
        if hasattr(self, "history_details") and self.history_list.count() == 0:
            self.history_details.clear()
            self._select_history_record(None)
        self._refresh_home()

    @staticmethod
    def _history_color(classification: str):
        return QColor(
            "#ff8494"
            if classification == "SUSPICIOUS"
            else "#ffc16f"
            if classification == "REVIEW"
            else "#71d9b1"
            if classification == "NO_INDICATORS_OBSERVED"
            else "#aab9ca"
        )

    def _open_history_item(self, item: QListWidgetItem) -> None:
        record_id = item.data(Qt.ItemDataRole.UserRole)
        self._show_page("history")
        for index in range(self.history_list.count()):
            candidate = self.history_list.item(index)
            if candidate.data(Qt.ItemDataRole.UserRole) == record_id:
                self.history_list.setCurrentItem(candidate)
                break

    def _selected_history_record(self) -> dict[str, Any] | None:
        if not hasattr(self, "history_list") or not self.history_list.currentItem():
            return None
        record_id = self.history_list.currentItem().data(Qt.ItemDataRole.UserRole)
        return next(
            (record for record in self.scan_history if record["id"] == record_id),
            None,
        )

    def _select_history_record(self, current, _previous=None) -> None:
        has_selection = current is not None
        for button in (
            getattr(self, "history_open_button", None),
            getattr(self, "history_export_button", None),
            getattr(self, "history_remove_button", None),
        ):
            if button is not None:
                button.setEnabled(has_selection)
        if current is None:
            self.history_details.clear()
            return
        record = next(
            (
                item
                for item in self.scan_history
                if item["id"] == current.data(Qt.ItemDataRole.UserRole)
            ),
            None,
        )
        if record:
            self.history_details.setPlainText(
                f"Target: {record.get('target', '')}\n"
                f"SHA-256: {record.get('sha256') or 'not available'}\n"
                f"Classification: {record.get('classification', 'UNKNOWN')}\n"
                f"Risk index: {record.get('score', 0)}/100"
            )

    def _validated_history_report(self, record: dict[str, Any]) -> Path:
        directory = (Path(REPORT_DIR) / "history").resolve()
        report_path = Path(record["report_path"]).resolve()
        if report_path.parent != directory or not report_path.is_file():
            raise ValueError(
                self.tr("The saved report is missing or outside the local history folder.")
            )
        return report_path

    def open_history_report(self) -> None:
        record = self._selected_history_record()
        if not record:
            QMessageBox.information(self, self.tr("Scan history"), self.tr("Select a history entry first."))
            return
        try:
            path = self._validated_history_report(record)
        except (OSError, ValueError) as exc:
            QMessageBox.critical(self, self.tr("Report unavailable"), str(exc))
            return
        if not QDesktopServices.openUrl(QUrl.fromLocalFile(str(path))):
            QMessageBox.critical(self, self.tr("Report unavailable"), self.tr("The report could not be opened."))

    def export_history_report(self) -> None:
        record = self._selected_history_record()
        if not record:
            QMessageBox.information(self, self.tr("Scan history"), self.tr("Select a history entry first."))
            return
        try:
            source = self._validated_history_report(record)
        except (OSError, ValueError) as exc:
            QMessageBox.critical(self, self.tr("Report unavailable"), str(exc))
            return
        destination, _filter = QFileDialog.getSaveFileName(
            self,
            self.tr("Export report"),
            f"{Path(record['target']).name or 'scan-report'}.json",
            "JSON (*.json);;Text report (*.txt)",
        )
        if not destination:
            return
        try:
            if Path(destination).suffix.casefold() == ".txt":
                payload = json.loads(source.read_text(encoding="utf-8"))
                result = self._result_from_report(payload)
                export_report(result, destination, "txt")
            else:
                shutil.copy2(source, destination)
        except (OSError, TypeError, ValueError, KeyError) as exc:
            QMessageBox.critical(self, self.tr("Export failed"), str(exc))
            return
        QMessageBox.information(self, self.tr("Export complete"), destination)

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

    def remove_history_record(self) -> None:
        record = self._selected_history_record()
        if not record:
            QMessageBox.information(self, self.tr("Scan history"), self.tr("Select a history entry first."))
            return
        answer = QMessageBox.question(
            self,
            self.tr("Remove history entry"),
            self.tr("Remove this saved history entry and its generated report? The original scanned file will not be deleted."),
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        updated = [entry for entry in self.scan_history if entry["id"] != record["id"]]
        try:
            self.ui_store.save_history(updated)
        except (OSError, TypeError, ValueError) as exc:
            QMessageBox.critical(self, self.tr("History could not be saved"), str(exc))
            return
        self.scan_history = updated
        try:
            self._validated_history_report(record).unlink()
        except (OSError, ValueError) as exc:
            self._append_log(f"History entry removed but report cleanup failed: {exc}")
        self.refresh_history()
        self.refresh_workspace_status()

    def export_current_report(self) -> None:
        if not self.last_payload:
            return
        result = self.last_payload[0]
        destination, selected_filter = QFileDialog.getSaveFileName(
            self,
            self.tr("Export report"),
            f"{Path(result.target).name or 'cyberscan-report'}.txt",
            "Text report (*.txt);;JSON (*.json)",
        )
        if not destination:
            return
        output_format = (
            "json"
            if Path(destination).suffix.casefold() == ".json"
            or "JSON" in selected_filter
            else "txt"
        )
        try:
            export_report(result, destination, output_format)
        except (OSError, ValueError, TypeError) as exc:
            QMessageBox.critical(self, self.tr("Export failed"), str(exc))
            return
        QMessageBox.information(self, self.tr("Export complete"), destination)

    def _pending_settings(self) -> dict[str, Any]:
        pending = dict(self.settings)
        for key, check in self.setting_checks.items():
            pending[key] = check.isChecked()
        pending["monitoring_directory"] = self.monitor_directory.text().strip()
        return pending

    def _settings_dirty(self, *_args) -> None:
        if not hasattr(self, "apply_settings_button"):
            return
        changed = self._pending_settings() != getattr(self, "_settings_snapshot", self.settings)
        self.apply_settings_button.setEnabled(changed)
        apply_tone(self.settings_saved_chip, "medium" if changed else "low")
        self.settings_saved_chip.setText(
            self.tr("Unsaved changes") if changed else self.tr("Saved · applied")
        )

    def _apply_text_scale(self) -> None:
        """Honor the persisted accessibility preference in the Qt interface."""
        enabled = bool(self.settings.get("large_text"))
        if enabled == self._large_text_applied:
            return
        self._large_text_applied = enabled
        scale = 1.18 if enabled else 1.0
        font = QFont(self.font())
        if font.pointSizeF() > 0:
            font.setPointSizeF(self._base_font_size * scale)
        else:
            # The stylesheet sets the size in pixels; override it here too.
            font.setPixelSize(round(13 * scale))
        self.setFont(font)
        self.setStyleSheet(self._scaled_stylesheet(scale))
        self._normalize_child_fonts(scale)
        for button in self.findChildren(QPushButton):
            if button.objectName() in {"primary", "sidebarPrimary"}:
                # Grow with the text scale, but keep the accent rule intact:
                # a local stylesheet here would replace it.
                button.setMinimumHeight(int(42 * scale))
            else:
                button.setMinimumHeight(int(34 * scale))
        self.target_entry.setMinimumHeight(int(48 * scale))
        self.monitor_directory.setMinimumHeight(int(34 * scale))

    def _normalize_child_fonts(self, scale: float = 1.0) -> None:
        """Give every child widget a concrete point size.

        Children built before setStyleSheet() report a -1 point size; Qt then
        falls back to a 1px face, which makes the primary action render as an
        empty box. This must run on every start, not only when text is
        enlarged, because large_text defaults to False.
        """
        target = self._base_font_size * scale
        for child in self.findChildren(QWidget):
            if child.font().pointSizeF() <= 0:
                resolved = QFont(child.font())
                resolved.setPointSizeF(target)
                child.setFont(resolved)

    @staticmethod
    def _scaled_stylesheet(scale: float) -> str:
        if scale == 1.0:
            return APP_STYLE
        return APP_STYLE.replace(
            "font-size: 13px;", f"font-size: {round(13 * scale)}px;"
        )

    def _apply_layout_mode(self) -> None:
        """Make the workspace usable on smaller windows or high display scaling."""
        compact = self.width() < 1180
        if compact != getattr(self, "_compact_layout", None):
            self._compact_layout = compact
            if compact:
                self.sidebar.setMinimumWidth(204)
                self.sidebar.setMaximumWidth(204)
                self.scan_core.setFixedSize(196, 196)
            else:
                self.sidebar.setMinimumWidth(232)
                self.sidebar.setMaximumWidth(232)
                self.scan_core.setFixedSize(248, 248)
            self.sidebar_history.setMaximumHeight(96 if compact else 150)
            self._reflow_stage_cards(2 if compact else 4)
            self.results_columns.setDirection(
                QBoxLayout.Direction.TopToBottom if compact else QBoxLayout.Direction.LeftToRight
            )

    def _reflow_stage_cards(self, columns: int) -> None:
        if columns == getattr(self, "_stage_columns", columns):
            return
        self._stage_columns = columns
        for card in self.stage_cards:
            self.stage_row.removeWidget(card)
            card.setVisible(False)
        for index, card in enumerate(self.stage_cards):
            row, column = divmod(index, columns)
            self.stage_row.addWidget(card, row, column)
            card.setVisible(True)

    def _append_log(self, message: str) -> None:
        timestamp = datetime.now().astimezone().strftime("%H:%M:%S")
        line = f"{timestamp}  {message}"
        self.audit_log.append(line)
        if hasattr(self, "log_view"):
            self.log_view.appendPlainText(line)

    def clear_logs(self) -> None:
        self.audit_log.clear()
        self.log_view.clear()

    def refresh_workspace_status(self) -> None:
        if not hasattr(self, "_workspace_metric_widgets"):
            return
        reports_dir = Path(REPORT_DIR) / "history"
        report_count = sum(1 for path in reports_dir.glob("*.json")) if reports_dir.exists() else 0
        model_path = DATA_DIR / "models" / "structural_classifier_4096.json"
        values = {
            "Scans in history": str(len(self.scan_history)),
            "Structural model": "Ready" if model_path.is_file() else "Not trained",
            "Downloads monitor": "Active" if self.settings.get("monitoring_enabled") else "Off",
            "Local reports": str(report_count),
        }
        for key, value in values.items():
            self._workspace_metric_widgets[key].setText(self.tr(value))
        self.sidebar_workspace_label.setText(
            self.tr("Local analysis · target files are not executed")
        )

    def apply_settings(self) -> None:
        updated = self.settings.copy()
        for key, check in self.setting_checks.items():
            updated[key] = check.isChecked()
        directory = self.monitor_directory.text().strip()
        if not directory:
            QMessageBox.warning(self, self.tr("Invalid folder"), self.tr("Choose a valid downloads folder."))
            return
        updated["monitoring_directory"] = str(Path(directory).expanduser())
        try:
            self.ui_store.save_settings(
                {**updated, "ui_language": self.language}
            )
        except (OSError, TypeError, ValueError) as exc:
            QMessageBox.critical(self, self.tr("Settings could not be saved"), str(exc))
            return
        self.settings = updated
        self._apply_text_scale()
        self.apply_settings_button.setEnabled(False)
        apply_tone(self.settings_saved_chip, "low")
        self.settings_saved_chip.setText(self.tr("Saved · applied"))
        self._settings_snapshot = dict(updated)
        if self.settings["monitoring_enabled"]:
            if (
                self._monitor.directory != Path(self.settings["monitoring_directory"])
                or not self._monitor._thread
                or not self._monitor._thread.is_alive()
            ):
                self._monitor.stop()
                self._monitor = DownloadMonitor(
                    self.settings["monitoring_directory"],
                    callback=self.monitor_file_detected.emit,
                )
            self._monitor.start()
            self._append_log("Downloads monitoring enabled.")
        else:
            self._monitor.stop()
            self._append_log("Downloads monitoring disabled.")
        self.refresh_workspace_status()
        self._settings_snapshot = dict(updated)
        self._refresh_home()

    def select_monitor_directory(self) -> None:
        directory = QFileDialog.getExistingDirectory(
            self,
            self.tr("Choose downloads folder"),
            self.monitor_directory.text(),
        )
        if directory:
            self.monitor_directory.setText(directory)

    def _queue_monitored_file(self, path: str) -> None:
        self.pending_monitor_scans.put(path)
        self._append_log(f"[Monitoring] Stable download detected: {path}")
        self._start_next_monitor_scan()

    def _start_next_monitor_scan(self) -> None:
        if self.worker and self.worker.isRunning():
            return
        try:
            path = self.pending_monitor_scans.get_nowait()
        except queue.Empty:
            return
        if not Path(path).is_file():
            self._append_log(f"[Monitoring] File no longer available; skipped: {path}")
            QTimer.singleShot(0, self._start_next_monitor_scan)
            return
        self._choose_mode_without_dialog("File")
        self.selected_path = path
        self.target_entry.setText(path)
        self.selected_file_label.setText(path)
        self.selected_file_label.setProperty("hint", False)
        self._append_log(f"[Monitoring] Starting static analysis: {path}")
        self.run_scan()

    def toggle_language(self) -> None:
        next_language = "ar" if self.language == "en" else "en"
        try:
            self.ui_store.save_settings(
                {**self.settings, "ui_language": next_language}
            )
        except (OSError, TypeError, ValueError) as exc:
            QMessageBox.critical(
                self,
                self.tr("Settings could not be saved"),
                str(exc),
            )
            return
        self.language = next_language
        self.setWindowTitle(
            "CyberScan · التحليل الساكن المحلي"
            if self.language == "ar"
            else "CyberScan · Local threat analysis"
        )
        self.setLayoutDirection(
            Qt.LayoutDirection.RightToLeft
            if self.language == "ar"
            else Qt.LayoutDirection.LeftToRight
        )
        self._sync_directional_styles()
        for widget, source in self._text_bindings:
            widget.setText(self.tr(source))
        self.language_button.setText("العربية" if self.language == "en" else "English")
        self.target_entry.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
        self.monitor_directory.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
        self.risk_gauge.language = self.language
        self.risk_gauge.update()
        self.signal_canvas.set_language(self.language)
        self.entropy_canvas.set_language(self.language)
        self.embedding_canvas.set_language(self.language)
        for index, mode in enumerate(self.mode_values):
            self.input_mode.setItemText(index, self.tr(mode))
        title, subtitle = self.PAGE_COPY.get(
            self.current_page, ("New analysis", "")
        )
        self.page_title.setText(self.tr(title))
        self.page_subtitle.setText(self.tr(subtitle))
        self.breadcrumb.setText(self.tr(dict((page, label) for label, page, _ in self.NAV_ITEMS).get(self.current_page, "New analysis")))
        self._populate_detail_tabs()
        self.status_banner.set_state(
            "ready", self.tr("Ready for a new target"), self.tr("Static analysis only.")
        )
        self.refresh_history()
        self.refresh_workspace_status()
        self._refresh_detection_summary()
        if self.setting_checks.get("large_text") is not None:
            self.setting_checks["large_text"].setChecked(
                bool(self.settings.get("large_text"))
            )
        self._settings_snapshot = dict(self.settings)
        self.settings_saved_chip.setText(self.tr("Saved \u00b7 applied"))
        self.apply_settings_button.setEnabled(False)
        if self.settings.get("large_text", False):
            self._apply_text_scale()
        if self.last_payload:
            self._render_result(*self.last_payload)
        self._show_page(self.current_page)

    def _refresh_detection_summary(self) -> None:
        """State plainly which engines are currently active."""
        engines = (
            ("entropy_analysis", "Entropy"),
            ("heuristic_rules", "Heuristics"),
            ("ml_analysis", "Structural model"),
        )
        active = [(key, label) for key, label in engines if self.settings.get(key)]
        summary = self.tr("Enabled in Settings: ") + (
            " · ".join(self._tx(label) for _key, label in active)
            if active
            else self.tr("None")
        )
        self.detection_summary.setText(summary)
        if hasattr(self, "settings_engine_summary"):
            self.settings_engine_summary.setText(summary)

        chips_layout = getattr(self, "engine_chips", None)
        if chips_layout is None:
            return
        while chips_layout.count():
            item = chips_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.setParent(None)
                widget.deleteLater()
        active_keys = {key for key, _label in active}
        for key, label in engines:
            chips_layout.addWidget(
                Chip(self._tx(label), "accent" if key in active_keys else "neutral")
            )

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        if hasattr(self, "page_indices"):
            self._apply_layout_mode()

    def closeEvent(self, event) -> None:
        if self._monitor:
            self._monitor.stop()
        if self.worker and self.worker.isRunning():
            event.ignore()
            QMessageBox.information(
                self,
                self.tr("Analysis in progress"),
                self.tr("Wait for the current static analysis to finish, then close the application."),
            )
            return
        # Nothing keeps ticking once the window has closed.
        self.scan_core.stop()
        self._workspace_timer.stop()
        for canvas in (self.signal_canvas, self.entropy_canvas, self.embedding_canvas):
            canvas._timer.stop()
        event.accept()


def main() -> None:
    app = QApplication.instance() or QApplication([])
    app.setApplicationName("CyberScan")
    app.setOrganizationName("CyberScan")
    app.setStyle("Fusion")
    window = CyberScanApp()
    window.show()
    app.exec()
