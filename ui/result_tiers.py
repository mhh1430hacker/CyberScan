"""The result, in three levels of reading.

Level 1 (always shown) says what we think and what to do. "Why?" opens
level 2, plain details in short sections. Only once level 2 is open does the
"Advanced data" button appear, which opens level 3: the engine's own output,
unchanged, in tabs. Each level unfolds below the previous one so the reader
never loses their place, and each can be closed again.
"""
from __future__ import annotations

import json
import re
from dataclasses import asdict, is_dataclass
from typing import Any, Mapping

from PySide6.QtCore import QEasingCurve, QPointF, QPropertyAnimation, QRectF, QSize, Qt, QTimer, Signal
from PySide6.QtGui import QColor, QGuiApplication, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import (
    QBoxLayout,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QSizePolicy,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from ui.copy import tr
from ui.file_kind import FileKind
from ui.icons import glyph_icon, glyph_pixmap
from ui.motion import VIEW_MS, prefers_reduced_motion, stagger
from ui.plain_language import SEVERITY_WORDS, Details, Summary
from ui.polish import toast
from ui.sonar import SonarCube
from ui.structure import Structure
from ui.theme import TOKENS, alpha, tone_color
from ui.widgets import Ambient, ElidedLabel, FlowLayout, KindTile, LevelMeter, Medallion, Pill, PlaceBars, card, label

FINDINGS_SHOWN = 5
_ARABIC = re.compile(r"[؀-ۿ]")


# --- level 3 content (plain text, engine output unchanged) --------------------


def _json_default(value: Any) -> Any:
    if is_dataclass(value):
        return asdict(value)
    if isinstance(value, (set, tuple)):
        return list(value)
    if isinstance(value, bytes):
        return f"<{len(value)} bytes>"
    return str(value)


def advanced_texts(result: Any, nextgen: Mapping[str, Any], prediction: Mapping[str, Any], intelligence: Mapping[str, Any]) -> dict[str, str]:
    """The engine's output for each advanced tab. Nothing is reworded."""
    findings = "\n\n".join(
        f"[{item.severity.upper()}] {item.evidence}\n"
        f"category={item.category} · contribution={item.contribution}\n{item.explanation}"
        for item in getattr(result, "evidence", []) or []
    ) or "(none)"
    position = (getattr(result, "feature_summary", {}) or {}).get("position_aware_evidence", {}) or {}
    lines = []
    for boundary in position.get("entropy_boundaries", [])[:12]:
        try:
            lines.append(
                f"entropy boundary 0x{boundary['offset_start']:X}-0x{boundary['offset_end']:X} "
                f"ΔH {boundary['entropy_delta_bits_per_byte']:+.3f} {str(boundary.get('severity', '')).upper()}"
            )
        except (KeyError, TypeError, ValueError):
            continue
    for section in position.get("pe_sections", [])[:16]:
        if section.get("file_offset_start") is not None:
            lines.append(f"PE section {section.get('name')} 0x{section['file_offset_start']:X}-0x{section.get('file_offset_end', 0):X}")
    if lines:
        findings += "\n\nPosition-aware evidence (measured only):\n" + "\n".join(lines)

    yara = [f"status: {getattr(result, 'engine_status', {}).get('YARA', 'unknown')}", f"matches: {len(result.yara_matches)}"]
    yara += [f"- {m.get('rule_name', 'unnamed')}: {m.get('description', '')}" for m in result.yara_matches]
    pe = getattr(result, "pe_analysis", {}) or {}
    pe_text = json.dumps(pe, indent=2, ensure_ascii=False, default=_json_default) if pe else "(not run)"
    mitre = "\n".join(
        f"{item.get('id', 'N/A')} · {item.get('name', 'Unknown')}\n  evidence: {', '.join(map(str, item.get('evidence', [])))}"
        for item in result.mitre_techniques
        if isinstance(item, Mapping)
    ) or "(none)"
    model = "\n".join(
        [
            f"model_status: {result.model_status}",
            f"prediction: {json.dumps(dict(prediction or {}), ensure_ascii=False, default=_json_default)}",
            "Scores are uncalibrated and are not probabilities.",
        ]
    )
    engines = "\n".join(f"{name}: {status}" for name, status in (result.engine_status or {}).items()) or "(none)"
    entropy = (nextgen or {}).get("entropy_topography", {}) or {}
    entropy_text = json.dumps(
        {key: value for key, value in entropy.items() if key != "trajectory"}, indent=2, default=_json_default
    ) if entropy else "(none)"
    intel = json.dumps(dict(intelligence or {}), indent=2, ensure_ascii=False, default=_json_default)
    report = result.as_text() if hasattr(result, "as_text") else str(result)
    raw = json.dumps(
        result.__dict__ if hasattr(result, "__dict__") else {}, indent=2, ensure_ascii=False, default=_json_default
    )
    return {
        "Findings": findings,
        "YARA": "\n".join(yara),
        "PE": pe_text,
        "MITRE ATT&CK": mitre,
        "Model": model,
        "Engines": engines,
        "Entropy": entropy_text,
        "Intelligence": intel,
        "Report": report,
        "JSON": raw,
    }


ADVANCED_TABS = ("Findings", "YARA", "PE", "MITRE ATT&CK", "Model", "Engines", "Entropy", "Intelligence", "Report", "JSON")


class EntropyChart(QWidget):
    """Entropy per window, 0..8 bits per byte, as measured."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.values: tuple[float, ...] = ()
        self.hue = QColor(TOKENS["accent"])
        self.setMinimumHeight(140)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

    def set_values(self, values, hue: str, name: str) -> None:
        self.values = tuple(float(v) for v in values or () if isinstance(v, (int, float)))
        self.hue = QColor(hue)
        self.setAccessibleName(name)
        self.update()

    def paintEvent(self, event) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        rect = QRectF(self.rect()).adjusted(8, 8, -8, -8)
        painter.setPen(QPen(QColor(TOKENS["line"]), 1))
        for level in (0, 4, 8):
            y = rect.bottom() - rect.height() * level / 8
            painter.drawLine(QPointF(rect.left(), y), QPointF(rect.right(), y))
        if len(self.values) < 2:
            return
        rtl = self.layoutDirection() == Qt.LayoutDirection.RightToLeft
        path = QPainterPath()
        count = len(self.values)
        for index, value in enumerate(self.values):
            fraction = index / (count - 1)
            x = rect.right() - rect.width() * fraction if rtl else rect.left() + rect.width() * fraction
            y = rect.bottom() - rect.height() * max(0.0, min(8.0, value)) / 8
            path.moveTo(x, y) if index == 0 else path.lineTo(x, y)
        area = QPainterPath(path)
        area.lineTo(rect.left() if rtl else rect.right(), rect.bottom())
        area.lineTo(rect.right() if rtl else rect.left(), rect.bottom())
        area.closeSubpath()
        painter.fillPath(area, alpha(self.hue, 0.14))
        painter.setPen(QPen(self.hue, 1.8))
        painter.drawPath(path)


# --- unfolding -------------------------------------------------------------------


def unfold(widget: QWidget, show: bool) -> None:
    """Open or close a section by animating its height (instant with reduced motion)."""
    if prefers_reduced_motion() or not widget.window().isVisible():
        widget.setMaximumHeight(16777215)
        widget.setVisible(show)
        return
    previous = getattr(widget, "_unfold_animation", None)
    if previous is not None:
        previous.stop()
    if show:
        widget.setMaximumHeight(0)
        widget.setVisible(True)
        target = max(1, widget.sizeHint().height())
        start, end = 0, target
    else:
        start, end = widget.height(), 0
    animation = QPropertyAnimation(widget, b"maximumHeight", widget)
    animation.setDuration(VIEW_MS)
    animation.setStartValue(start)
    animation.setEndValue(end)
    animation.setEasingCurve(QEasingCurve.Type.OutCubic)

    def done() -> None:
        widget.setMaximumHeight(16777215)
        widget.setVisible(show)

    animation.finished.connect(done)
    widget._unfold_animation = animation
    animation.start()


# --- the panel ---------------------------------------------------------------------


def severity_word(severity: str) -> str:
    """The plain word for a located region's severity ("critical" reads as serious)."""
    return SEVERITY_WORDS.get("high" if severity == "critical" else severity, "Moderate")


def hex_offset(value: int) -> str:
    """A byte offset that reads left to right even inside Arabic text."""
    return f"⁦0x{value:X}⁩"


def _where(start: int, end: int, size: int) -> str:
    middle = (start + end) / 2 / max(1, size)
    return "near the start" if middle < 0.2 else "near the end" if middle > 0.8 else "in the middle"


def region_sentence(region, size: int, language: str) -> str:
    """One unusual place in plain words: how serious, where, how big."""
    from ui.plain_language import format_size, isolate

    length = isolate(format_size(region.offset_end - region.offset_start), language)
    return " · ".join((
        tr(severity_word(region.severity), language),
        tr(_where(region.offset_start, region.offset_end, size), language),
        length,
    ))


def region_label(region, language: str) -> str:
    """Callout text for a region in the sonar cube: how serious and how big
    (the exact byte range is in the list's tooltip)."""
    from ui.plain_language import format_size, isolate

    return f"{tr(severity_word(region.severity), language)} · {isolate(format_size(region.offset_end - region.offset_start), language)}"


class ResultPanel(QWidget):
    newScanRequested = Signal()
    exportRequested = Signal()
    detailsToggled = Signal(bool)
    advancedToggled = Signal(bool)
    aiRequested = Signal()
    aiStopRequested = Signal()
    quarantineRequested = Signal()
    revealRequested = Signal()
    onlineRequested = Signal()
    repairRequested = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.language = "en"
        self._summary: Summary | None = None
        self._details: Details | None = None
        self._kind: FileKind | None = None
        self._texts: dict[str, str] = {}
        self._texts_shown = True  # the raw tabs are filled when Advanced first opens
        self._all_findings = False
        # A main column and, beside it, a properties inspector (Linear-style).
        self.body = QBoxLayout(QBoxLayout.Direction.LeftToRight, self)
        self.body.setContentsMargins(0, 0, 0, 0)
        self.body.setSpacing(16)
        self.main_column = QWidget()
        layout = QVBoxLayout(self.main_column)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(16)
        self.body.addWidget(self.main_column, 1)

        self.origin = label("", "mute")
        self.origin.setVisible(False)
        layout.addWidget(self.origin)

        # Level 1 ---------------------------------------------------------------
        self.summary_card = QWidget()
        self.summary_card.setObjectName("summaryCard")
        self.summary_ambient = Ambient(self.summary_card)
        summary = QVBoxLayout(self.summary_card)
        summary.setContentsMargins(34, 30, 34, 28)
        summary.setSpacing(18)
        top = QHBoxLayout()
        top.setSpacing(26)
        self.medallion = Medallion(92)
        top.addWidget(self.medallion, 0, Qt.AlignmentFlag.AlignTop)
        words = QVBoxLayout()
        words.setSpacing(8)
        self.headline = label("", "headline", wrap=True)
        self.sentence = label("", "lead", wrap=True)
        self.advice = label("", "title", wrap=True)
        self.limit = label("", "mute", wrap=True)
        for widget in (self.headline, self.sentence, self.advice, self.limit):
            words.addWidget(widget)
        words.addStretch(1)
        top.addLayout(words, 1)
        summary.addLayout(top)
        # A fact the reader must not miss (a disguised name, a lookalike link).
        self.notice_box = QFrame()
        self.notice_box.setObjectName("notice")
        notice = QHBoxLayout(self.notice_box)
        notice.setContentsMargins(14, 10, 14, 10)
        notice.setSpacing(10)
        self.notice_mark = label("⚠")
        self.notice_mark.setStyleSheet(f"color: {TOKENS['danger']}; font-size: 18px; font-weight: 700;")
        self.notice_text = label("", "noticeText", wrap=True)
        notice.addWidget(self.notice_mark, 0, Qt.AlignmentFlag.AlignTop)
        notice.addWidget(self.notice_text, 1)
        self.notice_box.setVisible(False)
        summary.addWidget(self.notice_box)
        # The main reasons, so "why" is answered without scrolling.
        self.reasons_host = QWidget()
        self.reasons_list = QVBoxLayout(self.reasons_host)
        self.reasons_list.setContentsMargins(0, 0, 0, 0)
        self.reasons_list.setSpacing(4)
        self.reasons_host.setVisible(False)
        summary.addWidget(self.reasons_host)
        actions_host = QWidget()
        actions = FlowLayout(actions_host, spacing=10)
        self.why_button = QPushButton()
        self.why_button.setObjectName("primary")
        self.why_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.why_button.clicked.connect(self.toggle_details)
        self.quarantine_button = QPushButton()
        self.quarantine_button.setObjectName("danger")
        self.quarantine_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.quarantine_button.clicked.connect(self.quarantineRequested)
        self.online_button = QPushButton()
        self.online_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.online_button.clicked.connect(self.onlineRequested)
        self.reveal_button = QPushButton()
        self.reveal_button.setObjectName("ghost")
        self.reveal_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.reveal_button.clicked.connect(self.revealRequested)
        self.copy_hash_button = QPushButton()
        self.copy_hash_button.setObjectName("ghost")
        self.copy_hash_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.copy_hash_button.clicked.connect(self._copy_fingerprint)
        # Offered only once the repair engine has found something it can cut out exactly.
        self.repair_button = QPushButton()
        self.repair_button.setObjectName("repairCta")
        self.repair_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.repair_button.clicked.connect(self.repairRequested)
        self.repair_button.setVisible(False)
        self.repair_count = 0
        self.again_button = QPushButton()
        self.again_button.setObjectName("ghost")
        self.again_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.again_button.clicked.connect(self.newScanRequested)
        for button in (self.why_button, self.repair_button, self.quarantine_button, self.online_button, self.reveal_button, self.copy_hash_button, self.again_button):
            actions.addWidget(button)
        summary.addWidget(actions_host)
        self.fingerprint = ""
        self.quarantined = False
        layout.addWidget(self.summary_card)

        # AI summary (written locally; explains, never decides) -----------------
        self.ai_card = card()
        ai = QVBoxLayout(self.ai_card)
        ai.setContentsMargins(22, 16, 22, 16)
        ai.setSpacing(8)
        ai_head = QHBoxLayout()
        ai_head.setSpacing(10)
        self.ai_mark = label("")
        self.ai_mark.setPixmap(glyph_pixmap("spark", TOKENS["accent"], 18))
        self.ai_title = label("", "section", wrap=True)
        self.ai_badge = Pill()
        ai_head.addWidget(self.ai_mark, 0, Qt.AlignmentFlag.AlignVCenter)
        ai_head.addWidget(self.ai_title, 1)
        ai_head.addWidget(self.ai_badge, 0, Qt.AlignmentFlag.AlignVCenter)
        ai.addLayout(ai_head)
        self.ai_text = label("", "lead", wrap=True)
        self.ai_text.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        ai.addWidget(self.ai_text)
        ai_foot = QHBoxLayout()
        ai_foot.setSpacing(10)
        self.ai_note = label("", "mute", wrap=True)
        self.ai_button = QPushButton()
        self.ai_button.setObjectName("ghost")
        self.ai_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.ai_button.clicked.connect(self._ai_clicked)
        ai_foot.addWidget(self.ai_note, 1)
        ai_foot.addWidget(self.ai_button, 0, Qt.AlignmentFlag.AlignBottom)
        ai.addLayout(ai_foot)
        self.ai_state = "hidden"
        self.ai_model = ""
        self.ai_card.setVisible(False)

        # Inside the file: the sonar cube, explorable by hand ----------------------
        self.inside_card = card()
        inside = QVBoxLayout(self.inside_card)
        inside.setContentsMargins(22, 16, 22, 16)
        inside.setSpacing(8)
        inside_head = QHBoxLayout()
        self.inside_title = label("", "section")
        self.map_button = QPushButton()
        self.map_button.setObjectName("link")
        self.map_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.map_button.clicked.connect(self._toggle_map)
        inside_head.addWidget(self.inside_title, 1)
        inside_head.addWidget(self.map_button)
        inside.addLayout(inside_head)
        self.regions_list = QVBoxLayout()
        self.regions_list.setSpacing(4)
        inside.addLayout(self.regions_list)
        # The 3D map is there for whoever wants it, folded by default.
        self.map_host = QWidget()
        map_layout = QVBoxLayout(self.map_host)
        map_layout.setContentsMargins(0, 6, 0, 0)
        map_layout.setSpacing(6)
        self.inside_hint = label("", "mute")
        self.inside_note = label("", "mute", wrap=True)
        map_layout.addWidget(self.inside_note)
        map_layout.addWidget(self.inside_hint)
        self.cube = SonarCube(interactive=True)
        self.cube.describe = self._describe_cell
        self.cube.label_for = lambda region: region_label(region, self.language)
        self.cube.setAccessibleDescription("")
        map_layout.addWidget(self.cube)
        self.map_host.setVisible(False)
        inside.addWidget(self.map_host)
        self.structure: Structure | None = None
        self.inside_card.setVisible(False)
        layout.addWidget(self.inside_card)
        layout.addWidget(self.ai_card)

        # Level 2 ---------------------------------------------------------------
        self.details = QWidget()
        details = QVBoxLayout(self.details)
        details.setContentsMargins(0, 0, 0, 0)
        details.setSpacing(14)
        self.columns = QBoxLayout(QBoxLayout.Direction.LeftToRight)
        self.columns.setSpacing(14)
        self.findings_card = card()
        findings = QVBoxLayout(self.findings_card)
        findings.setContentsMargins(22, 18, 22, 18)
        findings.setSpacing(10)
        self.findings_title = label("", "section")
        findings.addWidget(self.findings_title)
        self.findings_list = QVBoxLayout()
        self.findings_list.setSpacing(8)
        findings.addLayout(self.findings_list)
        self.more_button = QPushButton()
        self.more_button.setObjectName("link")
        self.more_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.more_button.clicked.connect(self._toggle_all_findings)
        findings.addWidget(self.more_button, 0, Qt.AlignmentFlag.AlignLeft)
        findings.addStretch(1)
        self.columns.addWidget(self.findings_card, 3)

        side = QVBoxLayout()
        side.setContentsMargins(0, 0, 0, 0)
        side.setSpacing(14)
        self.places_card = card()
        places = QVBoxLayout(self.places_card)
        places.setContentsMargins(22, 18, 22, 18)
        places.setSpacing(10)
        self.places_title = label("", "section")
        self.places = PlaceBars()
        places.addWidget(self.places_title)
        places.addWidget(self.places)
        side.addWidget(self.places_card)
        side.addStretch(1)
        side_widget = QWidget()
        side_widget.setLayout(side)
        self.columns.addWidget(side_widget, 2)
        details.addLayout(self.columns)

        self.about_card = card()
        about = QVBoxLayout(self.about_card)
        about.setContentsMargins(22, 18, 22, 18)
        about.setSpacing(10)
        about_head = QHBoxLayout()
        self.about_tile = KindTile(34)
        self.about_title = label("", "section")
        about_head.addWidget(self.about_tile)
        about_head.addWidget(self.about_title, 1)
        about.addLayout(about_head)
        self.about_grid = QGridLayout()
        self.about_grid.setHorizontalSpacing(18)
        self.about_grid.setVerticalSpacing(8)
        self.about_grid.setColumnStretch(1, 1)
        about.addLayout(self.about_grid)
        self.score_line = label("", "mute", wrap=True)
        about.addWidget(self.score_line)
        details.addWidget(self.about_card)

        detail_actions = QHBoxLayout()
        detail_actions.setSpacing(10)
        self.advanced_button = QPushButton()
        self.advanced_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.advanced_button.clicked.connect(self.toggle_advanced)
        self.export_button = QPushButton()
        self.export_button.setObjectName("ghost")
        self.export_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.export_button.clicked.connect(self.exportRequested)
        detail_actions.addWidget(self.advanced_button)
        detail_actions.addStretch(1)
        detail_actions.addWidget(self.export_button)
        details.addLayout(detail_actions)
        self.details.setVisible(False)
        layout.addWidget(self.details)

        # Level 3 ---------------------------------------------------------------
        self.advanced = card()
        advanced = QVBoxLayout(self.advanced)
        advanced.setContentsMargins(22, 18, 22, 18)
        advanced.setSpacing(10)
        head = QHBoxLayout()
        head_words = QVBoxLayout()
        head_words.setSpacing(2)
        self.advanced_title = label("", "section")
        self.advanced_note = label("", "mute", wrap=True)
        head_words.addWidget(self.advanced_title)
        head_words.addWidget(self.advanced_note)
        head.addLayout(head_words, 1)
        self.copy_button = QPushButton()
        self.copy_button.setObjectName("ghost")
        self.copy_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.copy_button.clicked.connect(self._copy_tab)
        head.addWidget(self.copy_button, 0, Qt.AlignmentFlag.AlignTop)
        advanced.addLayout(head)
        self.tabs = QTabWidget()
        self.tabs.setUsesScrollButtons(True)
        self.tab_texts: dict[str, QPlainTextEdit] = {}
        for key in ADVANCED_TABS:
            page = QWidget()
            page_layout = QVBoxLayout(page)
            page_layout.setContentsMargins(0, 8, 0, 0)
            page_layout.setSpacing(8)
            if key == "Entropy":
                self.entropy_chart = EntropyChart()
                self.entropy_caption = label("", "mute")
                page_layout.addWidget(self.entropy_chart)
                page_layout.addWidget(self.entropy_caption)
            text = QPlainTextEdit()
            text.setObjectName("mono")
            text.setReadOnly(True)
            text.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
            text.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
            text.setMinimumHeight(260)
            page_layout.addWidget(text)
            self.tab_texts[key] = text
            self.tabs.addTab(page, key.replace("&", "&&"))
        advanced.addWidget(self.tabs)
        self.advanced.setVisible(False)
        layout.addWidget(self.advanced)
        layout.addStretch(1)

        # Inspector: the result's properties at a glance --------------------------
        self.inspector = card()
        inspector = QVBoxLayout(self.inspector)
        inspector.setContentsMargins(20, 18, 20, 18)
        inspector.setSpacing(10)
        self.meter_caption = label("", "eyebrow")
        self.meter = LevelMeter()
        inspector.addWidget(self.meter_caption)
        inspector.addWidget(self.meter)
        inspector.addSpacing(4)
        self.facts_row = QVBoxLayout()
        self.facts_row.setSpacing(9)
        inspector.addLayout(self.facts_row)
        inspector.addSpacing(6)
        self.inspector_rule = QFrame()
        self.inspector_rule.setFixedHeight(1)
        self.inspector_rule.setStyleSheet("background: rgba(255, 255, 255, 0.07);")
        inspector.addWidget(self.inspector_rule)
        inspector.addSpacing(4)
        self.checks_caption = label("", "eyebrow")
        inspector.addWidget(self.checks_caption)
        self.inspector_checks = QVBoxLayout()
        self.inspector_checks.setSpacing(7)
        inspector.addLayout(self.inspector_checks)
        inspector.addStretch(1)
        self.body.addWidget(self.inspector, 0, Qt.AlignmentFlag.AlignTop)
        self._wide: bool | None = None

    # -- state -----------------------------------------------------------------
    @property
    def details_open(self) -> bool:
        return self.details.isVisible() or self.details.isVisibleTo(self)

    @property
    def advanced_open(self) -> bool:
        return self.advanced.isVisibleTo(self)

    def toggle_details(self) -> None:
        opening = not self.details.isVisibleTo(self)
        if not opening and self.advanced.isVisibleTo(self):
            unfold(self.advanced, False)
        unfold(self.details, opening)
        self._sync_buttons(details=opening)
        self.detailsToggled.emit(opening)
        if opening:
            stagger([self.findings_card, self.places_card, self.about_card])
        self._sync_reasons(opening)

    def toggle_advanced(self) -> None:
        opening = not self.advanced.isVisibleTo(self)
        if opening:
            self._fill_advanced()
        unfold(self.advanced, opening)
        self._sync_buttons(advanced=opening)
        self.advancedToggled.emit(opening)

    def collapse_all(self) -> None:
        for widget in (self.details, self.advanced):
            widget.setMaximumHeight(16777215)
            widget.setVisible(False)
        self._all_findings = False
        self._sync_reasons(False)
        self._sync_buttons(details=False, advanced=False)

    # -- content -------------------------------------------------------------------
    def show_result(
        self,
        summary: Summary,
        details: Details,
        kind: FileKind,
        texts: dict[str, str],
        entropy: tuple[float, ...],
        origin: str = "",
        *,
        reveal: bool = True,
        structure: Structure | None = None,
        fingerprint: str = "",
    ) -> None:
        self._summary, self._details, self._kind, self._texts = summary, details, kind, texts
        self.fingerprint = fingerprint
        self.quarantined = False
        self.repair_count = 0
        self.repair_button.setVisible(False)
        self.collapse_all()
        self.origin.setText(origin)
        self.origin.setVisible(bool(origin))
        self._render_summary()
        self._render_details()
        # Laying out the raw engine text takes ~0.1 s; doing it here would
        # stall the reveal, so it waits until someone opens Advanced.
        self._texts_shown = False
        self.entropy_chart.set_values(entropy, kind.hue, tr("Entropy", self.language))
        self._render_inside(structure)
        self._sync_buttons(details=False, advanced=False)
        if reveal:
            self.medallion.reveal()
            QTimer.singleShot(120, self.meter.reveal)
            stagger([self.headline, self.sentence, self.advice, self.limit, self.meter])

    def retranslate(self, language: str) -> None:
        self.language = language
        for index, key in enumerate(ADVANCED_TABS):
            # '&' would otherwise become a keyboard mnemonic (ATT&CK -> ATT_CK).
            self.tabs.setTabText(index, tr(key, language).replace("&", "&&"))
        self.advanced_title.setText(tr("Advanced data", language))
        self.advanced_note.setText(tr("Engine output, unchanged. For specialists.", language))
        self.copy_button.setText(tr("Copy all", language))
        self.copy_button.setIcon(glyph_icon("copy", TOKENS["text_dim"], 15))
        self.again_button.setText(tr("Scan something else", language))
        self.again_button.setToolTip("Ctrl+N")
        self.quarantine_button.setText(tr("Move to quarantine", language))
        self.quarantine_button.setToolTip(tr("Encrypts the file and moves it out of the way. Nothing is deleted; you can restore it from your scans.", language))
        self.reveal_button.setText(tr("Show in folder", language))
        self._label_repair()
        self.copy_hash_button.setText(tr("Copy fingerprint", language))
        self.copy_hash_button.setToolTip(tr("Copies the file's SHA-256 fingerprint, to look it up elsewhere.", language) + " · Ctrl+Shift+C")
        self.online_button.setText(tr("Turn on online lookups", language))
        if self.ai_state != "hidden":
            self.set_ai(self.ai_state, self.ai_text.text() if self.ai_state in {"done", "working"} else "")
        self.export_button.setText(tr("Export report", language))
        self.export_button.setIcon(glyph_icon("save", TOKENS["text_dim"], 15))
        self.findings_title.setText(tr("What caught our attention", language))
        self.places_title.setText(tr("Where we found it", language))
        self.checks_caption.setText(tr("What we checked", language).upper() if language == "en" else tr("What we checked", language))
        self.about_title.setText(tr("About this target", language))
        self.meter_caption.setText(tr("Warning level", language).upper() if language == "en" else tr("Warning level", language))
        self._sync_buttons()

    def _sync_buttons(self, *, details: bool | None = None, advanced: bool | None = None) -> None:
        details = self.details.isVisibleTo(self) if details is None else details
        advanced = self.advanced.isVisibleTo(self) if advanced is None else advanced
        self.why_button.setText(tr("Hide the details" if details else "Why?", self.language))
        self.advanced_button.setText(tr("Hide advanced data" if advanced else "Advanced data", self.language))

    def _render_summary(self) -> None:
        summary = self._summary
        if summary is None:
            return
        color = tone_color(summary.tone)
        self.summary_ambient.set_hue(color, 0.08)
        self.summary_card.setAccessibleName(summary.headline)
        self.medallion.set_verdict(summary.symbol, color, summary.headline)
        self.headline.setText(summary.headline)
        self.headline.setStyleSheet(f"color: {TOKENS['text']};")
        self.sentence.setText(summary.sentence)
        self.advice.setText(summary.advice)
        self.limit.setText(summary.limit)
        self.limit.setVisible(bool(summary.limit))
        self.notice_text.setText(summary.notice)
        self.notice_box.setVisible(bool(summary.notice))
        self.notice_box.setProperty("tone", summary.notice_tone)
        self.notice_mark.setStyleSheet(f"color: {tone_color(summary.notice_tone)}; font-size: 18px; font-weight: 700;")
        self.notice_box.style().unpolish(self.notice_box)
        self.notice_box.style().polish(self.notice_box)
        self.notice_box.setAccessibleName(summary.notice)
        _clear(self.reasons_list)
        if summary.reasons:
            caption = label(tr("Mainly because:", self.language), "eyebrow")
            self.reasons_list.addWidget(caption)
            for reason in summary.reasons:
                row = label(f"•  {reason}", "body", wrap=True)
                self.reasons_list.addWidget(row)
        self.reasons_host.setVisible(bool(summary.reasons))
        self.quarantine_button.setVisible("quarantine" in summary.actions and not self.quarantined)
        self.reveal_button.setVisible("reveal" in summary.actions)
        self.copy_hash_button.setVisible("copy" in summary.actions and bool(self.fingerprint))
        self.online_button.setVisible("online" in summary.actions)
        self.online_button.setObjectName("primary" if "online" in summary.actions else "")
        self.why_button.setObjectName("" if "online" in summary.actions else "primary")
        for button in (self.online_button, self.why_button):
            button.style().unpolish(button)
            button.style().polish(button)
        labels = [tr(word, self.language) for word in LevelMeter.LABELS]
        self.meter.set_level(summary.meter, labels, tr("Unknown", self.language), tr("Warning level", self.language))
        _clear(self.facts_row)
        icons = ("eye", self._kind.icon if self._kind else "file", "history")
        for icon, fact in zip(icons, summary.facts):
            holder = QWidget()
            row = QHBoxLayout(holder)
            row.setContentsMargins(0, 0, 0, 0)
            row.setSpacing(10)
            mark = label("")
            mark.setPixmap(glyph_pixmap(icon, TOKENS["text_mute"], 16))
            mark.setFixedSize(18, 18)
            text = label(fact, "body", wrap=True)
            row.addWidget(mark, 0, Qt.AlignmentFlag.AlignVCenter)
            row.addWidget(text, 1)
            self.facts_row.addWidget(holder)

    def _render_details(self) -> None:
        details, kind = self._details, self._kind
        if details is None or kind is None:
            return
        _clear(self.findings_list)
        shown = details.findings if self._all_findings else details.findings[:FINDINGS_SHOWN]
        for finding in shown:
            self.findings_list.addWidget(_finding_row(finding, self.language == "ar"))
        if not details.findings:
            self.findings_list.addWidget(label(tr("Nothing caught our attention.", self.language), "body", wrap=True))
        overflow = len(details.findings) > FINDINGS_SHOWN
        self.more_button.setVisible(overflow)
        self.more_button.setText(
            tr("Show fewer", self.language)
            if self._all_findings
            else tr("Show all {count}", self.language).format(count=len(details.findings))
        )
        self.places_card.setVisible(bool(details.places))
        self.places.set_rows(list(details.places), tr("Where we found it", self.language))
        # Checks live in the inspector: state always, the reason with level 2.
        _clear(self.inspector_checks)
        self._reason_labels = []
        for check in details.checks:
            holder = QWidget()
            column = QVBoxLayout(holder)
            column.setContentsMargins(0, 0, 0, 0)
            column.setSpacing(2)
            row = QHBoxLayout()
            row.setSpacing(8)
            dot = label(check.symbol)
            dot.setStyleSheet(f"color: {tone_color(check.tone)}; font-weight: 700;")
            dot.setFixedWidth(14)
            name = label(check.name, "body", wrap=True)
            row.addWidget(dot, 0, Qt.AlignmentFlag.AlignTop)
            row.addWidget(name, 1)
            column.addLayout(row)
            state = label(check.state, "mute", wrap=True)
            state.setStyleSheet(f"color: {tone_color(check.tone) if check.tone in {'ok', 'warn', 'danger'} else TOKENS['text_mute']};")
            state.setContentsMargins(22, 0, 0, 0)
            column.addWidget(state)
            if check.reason:
                reason = label(check.reason, "mute", wrap=True)
                reason.setContentsMargins(22, 0, 0, 2)
                reason.setVisible(self.details.isVisibleTo(self))
                self._reason_labels.append(reason)
                column.addWidget(reason)
            holder.setToolTip(check.raw)
            holder.setAccessibleName(f"{check.name}: {check.state}. {check.reason}".strip())
            self.inspector_checks.addWidget(holder)
        if not details.checks:
            self.inspector_checks.addWidget(label(tr("No checks were reported.", self.language), "mute"))
        self.about_tile.set_kind(kind, animate=False)
        _clear(self.about_grid)
        rtl = self.language == "ar"
        for row_index, (caption, value) in enumerate(details.facts):
            key = label(caption, "mute")
            fingerprint = "SHA-256" in caption
            if row_index == 0 or fingerprint:
                # Names and hashes have no break points: one elided line, full
                # text in the tooltip (and the hash one click from the clipboard).
                # A name keeps its ending (".pdf.exe"); a hash is shortened in the middle.
                text = ElidedLabel(value, mode=Qt.TextElideMode.ElideMiddle, file_name=not fingerprint)
                text.setObjectName("mono" if fingerprint else "body")
                text.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
                text.setToolTip(value)
            else:
                text = label(value, "body", wrap=True)
            text.setAlignment(_leading(rtl))
            self.about_grid.addWidget(key, row_index, 0, Qt.AlignmentFlag.AlignTop)
            if fingerprint:
                holder = QWidget()
                row = QHBoxLayout(holder)
                row.setContentsMargins(0, 0, 0, 0)
                row.setSpacing(8)
                copy = QPushButton(tr("Copy", self.language))
                copy.setObjectName("link")
                copy.setCursor(Qt.CursorShape.PointingHandCursor)
                copy.clicked.connect(lambda _checked=False, v=value, b=copy: self._copy_value(v, b))
                row.addWidget(text, 1)
                row.addWidget(copy)
                self.about_grid.addWidget(holder, row_index, 1)
            else:
                self.about_grid.addWidget(text, row_index, 1)
        self.score_line.setText(details.score_line)

    # -- AI summary --------------------------------------------------------------
    AI_MESSAGES = {
        "no_server": "A summary in plain words isn't available: the local AI helper isn't running on this computer.",
        "no_model": "A summary in plain words isn't available: the AI model isn't installed yet.",
        "unsafe": "The AI's summary claimed more certainty than the scan supports, so it was not shown.",
        "empty": "The AI didn't write anything. Try again.",
        "error": "The AI couldn't write a summary this time.",
        "stopped": "Stopped.",
    }

    def set_ai(self, state: str, text: str = "", model: str = "") -> None:
        """state: hidden | idle | working | done | <failure code>"""
        self.ai_state = state
        if model:
            self.ai_model = model
        t = lambda value: tr(value, self.language)  # noqa: E731
        self.ai_card.setVisible(state != "hidden")
        self.ai_title.setText(t("Summary in plain words"))
        self.ai_badge.set_pill(t("AI · on this computer"), "accent")
        self.ai_card.setAccessibleName(t("Summary in plain words"))
        if state == "working":
            self.ai_text.setText(text or t("Writing…"))
            self.ai_button.setText(t("Stop"))
            self.ai_note.setText("")
        elif state == "done":
            self.ai_text.setText(text)
            self.ai_button.setText(t("Write it again"))
            self.ai_note.setText(t("Written by a local AI model ({model}). It can make mistakes; the verdict above comes from the scanner.").format(model=self.ai_model))
        elif state == "idle":
            self.ai_text.setText(t("A local AI model can explain this result in a few plain sentences."))
            self.ai_button.setText(t("Write a summary"))
            self.ai_note.setText("")
        else:
            self.ai_text.setText(t(self.AI_MESSAGES.get(state, self.AI_MESSAGES["error"])).format(model=self.ai_model))
            self.ai_button.setText(t("Try again"))
            self.ai_note.setText("")
            # For whoever runs it: the exact fix, out of the way of everyone else.
            hint = {"no_server": "Start Ollama, then try again.", "no_model": f"In a terminal run: ollama pull {self.ai_model}"}.get(state, "")
            self.ai_text.setToolTip(hint)
        failed = state not in {"done", "working", "idle"}
        self.ai_badge.setVisible(not failed)
        self.ai_title.setVisible(not failed)
        self.ai_mark.setVisible(not failed)
        self.ai_text.setObjectName("lead" if state in {"done", "working"} else "body")
        self.ai_text.style().unpolish(self.ai_text)
        self.ai_text.style().polish(self.ai_text)
        _direction(self.ai_text, self.language == "ar")

    def _ai_clicked(self) -> None:
        if self.ai_state == "working":
            self.aiStopRequested.emit()
        else:
            self.aiRequested.emit()

    # -- inside the file ---------------------------------------------------------------
    def _render_inside(self, structure: Structure | None) -> None:
        self.structure = structure
        self.inside_card.setVisible(structure is not None)
        _clear(self.regions_list)
        if structure is None:
            return
        t = lambda text: tr(text, self.language)  # noqa: E731
        self.inside_title.setText(t("Inside the file"))
        self.inside_hint.setText(t("Drag to turn · scroll to zoom · point at a dot to read it"))
        note = t("Each dot is a small slice of the file, placed so that neighbouring bytes stay together. Brighter dots hold more scrambled content; glowing dots are the places listed above.")
        if structure.source == "windows":
            note += " " + t("Rebuilt from the measurements saved with this scan.")
        self.inside_note.setText(note)
        hue = self._kind.hue if self._kind else TOKENS["accent"]
        self.cube.show_structure(structure, hue)
        self.cube.highlight(())
        self.cube.setAccessibleName(t("3D map of the file"))
        self._sync_map_button()
        if not structure.regions:
            self.regions_list.addWidget(label(t("No particular place inside this file stood out."), "body", wrap=True))
            return
        intro = (
            t("The content changes suddenly in {count} places:").format(count=len(structure.regions))
            if len(structure.regions) > 1
            else t("The content changes suddenly in one place:")
        )
        self.regions_list.addWidget(label(intro, "body", wrap=True))
        for region in structure.regions[:6]:
            text = region_sentence(region, structure.file_size, self.language)
            button = QPushButton(text)
            button.setObjectName("ghost")
            button.setCursor(Qt.CursorShape.PointingHandCursor)
            button.setCheckable(True)
            button.setToolTip(t("Bytes {start} to {end}").format(start=hex_offset(region.offset_start), end=hex_offset(region.offset_end)))
            button.setAccessibleName(text)
            button.clicked.connect(lambda checked=False, r=region, b=button: self._show_region(r, b))
            self.regions_list.addWidget(button, 0, Qt.AlignmentFlag.AlignLeft if self.language != "ar" else Qt.AlignmentFlag.AlignRight)

    def _sync_map_button(self) -> None:
        shown = self.map_host.isVisibleTo(self)
        self.map_button.setText(tr("Hide the 3D map" if shown else "Show the 3D map", self.language))

    def _toggle_map(self) -> None:
        self.map_host.setVisible(not self.map_host.isVisibleTo(self))
        self._sync_map_button()

    def _show_region(self, region, button: QPushButton) -> None:
        if button.isChecked() and not self.map_host.isVisibleTo(self):
            self._toggle_map()  # pointing at a place shows where it is
        for index in range(self.regions_list.count()):
            other = self.regions_list.itemAt(index).widget()
            if isinstance(other, QPushButton) and other is not button:
                other.setChecked(False)
        self.cube.highlight(region.cells if button.isChecked() else ())

    def _describe_cell(self, index: int) -> str:
        structure = self.structure
        if structure is None:
            return ""
        start, end = (int(v) for v in structure.offsets[index])
        text = tr("Bytes {start} to {end} · randomness {value} of 8", self.language).format(
            start=hex_offset(start), end=hex_offset(end), value=f"{float(structure.entropy[index]):.1f}"
        )
        if structure.flags[index] > 0:
            text += " · " + tr("Flagged by the scan", self.language)
        return text

    def _copy_fingerprint(self) -> None:
        if self.fingerprint:
            QGuiApplication.clipboard().setText(self.fingerprint)
            self.copy_hash_button.setText(tr("Copied", self.language))
            toast(self, "✓  " + tr("Fingerprint copied to the clipboard", self.language))

    def offer_repair(self, count: int) -> None:
        """Show "Repair this file" when ``count`` parts can be cut out exactly."""
        self.repair_count = count
        self._label_repair()
        self.repair_button.setVisible(count > 0 and not self.quarantined)

    def _label_repair(self) -> None:
        if self.repair_count:
            self.repair_button.setText("✦  " + tr("Repair this file · {count} can be fixed", self.language).format(count=self.repair_count))
            self.repair_button.setToolTip(tr("Opens Repair on a copy of this file. The original isn't changed.", self.language))

    def mark_quarantined(self, where: str) -> None:
        self.quarantined = True
        self.repair_button.setVisible(False)
        self.quarantine_button.setVisible(False)
        self.reveal_button.setVisible(False)
        self.notice_text.setText(tr("Moved to quarantine. It's encrypted and can't be opened by accident. You can restore it from your scans.", self.language))
        self.notice_box.setProperty("tone", "warn")
        self.notice_box.style().unpolish(self.notice_box)
        self.notice_box.style().polish(self.notice_box)
        self.notice_box.setVisible(True)
        self.notice_box.setToolTip(where)

    def _copy_value(self, value: str, button: QPushButton) -> None:
        QGuiApplication.clipboard().setText(value)
        button.setText(tr("Copied", self.language))

    def _sync_reasons(self, show: bool) -> None:
        for reason in getattr(self, "_reason_labels", []):
            reason.setVisible(show)

    def _toggle_all_findings(self) -> None:
        self._all_findings = not self._all_findings
        self._render_details()

    def _fill_advanced(self) -> None:
        if self._texts_shown:
            return
        self._texts_shown = True
        for key, text in self._texts.items():
            self.tab_texts[key].setPlainText(text)

    def _copy_tab(self) -> None:
        self._fill_advanced()
        key = ADVANCED_TABS[self.tabs.currentIndex()]
        QGuiApplication.clipboard().setText(self.tab_texts[key].toPlainText())
        self.copy_button.setText(tr("Copied", self.language))

    INSPECTOR_WIDTH = 300

    def resizeEvent(self, event) -> None:  # noqa: N802
        super().resizeEvent(event)
        self.summary_ambient.setGeometry(self.summary_card.rect())
        side_by_side = self.width() >= 1000
        main_width = self.width() - (self.INSPECTOR_WIDTH + 16 if side_by_side else 0)
        state = (side_by_side, main_width >= 820)
        if state != self._wide:
            self._wide = state
            self.body.setDirection(QBoxLayout.Direction.LeftToRight if side_by_side else QBoxLayout.Direction.TopToBottom)
            if side_by_side:
                self.inspector.setFixedWidth(self.INSPECTOR_WIDTH)
            else:
                self.inspector.setMinimumWidth(0)
                self.inspector.setMaximumWidth(16777215)
            self.columns.setDirection(QBoxLayout.Direction.LeftToRight if state[1] else QBoxLayout.Direction.TopToBottom)

    def showEvent(self, event) -> None:  # noqa: N802
        super().showEvent(event)
        self.summary_ambient.setGeometry(self.summary_card.rect())

    def sizeHint(self) -> QSize:  # noqa: N802
        return QSize(820, super().sizeHint().height())


def _leading(rtl: bool) -> Qt.AlignmentFlag:
    """The reading-start edge, even for left-to-right text inside RTL."""
    return (Qt.AlignmentFlag.AlignRight if rtl else Qt.AlignmentFlag.AlignLeft) | Qt.AlignmentFlag.AlignAbsolute | Qt.AlignmentFlag.AlignVCenter


def _finding_row(finding, rtl: bool = False) -> QWidget:
    row = QFrame()
    row.setObjectName("cardQuiet")
    layout = QVBoxLayout(row)
    layout.setContentsMargins(14, 12, 14, 12)
    layout.setSpacing(4)
    head = QHBoxLayout()
    head.setSpacing(10)
    pill = Pill(finding.word, finding.tone)
    title = label(finding.title, "section", wrap=True)
    _direction(title, rtl)
    head.addWidget(pill, 0, Qt.AlignmentFlag.AlignTop)
    head.addWidget(title, 1)
    if finding.count > 1:
        head.addWidget(Pill(f"×{finding.count}", "neutral"), 0, Qt.AlignmentFlag.AlignTop)
    layout.addLayout(head)
    if finding.body and finding.body.strip().casefold() != finding.title.strip().casefold():
        body = label(finding.body, "body", wrap=True)
        _direction(body, rtl)
        layout.addWidget(body)
    where = label(finding.where, "mute")
    layout.addWidget(where)
    row.setAccessibleName(f"{finding.word}: {finding.title}" + (f" ×{finding.count}" if finding.count > 1 else ""))
    return row


def _direction(widget: QLabel, rtl: bool) -> None:
    """Arabic text flows right to left; untranslated engine English stays left
    to right but starts at the reading edge."""
    if not _ARABIC.search(widget.text()):
        widget.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
    widget.setAlignment(_leading(rtl))


def _clear(layout) -> None:
    while layout.count():
        item = layout.takeAt(0)
        widget = item.widget()
        if widget is not None:
            widget.setParent(None)
            widget.deleteLater()
        elif item.layout() is not None:
            _clear(item.layout())
