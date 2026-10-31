"""The result, in three levels of reading.

Level 1 (always shown) says what we think and what to do. "Why?" opens
level 2, plain details in short sections. Only once level 2 is open does the
"Advanced data" button appear, which opens level 3: the engine's own output,
unchanged, in tabs. Each level unfolds below the previous one so the reader
never loses their place, and each can be closed again.
"""
from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass
from typing import Any, Mapping

from PySide6.QtCore import QEasingCurve, QPointF, QPropertyAnimation, QRectF, QSize, Qt, Signal
from PySide6.QtGui import QColor, QGuiApplication, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import (
    QBoxLayout,
    QFrame,
    QGridLayout,
    QHBoxLayout,
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
from ui.plain_language import Details, Summary
from ui.theme import TOKENS, alpha, tone_color
from ui.widgets import Ambient, ElidedLabel, KindTile, LevelMeter, Medallion, Pill, PlaceBars, card, label

FINDINGS_SHOWN = 5


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


class ResultPanel(QWidget):
    newScanRequested = Signal()
    exportRequested = Signal()
    detailsToggled = Signal(bool)
    advancedToggled = Signal(bool)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.language = "en"
        self._summary: Summary | None = None
        self._details: Details | None = None
        self._kind: FileKind | None = None
        self._texts: dict[str, str] = {}
        self._all_findings = False
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(16)

        self.origin = label("", "mute")
        self.origin.setVisible(False)
        layout.addWidget(self.origin)

        # Level 1 ---------------------------------------------------------------
        self.summary_card = QWidget()
        self.summary_ambient = Ambient(self.summary_card)
        summary = QVBoxLayout(self.summary_card)
        summary.setContentsMargins(34, 30, 34, 28)
        summary.setSpacing(18)
        top = QHBoxLayout()
        top.setSpacing(26)
        self.medallion = Medallion(132)
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
        meter_row = QHBoxLayout()
        meter_row.setSpacing(18)
        meter_col = QVBoxLayout()
        meter_col.setSpacing(4)
        self.meter_caption = label("", "eyebrow")
        self.meter = LevelMeter()
        meter_col.addWidget(self.meter_caption)
        meter_col.addWidget(self.meter)
        meter_col.addStretch(1)
        meter_row.addLayout(meter_col, 2)
        self.facts_row = QVBoxLayout()
        self.facts_row.setSpacing(8)
        meter_row.addLayout(self.facts_row, 3)
        summary.addLayout(meter_row)
        actions = QHBoxLayout()
        actions.setSpacing(10)
        self.why_button = QPushButton()
        self.why_button.setObjectName("primary")
        self.why_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.why_button.clicked.connect(self.toggle_details)
        self.again_button = QPushButton()
        self.again_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.again_button.clicked.connect(self.newScanRequested)
        actions.addWidget(self.why_button)
        actions.addWidget(self.again_button)
        actions.addStretch(1)
        summary.addLayout(actions)
        layout.addWidget(self.summary_card)

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
        self.checks_card = card()
        checks = QVBoxLayout(self.checks_card)
        checks.setContentsMargins(22, 18, 22, 18)
        checks.setSpacing(8)
        self.checks_title = label("", "section")
        checks.addWidget(self.checks_title)
        self.checks_list = QVBoxLayout()
        self.checks_list.setSpacing(6)
        checks.addLayout(self.checks_list)
        side.addWidget(self.checks_card)
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
            stagger([self.findings_card, self.places_card, self.checks_card, self.about_card])

    def toggle_advanced(self) -> None:
        opening = not self.advanced.isVisibleTo(self)
        unfold(self.advanced, opening)
        self._sync_buttons(advanced=opening)
        self.advancedToggled.emit(opening)

    def collapse_all(self) -> None:
        for widget in (self.details, self.advanced):
            widget.setMaximumHeight(16777215)
            widget.setVisible(False)
        self._all_findings = False
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
    ) -> None:
        self._summary, self._details, self._kind, self._texts = summary, details, kind, texts
        self.collapse_all()
        self.origin.setText(origin)
        self.origin.setVisible(bool(origin))
        self._render_summary()
        self._render_details()
        for key, text in texts.items():
            self.tab_texts[key].setPlainText(text)
        self.entropy_chart.set_values(entropy, kind.hue, tr("Entropy", self.language))
        self._sync_buttons(details=False, advanced=False)
        if reveal:
            self.medallion.reveal()
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
        self.export_button.setText(tr("Export report", language))
        self.export_button.setIcon(glyph_icon("save", TOKENS["text_dim"], 15))
        self.findings_title.setText(tr("What caught our attention", language))
        self.places_title.setText(tr("Where we found it", language))
        self.checks_title.setText(tr("What we checked", language))
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
        self.summary_ambient.set_hue(color, 0.16)
        self.summary_card.setAccessibleName(summary.headline)
        self.medallion.set_verdict(summary.symbol, color, summary.headline)
        self.headline.setText(summary.headline)
        self.headline.setStyleSheet(f"color: {TOKENS['text']};")
        self.sentence.setText(summary.sentence)
        self.advice.setText(summary.advice)
        self.limit.setText(summary.limit)
        self.limit.setVisible(bool(summary.limit))
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
        self.facts_row.addStretch(1)

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
        _clear(self.checks_list)
        for check in details.checks:
            row = QHBoxLayout()
            row.setSpacing(10)
            name = label(check.name, "body")
            pill = Pill(f"{check.symbol} {check.state}", check.tone)
            holder = QWidget()
            holder.setLayout(row)
            holder.setToolTip(check.raw)
            row.setContentsMargins(0, 0, 0, 0)
            row.addWidget(name, 1)
            row.addWidget(pill)
            self.checks_list.addWidget(holder)
        if not details.checks:
            self.checks_list.addWidget(label(tr("No checks were reported.", self.language), "mute"))
        self.about_tile.set_kind(kind, animate=False)
        _clear(self.about_grid)
        rtl = self.language == "ar"
        for row_index, (caption, value) in enumerate(details.facts):
            key = label(caption, "mute")
            fingerprint = "SHA-256" in caption
            if row_index == 0 or fingerprint:
                # Names and hashes have no break points: one elided line, full
                # text in the tooltip (and the hash one click from the clipboard).
                text = ElidedLabel(value, mode=Qt.TextElideMode.ElideMiddle)
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

    def _copy_value(self, value: str, button: QPushButton) -> None:
        QGuiApplication.clipboard().setText(value)
        button.setText(tr("Copied", self.language))

    def _toggle_all_findings(self) -> None:
        self._all_findings = not self._all_findings
        self._render_details()

    def _copy_tab(self) -> None:
        key = ADVANCED_TABS[self.tabs.currentIndex()]
        QGuiApplication.clipboard().setText(self.tab_texts[key].toPlainText())
        self.copy_button.setText(tr("Copied", self.language))

    def resizeEvent(self, event) -> None:  # noqa: N802
        super().resizeEvent(event)
        self.summary_ambient.setGeometry(self.summary_card.rect())
        wide = self.width() >= 860
        if wide != self._wide:
            self._wide = wide
            self.columns.setDirection(QBoxLayout.Direction.LeftToRight if wide else QBoxLayout.Direction.TopToBottom)

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
    title.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
    title.setAlignment(_leading(rtl))
    head.addWidget(pill, 0, Qt.AlignmentFlag.AlignTop)
    head.addWidget(title, 1)
    layout.addLayout(head)
    if finding.body and finding.body.strip().casefold() != finding.title.strip().casefold():
        body = label(finding.body, "body", wrap=True)
        body.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
        body.setAlignment(_leading(rtl))
        layout.addWidget(body)
    where = label(finding.where, "mute")
    layout.addWidget(where)
    row.setAccessibleName(f"{finding.word}: {finding.title}")
    return row


def _clear(layout) -> None:
    while layout.count():
        item = layout.takeAt(0)
        widget = item.widget()
        if widget is not None:
            widget.setParent(None)
            widget.deleteLater()
        elif item.layout() is not None:
            _clear(item.layout())
