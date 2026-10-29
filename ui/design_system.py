"""CyberScan design system - tokens, primitives and custom-painted parts.

Owned by NOR (Agent 2). Presentation layer only: nothing in this module
executes scans, reads verdicts from the engine, or invents security data.
"""
from __future__ import annotations

from PySide6.QtCore import (
    Property,
    QEasingCurve,
    QPointF,
    QPropertyAnimation,
    QRectF,
    QSize,
    Qt,
    Signal,
)
from PySide6.QtGui import (
    QColor,
    QFont,
    QFontMetrics,
    QLinearGradient,
    QPainter,
    QPainterPath,
    QPen,
)
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

# --------------------------------------------------------------------------
# Tokens
# --------------------------------------------------------------------------

TOKENS = {
    # canvas / surfaces (one family, four steps of elevation)
    "bg": "#070b12",
    "surface": "#0b1220",
    "surface_2": "#0f1826",
    "surface_3": "#141f30",
    "rail": "#080d16",
    # lines
    "line": "#1a2637",
    "line_soft": "#131e2c",
    "line_strong": "#26364b",
    # text
    "text": "#e8eef8",
    "text_dim": "#9bacbf",
    "text_mute": "#6b7d92",
    # accent - used for primary action and live state only
    "accent": "#5ee0d0",
    "accent_dim": "#2f8f87",
    "accent_wash": "#0e2527",
    # semantic
    "ok": "#4ade80",
    "warn": "#f5b544",
    "danger": "#f0645f",
    "info": "#6fa8ff",
    # severity (findings)
    "sev_high": "#f0645f",
    "sev_medium": "#f5b544",
    "sev_low": "#6fa8ff",
    "sev_info": "#7c8ca1",
}

SEVERITY_MAP = {
    "critical": TOKENS["sev_high"],
    "high": TOKENS["sev_high"],
    "medium": TOKENS["sev_medium"],
    "moderate": TOKENS["sev_medium"],
    "low": TOKENS["sev_low"],
    "info": TOKENS["sev_info"],
    "informational": TOKENS["sev_info"],
}

RADIUS = {"sm": "6px", "md": "10px", "lg": "14px", "pill": "999px"}
DURATION = {"quick": 120, "base": 180, "slow": 260}


def severity_color(severity: str) -> str:
    return SEVERITY_MAP.get(str(severity).strip().lower(), TOKENS["sev_info"])


# --------------------------------------------------------------------------
# Typographic helpers
# --------------------------------------------------------------------------

def mono_font(point_size: float = 9.0) -> QFont:
    font = QFont("Cascadia Mono")
    font.setStyleHint(QFont.StyleHint.Monospace)
    font.setFamilies(
        ["Cascadia Mono", "Consolas", "JetBrains Mono", "Menlo", "Courier New"]
    )
    font.setPointSizeF(point_size)
    return font


# --------------------------------------------------------------------------
# Widgets
# --------------------------------------------------------------------------

class Hairline(QFrame):
    """1px separator that never grabs attention."""

    def __init__(self, horizontal: bool = True, parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("hairline")
        if horizontal:
            self.setFixedHeight(1)
            self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        else:
            self.setFixedWidth(1)
            self.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Expanding)
        self.setStyleSheet(
            f"background:{TOKENS['line']};border:none;border-radius:0;"
        )


class SeverityDot(QWidget):
    """Small painted dot; the colour comes from the engine's severity."""

    def __init__(self, color: str = TOKENS["sev_info"], size: int = 8, parent=None):
        super().__init__(parent)
        self._color = QColor(color)
        self.setFixedSize(size, size)

    def set_color(self, color: str) -> None:
        self._color = QColor(color)
        self.update()

    def paintEvent(self, event) -> None:  # noqa: N802 (Qt naming)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        r = QRectF(0, 0, self.width(), self.height())
        halo = QColor(self._color)
        halo.setAlpha(46)
        painter.setBrush(halo)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawEllipse(r)
        inner = r.adjusted(2, 2, -2, -2)
        painter.setBrush(self._color)
        painter.drawEllipse(inner)


class Chip(QLabel):
    """Compact status token. Tones: neutral | accent | ok | warn | danger | info."""

    def __init__(self, text: str = "", tone: str = "neutral", parent=None):
        super().__init__(text, parent)
        self.setObjectName("chip")
        self.set_tone(tone)

    def set_tone(self, tone: str) -> None:
        self._tone = tone
        self.setProperty("tone", tone)
        self.style().unpolish(self)
        self.style().polish(self)


class MetaRow(QWidget):
    """label ................ value, with a monospaced value."""

    def __init__(self, label: str, value: str = "-", mono: bool = True, parent=None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)
        self.label = QLabel(label)
        self.label.setObjectName("metaLabel")
        self.value = QLabel(value)
        self.value.setObjectName("metaValueMono" if mono else "metaValue")
        self.value.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        self.value.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(self.label, 0)
        layout.addStretch(1)
        layout.addWidget(self.value, 0)

    def set_value(self, value: str) -> None:
        self.value.setText(value or "-")


class MeterBar(QWidget):
    """Thin horizontal meter for a real 0..100 metric from the engine."""

    def __init__(self, color: str = TOKENS["accent"], parent=None):
        super().__init__(parent)
        self._value = 0.0
        self._shown = 0.0
        self._color = QColor(color)
        self.setFixedHeight(6)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        from PySide6.QtCore import QPropertyAnimation

        self._anim = QPropertyAnimation(self, b"shown", self)
        self._anim.setDuration(DURATION["slow"])
        self._anim.setEasingCurve(QEasingCurve.Type.OutCubic)

    def get_shown(self) -> float:
        return self._shown

    def set_shown(self, value: float) -> None:
        self._shown = max(0.0, min(1.0, float(value)))
        self.update()

    shown = Property(float, get_shown, set_shown)

    def set_value(self, value: float, animate: bool = True) -> None:
        self._value = max(0.0, min(100.0, float(value))) / 100.0
        if animate:
            self._anim.stop()
            self._anim.setStartValue(self._shown)
            self._anim.setEndValue(self._value)
            self._anim.start()
        else:
            self.set_shown(self._value)

    def set_color(self, color: str) -> None:
        self._color = QColor(color)
        self.update()

    def paintEvent(self, event) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        r = QRectF(0, 0, self.width(), self.height())
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(TOKENS["surface_3"]))
        painter.drawRoundedRect(r, 3, 3)
        if self._shown <= 0:
            return
        fill = QRectF(r)
        fill.setWidth(r.width() * self._shown)
        if self.isRightToLeft():
            # Fill from the reading start: the right edge in RTL layouts.
            fill.moveRight(r.right())
            gradient = QLinearGradient(fill.right(), 0, fill.left(), 0)
        else:
            gradient = QLinearGradient(0, 0, fill.width(), 0)
        start = QColor(self._color)
        start.setAlpha(150)
        gradient.setColorAt(0.0, start)
        gradient.setColorAt(1.0, self._color)
        painter.setBrush(gradient)
        painter.drawRoundedRect(fill, 3, 3)


class StageTrack(QWidget):
    """Live analysis progress built from the four real engine stages.

    Indeterminate by design: the service reports stage boundaries, not a
    percentage, so this never shows a fabricated completion figure.
    """

    stageChanged = Signal(int)

    def __init__(self, titles: list[str], parent=None):
        super().__init__(parent)
        self.titles = titles
        self._states = ["idle"] * len(titles)
        self._pulse = 0.0
        self.setMinimumHeight(54)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        from PySide6.QtCore import QPropertyAnimation

        self._pulse_anim = QPropertyAnimation(self, b"pulse", self)
        self._pulse_anim.setDuration(1400)
        self._pulse_anim.setStartValue(0.0)
        self._pulse_anim.setEndValue(1.0)
        self._pulse_anim.setLoopCount(-1)
        self._pulse_anim.setEasingCurve(QEasingCurve.Type.InOutSine)

    def get_pulse(self) -> float:
        return self._pulse

    def set_pulse(self, value: float) -> None:
        self._pulse = float(value)
        self.update()

    pulse = Property(float, get_pulse, set_pulse)

    def reset_states(self) -> None:
        self._states = ["idle"] * len(self.titles)
        self._pulse_anim.stop()
        self.update()

    def set_states(self, states: list[str]) -> None:
        self._states = (list(states) + ["idle"] * len(self.titles))[: len(self.titles)]
        running = "running" in self._states
        if running and self._pulse_anim.state() != QPropertyAnimation.State.Running:
            self._pulse_anim.start()
        elif not running:
            self._pulse_anim.stop()
        self.update()

    def state_of(self, index: int) -> str:
        if 0 <= index < len(self._states):
            return self._states[index]
        return "idle"

    def paintEvent(self, event) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        count = max(1, len(self.titles))
        gap = 10.0
        usable = self.width() - gap * (count - 1)
        cell = usable / count
        height = self.height()

        font = QFont(self.font())
        font.setPointSizeF(max(8.0, font.pointSizeF() - 1.0))
        painter.setFont(font)

        for index, title in enumerate(self.titles):
            x = index * (cell + gap)
            state = self._states[index]
            if state == "complete":
                bar = QColor(TOKENS["ok"])
            elif state == "running":
                bar = QColor(TOKENS["accent"])
            elif state == "failed":
                bar = QColor(TOKENS["danger"])
            else:
                bar = QColor(TOKENS["surface_3"])

            track = QRectF(x, height - 6, cell, 3)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor(TOKENS["surface_3"]))
            painter.drawRoundedRect(track, 1.5, 1.5)

            if state == "running":
                sweep = max(0.22, 0.55)
                travel = (self._pulse * (1.0 + sweep)) - sweep
                left = max(0.0, min(1.0 - sweep, travel))
                fill = QRectF(
                    track.x() + track.width() * left, track.y(),
                    track.width() * sweep, track.height(),
                )
                painter.setBrush(bar)
                painter.drawRoundedRect(fill, 1.5, 1.5)
            elif state != "idle":
                painter.setBrush(bar)
                painter.drawRoundedRect(track, 1.5, 1.5)

            text_color = QColor(
                TOKENS["text"] if state == "running" else TOKENS["text_mute"]
            )
            if state == "complete":
                text_color = QColor(TOKENS["text_dim"])
            painter.setPen(QPen(text_color))
            label_rect = QRectF(x, 0, cell, height - 10)
            painter.drawText(
                label_rect,
                int(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter),
                f"{index + 1:02d}  {title}",
            )


class EmptyState(QWidget):
    """Honest placeholder: says what will appear here and why it is empty."""

    def __init__(self, title: str, body: str = "", parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 22, 4, 22)
        layout.setSpacing(6)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._mark = QLabel("-")
        self._mark.setObjectName("emptyMark")
        self._mark.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.title = QLabel(title)
        self.title.setObjectName("emptyTitle")
        self.title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.body = QLabel(body)
        self.body.setObjectName("emptyBody")
        self.body.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.body.setWordWrap(True)
        self.body.setVisible(bool(body))
        layout.addWidget(self._mark)
        layout.addWidget(self.title)
        layout.addWidget(self.body)

    def set_text(self, title: str, body: str = "") -> None:
        self.title.setText(title)
        self.body.setText(body)
        self.body.setVisible(bool(body))


class SectionHeader(QWidget):
    """Section title with an optional right-aligned caption."""

    def __init__(self, title: str, caption: str = "", parent=None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        self.title = QLabel(title)
        self.title.setObjectName("sectionTitle")
        self.caption = QLabel(caption)
        self.caption.setObjectName("sectionCaption")
        layout.addWidget(self.title)
        layout.addStretch(1)
        layout.addWidget(self.caption)

    def set_caption(self, text: str) -> None:
        self.caption.setText(text)
        self.caption.setVisible(bool(text))


class PrimaryButton(QPushButton):
    """Accent action painted directly.

    QSS `#primary` backgrounds proved unreliable under Fusion + display
    scaling (the fill silently dropped to transparent), which left the most
    important control in the product looking like an empty box. Painting it
    here makes the primary action immune to style-engine differences.
    """

    def __init__(self, text: str = "", parent=None):
        super().__init__(text, parent)
        self.setObjectName("primary")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self._pressed = False
        self.setMinimumHeight(44)
        self.setMinimumWidth(188)

    def enterEvent(self, event) -> None:  # noqa: N802
        self.update()
        super().enterEvent(event)

    def leaveEvent(self, event) -> None:  # noqa: N802
        self.update()
        super().leaveEvent(event)

    def paintEvent(self, event) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        r = QRectF(self.rect()).adjusted(0.5, 0.5, -0.5, -0.5)

        enabled = self.isEnabled()
        hovered = self.underMouse() and enabled
        if not enabled:
            fill, ink, edge = QColor("#10252a"), QColor("#4f8079"), QColor("#1b3a3d")
        elif self.isDown():
            fill, ink, edge = QColor("#46c6b7"), QColor("#04110f"), QColor("#46c6b7")
        elif hovered:
            fill, ink, edge = QColor("#74f0e1"), QColor("#04110f"), QColor("#74f0e1")
        else:
            fill, ink, edge = QColor("#5ee0d0"), QColor("#04110f"), QColor("#5ee0d0")

        painter.setPen(QPen(edge, 1))
        painter.setBrush(fill)
        painter.drawRoundedRect(r, 9, 9)

        font = QFont(self.font())
        font.setPointSizeF(max(self.font().pointSizeF(), 10.0))
        font.setWeight(QFont.Weight.Bold)
        painter.setFont(font)
        painter.setPen(QPen(ink))
        painter.drawText(
            self.rect(), int(Qt.AlignmentFlag.AlignCenter), self.text()
        )
        if self.hasFocus():
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.setPen(QPen(QColor("#dffbf6"), 2))
            painter.drawRoundedRect(r.adjusted(2, 2, -2, -2), 8, 8)


class IconRailButton(QPushButton):
    """Navigation entry: glyph over label, selected state painted by qss."""

    def __init__(self, glyph: str, label: str, parent=None, icon=None):
        super().__init__(parent)
        self.setObjectName("railButton")
        self.setCheckable(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setMinimumHeight(46)
        # With an icon the glyph is drawn by the icon, not as text.
        self.glyph = "" if icon is not None else glyph
        if icon is not None:
            self.setIcon(icon)
            self.setIconSize(QSize(18, 18))
        self.text_label = label
        self._sync_text()

    def _sync_text(self) -> None:
        # Escape the ampersand: Qt treats "&X" in button text as a mnemonic
        # and silently swallows both characters ("YARA & PE" -> "YARA_PE").
        label = self.text_label.replace("&", "&&")
        self.setText(f"{self.glyph}   {label}" if self.glyph else f"  {label}")

    def set_label(self, label: str) -> None:
        self.text_label = label
        self._sync_text()


class VerdictBadge(QWidget):
    """Painted verdict token - state comes only from the engine result."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._label = "-"
        self._detail = ""
        self._color = QColor(TOKENS["text_mute"])
        self.setMinimumHeight(84)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)

    def set_verdict(self, label: str, detail: str, color: str) -> None:
        self._label = label
        self._detail = detail
        self._color = QColor(color)
        self._resize_for_text()
        self.update()

    def _fonts(self):
        # A stylesheet font-size in px leaves pointSizeF() at -1; derive a real
        # base size so the verdict is never drawn in a 3pt face.
        base = self.font().pointSizeF()
        if base <= 0:
            pixels = self.font().pixelSize()
            base = pixels * 0.75 if pixels > 0 else 9.75
        title = QFont(self.font())
        title.setPointSizeF(base + 9.0)
        title.setWeight(QFont.Weight.Bold)
        body = QFont(self.font())
        body.setPointSizeF(max(9.0, base + 0.5))
        return title, body

    def _resize_for_text(self) -> None:
        title, body = self._fonts()
        width = max(240, self.width() - 32)
        title_h = QFontMetrics(title).boundingRect(
            0, 0, width, 4000, int(Qt.TextFlag.TextWordWrap), self._label
        ).height()
        body_h = QFontMetrics(body).boundingRect(
            0, 0, width, 4000, int(Qt.TextFlag.TextWordWrap), self._detail
        ).height()
        self.setMinimumHeight(max(84, title_h + body_h + 44))

    def resizeEvent(self, event) -> None:  # noqa: N802
        super().resizeEvent(event)
        self._resize_for_text()

    def paintEvent(self, event) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        r = QRectF(0, 0, self.width(), self.height())

        wash = QColor(self._color)
        wash.setAlpha(20)
        path = QPainterPath()
        path.addRoundedRect(r, 12, 12)
        painter.fillPath(path, wash)
        painter.setPen(QPen(QColor(self._color).darker(180), 1))
        painter.drawPath(path)

        rtl = self.isRightToLeft()
        painter.setLayoutDirection(self.layoutDirection())
        accent_x = r.right() - 3 if rtl else r.x()
        accent = QRectF(accent_x, r.y() + 14, 3, r.height() - 28)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(self._color)
        painter.drawRoundedRect(accent, 1.5, 1.5)

        # Text starts at the reading edge: left in LTR, right in RTL.
        side = Qt.AlignmentFlag.AlignRight if rtl else Qt.AlignmentFlag.AlignLeft
        flags = int(side | Qt.AlignmentFlag.AlignTop | Qt.TextFlag.TextWordWrap)
        title, body = self._fonts()
        painter.setFont(title)
        painter.setPen(QPen(QColor(TOKENS["text"])))
        text_w = r.width() - 40
        painter.drawText(QRectF(20, 12, text_w, 60), flags, self._label)

        title_h = QFontMetrics(title).boundingRect(
            0, 0, int(text_w), 4000, int(Qt.TextFlag.TextWordWrap), self._label
        ).height()
        painter.setFont(body)
        painter.setPen(QPen(QColor(TOKENS["text_dim"])))
        painter.drawText(
            QRectF(20, 12 + title_h + 6, text_w, r.height() - title_h - 30),
            flags,
            self._detail,
        )


# --------------------------------------------------------------------------
# Results screen parts
# --------------------------------------------------------------------------

TONE_COLORS = {
    "danger": TOKENS["danger"],
    "warn": TOKENS["warn"],
    "ok": TOKENS["ok"],
    "info": TOKENS["info"],
    "neutral": TOKENS["text_mute"],
    "accent": TOKENS["accent"],
}


def tone_color(tone: str) -> str:
    return TONE_COLORS.get(tone, TOKENS["text_mute"])


class CollapsibleSection(QWidget):
    """Section whose body is hidden until the header is activated.

    Rarely needed detail lives here instead of being removed. The header is a
    real button, so it is reachable and operable from the keyboard.
    """

    toggled = Signal(bool)

    def __init__(self, title: str = "", parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        self.header = QPushButton()
        self.header.setObjectName("sectionToggle")
        self.header.setCheckable(True)
        self.header.setCursor(Qt.CursorShape.PointingHandCursor)
        self.header.toggled.connect(self._on_toggled)
        layout.addWidget(self.header)
        self.body = QWidget()
        self.body_layout = QVBoxLayout(self.body)
        self.body_layout.setContentsMargins(2, 0, 2, 2)
        self.body_layout.setSpacing(10)
        self.body.setVisible(False)
        layout.addWidget(self.body)
        self._title = title
        self._sync_header()

    def set_title(self, title: str) -> None:
        self._title = title
        self._sync_header()

    def is_expanded(self) -> bool:
        return self.header.isChecked()

    def set_expanded(self, expanded: bool) -> None:
        self.header.setChecked(expanded)

    def _on_toggled(self, expanded: bool) -> None:
        self.body.setVisible(expanded)
        self._sync_header()
        self.toggled.emit(expanded)

    def _sync_header(self) -> None:
        if self.header.isChecked():
            arrow = "▾"
        else:
            arrow = "◂" if self.isRightToLeft() else "▸"
        self.header.setText(f"{arrow}  {self._title}".replace("&", "&&"))
        self.header.setAccessibleName(self._title)

    def changeEvent(self, event) -> None:  # noqa: N802
        super().changeEvent(event)
        from PySide6.QtCore import QEvent

        if event.type() == QEvent.Type.LayoutDirectionChange:
            self._sync_header()


class StatTile(QFrame):
    """One real number from the scan with a short caption."""

    def __init__(self, caption: str = "", parent=None):
        super().__init__(parent)
        self.setObjectName("metric")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(2)
        self.caption = QLabel(caption)
        self.caption.setObjectName("muted")
        self.caption.setWordWrap(True)
        self.value = QLabel("-")
        self.value.setObjectName("metricValue")
        self.note = QLabel("")
        self.note.setObjectName("subtle")
        self.note.setWordWrap(True)
        self.note.setVisible(False)
        layout.addWidget(self.caption)
        layout.addWidget(self.value)
        layout.addWidget(self.note)

    def set_value(self, value: str, note: str = "", color: str | None = None) -> None:
        self.value.setText(value)
        self.value.setStyleSheet(f"color:{color};" if color else "")
        self.note.setText(note)
        self.note.setVisible(bool(note))


class FindingCard(QFrame):
    """One finding: severity (symbol + word + colour), title, explanation.

    Title and explanation are the engine's own text and are shown unchanged.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("findingCard")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 11, 14, 12)
        layout.setSpacing(5)
        top = QHBoxLayout()
        top.setSpacing(8)
        self.severity = Chip("", "neutral")
        self.category = QLabel("")
        self.category.setObjectName("subtle")
        self.contribution = QLabel("")
        self.contribution.setObjectName("subtle")
        top.addWidget(self.severity)
        top.addWidget(self.category)
        top.addStretch(1)
        top.addWidget(self.contribution)
        layout.addLayout(top)
        self.title = QLabel("")
        self.title.setObjectName("cardTitle")
        self.title.setWordWrap(True)
        self.title.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.explanation = QLabel("")
        self.explanation.setObjectName("muted")
        self.explanation.setWordWrap(True)
        self.explanation.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(self.title)
        layout.addWidget(self.explanation)

    def set_finding(
        self,
        severity_text: str,
        tone: str,
        category: str,
        title: str,
        explanation: str,
        contribution: str,
    ) -> None:
        self.severity.setText(severity_text)
        self.severity.set_tone(tone)
        self.category.setText(category)
        self.title.setText(title)
        self.explanation.setText(explanation)
        self.explanation.setVisible(bool(explanation) and explanation != title)
        self.contribution.setText(contribution)
        self.setAccessibleName(f"{severity_text}: {title}")


class CategoryBars(QWidget):
    """Horizontal bars: number of findings per category (real counts only)."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._grid = QVBoxLayout(self)
        self._grid.setContentsMargins(0, 0, 0, 0)
        self._grid.setSpacing(9)
        self.rows: list[tuple[QLabel, MeterBar, QLabel]] = []

    def set_rows(self, rows: list[tuple[str, int, str]]) -> None:
        """rows: (label, count, colour). Bar length is count / largest count."""
        while self._grid.count():
            item = self._grid.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.setParent(None)
                widget.deleteLater()
        self.rows = []
        largest = max((count for _label, count, _color in rows), default=0)
        for label, count, color in rows:
            row = QWidget()
            row_layout = QHBoxLayout(row)
            row_layout.setContentsMargins(0, 0, 0, 0)
            row_layout.setSpacing(10)
            name = QLabel(label)
            name.setObjectName("muted")
            name.setMinimumWidth(150)
            bar = MeterBar(color)
            bar.setFixedHeight(10)
            bar.set_value(100.0 * count / largest if largest else 0.0, animate=False)
            value = QLabel(str(count))
            value.setObjectName("metaValueMono")
            value.setMinimumWidth(22)
            value.setAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignRight)
            row_layout.addWidget(name)
            row_layout.addWidget(bar, 1)
            row_layout.addWidget(value)
            self._grid.addWidget(row)
            self.rows.append((name, bar, value))
