"""Main-screen components: identity art, hero, scan modes, recent activity.

Presentation only. Nothing here runs a scan or decides a verdict: the art
reflects pipeline stage states reported by the real scan worker, and recent
activity lists records already saved in the local scan history.
"""
from __future__ import annotations

import ctypes
import math
import os
import sys
import time
from datetime import datetime
from functools import lru_cache
from typing import Any, Callable, Iterable, Mapping

from PySide6.QtCore import QPointF, QRectF, QSize, Qt, QTimer, Signal
from PySide6.QtGui import (
    QColor,
    QFont,
    QFontDatabase,
    QIcon,
    QPainter,
    QPainterPath,
    QPen,
    QPixmap,
    QRadialGradient,
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

from ui.design_system import TOKENS, tone_color

# --------------------------------------------------------------------------
# Icons: Segoe Fluent Icons when installed, plain symbols otherwise.
# --------------------------------------------------------------------------

ICON_FONT = "Segoe Fluent Icons"
ICONS = {
    "analysis": ("", "▸"),
    "history": ("", "◴"),
    "yara": ("", "▣"),
    "mitre": ("", "≣"),
    "model": ("", "◇"),
    "logs": ("", "≡"),
    "settings": ("", "⚙"),
    "about": ("", "ⓘ"),
    "file": ("", "▤"),
    "url": ("", "⧉"),
    "text": ("", "T"),
    "folder": ("", "▥"),
    "lock": ("", "◉"),
    "globe": ("", "◍"),
    "monitor": ("", "▦"),
    "engines": ("", "⚙"),
    "drop": ("", "↑"),
}


@lru_cache(maxsize=1)
def icon_font_available() -> bool:
    return ICON_FONT in QFontDatabase.families()


def glyph(name: str) -> str:
    fluent, fallback = ICONS.get(name, ("", "●"))
    return fluent if icon_font_available() and fluent else fallback


def glyph_pixmap(name: str, color: str, size: int = 18) -> QPixmap:
    ratio = 2.0
    pixmap = QPixmap(int(size * ratio), int(size * ratio))
    pixmap.setDevicePixelRatio(ratio)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setRenderHint(QPainter.RenderHint.TextAntialiasing)
    font = QFont(ICON_FONT if icon_font_available() else "Segoe UI Symbol")
    font.setPixelSize(int(size * 0.86))
    painter.setFont(font)
    painter.setPen(QColor(color))
    painter.drawText(QRectF(0, 0, size, size), int(Qt.AlignmentFlag.AlignCenter), glyph(name))
    painter.end()
    return pixmap


def glyph_icon(name: str, color: str = TOKENS["text_dim"], active: str = TOKENS["accent"], size: int = 18) -> QIcon:
    icon = QIcon()
    icon.addPixmap(glyph_pixmap(name, color, size), QIcon.Mode.Normal, QIcon.State.Off)
    icon.addPixmap(glyph_pixmap(name, active, size), QIcon.Mode.Normal, QIcon.State.On)
    icon.addPixmap(glyph_pixmap(name, TOKENS["text_mute"], size), QIcon.Mode.Disabled, QIcon.State.Off)
    return icon


# --------------------------------------------------------------------------
# Motion preference
# --------------------------------------------------------------------------


def prefers_reduced_motion() -> bool:
    """True when the user asked for less motion.

    Honors CYBERSCAN_REDUCE_MOTION=1 and, on Windows, the system setting
    "Show animations in Windows" (SPI_GETCLIENTAREAANIMATION).
    """
    override = os.environ.get("CYBERSCAN_REDUCE_MOTION", "").strip().lower()
    if override in {"1", "true", "yes"}:
        return True
    if override in {"0", "false", "no"}:
        return False
    if sys.platform == "win32":
        try:
            enabled = ctypes.c_bool(True)
            ok = ctypes.windll.user32.SystemParametersInfoW(0x1042, 0, ctypes.byref(enabled), 0)
            return bool(ok) and not enabled.value
        except (AttributeError, OSError):
            return False
    return False


# --------------------------------------------------------------------------
# ScanCore: the identity element
# --------------------------------------------------------------------------


class ScanCore(QWidget):
    """Hexagonal core inside a ring of four arcs, one per real pipeline stage.

    States: ``idle``, ``scanning``, ``complete``, ``failed``. Stage arcs show
    only what the worker reported: waiting, running (an indeterminate glint,
    never a percentage), complete or failed. Motion is slow, stops while the
    widget is hidden, and is disabled entirely under reduced motion.
    """

    STAGES = 4
    IDLE_INTERVAL = 66
    ACTIVE_INTERVAL = 33

    def __init__(self, parent=None, *, reduced_motion: bool | None = None):
        super().__init__(parent)
        self.setMinimumSize(196, 196)
        self.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        self.setFixedSize(300, 300)
        self.reduced_motion = prefers_reduced_motion() if reduced_motion is None else reduced_motion
        self.state = "idle"
        self.stage_states = ["waiting"] * self.STAGES
        self.result_color = QColor(TOKENS["accent"])
        self._phase = 0.0
        self._last_tick = time.monotonic()
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self.setAccessibleName("Analysis status")
        self._describe()

    # -- state ------------------------------------------------------------
    def set_idle(self) -> None:
        self.state = "idle"
        self.stage_states = ["waiting"] * self.STAGES
        self.result_color = QColor(TOKENS["accent"])
        self._refresh()

    def begin(self) -> None:
        self.state = "scanning"
        self.stage_states = ["waiting"] * self.STAGES
        self.result_color = QColor(TOKENS["accent"])
        self._refresh()

    def set_stage_states(self, states: Iterable[str]) -> None:
        values = list(states)[: self.STAGES]
        values += ["waiting"] * (self.STAGES - len(values))
        self.stage_states = [s if s in {"waiting", "running", "complete", "failed"} else "waiting" for s in values]
        self._refresh()

    def finish(self, color: str) -> None:
        self.state = "complete"
        self.stage_states = ["complete"] * self.STAGES
        self.result_color = QColor(color)
        self._refresh()

    def fail(self) -> None:
        self.state = "failed"
        self.stage_states = [
            "failed" if s == "running" else s for s in self.stage_states
        ]
        if "failed" not in self.stage_states:
            first_open = next((i for i, s in enumerate(self.stage_states) if s != "complete"), 0)
            self.stage_states[first_open] = "failed"
        self.result_color = QColor(TOKENS["danger"])
        self._refresh()

    def _describe(self) -> None:
        done = self.stage_states.count("complete")
        self.setAccessibleDescription(f"{self.state}; {done} of {self.STAGES} stages complete")

    # -- animation --------------------------------------------------------
    @property
    def animating(self) -> bool:
        return self._timer.isActive()

    def _refresh(self) -> None:
        self._describe()
        self._sync_timer()
        self.update()

    def _sync_timer(self) -> None:
        should_run = self.isVisible() and not self.reduced_motion
        if not should_run:
            self._timer.stop()
            return
        interval = self.ACTIVE_INTERVAL if self.state == "scanning" else self.IDLE_INTERVAL
        if not self._timer.isActive() or self._timer.interval() != interval:
            self._last_tick = time.monotonic()
            self._timer.start(interval)

    def _tick(self) -> None:
        now = time.monotonic()
        self._phase += min(0.25, now - self._last_tick)
        self._last_tick = now
        self.update()

    def showEvent(self, event) -> None:  # noqa: N802
        super().showEvent(event)
        self._sync_timer()

    def hideEvent(self, event) -> None:  # noqa: N802
        self._timer.stop()
        super().hideEvent(event)

    def stop(self) -> None:
        self._timer.stop()

    # -- painting ---------------------------------------------------------
    def paintEvent(self, event) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        side = min(self.width(), self.height())
        center = QPointF(self.width() / 2, self.height() / 2)
        radius = side / 2 - 6
        phase = 0.0 if self.reduced_motion else self._phase
        accent = QColor(TOKENS["accent"])
        tint = self.result_color if self.state in {"complete", "failed"} else accent

        # Ambient depth: one soft glow, no flat black disc.
        glow = QRadialGradient(center, radius)
        inner = QColor(tint)
        inner.setAlpha(46 if self.state != "idle" else 30)
        glow.setColorAt(0.0, inner)
        glow.setColorAt(0.65, QColor(tint.red(), tint.green(), tint.blue(), 10))
        glow.setColorAt(1.0, QColor(0, 0, 0, 0))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(glow)
        painter.drawEllipse(center, radius, radius)

        # Outer instrument ring: fine ticks, turning very slowly.
        painter.save()
        painter.translate(center)
        painter.rotate(phase * 3.0)
        for index in range(96):
            major = index % 8 == 0
            length = 7 if major else 3
            color = QColor(TOKENS["line_strong"] if major else TOKENS["line"])
            painter.setPen(QPen(color, 1.2 if major else 1.0))
            painter.drawLine(QPointF(0, -radius), QPointF(0, -radius + length))
            painter.rotate(360 / 96)
        painter.restore()

        # Stage ring: four arcs, one per pipeline stage, clockwise from the top.
        ring = radius * 0.8
        rect = QRectF(center.x() - ring, center.y() - ring, ring * 2, ring * 2)
        span, gap = 80.0, 10.0
        for index, stage in enumerate(self.stage_states):
            start = 90 - gap / 2 - index * (span + gap)
            base = QPen(QColor(TOKENS["line"]), 6, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap)
            painter.setPen(base)
            painter.drawArc(rect, int(start * 16), int(-span * 16))
            if stage == "complete" or (self.state == "complete"):
                # A stage that finished keeps the accent even when a later
                # stage fails; the verdict colour applies only to a full run.
                done = tint if self.state == "complete" else accent
                painter.setPen(QPen(done, 6, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
                painter.drawArc(rect, int(start * 16), int(-span * 16))
            elif stage == "failed":
                painter.setPen(QPen(QColor(TOKENS["danger"]), 6, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
                painter.drawArc(rect, int(start * 16), int(-span * 16))
            elif stage == "running":
                dim = QColor(accent)
                dim.setAlpha(70)
                painter.setPen(QPen(dim, 6, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
                painter.drawArc(rect, int(start * 16), int(-span * 16))
                glint = 24.0
                offset = (phase * 70.0) % (span - glint) if not self.reduced_motion else (span - glint) / 2
                painter.setPen(QPen(accent, 6, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
                painter.drawArc(rect, int((start - offset) * 16), int(-glint * 16))

        # Hexagonal core: two lattices joined by spokes.
        outer_hex = self._hexagon(center, radius * 0.52, 0)
        inner_hex = self._hexagon(center, radius * 0.31, 30)
        line_color = QColor(tint)
        line_color.setAlpha(150)
        faint = QColor(tint)
        faint.setAlpha(70)
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.setPen(QPen(line_color, 1.4))
        painter.drawPolygon(outer_hex)
        painter.setPen(QPen(faint, 1.0))
        painter.drawPolygon(inner_hex)
        for a, b in zip(outer_hex, inner_hex):
            painter.drawLine(a, b)
            painter.drawLine(b, center)

        nodes = list(outer_hex) + list(inner_hex)
        lit = int(phase * 4) % len(nodes) if self.state == "scanning" and not self.reduced_motion else -1
        for index, node in enumerate(nodes):
            color = QColor(tint)
            color.setAlpha(255 if index == lit else 170 if index < 6 else 110)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(color)
            size = 3.6 if index == lit else 2.4
            painter.drawEllipse(node, size, size)

        # Nucleus: breathes very slowly while idle.
        breathe = 0.5 + 0.5 * math.sin(phase * (2 * math.pi / 6.0))
        core_r = radius * (0.12 + 0.012 * breathe)
        core = QRadialGradient(center, core_r * 1.8)
        bright = QColor(tint)
        bright.setAlpha(235)
        core.setColorAt(0.0, bright)
        core.setColorAt(0.55, QColor(tint.red(), tint.green(), tint.blue(), 120))
        core.setColorAt(1.0, QColor(tint.red(), tint.green(), tint.blue(), 0))
        painter.setBrush(core)
        painter.drawEllipse(center, core_r * 1.8, core_r * 1.8)
        painter.setBrush(QColor(TOKENS["bg"]))
        painter.drawEllipse(center, core_r * 0.42, core_r * 0.42)

    @staticmethod
    def _hexagon(center: QPointF, radius: float, rotation: float) -> list[QPointF]:
        points = []
        for index in range(6):
            angle = math.radians(rotation - 90 + index * 60)
            points.append(QPointF(center.x() + radius * math.cos(angle), center.y() + radius * math.sin(angle)))
        return points


# --------------------------------------------------------------------------
# Hero surface
# --------------------------------------------------------------------------


class HeroPanel(QFrame):
    """Deep surface with a soft light and a fading dot grid behind the art."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("hero")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, False)

    def paintEvent(self, event) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        rect = QRectF(self.rect()).adjusted(0.5, 0.5, -0.5, -0.5)
        path = QPainterPath()
        path.addRoundedRect(rect, 16, 16)
        painter.fillPath(path, QColor(TOKENS["surface"]))
        painter.setClipPath(path)

        art_x = rect.left() + 150 if self.isRightToLeft() else rect.right() - 150
        light = QRadialGradient(QPointF(art_x, rect.center().y()), rect.height() * 1.05)
        light.setColorAt(0.0, QColor(94, 224, 208, 34))
        light.setColorAt(0.5, QColor(94, 224, 208, 8))
        light.setColorAt(1.0, QColor(0, 0, 0, 0))
        painter.fillRect(rect, light)

        step = 22
        painter.setPen(Qt.PenStyle.NoPen)
        y = rect.top() + 14
        while y < rect.bottom():
            x = rect.left() + 14
            while x < rect.right():
                distance = abs(x - art_x) / max(1.0, rect.width())
                alpha = int(max(0.0, 1.0 - distance * 1.6) * 34)
                if alpha > 2:
                    painter.setBrush(QColor(155, 172, 191, alpha))
                    painter.drawEllipse(QPointF(x, y), 0.9, 0.9)
                x += step
            y += step

        painter.setClipping(False)
        painter.setPen(QPen(QColor(TOKENS["line"]), 1))
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawPath(path)


class FactRow(QWidget):
    """Icon + one line of verifiable application state."""

    def __init__(self, icon: str, parent=None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(9)
        self.icon_name = icon
        self.icon = QLabel()
        self.icon.setFixedSize(18, 18)
        self.text = QLabel("")
        self.text.setObjectName("heroFact")
        self.text.setWordWrap(True)
        layout.addWidget(self.icon, 0, Qt.AlignmentFlag.AlignTop)
        layout.addWidget(self.text, 1)
        self.set_text("", "neutral")

    def set_text(self, text: str, tone: str = "neutral") -> None:
        color = TOKENS["accent"] if tone == "accent" else tone_color(tone) if tone != "neutral" else TOKENS["text_dim"]
        self.icon.setPixmap(glyph_pixmap(self.icon_name, color, 16))
        self.text.setText(text)


# --------------------------------------------------------------------------
# Scan mode selector
# --------------------------------------------------------------------------


class ModeSegment(QWidget):
    """The three real target types as one segmented control."""

    modeSelected = Signal(str)

    ICON_FOR = {"File": "file", "URL": "url", "Indicator / text": "text"}

    def __init__(self, modes: Iterable[str], parent=None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)
        self.buttons: dict[str, QPushButton] = {}
        for mode in modes:
            button = QPushButton(mode)
            button.setObjectName("modeChip")
            button.setCheckable(True)
            button.setAutoExclusive(True)
            button.setCursor(Qt.CursorShape.PointingHandCursor)
            button.setIcon(glyph_icon(self.ICON_FOR.get(mode, "file"), size=16))
            button.setIconSize(QSize(16, 16))
            button.clicked.connect(lambda _checked=False, value=mode: self.modeSelected.emit(value))
            layout.addWidget(button)
            self.buttons[mode] = button
        layout.addStretch(1)

    def set_mode(self, mode: str) -> None:
        for value, button in self.buttons.items():
            button.setChecked(value == mode)
            button.setProperty("selected", value == mode)
            button.style().unpolish(button)
            button.style().polish(button)

    def set_labels(self, translate: Callable[[str], str]) -> None:
        for value, button in self.buttons.items():
            button.setText(translate(value))

    def setEnabled(self, enabled: bool) -> None:  # noqa: N802
        super().setEnabled(enabled)
        for button in self.buttons.values():
            button.setEnabled(enabled)


# --------------------------------------------------------------------------
# Recent activity
# --------------------------------------------------------------------------

VERDICT_FOR_CLASSIFICATION = {
    "SUSPICIOUS": ("▲", "High risk", "danger"),
    "REVIEW": ("◆", "Needs review", "warn"),
    "NO_INDICATORS_OBSERVED": ("●", "Low risk", "ok"),
}
UNKNOWN_VERDICT = ("?", "Unknown", "neutral")


def verdict_for(classification: Any) -> tuple[str, str, str]:
    return VERDICT_FOR_CLASSIFICATION.get(str(classification or ""), UNKNOWN_VERDICT)


def parse_timestamp(value: Any) -> datetime | None:
    try:
        return datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None


class VerdictMix(QWidget):
    """One stacked bar of saved verdicts; segment widths are real counts."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(10)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.segments: list[tuple[int, str]] = []

    def set_segments(self, segments: list[tuple[int, str]]) -> None:
        self.segments = [(count, color) for count, color in segments if count > 0]
        self.update()

    def paintEvent(self, event) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        rect = QRectF(self.rect())
        path = QPainterPath()
        path.addRoundedRect(rect, 5, 5)
        painter.fillPath(path, QColor(TOKENS["surface_3"]))
        total = sum(count for count, _color in self.segments)
        if not total:
            return
        painter.setClipPath(path)
        x = rect.right() if self.isRightToLeft() else rect.left()
        for count, color in self.segments:
            width = rect.width() * count / total
            left = x - width if self.isRightToLeft() else x
            painter.fillRect(QRectF(left, rect.top(), width - 1.5, rect.height()), QColor(color))
            x = left if self.isRightToLeft() else x + width


class ElidedLabel(QLabel):
    """Single-line label that shortens its text with an ellipsis to fit.

    It never forces its parent wider than the space available; the full text
    stays in ``text()`` and the tooltip.
    """

    def minimumSizeHint(self):  # noqa: N802
        hint = super().minimumSizeHint()
        return QSize(24, hint.height())

    def setText(self, text: str) -> None:  # noqa: N802
        super().setText(text)
        self.setToolTip(text)

    def paintEvent(self, event) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setFont(self.font())
        painter.setPen(self.palette().color(self.foregroundRole()))
        rect = self.contentsRect()
        shown = self.fontMetrics().elidedText(self.text(), Qt.TextElideMode.ElideMiddle, rect.width())
        painter.drawText(rect, int(self.alignment()), shown)


class ActivityRow(QPushButton):
    """A saved scan: verdict, name, type and time, score. Opens the record."""

    def __init__(self, record_id: str, parent=None):
        super().__init__(parent)
        self.record_id = record_id
        self.setObjectName("activityRow")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setMinimumHeight(58)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 8, 14, 8)
        layout.setSpacing(12)
        self.verdict = QLabel("")
        self.verdict.setObjectName("chip")
        self.verdict.setMinimumWidth(118)
        self.verdict.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)
        self.verdict.setAlignment(Qt.AlignmentFlag.AlignCenter)
        copy = QVBoxLayout()
        copy.setSpacing(1)
        self.name = ElidedLabel("")
        self.name.setObjectName("activityName")
        self.meta = ElidedLabel("")
        self.meta.setObjectName("subtle")
        copy.addWidget(self.name)
        copy.addWidget(self.meta)
        self.score = QLabel("")
        self.score.setObjectName("activityScore")
        self.score.setAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignRight)
        for label in (self.verdict, self.name, self.meta, self.score):
            label.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        layout.addWidget(self.verdict, 0, Qt.AlignmentFlag.AlignVCenter)
        layout.addLayout(copy, 1)
        layout.addWidget(self.score, 0, Qt.AlignmentFlag.AlignVCenter)


class RecentActivity(QFrame):
    """Latest saved scans plus the verdict mix, or a designed empty state."""

    recordActivated = Signal(str)
    viewAllRequested = Signal()
    MAX_ROWS = 3

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("activityPanel")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 16, 20, 18)
        layout.setSpacing(12)
        header = QHBoxLayout()
        header.setSpacing(10)
        titles = QVBoxLayout()
        titles.setSpacing(2)
        self.title = QLabel("")
        self.title.setObjectName("sectionTitle")
        self.caption = QLabel("")
        self.caption.setObjectName("sectionCaption")
        self.caption.setWordWrap(True)
        titles.addWidget(self.title)
        titles.addWidget(self.caption)
        header.addLayout(titles, 1)
        self.view_all = QPushButton("")
        self.view_all.setObjectName("quiet")
        self.view_all.setCursor(Qt.CursorShape.PointingHandCursor)
        self.view_all.clicked.connect(self.viewAllRequested.emit)
        header.addWidget(self.view_all, 0, Qt.AlignmentFlag.AlignTop)
        layout.addLayout(header)

        self.mix_row = QWidget()
        mix_layout = QVBoxLayout(self.mix_row)
        mix_layout.setContentsMargins(0, 0, 0, 0)
        mix_layout.setSpacing(7)
        self.mix = VerdictMix()
        self.legend = QLabel("")
        self.legend.setObjectName("subtle")
        self.legend.setWordWrap(True)
        mix_layout.addWidget(self.mix)
        mix_layout.addWidget(self.legend)
        layout.addWidget(self.mix_row)

        self.rows_layout = QVBoxLayout()
        self.rows_layout.setSpacing(6)
        layout.addLayout(self.rows_layout)
        self.rows: list[ActivityRow] = []

        self.empty = QWidget()
        empty_layout = QHBoxLayout(self.empty)
        empty_layout.setContentsMargins(4, 10, 4, 8)
        empty_layout.setSpacing(16)
        self.empty_icon = QLabel()
        self.empty_icon.setPixmap(glyph_pixmap("history", TOKENS["accent_dim"], 34))
        self.empty_icon.setFixedSize(40, 40)
        empty_copy = QVBoxLayout()
        empty_copy.setSpacing(3)
        self.empty_title = QLabel("")
        self.empty_title.setObjectName("emptyTitle")
        self.empty_body = QLabel("")
        self.empty_body.setObjectName("emptyBody")
        self.empty_body.setWordWrap(True)
        empty_copy.addWidget(self.empty_title)
        empty_copy.addWidget(self.empty_body)
        empty_layout.addWidget(self.empty_icon, 0, Qt.AlignmentFlag.AlignTop)
        empty_layout.addLayout(empty_copy, 1)
        layout.addWidget(self.empty)

    def set_records(
        self,
        records: list[Mapping[str, Any]],
        translate: Callable[[str], str],
        name_for: Callable[[str], str],
        when: Callable[[datetime | None, str], str],
    ) -> None:
        tr = translate
        self.title.setText(tr("Recent activity"))
        self.view_all.setText(tr("Open scan history"))
        while self.rows_layout.count():
            item = self.rows_layout.takeAt(0)
            if item.widget() is not None:
                item.widget().setParent(None)
                item.widget().deleteLater()
        self.rows = []

        has_records = bool(records)
        self.empty.setVisible(not has_records)
        self.mix_row.setVisible(has_records)
        self.view_all.setVisible(has_records)
        if not has_records:
            self.caption.setText(tr("Saved on this device only"))
            self.empty_title.setText(tr("No scans yet"))
            self.empty_body.setText(
                tr("Results you run here are saved on this device and listed newest first.")
            )
            return

        self.caption.setText(
            tr("1 saved scan · on this device only")
            if len(records) == 1
            else tr("{count} saved scans · on this device only").format(count=len(records))
        )
        counts = {key: 0 for key in ("SUSPICIOUS", "REVIEW", "NO_INDICATORS_OBSERVED", "other")}
        for record in records:
            key = str(record.get("classification", ""))
            counts[key if key in counts else "other"] += 1
        segments = []
        legend = []
        for key in ("SUSPICIOUS", "REVIEW", "NO_INDICATORS_OBSERVED", "other"):
            symbol, label, tone = verdict_for(key) if key != "other" else UNKNOWN_VERDICT
            segments.append((counts[key], tone_color(tone)))
            if counts[key]:
                legend.append(f"{symbol} {tr(label)} {counts[key]}")
        self.mix.set_segments(segments)
        self.legend.setText("   ·   ".join(legend))

        for record in list(reversed(records))[: self.MAX_ROWS]:
            symbol, label, tone = verdict_for(record.get("classification"))
            row = ActivityRow(str(record.get("id", "")))
            row.verdict.setText(f"{symbol} {tr(label)}")
            row.verdict.setProperty("tone", tone)
            row.name.setText(name_for(str(record.get("target", ""))))
            # Names are raw paths/URLs (LTR text); keep them on the reading edge.
            edge = Qt.AlignmentFlag.AlignRight if self.isRightToLeft() else Qt.AlignmentFlag.AlignLeft
            for label in (row.name, row.meta):
                label.setAlignment(edge | Qt.AlignmentFlag.AlignAbsolute | Qt.AlignmentFlag.AlignVCenter)
            row.meta.setText(when(parse_timestamp(record.get("timestamp")), str(record.get("target", ""))))
            score = record.get("score")
            row.score.setText(f"{score}/100" if isinstance(score, (int, float)) and not isinstance(score, bool) else "")
            row.setAccessibleName(f"{tr(label)}: {row.name.text()}")
            row.clicked.connect(lambda _checked=False, rid=row.record_id: self.recordActivated.emit(rid))
            self.rows_layout.addWidget(row)
            self.rows.append(row)
