"""Finishing touches: the details people notice without being told.

Each one follows the motion rules in ``ui.motion``: it answers an event (a
click, a hover, a mode change, a result) and never loops while the app is
idle; reduced motion makes every one of them an immediate change.

* ``window_chrome``: on Windows 11 the title bar turns dark and takes the
  app's colours, the border follows the mode (teal for Scan, indigo for
  Repair), corners are rounded.
* ``fade_in_window``: the window arrives with a short fade instead of
  popping in.
* ``SegmentGlider``: the Scan | Repair switch has one pill that slides to
  the chosen side.
* ``CursorLight``: glass cards catch a soft light where the pointer is, and
  their top edge brightens under it.
* ``Ripples``: buttons answer a press with a ripple from the exact point.
* ``toast``: short confirmations ("Copied", "Saved") rise from the bottom
  and leave on their own.
* ``SuccessMark``: a check drawn in one stroke, with two rings, for a
  repaired copy.
"""
from __future__ import annotations

import ctypes
import sys

from PySide6.QtCore import QEasingCurve, QEvent, QObject, QPointF, QPropertyAnimation, QRect, QRectF, Qt, QTimer, QVariantAnimation
from PySide6.QtGui import QBrush, QColor, QLinearGradient, QPainter, QPainterPath, QPen, QRadialGradient
from PySide6.QtWidgets import QApplication, QLabel, QPushButton, QWidget

from ui.motion import EMPHASIS_MS, FEEDBACK_MS, VIEW_MS, prefers_reduced_motion
from ui.theme import MODE_ACCENTS, TOKENS

# -- window chrome (Windows 11) -----------------------------------------------------------

_DARK_MODE, _BORDER, _CAPTION, _TEXT, _CORNERS = 20, 34, 35, 36, 33


def _colorref(color: str) -> int:
    c = QColor(color)
    return c.red() | (c.green() << 8) | (c.blue() << 16)


def window_chrome(window: QWidget, mode: str = "scan") -> bool:
    """Dark, app-coloured title bar and a mode-coloured border. False where unsupported."""
    if sys.platform != "win32" or QApplication.platformName() in {"offscreen", "minimal"}:
        return False
    try:
        hwnd = int(window.winId())
        dwm = ctypes.windll.dwmapi
        for attribute, value in (
            (_DARK_MODE, 1),
            (_CORNERS, 2),  # rounded
            (_CAPTION, _colorref(TOKENS["bg"])),
            (_TEXT, _colorref(TOKENS["text"])),
            (_BORDER, _colorref(MODE_ACCENTS.get(mode, MODE_ACCENTS["scan"])["bottom"])),
        ):
            data = ctypes.c_int(value)
            dwm.DwmSetWindowAttribute(hwnd, attribute, ctypes.byref(data), ctypes.sizeof(data))
        return True
    except (AttributeError, OSError):
        return False


def fade_in_window(window: QWidget, duration: int = 320) -> None:
    if prefers_reduced_motion() or QApplication.platformName() == "offscreen":
        return
    window.setWindowOpacity(0.0)
    animation = QPropertyAnimation(window, b"windowOpacity", window)
    animation.setDuration(duration)
    animation.setStartValue(0.0)
    animation.setEndValue(1.0)
    animation.setEasingCurve(QEasingCurve.Type.OutCubic)
    animation.start(QPropertyAnimation.DeletionPolicy.DeleteWhenStopped)


# -- the sliding segment ------------------------------------------------------------------


class SegmentGlider(QWidget):
    """One pill under a row of checkable buttons, gliding to the checked one."""

    def __init__(self, bar: QWidget, buttons: list[QPushButton]):
        super().__init__(bar)
        self.bar, self.buttons = bar, buttons
        self.color = QColor(MODE_ACCENTS["scan"]["accent"])
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
        self._animation = QPropertyAnimation(self, b"geometry", self)
        self._animation.setDuration(VIEW_MS + 60)
        self._animation.setEasingCurve(QEasingCurve.Type.OutCubic)
        for button in buttons:
            button.toggled.connect(lambda checked: checked and self.glide())
        bar.installEventFilter(self)
        self.lower()
        QTimer.singleShot(0, self.snap)

    def set_color(self, color: str) -> None:
        self.color = QColor(color)
        self.update()

    def _target(self) -> QRect | None:
        checked = next((b for b in self.buttons if b.isChecked()), None)
        return checked.geometry() if checked is not None else None

    def snap(self) -> None:
        target = self._target()
        if target is not None:
            self._animation.stop()
            self.setGeometry(target)
            self.lower()
            self.show()

    def glide(self) -> None:
        target = self._target()
        if target is None:
            return
        if prefers_reduced_motion() or not self.isVisible() or self.width() == 0:
            self.snap()
            return
        self._animation.stop()
        self._animation.setStartValue(self.geometry())
        self._animation.setEndValue(target)
        self._animation.start()

    def eventFilter(self, watched, event) -> bool:  # noqa: N802
        if event.type() in (QEvent.Type.Resize, QEvent.Type.LayoutRequest, QEvent.Type.Show):
            QTimer.singleShot(0, self.snap)
        return False

    def paintEvent(self, event) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        rect = QRectF(self.rect()).adjusted(0.5, 0.5, -0.5, -0.5)
        fill = QColor(self.color)
        fill.setAlphaF(0.17)
        edge = QColor(self.color)
        edge.setAlphaF(0.5)
        painter.setPen(QPen(edge, 1))
        painter.setBrush(fill)
        painter.drawRoundedRect(rect, 7, 7)
        shine = QColor(255, 255, 255, 34)
        painter.setPen(QPen(shine, 1))
        painter.drawLine(QPointF(rect.left() + 8, rect.top() + 1), QPointF(rect.right() - 8, rect.top() + 1))


# -- light that follows the pointer on glass ------------------------------------------------


class _Light(QWidget):
    def __init__(self, card: QWidget):
        super().__init__(card)
        self.card = card
        self.point: QPointF | None = None
        self.strength = 0.0
        self.color = QColor(TOKENS["accent"])
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
        self.setAttribute(Qt.WidgetAttribute.WA_NoSystemBackground, True)
        self._fade = QVariantAnimation(self)
        self._fade.setDuration(FEEDBACK_MS * 2)
        self._fade.valueChanged.connect(self._set_strength)

    def _set_strength(self, value) -> None:
        self.strength = float(value)
        self.update()

    def fade_to(self, value: float) -> None:
        if prefers_reduced_motion():
            self._set_strength(value)
            return
        self._fade.stop()
        self._fade.setStartValue(self.strength)
        self._fade.setEndValue(value)
        self._fade.start()

    def paintEvent(self, event) -> None:  # noqa: N802
        if self.point is None or self.strength <= 0.01:
            return
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        clip = QPainterPath()
        clip.addRoundedRect(QRectF(self.rect()).adjusted(1, 1, -1, -1), 14, 14)
        painter.setClipPath(clip)
        radius = max(160.0, self.width() * 0.42)
        glow = QRadialGradient(self.point, radius)
        inner = QColor(self.color)
        inner.setAlphaF(0.10 * self.strength)
        outer = QColor(self.color)
        outer.setAlphaF(0.0)
        glow.setColorAt(0.0, inner)
        glow.setColorAt(1.0, outer)
        painter.fillRect(self.rect(), glow)
        # The rim nearest the pointer brightens.
        rim = QRadialGradient(self.point, radius * 0.9)
        bright = QColor(self.color)
        bright.setAlphaF(0.7 * self.strength)
        rim.setColorAt(0.0, bright)
        rim.setColorAt(1.0, outer)
        painter.setClipping(False)
        painter.setPen(QPen(rim, 1.2))
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawRoundedRect(QRectF(self.rect()).adjusted(0.6, 0.6, -0.6, -0.6), 14, 14)


LIT = {"card", "summaryCard"}  # the glass surfaces that catch the light


class CursorLight(QObject):
    """Give every glass card under ``root`` a light that follows the pointer."""

    def __init__(self, root: QWidget):
        super().__init__(root)
        self.root = root
        self.color = QColor(TOKENS["accent"])
        self.lights: dict[QWidget, _Light] = {}
        self.attach()

    def attach(self) -> None:
        for frame in [w for w in self.root.findChildren(QWidget) if w.objectName() in LIT]:
            if frame in self.lights:
                continue
            light = _Light(frame)
            light.color = self.color
            light.setGeometry(frame.rect())
            self.lights[frame] = light
            frame.setAttribute(Qt.WidgetAttribute.WA_Hover, True)
            frame.installEventFilter(self)
            frame.destroyed.connect(lambda _o=None, f=frame: self.lights.pop(f, None))

    def set_color(self, color: str) -> None:
        self.color = QColor(color)
        for light in self.lights.values():
            light.color = self.color
            light.update()

    def eventFilter(self, watched, event) -> bool:  # noqa: N802
        light = self.lights.get(watched)
        if light is None:
            return False
        kind = event.type()
        if kind == QEvent.Type.Resize:
            light.setGeometry(watched.rect())
        elif kind in (QEvent.Type.HoverEnter, QEvent.Type.HoverMove):
            light.point = QPointF(event.position())
            light.raise_()
            if light.strength < 1.0 and kind == QEvent.Type.HoverEnter:
                light.fade_to(1.0)
            light.update()
        elif kind == QEvent.Type.HoverLeave:
            light.fade_to(0.0)
        return False


# -- press ripples ----------------------------------------------------------------------------


class _Ripple(QWidget):
    def __init__(self, button: QPushButton, origin: QPointF, color: QColor):
        super().__init__(button)
        self.origin, self.color, self.progress = origin, color, 0.0
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
        self.setGeometry(button.rect())
        corners = [QPointF(0, 0), QPointF(self.width(), 0), QPointF(0, self.height()), QPointF(self.width(), self.height())]
        self.reach = max(((c.x() - origin.x()) ** 2 + (c.y() - origin.y()) ** 2) ** 0.5 for c in corners)
        self._animation = QVariantAnimation(self)
        self._animation.setDuration(EMPHASIS_MS + 120)
        self._animation.setStartValue(0.0)
        self._animation.setEndValue(1.0)
        self._animation.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._animation.valueChanged.connect(self._step)
        self._animation.finished.connect(self.deleteLater)
        self.show()
        self._animation.start()

    def _step(self, value) -> None:
        self.progress = float(value)
        self.update()

    def paintEvent(self, event) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        clip = QPainterPath()
        clip.addRoundedRect(QRectF(self.rect()), 8, 8)
        painter.setClipPath(clip)
        color = QColor(self.color)
        color.setAlphaF(0.32 * (1.0 - self.progress))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(color)
        radius = self.reach * (0.15 + 0.85 * self.progress)
        painter.drawEllipse(self.origin, radius, radius)


class Ripples(QObject):
    """A ripple from the press point on every push button in the application."""

    def __init__(self, app: QApplication):
        super().__init__(app)
        app.installEventFilter(self)

    def eventFilter(self, watched, event) -> bool:  # noqa: N802
        if (
            event.type() == QEvent.Type.MouseButtonPress
            and isinstance(watched, QPushButton)
            and watched.isEnabled()
            and event.button() == Qt.MouseButton.LeftButton
            and not prefers_reduced_motion()
        ):
            dark = watched.objectName() in {"primary", "repairCta", "next"}
            _Ripple(watched, QPointF(event.position()), QColor("#ffffff") if dark else QColor(TOKENS["text"]))
        return False


# -- toasts --------------------------------------------------------------------------------------


class Toast(QLabel):
    def __init__(self, parent: QWidget, text: str, tone: str = "ok"):
        super().__init__(text, parent)
        color = {"ok": TOKENS["ok"], "warn": TOKENS["warn"], "repair": MODE_ACCENTS["repair"]["accent"]}.get(tone, TOKENS["accent"])
        self.setObjectName("toast")
        self.setStyleSheet(
            f"QLabel#toast {{ background: rgba(18, 20, 24, 0.96); color: {TOKENS['text']}; border: 1px solid {color};"
            f" border-radius: 12px; padding: 10px 18px; font-weight: 600; }}"
        )
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
        self.adjustSize()
        bottom = parent.height() - 36
        self._end = QRect((parent.width() - self.width()) // 2, bottom - self.height(), self.width(), self.height())
        self.setAccessibleName(text)
        self.show()
        self.raise_()
        if prefers_reduced_motion():
            self.setGeometry(self._end)
        else:
            rise = QPropertyAnimation(self, b"geometry", self)
            rise.setDuration(VIEW_MS + 40)
            rise.setStartValue(self._end.translated(0, 26))
            rise.setEndValue(self._end)
            rise.setEasingCurve(QEasingCurve.Type.OutBack)
            rise.start(QPropertyAnimation.DeletionPolicy.DeleteWhenStopped)
        QTimer.singleShot(2300, self._leave)

    def _leave(self) -> None:
        if prefers_reduced_motion():
            self.deleteLater()
            return
        fall = QPropertyAnimation(self, b"geometry", self)
        fall.setDuration(VIEW_MS)
        fall.setStartValue(self.geometry())
        fall.setEndValue(self.geometry().translated(0, 30))
        fall.setEasingCurve(QEasingCurve.Type.InCubic)
        fall.finished.connect(self.deleteLater)
        fall.start(QPropertyAnimation.DeletionPolicy.DeleteWhenStopped)


def toast(widget: QWidget, text: str, tone: str = "ok") -> Toast | None:
    """A short confirmation at the bottom of ``widget``'s window."""
    window = widget.window() if widget is not None else None
    if window is None:
        return None
    for old in window.findChildren(Toast):
        old.deleteLater()
    return Toast(window, text, tone)


# -- the repaired check -----------------------------------------------------------------------


class SuccessMark(QWidget):
    """A ring and a check, drawn in one stroke, with two rings spreading out."""

    def __init__(self, size: int = 46, color: str = TOKENS["ok"], parent=None):
        super().__init__(parent)
        self.setFixedSize(size, size)
        self.color = QColor(color)
        self.progress = 1.0
        self._animation = QVariantAnimation(self)
        self._animation.setDuration(900)
        self._animation.setStartValue(0.0)
        self._animation.setEndValue(1.0)
        self._animation.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._animation.valueChanged.connect(self._step)

    def _step(self, value) -> None:
        self.progress = float(value)
        self.update()

    def play(self, color: str | None = None) -> None:
        if color:
            self.color = QColor(color)
        if prefers_reduced_motion():
            self._step(1.0)
            return
        self._animation.stop()
        self._step(0.0)  # the first frame starts undrawn
        self._animation.start()

    def paintEvent(self, event) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        t = self.progress
        center = QPointF(self.width() / 2, self.height() / 2)
        radius = self.width() / 2 - 4
        for lag in (0.0, 0.18):  # two rings spread and fade
            spread = min(1.0, max(0.0, (t - lag) / (1 - lag)))
            if 0 < spread < 1:
                ring = QColor(self.color)
                ring.setAlphaF(0.45 * (1 - spread))
                painter.setPen(QPen(ring, 1.4))
                painter.setBrush(Qt.BrushStyle.NoBrush)
                painter.drawEllipse(center, radius * (0.6 + 0.4 * spread), radius * (0.6 + 0.4 * spread))
        fill = QColor(self.color)
        fill.setAlphaF(0.14 * min(1.0, t * 2))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(fill)
        painter.drawEllipse(center, radius * 0.78, radius * 0.78)
        pen = QPen(self.color, 2.4)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
        painter.setPen(pen)
        painter.setBrush(Qt.BrushStyle.NoBrush)
        arc = min(1.0, t / 0.55)
        box = QRectF(center.x() - radius * 0.78, center.y() - radius * 0.78, radius * 1.56, radius * 1.56)
        painter.drawArc(box, 90 * 16, int(-360 * 16 * arc))
        tick = min(1.0, max(0.0, (t - 0.45) / 0.45))
        if tick > 0:
            a = QPointF(center.x() - radius * 0.34, center.y() + radius * 0.02)
            b = QPointF(center.x() - radius * 0.08, center.y() + radius * 0.28)
            c = QPointF(center.x() + radius * 0.38, center.y() - radius * 0.26)
            first = min(1.0, tick / 0.4)
            path = QPainterPath(a)
            path.lineTo(a + (b - a) * first)
            if tick > 0.4:
                path.lineTo(b + (c - b) * ((tick - 0.4) / 0.6))
            painter.drawPath(path)


# -- the headline -------------------------------------------------------------------------------


class SheenTitle(QLabel):
    """A display headline lit from one side, with a band of light that crosses it once on ``sweep``."""

    def __init__(self, text: str = "", parent=None):
        super().__init__(text, parent)
        self.accent = QColor(TOKENS["accent"])
        self.sheen = -1.0  # band position 0 .. 1 while sweeping
        self._animation = QVariantAnimation(self)
        self._animation.setDuration(1500)
        self._animation.setStartValue(-0.2)
        self._animation.setEndValue(1.2)
        self._animation.setEasingCurve(QEasingCurve.Type.InOutCubic)
        self._animation.valueChanged.connect(self._step)
        self._animation.finished.connect(lambda: self._step(-1.0))

    def _step(self, value) -> None:
        self.sheen = float(value)
        self.update()

    def set_accent(self, color: str) -> None:
        self.accent = QColor(color)
        self.update()

    def sweep(self) -> None:
        if prefers_reduced_motion():
            return
        self._animation.stop()
        self._animation.start()

    def paintEvent(self, event) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.TextAntialiasing)
        rect = QRectF(self.contentsRect())
        text = QColor(TOKENS["text"])
        tint = QColor(
            round(text.red() * 0.55 + self.accent.red() * 0.45),
            round(text.green() * 0.55 + self.accent.green() * 0.45),
            round(text.blue() * 0.55 + self.accent.blue() * 0.45),
        )
        rtl = self.layoutDirection() == Qt.LayoutDirection.RightToLeft
        start, end = (rect.topRight(), rect.topLeft()) if rtl else (rect.topLeft(), rect.topRight())
        gradient = QLinearGradient(start, end)
        stops = [(0.0, text), (0.55, text), (1.0, tint)]
        if -0.2 < self.sheen < 1.2:
            band = 0.09
            stops = [(p, c) for p, c in stops if abs(p - self.sheen) > band]
            for offset, color in ((-band, None), (0.0, QColor("#ffffff")), (band, None)):
                position = self.sheen + offset
                if 0.0 <= position <= 1.0:
                    stops.append((position, color or (tint if position > 0.55 else text)))
        for position, color in sorted(stops, key=lambda s: s[0]):
            gradient.setColorAt(position, color)
        painter.setPen(QPen(QBrush(gradient), 1))
        painter.setFont(self.font())
        painter.setLayoutDirection(self.layoutDirection())  # Arabic keeps its full stop at the end
        flags = int(self.alignment()) | int(Qt.TextFlag.TextWordWrap)
        painter.drawText(rect, flags, self.text())


# -- dragging a file in ---------------------------------------------------------------------------


class SonarDrop(QWidget):
    """Over the whole stage while a file is dragged in: sonar rings answer the pointer."""

    PERIOD = 1.6

    def __init__(self, parent=None):
        super().__init__(parent)
        self.text, self.hint = "", ""
        self.point: QPointF | None = None
        self.color = QColor(TOKENS["accent"])
        self.started = 0.0
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        self._timer = QTimer(self)
        self._timer.timeout.connect(self.update)
        self.hide()

    def set_text(self, text: str, hint: str) -> None:
        self.text, self.hint = text, hint
        self.update()

    def follow(self, point: QPointF) -> None:
        self.point = QPointF(point)
        self.update()

    def showEvent(self, event) -> None:  # noqa: N802
        super().showEvent(event)
        import time

        self.started = time.monotonic()
        if not prefers_reduced_motion():
            self._timer.start(16)  # only while a file is actually being dragged in

    def hideEvent(self, event) -> None:  # noqa: N802
        self._timer.stop()
        super().hideEvent(event)

    def paintEvent(self, event) -> None:  # noqa: N802
        import time

        from ui.icons import glyph, icon_font
        from ui.theme import ui_font

        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        rect = QRectF(self.rect())
        point = self.point or rect.center()
        shade = QRadialGradient(point, max(rect.width(), rect.height()) * 0.9)
        shade.setColorAt(0.0, QColor(5, 7, 9, 215))
        shade.setColorAt(1.0, QColor(3, 4, 6, 248))
        painter.fillRect(rect, shade)
        elapsed = time.monotonic() - self.started
        painter.setBrush(Qt.BrushStyle.NoBrush)
        reach = max(rect.width(), rect.height()) * 0.55
        for index in range(4):  # rings leave the pointer one after another
            phase = ((elapsed / self.PERIOD) + index / 4) % 1.0
            if prefers_reduced_motion():
                phase = 0.18 + index * 0.18
            radius = 18 + reach * phase
            ring = QColor(self.color)
            ring.setAlphaF(0.55 * (1 - phase) ** 1.4)
            painter.setPen(QPen(ring, 1.6))
            painter.drawEllipse(point, radius, radius)
        core = QRadialGradient(point, 46)
        glow = QColor(self.color)
        glow.setAlphaF(0.35)
        clear = QColor(self.color)
        clear.setAlphaF(0.0)
        core.setColorAt(0.0, glow)
        core.setColorAt(1.0, clear)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(core)
        painter.drawEllipse(point, 46, 46)
        painter.setFont(icon_font(30))
        painter.setPen(self.color)
        painter.drawText(QRectF(point.x() - 30, point.y() - 30, 60, 60), int(Qt.AlignmentFlag.AlignCenter), glyph("drop"))
        band = QRectF(0, rect.height() * 0.70, rect.width(), 90)
        painter.setFont(ui_font(30, 600, -0.6))
        painter.setPen(QColor(TOKENS["text"]))
        painter.drawText(band.adjusted(0, 0, 0, -44), int(Qt.AlignmentFlag.AlignCenter), self.text)
        painter.setFont(ui_font(14))
        painter.setPen(QColor(TOKENS["text_mute"]))
        painter.drawText(band.adjusted(0, 48, 0, 0), int(Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop), self.hint)
