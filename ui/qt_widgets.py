from __future__ import annotations

import math
from typing import Sequence

from PySide6.QtCore import QEasingCurve, Property, QPropertyAnimation, QTimer, Qt
from PySide6.QtGui import (
    QColor,
    QLinearGradient,
    QPainter,
    QPainterPath,
    QPen,
    QRadialGradient,
)
from PySide6.QtWidgets import QFrame, QSizePolicy, QWidget
from ui.translations import translate_text


class BrandMark(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setFixedSize(42, 42)

    def paintEvent(self, _event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        gradient = QLinearGradient(0, 0, self.width(), self.height())
        gradient.setColorAt(0.0, QColor("#205c52"))
        gradient.setColorAt(1.0, QColor("#10222a"))
        painter.setBrush(gradient)
        painter.setPen(QPen(QColor("#397d71"), 1))
        painter.drawRoundedRect(self.rect().adjusted(1, 1, -1, -1), 14, 14)

        shield = QPainterPath()
        shield.moveTo(21, 7)
        shield.lineTo(32, 11)
        shield.lineTo(31, 23)
        shield.cubicTo(30, 29, 25, 33, 21, 35)
        shield.cubicTo(17, 33, 12, 29, 11, 23)
        shield.lineTo(10, 11)
        shield.closeSubpath()
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.setPen(QPen(QColor("#a5f8e8"), 1.8, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
        painter.drawPath(shield)
        painter.setPen(QPen(QColor("#67e8d1"), 1.8, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        painter.drawLine(15, 21, 19, 21)
        painter.drawLine(19, 21, 22, 17)
        painter.drawLine(22, 17, 27, 17)
        painter.drawLine(21, 23, 21, 28)


class AnimatedBackground(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._phase = 0.0
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._timer.start(50)

    def _tick(self) -> None:
        self._phase = (self._phase + 0.012) % math.tau
        if self.isVisible():
            self.update()

    def showEvent(self, event) -> None:
        super().showEvent(event)
        self._timer.start(50)

    def hideEvent(self, event) -> None:
        self._timer.stop()
        super().hideEvent(event)

    def paintEvent(self, _event) -> None:
        """A calm, static canvas: one soft top-light, no grid, no motion.

        The old animated grid, orbital rings and drifting glows read as
        decoration and competed with the data, so they are gone. What is
        left is a single very low-contrast vertical wash that gives the
        window depth without drawing the eye.
        """
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.fillRect(self.rect(), QColor("#070b12"))

        width = self.width()
        height = max(1, self.height())
        wash = QLinearGradient(0, 0, 0, height)
        wash.setColorAt(0.0, QColor(18, 32, 48, 150))
        wash.setColorAt(0.45, QColor(11, 18, 30, 90))
        wash.setColorAt(1.0, QColor(7, 11, 18, 0))
        painter.fillRect(self.rect(), wash)

        sheen = QRadialGradient(width * 0.18, -height * 0.15,
                                max(width, height) * 0.85)
        sheen.setColorAt(0.0, QColor(94, 224, 208, 16))
        sheen.setColorAt(1.0, QColor(94, 224, 208, 0))
        painter.fillRect(self.rect(), sheen)


class Surface(QFrame):
    def __init__(self, parent: QWidget | None = None, *, accent: str = "#26394d") -> None:
        super().__init__(parent)
        self.setObjectName("surface")
        self.setProperty("accent", accent)


class RiskGauge(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setMinimumSize(168, 168)
        self.setMaximumSize(200, 200)
        self._value = 0.0
        self._animation = QPropertyAnimation(self, b"value", self)
        self._animation.setDuration(1100)
        self._animation.setEasingCurve(QEasingCurve.Type.OutCubic)

    def get_value(self) -> float:
        return self._value

    def set_value(self, value: float) -> None:
        self._value = max(0.0, min(100.0, value))
        self.update()

    value = Property(float, get_value, set_value)

    def animate_to(self, value: float) -> None:
        self._animation.stop()
        self._animation.setStartValue(self._value)
        self._animation.setEndValue(max(0.0, min(100.0, value)))
        self._animation.start()

    def paintEvent(self, _event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        side = min(self.width(), self.height()) - 22
        rect_x = (self.width() - side) / 2
        rect_y = (self.height() - side) / 2
        arc = self.rect().adjusted(
            int(rect_x), int(rect_y), -int(rect_x), -int(rect_y)
        )
        painter.setPen(QPen(QColor("#202f40"), 11, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        painter.drawArc(arc, 225 * 16, -270 * 16)
        color = (
            QColor("#ff7185")
            if self._value >= 50
            else QColor("#ffbd6d")
            if self._value > 0
            else QColor("#55d7b4")
        )
        painter.setPen(QPen(color, 11, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        painter.drawArc(arc, 225 * 16, -int(270 * 16 * self._value / 100))
        painter.setPen(QColor("#f1f6ff"))
        number_font = self.font()
        number_font.setPointSize(27)
        number_font.setBold(True)
        painter.setFont(number_font)
        painter.drawText(
            self.rect().adjusted(0, -3, 0, -3),
            Qt.AlignmentFlag.AlignCenter,
            f"{self._value:.0f}",
        )
        painter.setPen(QColor("#8da0b5"))
        caption_font = self.font()
        caption_font.setPointSize(8)
        painter.setFont(caption_font)
        painter.drawText(
            self.rect().adjusted(0, 49, 0, 0),
            Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignVCenter,
            translate_text("RISK INDEX", getattr(self, "language", "en")),
        )


class SignalCanvas(QWidget):
    """Live visualization driven by observed entropy and structural coordinates."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setMinimumHeight(230)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.entropy: Sequence[float] = ()
        self.vector: Sequence[float] = ()
        self.scanning = False
        self.language = "en"
        self._phase = 0.0
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)

    def showEvent(self, event) -> None:
        super().showEvent(event)
        self._timer.start(40)

    def hideEvent(self, event) -> None:
        self._timer.stop()
        super().hideEvent(event)

    def set_data(
        self,
        entropy: Sequence[float] = (),
        vector: Sequence[float] = (),
    ) -> None:
        self.entropy = entropy
        self.vector = vector
        self.scanning = False
        self.update()

    def set_scanning(self, scanning: bool) -> None:
        self.scanning = scanning
        self.update()

    def set_language(self, language: str) -> None:
        self.language = language
        self.update()

    def _tick(self) -> None:
        self._phase = (self._phase + 0.035) % math.tau
        if not self.isVisible():
            return
        if self.scanning or (not self.vector and not self.entropy):
            self.update()

    def paintEvent(self, _event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.fillRect(self.rect(), QColor("#0d1521"))
        bounds = self.rect().adjusted(20, 18, -20, -18)
        if self.vector:
            self._paint_embedding(painter, bounds)
        elif self.entropy:
            self._paint_entropy(painter, bounds)
        else:
            self._paint_idle(painter, bounds)

    def _paint_idle(self, painter: QPainter, bounds) -> None:
        painter.setPen(QPen(QColor("#1a3444"), 1))
        for index in range(6):
            y = bounds.top() + bounds.height() * index / 5
            painter.drawLine(bounds.left(), int(y), bounds.right(), int(y))
        painter.setPen(QColor("#7e94aa"))
        painter.drawText(
            bounds,
            Qt.AlignmentFlag.AlignCenter,
            translate_text(
                "LIVE WORKSPACE SIGNALS" if self.scanning else "READY FOR LOCAL EVIDENCE",
                self.language,
            ),
        )
        baseline = bounds.center().y() + bounds.height() * 0.23
        waveform = QPainterPath()
        for index in range(100):
            fraction = index / 99
            x = bounds.left() + fraction * bounds.width()
            envelope = 0.25 + 0.75 * math.sin(math.pi * fraction) ** 2
            y = baseline + (
                math.sin(fraction * 18 + self._phase * 1.5)
                + 0.32 * math.sin(fraction * 41 - self._phase)
            ) * bounds.height() * 0.055 * envelope
            if index == 0:
                waveform.moveTo(x, y)
            else:
                waveform.lineTo(x, y)
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.setPen(QPen(QColor(67, 217, 196, 48 if not self.scanning else 112), 1.5))
        painter.drawPath(waveform)
        if self.scanning:
            x = bounds.left() + (math.sin(self._phase) + 1) * 0.5 * bounds.width()
            painter.setPen(QPen(QColor(65, 220, 198, 110), 2))
            painter.drawLine(int(x), bounds.top(), int(x), bounds.bottom())
            for index in range(5):
                cx = bounds.left() + ((index * 0.23 + self._phase * 0.035) % 1.0) * bounds.width()
                cy = bounds.center().y() + math.sin(self._phase + index) * bounds.height() * 0.28
                painter.setBrush(QColor(65, 220, 198, 90 - index * 12))
                painter.setPen(Qt.PenStyle.NoPen)
                painter.drawEllipse(int(cx - 4), int(cy - 4), 8, 8)

    def _paint_entropy(self, painter: QPainter, bounds) -> None:
        values = self.entropy
        painter.setPen(QPen(QColor("#283a4c"), 1, Qt.PenStyle.DashLine))
        for threshold in (3.5, 7.2):
            y = bounds.bottom() - bounds.height() * threshold / 8
            painter.drawLine(bounds.left(), int(y), bounds.right(), int(y))
        path_points = []
        count = len(values)
        for index, value in enumerate(values):
            x = bounds.left() + bounds.width() * index / max(1, count - 1)
            y = bounds.bottom() - bounds.height() * max(0.0, min(8.0, value)) / 8
            path_points.append((int(x), int(y)))
        painter.setPen(QPen(QColor("#52e1cb"), 2))
        for start, end in zip(path_points, path_points[1:]):
            painter.drawLine(*start, *end)
        painter.setPen(QColor("#8499ad"))
        painter.drawText(
            bounds.adjusted(0, 0, 0, -4),
            Qt.AlignmentFlag.AlignBottom,
            translate_text("Measured Shannon entropy · bits per byte", self.language),
        )

    def _paint_embedding(self, painter: QPainter, bounds) -> None:
        size = min(bounds.width(), bounds.height())
        x0 = bounds.center().x() - size / 2
        y0 = bounds.center().y() - size / 2
        cell = size / 64
        scale = max((abs(value) for value in self.vector), default=1.0) or 1.0
        for index, value in enumerate(self.vector[:4096]):
            row, column = divmod(index, 64)
            strength = min(1.0, abs(value) / scale)
            if value >= 0:
                color = QColor(12, int(44 + 174 * strength), int(53 + 160 * strength))
            else:
                color = QColor(int(52 + 188 * strength), int(36 + 50 * strength), int(42 + 48 * strength))
            painter.fillRect(
                int(x0 + column * cell),
                int(y0 + row * cell),
                max(1, math.ceil(cell)),
                max(1, math.ceil(cell)),
                color,
            )
