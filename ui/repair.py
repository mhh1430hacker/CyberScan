"""Repair mode: a preview of what is planned, and nothing more.

CyberScan cannot repair files yet. This screen says so first, shows the
planned steps and the rules repair will follow, and offers no control that
could change a file.
"""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFrame, QHBoxLayout, QPushButton, QSizePolicy, QVBoxLayout, QWidget

from ui.copy import tr
from ui.sonar import SonarCube
from ui.theme import TONES
from ui.widgets import Pill, card, label

STEPS = (
    ("1", "Choose a scanned file", "Start from a result in your scans, so repair knows what was found and where."),
    ("2", "Review a repair plan", "See exactly which bytes would change, and why, before anything happens."),
    ("3", "Restore from a trusted copy", "Replace damaged parts only from a copy you trust; the original is kept."),
)
RULES = (
    "The original file is always kept.",
    "Nothing changes without your approval.",
    "Every change is written to the session log.",
)


class RepairView(QWidget):
    WIDTH = 820

    def __init__(self, parent=None):
        super().__init__(parent)
        self.language = "en"
        outer = QHBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addStretch(1)
        host = QWidget()
        host.setMaximumWidth(self.WIDTH)
        host.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        column = QVBoxLayout(host)
        column.setContentsMargins(8, 24, 8, 24)
        column.setSpacing(0)
        outer.addWidget(host, 100)
        outer.addStretch(1)

        # The same glass cube as scanning, empty and in the repair hue.
        self.cube = SonarCube(height=230)
        self.cube.setAccessibleName("")
        column.addWidget(self.cube)
        self.badge = Pill()
        column.addWidget(self.badge, 0, Qt.AlignmentFlag.AlignHCenter)
        column.addSpacing(20)
        self.title = label("", "display", wrap=True)
        self.title.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        column.addWidget(self.title)
        column.addSpacing(10)
        self.lead = label("", "lead", wrap=True)
        self.lead.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        column.addWidget(self.lead)
        column.addSpacing(28)

        self.bar = QFrame()
        self.bar.setObjectName("command")
        bar = QHBoxLayout(self.bar)
        bar.setContentsMargins(16, 8, 8, 8)
        self.bar_text = label("", "mute")
        bar.addWidget(self.bar_text, 1)
        self.bar_button = QPushButton()
        self.bar_button.setObjectName("primary")
        self.bar_button.setEnabled(False)
        bar.addWidget(self.bar_button)
        column.addWidget(self.bar)
        column.addSpacing(22)

        steps = QHBoxLayout()
        steps.setSpacing(12)
        self.step_widgets: list[tuple] = []
        for number, _title, _body in STEPS:
            frame = card()
            box = QVBoxLayout(frame)
            box.setContentsMargins(18, 16, 18, 16)
            box.setSpacing(6)
            mark = label(number, "eyebrow")
            title = label("", "section", wrap=True)
            body = label("", "mute", wrap=True)
            # Plain-text wrapping misjudges Arabic widths here and clips the
            # line ends; the rich-text layout measures them correctly.
            body.setTextFormat(Qt.TextFormat.RichText)
            state = Pill()
            for widget in (mark, title, body):
                box.addWidget(widget)
            box.addStretch(1)
            box.addWidget(state, 0, Qt.AlignmentFlag.AlignLeft)
            steps.addWidget(frame, 1)
            self.step_widgets.append((title, body, state))
        column.addLayout(steps)
        column.addSpacing(20)

        self.rules_title = label("", "eyebrow")
        self.rules_title.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        column.addWidget(self.rules_title)
        column.addSpacing(8)
        self.rule_labels = []
        for _rule in RULES:
            rule = label("", "body")
            rule.setAlignment(Qt.AlignmentFlag.AlignHCenter)
            column.addWidget(rule)
            self.rule_labels.append(rule)

    def showEvent(self, event) -> None:  # noqa: N802
        super().showEvent(event)
        self.cube.show_empty(TONES["repair"])

    def retranslate(self, language: str) -> None:
        self.language = language
        t = lambda text: tr(text, language)  # noqa: E731
        self.badge.set_pill(t("Coming soon · preview"), "repair")
        self.title.setText(t("Repair, carefully."))
        self.lead.setText(t("Repair will help you restore a damaged or tampered file from a trusted copy. It isn't available in this version, and nothing on this screen changes any file."))
        self.bar_text.setText(t("Choose a scanned file to repair"))
        self.bar_button.setText(t("Not available yet"))
        for (title, body, state), (_number, step_title, step_body) in zip(self.step_widgets, STEPS):
            title.setText(t(step_title))
            body.setText(t(step_body))
            state.set_pill(t("Planned"), "neutral")
        self.rules_title.setText(t("How repair will work").upper() if language == "en" else t("How repair will work"))
        for widget, rule in zip(self.rule_labels, RULES):
            widget.setText("✓  " + t(rule))
