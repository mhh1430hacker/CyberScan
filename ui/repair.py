"""Repair mode: find what was added to a file, cut it out of a copy, prove it.

1. Choose a file (field, file dialog, drop, or a scan from the rail).
2. Review: every finding with its exact place in the file, shown in the
   sonar cube, what repair would do, and whether it is pre-selected. Things
   that can't be removed exactly are listed as "reported only", with why.
3. Repair a copy: the selected repairs are applied to the file's bytes in
   memory, the result is validated (it must still parse and keep its
   structure) and analysed again; only then is the copy written next to the
   original, under its true name. Removed bytes are sealed in the encrypted
   quarantine. The original is never changed.

The engine is ``repair_engine.analyze`` (structure the parsers can prove;
no trained model), and the screen says so.
"""
from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QThread, QTimer, QUrl, Qt, Signal
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QCheckBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLineEdit,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from ui.copy import tr
from ui.names import inspect as inspect_name, visible
from ui.plain_language import format_size, isolate
from ui.polish import SuccessMark, toast
from ui.sonar import SonarCube
from ui.structure import build_structure
from ui.theme import TONES, tone_color
from ui.widgets import ElidedLabel, FlowLayout, Pill, card, label

MAX_BYTES = 200 * 1024 * 1024
SEVERITY = {"high": ("Serious", "danger"), "medium": ("Moderate", "warn"), "low": ("Minor", "info")}
RULES = (
    "The original file is always kept.",
    "Nothing changes without your approval.",
    "Every change is written to the session log.",
)
# The engine's sentences carry numbers and names; in Arabic each finding reads
# a fixed sentence for its kind instead (the numbers are shown on their own line).
SUMMARIES = {
    "name_hidden": "The name contains invisible direction characters that make it read as something else.",
    "name_double": "It's named like a document or picture, but the real extension is a program that can run.",
    "name_mismatch": "The name's extension doesn't match what the file really contains.",
    "after_eof": "Data is stored after the point where the format ends. Readers ignore it; other programs can use it.",
    "pe_overlay": "Data after the program's last section. Installers often keep their payload there, so it isn't removed unless you choose to.",
    "pdf_update": "The last update to this PDF only adds active content. Removing that update returns the document to its previous version.",
    "pdf_active": "Part of the document carries active content: JavaScript, automatic actions or embedded files.",
    "ooxml_vba_project": "Code that can run when the document is opened.",
    "ooxml_embedded_object": "Another file stored inside the document; it can be a program.",
    "ooxml_activex": "A control that can run code inside Office.",
    "ooxml_link": "The document fetches something from the internet when it opens.",
    "ole_vba": "This older Office file contains macro code.",
}
# Every sentence the engine can hand this screen, so each has a translation.
PHRASES = (
    "Hidden characters disguise the name", "A double extension hides the real type", "The extension doesn't match the content",
    "Data hidden after the end of the file", "Extra data after the end of the program", "Active content added in a later update",
    "Active content inside the document", "Active content hidden in compressed objects", "Macros (VBA code)", "Embedded object",
    "ActiveX control", "Loads something from the internet when opened",
    "It's part of the document itself; removing it would need rewriting the PDF, which isn't supported yet.",
    "Compressed object streams can't be edited safely yet.",
    "Removing an external link safely needs editing the part that uses it; that isn't supported yet.",
    "Removing macros from older Office files isn't supported yet. Opening it in Office and saving as .docx/.xlsx removes them.",
    "Nothing was changed.", "The repaired copy failed its checks, so nothing was written.",
    "Serious", "Moderate", "Minor",
)


class _Analyze(QThread):
    done = Signal(object, object)  # (report | None, error | None)

    def __init__(self, path: str):
        super().__init__()
        self.path = path

    def run(self) -> None:
        from repair_engine.analyze import analyze

        try:
            path = Path(self.path)
            if path.stat().st_size > MAX_BYTES:
                raise ValueError("This file is larger than 200 MB, which Repair doesn't handle yet.")
            data = path.read_bytes()
            self.done.emit((analyze(data, path.name), data), None)
        except Exception as exc:  # noqa: BLE001 - shown to the user
            self.done.emit(None, exc)


class _Repair(QThread):
    done = Signal(object, object)  # (result, output path | None)

    def __init__(self, data: bytes, name: str, findings, folder: Path, data_dir: Path | None):
        super().__init__()
        self.data, self.name, self.findings, self.folder, self.data_dir = data, name, findings, folder, data_dir

    def run(self) -> None:
        from repair_engine.analyze import repair

        result = repair(self.data, self.name, self.findings)
        if not result.ok or result.repaired is None:
            self.done.emit(result, None)
            return
        try:
            output = _free_path(self.folder, result.name)
            temporary = output.with_name(output.name + ".tmp")
            temporary.write_bytes(result.repaired)
            temporary.replace(output)
            if result.removed and self.data_dir is not None:
                from repair_engine.executor.vault import seal
                from ui.vault import _key

                seal(result.removed, _key(self.data_dir), Path(self.data_dir) / "quarantine" / "repair", result.sha256_before)
            self.done.emit(result, output)
        except Exception as exc:  # noqa: BLE001 - e.g. a local antivirus blocking the new file
            result.ok = False
            result.message = f"The repaired copy couldn't be saved: {type(exc).__name__}: {exc}"
            self.done.emit(result, None)


def _free_path(folder: Path, name: str) -> Path:
    stem, dot, suffix = name.rpartition(".")
    if not dot:
        stem, suffix = name, ""
    candidate = folder / f"{stem} (repaired){'.' + suffix if suffix else ''}"
    number = 2
    while candidate.exists():
        candidate = folder / f"{stem} (repaired {number}){'.' + suffix if suffix else ''}"
        number += 1
    return candidate


class RepairView(QWidget):
    WIDTH = 900
    logged = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.language = "en"
        self.data_dir: Path | None = None
        self.path: Path | None = None
        self.report = None
        self.data: bytes = b""
        self.output: Path | None = None
        self._threads: list[QThread] = []
        self._checks: list[tuple[QCheckBox, object]] = []
        self.setAcceptDrops(True)

        outer = QHBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addStretch(1)
        host = QWidget()
        host.setMaximumWidth(self.WIDTH)
        host.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        column = QVBoxLayout(host)
        column.setContentsMargins(8, 16, 8, 24)
        column.setSpacing(0)
        outer.addWidget(host, 100)
        outer.addStretch(1)

        # The same glass cube as scanning, in the repair hue; it fills with the file once chosen.
        self.cube = SonarCube(interactive=True, height=260)
        self.cube.label_for = lambda region: tr(SEVERITY.get(region.severity, ("Moderate",))[0], self.language)
        column.addWidget(self.cube)
        self.badge = Pill()
        column.addWidget(self.badge, 0, Qt.AlignmentFlag.AlignHCenter)
        column.addSpacing(14)
        self.title = label("", "display", wrap=True)
        self.title.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        column.addWidget(self.title)
        column.addSpacing(8)
        self.lead = label("", "lead", wrap=True)
        self.lead.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        column.addWidget(self.lead)
        column.addSpacing(22)

        # Step 1: choose -----------------------------------------------------------------
        self.bar = QFrame()
        self.bar.setObjectName("command")
        bar = QHBoxLayout(self.bar)
        bar.setContentsMargins(16, 8, 8, 8)
        bar.setSpacing(8)
        self.field = QLineEdit()
        self.field.setObjectName("target")
        self.field.setClearButtonEnabled(True)
        self.field.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
        self.field.returnPressed.connect(self.analyze_field)
        bar.addWidget(self.field, 1)
        self.choose_button = QPushButton()
        self.choose_button.setObjectName("ghost")
        self.choose_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.choose_button.clicked.connect(self._choose)
        bar.addWidget(self.choose_button)
        self.analyze_button = QPushButton()
        self.analyze_button.setObjectName("primary")
        self.analyze_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.analyze_button.clicked.connect(self.analyze_field)
        bar.addWidget(self.analyze_button)
        column.addWidget(self.bar)
        column.addSpacing(8)
        self.error = label("", "error", wrap=True)
        self.error.setVisible(False)
        column.addWidget(self.error)
        column.addSpacing(10)

        # Step 2: review ------------------------------------------------------------------
        self.review = card()
        review = QVBoxLayout(self.review)
        review.setContentsMargins(22, 18, 22, 18)
        review.setSpacing(10)
        self.file_name = ElidedLabel(file_name=True)
        self.file_name.setObjectName("title")
        self.file_meta = label("", "mute", wrap=True)
        self.summary = label("", "body", wrap=True)
        review.addWidget(self.file_name)
        review.addWidget(self.file_meta)
        review.addWidget(self.summary)
        # A program stays dangerous whatever its name: say so where the choice is made.
        self.caution = label("", "error", wrap=True)
        self.caution.setVisible(False)
        review.addWidget(self.caution)
        self.findings = QVBoxLayout()
        self.findings.setSpacing(8)
        review.addLayout(self.findings)
        actions_host = QWidget()
        actions = FlowLayout(actions_host, spacing=10)
        self.repair_button = QPushButton()
        self.repair_button.setObjectName("primary")
        self.repair_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.repair_button.clicked.connect(self.repair_selected)
        self.other_button = QPushButton()
        self.other_button.setObjectName("ghost")
        self.other_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.other_button.clicked.connect(self.reset)
        actions.addWidget(self.repair_button)
        actions.addWidget(self.other_button)
        review.addWidget(actions_host)
        self.destination = label("", "mute", wrap=True)
        review.addWidget(self.destination)
        self.review.setVisible(False)
        column.addWidget(self.review)
        column.addSpacing(12)

        # Step 3: the result --------------------------------------------------------------
        self.outcome = card()
        outcome = QVBoxLayout(self.outcome)
        outcome.setContentsMargins(22, 18, 22, 18)
        outcome.setSpacing(8)
        self.outcome_title = label("", "title", wrap=True)
        self.outcome_body = label("", "body", wrap=True)
        self.outcome_checks = label("", "mute", wrap=True)
        self.outcome_hashes = label("", "mono", wrap=True)
        self.outcome_hashes.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
        self.outcome_hashes.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        heading = QHBoxLayout()
        heading.setSpacing(12)
        self.success_mark = SuccessMark(40)
        heading.addWidget(self.success_mark, 0, Qt.AlignmentFlag.AlignVCenter)
        heading.addWidget(self.outcome_title, 1)
        outcome.addLayout(heading)
        for widget in (self.outcome_body, self.outcome_checks, self.outcome_hashes):
            outcome.addWidget(widget)
        outcome_actions = QHBoxLayout()
        self.folder_button = QPushButton()
        self.folder_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.folder_button.clicked.connect(self._show_folder)
        outcome_actions.addWidget(self.folder_button)
        outcome_actions.addStretch(1)
        outcome.addLayout(outcome_actions)
        self.outcome.setVisible(False)
        column.addWidget(self.outcome)
        column.addSpacing(16)

        self.rules_title = label("", "eyebrow")
        self.rules_title.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        column.addWidget(self.rules_title)
        column.addSpacing(6)
        self.rule_labels = []
        for _rule in RULES:
            rule = label("", "mute")
            rule.setAlignment(Qt.AlignmentFlag.AlignHCenter)
            column.addWidget(rule)
            self.rule_labels.append(rule)

    # -- text ---------------------------------------------------------------------------------
    def t(self, text: str) -> str:
        return tr(text, self.language)

    def retranslate(self, language: str) -> None:
        self.language = language
        t = self.t
        self.badge.set_pill(t("Works on a copy · the original is never changed"), "repair")
        self.title.setText(t("Repair, carefully."))
        self.lead.setText(t("Choose a file. CyberScan looks for parts that were added to it and can be cut out exactly, then writes a repaired copy and checks it."))
        self.field.setPlaceholderText(t("Paste a file path, or drop a file here…"))
        self.choose_button.setText(t("Choose a file"))
        self.analyze_button.setText(t("Check for repairs"))
        self.repair_button.setText(t("Repair a copy"))
        self.other_button.setText(t("Choose another file"))
        self.folder_button.setText(t("Show in folder"))
        self.rules_title.setText(t("How repair works").upper() if language == "en" else t("How repair works"))
        for widget, rule in zip(self.rule_labels, RULES):
            widget.setText("✓  " + t(rule))
        if self.report is not None:
            self._render()
        if not self.cube.structure:
            self.cube.show_empty(TONES["repair"])

    def showEvent(self, event) -> None:  # noqa: N802
        super().showEvent(event)
        if self.report is None:
            self.cube.show_empty(TONES["repair"])

    # -- step 1 -------------------------------------------------------------------------------
    def load(self, path: str) -> None:
        self.field.setText(path)
        self.analyze_field()

    def present(self, path: str, report, data: bytes, *, held: bool = False) -> None:
        """Open an analysis already made (a scan result handing over to Repair).

        With ``held`` the cube waits, empty, for ``sonar()``: the transition
        plays first, then the sonar runs on the file in front of the visitor.
        """
        self.field.setText(path)
        self._show_error("")
        self.outcome.setVisible(False)
        self.path, self.report, self.data, self.output = Path(path), report, data, None
        self._render(cube=not held)
        if held:
            self.cube.show_empty(TONES["repair"])
        self.logged.emit(f"Repair opened from a scan: {path} · {len(report.findings)} finding(s)")

    def sonar(self) -> None:
        """Send the sonar through the file, then light up what will be repaired."""
        structure = self._structure()
        if structure is None:
            return
        self.cube.start(TONES["repair"])
        QTimer.singleShot(900, lambda s=structure: self.cube.structure is None and self.cube.reveal(s))

    def _choose(self) -> None:
        path, _filter = QFileDialog.getOpenFileName(self, self.t("Choose a file"))
        if path:
            self.load(path)

    def _show_error(self, text: str) -> None:
        self.error.setText(text)
        self.error.setVisible(bool(text))

    def analyze_field(self) -> None:
        value = self.field.text().strip().strip('"')
        self._show_error("")
        if not value:
            self._show_error(self.t("Choose a file to repair first."))
            return
        path = Path(value)
        if not path.is_file():
            self._show_error(self.t("That file doesn't exist. Check the path, or choose the file again."))
            return
        self.path = path
        self.outcome.setVisible(False)
        self.analyze_button.setEnabled(False)
        self.analyze_button.setText(self.t("Checking…"))
        worker = _Analyze(str(path))
        worker.done.connect(self._analyzed)
        self._keep(worker)
        worker.start()

    def _keep(self, thread: QThread) -> None:
        self._threads.append(thread)
        thread.finished.connect(lambda t=thread: self._threads.remove(t) if t in self._threads else None)

    def wait(self, timeout: int = 30000) -> None:
        for thread in list(self._threads):
            thread.wait(timeout)

    def _analyzed(self, payload, error) -> None:
        self.analyze_button.setEnabled(True)
        self.analyze_button.setText(self.t("Check for repairs"))
        if error is not None:
            self._show_error(self.t("This file couldn't be read.") + f" ({type(error).__name__}: {error})")
            return
        self.report, self.data = payload
        self._render()
        self.logged.emit(f"Repair check: {self.path} · {len(self.report.findings)} finding(s)")

    # -- step 2 -------------------------------------------------------------------------------
    def _render(self, *, cube: bool = True) -> None:
        report, t = self.report, self.t
        self.file_name.setText(visible(report.name))
        self.file_meta.setText(" · ".join((
            report.format.upper() if report.format != "unknown" else t("Unrecognised format"),
            isolate(format_size(report.size), self.language),
            "SHA-256 " + isolate(report.sha256[:16] + "…", self.language),
        )))
        repairable = [f for f in report.findings if f.repairable]
        program = report.format in {"pe", "elf"} or inspect_name(report.name).runs
        self.caution.setText("⚠  " + t("This is a program. Repair can only show its true name; it can't make it safe. If you don't trust it, move it to quarantine from its scan result."))
        self.caution.setVisible(program)
        reported = [f for f in report.findings if not f.repairable]
        if not report.findings:
            self.summary.setText(t("Nothing to repair: no added parts were found. This checks structure only; it doesn't prove the file is safe."))
        else:
            self.summary.setText(t("{fixable} can be repaired, {reported} reported only.").format(fixable=len(repairable), reported=len(reported)))
        while self.findings.count():
            item = self.findings.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        self._checks = []
        for finding in report.findings:
            self.findings.addWidget(self._finding_row(finding))
        self.repair_button.setVisible(bool(repairable))
        self._sync_repair_button()
        self.review.setVisible(True)
        if cube:
            structure = self._structure()
            if structure is not None:
                self.cube.show_structure(structure, TONES["repair"])

    def _structure(self):
        """The file's real structure, with each finding's place flagged."""
        if not self.data or self.report is None:
            return None
        position = {"entropy_boundaries": [
            {"offset_start": f.start, "offset_end": max(f.end or 0, (f.start or 0) + 1), "severity": f.severity}
            for f in self.report.findings if f.start is not None and f.end is not None
        ]}
        return build_structure(self.data, None, {}, position)

    def _finding_row(self, finding) -> QWidget:
        t = self.t
        row = QFrame()
        row.setObjectName("cardQuiet")
        layout = QVBoxLayout(row)
        layout.setContentsMargins(0, 6, 0, 8)
        layout.setSpacing(4)
        head = QHBoxLayout()
        head.setSpacing(10)
        word, tone = SEVERITY.get(finding.severity, ("Moderate", "warn"))
        check = QCheckBox()
        check.setEnabled(finding.repairable)
        check.setChecked(finding.repairable and finding.recommended)
        check.stateChanged.connect(lambda _state: self._sync_repair_button())
        check.setAccessibleName(t(finding.title))
        self._checks.append((check, finding))
        pill = Pill()
        pill.set_pill(t(word), tone)
        title = label(t(finding.title), "section", wrap=True)
        head.addWidget(check, 0, Qt.AlignmentFlag.AlignTop)
        head.addWidget(pill, 0, Qt.AlignmentFlag.AlignTop)
        head.addWidget(title, 1)
        layout.addLayout(head)
        summary = SUMMARIES.get(finding.key.split("@")[0]) or SUMMARIES.get(finding.kind) or ""
        detail = label(finding.detail if self.language == "en" or not summary else t(summary), "mute", wrap=True)
        detail.setContentsMargins(30, 0, 0, 0)
        layout.addWidget(detail)
        if finding.rename_to:
            what = label(t("Repair: save the copy as “{name}”").format(name=visible(finding.rename_to)), "body", wrap=True)
        elif finding.plans:
            what = label(t("Repair: cut it out exactly ({size})").format(size=isolate(format_size(max(0, (finding.end or 0) - (finding.start or 0))), self.language)), "body", wrap=True)
        else:
            what = label(t("Reported only: ") + t(finding.reason or "It can't be removed exactly."), "body", wrap=True)
            what.setStyleSheet(f"color: {tone_color('warn')};")
        what.setContentsMargins(30, 0, 0, 0)
        layout.addWidget(what)
        if finding.start is not None:
            where = label(t("Bytes {start} to {end}").format(start=isolate(f"0x{finding.start:X}", self.language), end=isolate(f"0x{(finding.end or finding.start):X}", self.language)), "mute")
            where.setContentsMargins(30, 0, 0, 0)
            layout.addWidget(where)
        return row

    def selected(self) -> list:
        return [finding for check, finding in self._checks if check.isChecked() and check.isEnabled()]

    def _sync_repair_button(self) -> None:
        chosen = self.selected()
        self.repair_button.setEnabled(bool(chosen))
        if self.path is not None:
            self.destination.setText(self.t("The repaired copy is saved next to the original, in {folder}. The original isn't touched.").format(folder=str(self.path.parent)))

    # -- step 3 -------------------------------------------------------------------------------
    def repair_selected(self) -> None:
        chosen = self.selected()
        if not chosen or self.path is None:
            return
        self.repair_button.setEnabled(False)
        self.repair_button.setText(self.t("Repairing…"))
        worker = _Repair(self.data, self.path.name, chosen, self.path.parent, self.data_dir)
        worker.done.connect(self._repaired)
        self._keep(worker)
        worker.start()

    def _repaired(self, result, output) -> None:
        t = self.t
        self.repair_button.setText(t("Repair a copy"))
        self._sync_repair_button()
        self.outcome.setVisible(True)
        self.output = output
        if output is None:
            self.success_mark.setVisible(False)
            self.outcome_title.setText("✕  " + t("Nothing was written"))
            self.outcome_body.setText(t(result.message) if result.message else t("The repair couldn't be completed."))
            failures = result.validation.failures if result.validation else {}
            self.outcome_checks.setText("; ".join(f"{k}: {v}" for k, v in failures.items()))
            self.outcome_hashes.setText("")
            self.folder_button.setVisible(False)
            self.logged.emit(f"Repair not written: {self.path} · {result.message}")
            return
        self.outcome_title.setText(t("Repaired copy saved"))
        self.success_mark.setVisible(True)
        self.success_mark.play(tone_color("ok"))
        toast(self, "✓  " + t("Repaired copy saved"), "repair")
        self.outcome_body.setText(t("“{name}” · {removed} removed · problems found: {before} before, {after} after.").format(
            name=visible(output.name), removed=isolate(format_size(result.removed_bytes), self.language), before=result.before, after=result.after))
        checks = result.validation.checks if result.validation else {}
        passed = all(value.startswith("ok") for key, value in checks.items() if key != "scores")
        self.outcome_checks.setText(
            (t("Checks passed: the copy still opens as the same kind of file, and its structure is intact.") if passed else t("Some checks need attention."))
            + " " + t("The removed parts are sealed in the encrypted quarantine."))
        self.outcome_hashes.setText(f"SHA-256 before  {result.sha256_before}\nSHA-256 after   {result.sha256_after}")
        self.folder_button.setVisible(True)
        self.logged.emit(f"Repaired copy written: {output} · removed {result.removed_bytes} bytes · findings {result.before} -> {result.after}")

    def _show_folder(self) -> None:
        if self.output is not None:
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(self.output.parent)))

    def reset(self) -> None:
        self.report, self.data, self.path, self.output = None, b"", None, None
        self.field.clear()
        self.review.setVisible(False)
        self.outcome.setVisible(False)
        self._show_error("")
        self.cube.show_empty(TONES["repair"])
        self.field.setFocus()

    # -- dropping a file here -------------------------------------------------------------
    def dragEnterEvent(self, event) -> None:  # noqa: N802
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event) -> None:  # noqa: N802
        paths = [url.toLocalFile() for url in event.mimeData().urls() if url.isLocalFile()]
        if paths:
            self.load(paths[0])
            event.acceptProposedAction()
