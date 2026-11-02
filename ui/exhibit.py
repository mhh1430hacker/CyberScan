"""Exhibit mode: live file surgery, for a screen at a stand.

A visitor picks a clean file, watches it get "infected", sends the sonar in,
and watches the infection cut out, with the file's fingerprint proving it is
the original again. Everything shown is real:

* the samples are built in memory (a picture, a PDF letter, a Word file) or
  read from Windows' own Notepad, read-only, never run and never written;
* the infection is the repair engine's inert injector: random bytes, zero
  padding or placeholder text placed the way real tampering places things;
  nothing that can run;
* the scan is ``repair_engine.analyze`` on those bytes, timed;
* the heal is ``repair_engine.analyze.repair`` (the real executor and its
  validator), and the SHA-256 shown is computed on the result.

Around it: sonar sounds, an attract loop when nobody is playing, a
"Spot the disguise" game with a leaderboard, and a souvenir card (PNG) plus
the file's point cloud (.ply) to take home.

Keys: 1-4 choose a file · Space next step · G game · S souvenir ·
L language · M sound · Esc leave.
"""
from __future__ import annotations

import hashlib
import io
import json
import random
import tempfile
import time
import wave
import zipfile
import zlib
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable

import numpy as np
from PySide6.QtCore import QBuffer, QIODevice, QPointF, QRectF, Qt, QTimer, Signal
from PySide6.QtGui import QColor, QFont, QImage, QLinearGradient, QPainter, QPen, QRadialGradient
from PySide6.QtWidgets import QFrame, QGridLayout, QHBoxLayout, QLabel, QPushButton, QVBoxLayout, QWidget

from ui import brand
from ui.copy import tr
from ui.names import visible
from ui.plain_language import format_size, isolate
from ui.sonar import SonarCube
from ui.structure import build_structure
from ui.theme import TOKENS

IDLE_SECONDS = 45
ATTRACT_STEP_MS = 3400
ROUNDS = 5
NOTEPAD = Path(r"C:\Windows\System32\notepad.exe")
STEPS = ("Choose", "Infect", "Scan", "Heal")
SEVERITY = {"high": "Serious", "medium": "Moderate", "low": "Minor"}
HUES = {"clean": TOKENS["accent"], "infected": TOKENS["warn"], "scan": "#a594ff", "healed": TOKENS["ok"]}
RLO = chr(0x202E)


# -- samples (all in memory) -----------------------------------------------------------


def picture() -> bytes:
    image = QImage(720, 440, QImage.Format.Format_RGB32)
    painter = QPainter(image)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    sky = QLinearGradient(0, 0, 0, 440)
    sky.setColorAt(0, QColor("#0b1d33"))
    sky.setColorAt(0.62, QColor("#c86b3c"))
    sky.setColorAt(1, QColor("#f2b45a"))
    painter.fillRect(image.rect(), sky)
    sun = QRadialGradient(QPointF(500, 300), 90)
    sun.setColorAt(0, QColor("#fff3c4"))
    sun.setColorAt(1, QColor(255, 220, 140, 0))
    painter.setBrush(sun)
    painter.setPen(Qt.PenStyle.NoPen)
    painter.drawEllipse(QPointF(500, 300), 90, 90)
    painter.setBrush(QColor("#2a1a22"))
    for index, height in enumerate((150, 110, 170, 95, 130)):
        painter.drawRect(QRectF(index * 150 - 20, 440 - height * 0.6, 190, height))
    painter.end()
    buffer = QBuffer()
    buffer.open(QIODevice.OpenModeFlag.WriteOnly)
    image.save(buffer, "PNG")
    return bytes(buffer.data())


def letter() -> bytes:
    """A few pages of text; the last page's drawing is compressed, as most PDFs are."""
    pages = []
    for page in range(6):
        lines = [b"BT /F1 22 Tf 60 740 Td (A letter from CyberScan, page %d) Tj ET" % (page + 1)]
        lines += [b"BT /F1 11 Tf 60 %d Td (Line %d: nothing in this file can run; it is only text and shapes.) Tj ET" % (710 - 14 * n, n)
                  for n in range(46)]
        pages.append(b"\n".join(lines))
    rng = random.Random(7)
    drawing = b"\n".join(b"%d %d %d %d re f" % (rng.randrange(600), rng.randrange(780), rng.randrange(1, 40), rng.randrange(1, 40))
                         for _ in range(5000))
    count = len(pages) + 1
    bodies = [b"<< /Type /Catalog /Pages 2 0 R >>",
              b"<< /Type /Pages /Kids [%s] /Count %d >>" % (b" ".join(b"%d 0 R" % (4 + 2 * i) for i in range(count)), count),
              b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"]
    for index, content in enumerate(pages + [zlib.compress(drawing, 9)]):
        filters = b" /Filter /FlateDecode" if index == len(pages) else b""
        bodies.append(b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents %d 0 R /Resources << /Font << /F1 3 0 R >> >> >>" % (5 + 2 * index))
        bodies.append(b"<< /Length %d%s >>\nstream\n" % (len(content), filters) + content + b"\nendstream")
    out, offsets = bytearray(b"%PDF-1.4\n"), []
    for number, body in enumerate(bodies, 1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % number + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f\r\n" % (len(bodies) + 1)
    out += b"".join(b"%010d 00000 n\r\n" % offset for offset in offsets)
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(bodies) + 1, xref)
    return bytes(out)


def word_file() -> bytes:
    paragraphs = "".join(f"<w:p><w:r><w:t>{line}</w:t></w:r></w:p>" for line in (
        "Quarterly report", "Sales grew in every region this quarter.", "Nothing in this file can run.") * 400)
    parts = {
        "[Content_Types].xml": '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Default Extension="png" ContentType="image/png"/>'
        '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>',
        "_rels/.rels": '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>',
        "word/document.xml": '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>' + paragraphs + "</w:body></w:document>",
        "word/_rels/document.xml.rels": '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId9" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="media/image1.png"/></Relationships>',
    }
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as package:
        for name, content in parts.items():
            package.writestr(zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0)), content, zipfile.ZIP_DEFLATED)
        # The report's chart, stored as Word stores pictures (already compressed, so not deflated again).
        package.writestr(zipfile.ZipInfo("word/media/image1.png", date_time=(2026, 1, 1, 0, 0, 0)), picture(), zipfile.ZIP_STORED)
    return buffer.getvalue()


def notepad() -> bytes | None:
    try:
        return NOTEPAD.read_bytes() if NOTEPAD.is_file() else None  # read only; never run, never copied
    except OSError:
        return None


@dataclass(frozen=True)
class Sample:
    key: str
    title: str  # English, translated on screen
    name: str
    build: Callable[[], bytes | None]
    families: tuple[str, ...]


SAMPLES = (
    Sample("picture", "A holiday photo", "holiday.png", picture, ("append_after_end",)),
    Sample("letter", "A PDF letter", "letter.pdf", letter, ("pdf_javascript", "pdf_embedded_file", "append_after_end")),
    Sample("word", "A Word report", "report.docx", word_file, ("ooxml_vba_part", "ooxml_embedded_object", "append_after_end")),
    Sample("program", "Windows Notepad", "notepad.exe", notepad, ("append_after_end",)),
)
FAMILY_WORDS = {
    "append_after_end": "Filler hidden after the file's end",
    "pdf_javascript": "A script slot added in a PDF update",
    "pdf_embedded_file": "An attachment added in a PDF update",
    "ooxml_vba_part": "A macro part slipped into the document",
    "ooxml_embedded_object": "An embedded object slipped into the document",
}


@dataclass
class Round:
    sample: Sample
    original: bytes
    infected: bytes | None = None
    family: str = ""
    content: str = ""
    report: object = None
    seconds: float = 0.0
    result: object = None


def infect(sample: Sample, data: bytes, rng: random.Random) -> tuple[bytes, str, str] | None:
    """An inert infection the analyzer can find and the executor can cut out exactly."""
    from repair_engine.analyze import analyze
    from repair_engine.synth.injector import inject

    families = list(sample.families)
    rng.shuffle(families)
    for family in families:
        for _attempt in range(12):
            injection = inject(data, sample.name, family, rng.randrange(1 << 30))
            if injection is None or injection.content_kind == "zeros":
                continue
            if any(f.repairable for f in analyze(injection.modified, sample.name).findings):
                return injection.modified, family, injection.content_kind
    return None


def heal(round_: Round):
    from repair_engine.analyze import repair

    chosen = [f for f in round_.report.findings if f.repairable]
    return repair(round_.infected, round_.sample.name, chosen)


def same_parts(a: bytes, b: bytes) -> bool:
    """For a rebuilt package: the same members with the same content."""
    try:
        with zipfile.ZipFile(io.BytesIO(a)) as one, zipfile.ZipFile(io.BytesIO(b)) as two:
            return sorted(one.namelist()) == sorted(two.namelist()) and all(one.read(n) == two.read(n) for n in one.namelist())
    except (zipfile.BadZipFile, OSError, ValueError):
        return False


# -- sound -------------------------------------------------------------------------------


class Sounds:
    """Short synthesised cues, played asynchronously (Windows only; silent elsewhere)."""

    RATE = 22050

    def __init__(self) -> None:
        self.enabled = True
        self.folder = Path(tempfile.mkdtemp(prefix="cyberscan_sounds_"))
        self.paths: dict[str, Path] = {}
        try:
            import winsound  # noqa: F401
        except ImportError:
            self.enabled = False
            return
        for name, samples in self._cues().items():
            path = self.folder / f"{name}.wav"
            with wave.open(str(path), "wb") as out:
                out.setnchannels(1)
                out.setsampwidth(2)
                out.setframerate(self.RATE)
                out.writeframes((np.clip(samples, -1, 1) * 30000).astype("<i2").tobytes())
            self.paths[name] = path

    def _tone(self, frequency: float, seconds: float, decay: float = 6.0, start: float = 0.0) -> np.ndarray:
        t = np.arange(int(self.RATE * (start + seconds))) / self.RATE
        wave_ = np.sin(2 * np.pi * frequency * t) * np.exp(-decay * np.maximum(t - start, 0)) * (t >= start)
        return wave_

    def _mix(self, *parts: np.ndarray) -> np.ndarray:
        length = max(len(p) for p in parts)
        out = np.zeros(length)
        for part in parts:
            out[: len(part)] += part
        return out / max(1.0, np.abs(out).max() / 0.9)

    def _cues(self) -> dict[str, np.ndarray]:
        ping = self._tone(1480, 0.9, 7)
        echo = self._mix(ping, 0.45 * self._tone(1480, 0.7, 8, 0.32), 0.2 * self._tone(1480, 0.5, 9, 0.62))
        found = self._mix(self._tone(740, 0.5, 5), self._tone(523, 0.7, 4, 0.16))
        healed = self._mix(*(0.8 * self._tone(f, 1.2, 3, i * 0.11) for i, f in enumerate((523.3, 659.3, 784.0, 1046.5))))
        infect_ = self._mix(self._tone(220, 0.5, 6), 0.6 * self._tone(233, 0.5, 6, 0.05))
        tick = self._tone(2200, 0.05, 60)
        wrong = self._mix(self._tone(196, 0.35, 5), self._tone(185, 0.35, 5, 0.12))
        return {"ping": ping, "echo": echo, "found": found, "healed": healed, "infect": infect_, "tick": tick, "wrong": wrong}

    def play(self, name: str) -> None:
        path = self.paths.get(name)
        if not self.enabled or path is None:
            return
        import winsound

        try:
            winsound.PlaySound(str(path), winsound.SND_FILENAME | winsound.SND_ASYNC | winsound.SND_NODEFAULT)
        except RuntimeError:
            pass


# -- the disguise game ---------------------------------------------------------------


STEMS = ("invoice_2026", "holiday", "CV_Sara", "payslip", "contract", "tickets", "scan_0412", "party_photos", "menu", "results")
HARMLESS = ("pdf", "jpg", "docx", "png", "xlsx", "mp4", "txt")
PROGRAMS = ("exe", "scr", "js", "bat", "com")


def disguised_name(rng: random.Random) -> tuple[str, str]:
    """A program named to look harmless, and how it was disguised."""
    stem, decoy, real = rng.choice(STEMS), rng.choice(HARMLESS), rng.choice(PROGRAMS)
    trick = rng.choice(("rlo", "double", "spaces"))
    if trick == "rlo":
        # Right-to-left override: the end of the name is drawn backwards.
        return f"{stem}{RLO}{decoy[::-1]}.{real}", "rlo"
    if trick == "double":
        return f"{stem}.{decoy}.{real}", "double"
    return f"{stem}.{decoy}{' ' * 34}.{real}", "spaces"


def game_round(rng: random.Random) -> tuple[list[str], int, str]:
    names = rng.sample(STEMS, 2)
    honest = [f"{stem}.{rng.choice(HARMLESS)}" for stem in names]
    fake, trick = disguised_name(rng)
    answer = rng.randrange(3)
    honest.insert(answer, fake)
    return honest, answer, trick


TRICKS = {
    "rlo": "A hidden right-to-left character drew the end of the name backwards. It's really a program.",
    "double": "The real extension is the last one. The first one is a decoy.",
    "spaces": "Many spaces push the real extension out of sight.",
}


class Leaderboard:
    def __init__(self, path: Path | None):
        self.path = path

    def load(self) -> list[dict]:
        if self.path is None:
            return []
        try:
            rows = json.loads(self.path.read_text(encoding="utf-8"))
            return [r for r in rows if isinstance(r, dict) and isinstance(r.get("score"), int)][:50]
        except (OSError, ValueError):
            return []

    def add(self, initials: str, score: int) -> int:
        rows = self.load()
        row = {"initials": initials[:3].upper() or "???", "score": int(score), "when": datetime.now().isoformat(timespec="seconds")}
        rows.append(row)
        rows.sort(key=lambda r: (-r["score"], r["when"]))
        if self.path is not None:
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                self.path.write_text(json.dumps(rows[:50], indent=1), encoding="utf-8")
            except OSError:
                pass
        return rows.index(row) + 1


# -- souvenir -----------------------------------------------------------------------------


def write_ply(structure, path: Path) -> None:
    """The file's cells as a coloured point cloud (opens in Blender, MeshLab, Windows 3D Viewer)."""
    lines = ["ply", "format ascii 1.0", f"element vertex {structure.count}", "property float x", "property float y", "property float z",
             "property uchar red", "property uchar green", "property uchar blue", "end_header"]
    for (x, y, z), entropy, flag in zip(structure.positions, structure.entropy, structure.flags):
        level = float(entropy) / 8.0
        red, green, blue = (240, 90, 90) if flag else (int(40 + 60 * level), int(120 + 120 * level), int(140 + 90 * level))
        lines.append(f"{x:.4f} {y:.4f} {z:.4f} {red} {green} {blue}")
    path.write_text("\n".join(lines) + "\n", encoding="ascii")


# -- the screen ---------------------------------------------------------------------------


class ExhibitWindow(QWidget):
    closed = Signal()

    def __init__(self, language: str = "en", data_dir: Path | None = None, parent=None):
        super().__init__(parent)
        self.language = language
        self.data_dir = Path(data_dir) if data_dir else None
        self.rng = random.Random()
        self.sounds = Sounds()
        self.board = Leaderboard(self.data_dir / "exhibit" / "leaderboard.json" if self.data_dir else None)
        self.round: Round | None = None
        self.step = 0  # 0 choose, 1 chosen, 2 infected, 3 found, 4 healed
        self.attract = False
        self.game: dict | None = None
        self.souvenir: Path | None = None
        self._samples: dict[str, bytes | None] = {}
        self.setWindowTitle("CyberScan · Exhibit")
        self.setObjectName("exhibit")
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.setStyleSheet(STYLE)

        root = QVBoxLayout(self)
        root.setContentsMargins(48, 28, 48, 24)
        root.setSpacing(10)
        top = QHBoxLayout()
        self.mark = brand.SonarMark(54)
        top.addWidget(self.mark)
        self.brand_label = QLabel()
        self.brand_label.setObjectName("brand")
        top.addWidget(self.brand_label)
        top.addStretch(1)
        self.step_labels = []
        for _step in STEPS:
            chip = QLabel()
            chip.setObjectName("step")
            top.addWidget(chip)
            self.step_labels.append(chip)
        root.addLayout(top)

        self.cube = SonarCube(interactive=True, reduced_motion=False, height=520)
        self.cube.turntable = True
        self.cube.label_for = lambda region: self.t(SEVERITY.get(region.severity, "Moderate"))
        root.addWidget(self.cube, 1)

        self.headline = QLabel()
        self.headline.setObjectName("headline")
        self.headline.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.headline.setWordWrap(True)
        root.addWidget(self.headline)
        self.caption = QLabel()
        self.caption.setObjectName("caption")
        self.caption.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.caption.setWordWrap(True)
        root.addWidget(self.caption)
        self.proof = QLabel()
        self.proof.setObjectName("proof")
        self.proof.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.proof.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
        root.addWidget(self.proof)

        # The game takes the place of the sample cards while it runs.
        self.cards = QWidget()
        cards = QHBoxLayout(self.cards)
        cards.setSpacing(16)
        self.card_buttons: list[QPushButton] = []
        for index, sample in enumerate(SAMPLES):
            button = QPushButton()
            button.setObjectName("sample")
            button.setCursor(Qt.CursorShape.PointingHandCursor)
            button.setFocusPolicy(Qt.FocusPolicy.NoFocus)
            button.clicked.connect(lambda _c=False, i=index: self._pressed(lambda: self.choose(i)))
            cards.addWidget(button)
            self.card_buttons.append(button)
        root.addWidget(self.cards)

        self.game_panel = QFrame()
        self.game_panel.setObjectName("game")
        game = QGridLayout(self.game_panel)
        game.setContentsMargins(24, 16, 24, 16)
        game.setHorizontalSpacing(16)
        self.game_buttons: list[QPushButton] = []
        for index in range(3):
            button = QPushButton()
            button.setObjectName("choice")
            button.setFocusPolicy(Qt.FocusPolicy.NoFocus)
            button.setCursor(Qt.CursorShape.PointingHandCursor)
            button.clicked.connect(lambda _c=False, i=index: self._pressed(lambda: self.answer(i)))
            game.addWidget(button, 0, index)
            self.game_buttons.append(button)
        self.game_panel.setVisible(False)
        root.addWidget(self.game_panel)

        bottom = QHBoxLayout()
        self.next_button = QPushButton()
        self.next_button.setObjectName("next")
        self.next_button.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.next_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.next_button.clicked.connect(lambda: self._pressed(self.advance))
        self.keys = QLabel()
        self.keys.setObjectName("keys")
        self.keys.setWordWrap(True)
        self.board_label = QLabel()
        self.board_label.setObjectName("board")
        self.board_label.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        bottom.addWidget(self.next_button)
        bottom.addSpacing(18)
        bottom.addWidget(self.keys, 1)
        bottom.addWidget(self.board_label)
        root.addLayout(bottom)

        self.idle = QTimer(self)
        self.idle.setSingleShot(True)
        self.idle.timeout.connect(self.start_attract)
        self.attract_timer = QTimer(self)
        self.attract_timer.timeout.connect(self._attract_step)
        self.cube.finished.connect(self._echo_done)
        self.retranslate()
        self.reset()

    # -- text -----------------------------------------------------------------------------
    def t(self, text: str) -> str:
        return tr(text, self.language)

    def retranslate(self) -> None:
        rtl = self.language == "ar"
        self.setLayoutDirection(Qt.LayoutDirection.RightToLeft if rtl else Qt.LayoutDirection.LeftToRight)
        self.brand_label.setText(f"{brand.name(self.language)}  ·  {self.t('Live file surgery')}")
        self.brand_label.setFont(QFont(brand.family(self.language), 26, QFont.Weight.DemiBold))
        for index, sample in enumerate(SAMPLES):
            available = self._sample(index) is not None
            self.card_buttons[index].setText(f"{index + 1}\n{self.t(sample.title)}\n{sample.name}")
            self.card_buttons[index].setEnabled(available)
        self.keys.setText(self.t("Space next · 1–4 choose a file · G spot the disguise · S souvenir · L language · M sound · Esc leave"))
        self._render()

    def _sample(self, index: int) -> bytes | None:
        sample = SAMPLES[index]
        if sample.key not in self._samples:
            self._samples[sample.key] = sample.build()
        return self._samples[sample.key]

    # -- the surgery ------------------------------------------------------------------------
    def reset(self) -> None:
        self.round, self.step, self.souvenir = None, 0, None
        self.cube.show_empty(HUES["clean"])
        self._render()

    def choose(self, index: int) -> None:
        data = self._sample(index)
        if data is None or self.game is not None:
            return
        self.round = Round(SAMPLES[index], data)
        self.step, self.souvenir = 1, None
        self.cube.highlight([])
        self.cube.show_structure(build_structure(data, None, {}, {}), HUES["clean"])
        self.sounds.play("tick")
        self._render()

    def advance(self) -> None:
        if self.game is not None:
            return
        if self.round is None or self.step == 0:
            self.choose(self.rng.choice([i for i in range(len(SAMPLES)) if self._sample(i) is not None]))
        elif self.step == 1:
            self._infect()
        elif self.step == 2:
            self._scan()
        elif self.step == 3:
            self._heal()
        elif self.step == 4:
            self.reset()

    def _infect(self) -> None:
        infected = infect(self.round.sample, self.round.original, self.rng)
        if infected is None:
            self.caption.setText(self.t("This file can't be infected safely for the demo. Choose another."))
            return
        self.round.infected, self.round.family, self.round.content = infected
        self.step = 2
        self.cube.show_structure(build_structure(self.round.infected, None, {}, {}), HUES["infected"])
        self.sounds.play("infect")
        self._render()

    def _scan(self) -> None:
        from repair_engine.analyze import analyze

        started = time.perf_counter()
        self.round.report = analyze(self.round.infected, self.round.sample.name)
        self.round.seconds = time.perf_counter() - started
        position = {"entropy_boundaries": [
            {"offset_start": f.start, "offset_end": max(f.end, f.start + 1), "severity": f.severity}
            for f in self.round.report.findings if f.start is not None and f.end is not None]}
        self.step = 3
        self.cube.start(HUES["scan"])
        self.sounds.play("ping")
        self._render(scanning=True)
        structure = build_structure(self.round.infected, None, {}, position)
        QTimer.singleShot(1800, lambda r=self.round: r is self.round and self.step == 3 and self._reveal(structure))

    def _reveal(self, structure) -> None:
        self.sounds.play("echo")
        self.cube.reveal(structure)

    def _echo_done(self) -> None:
        if self.step == 3 and self.round is not None:
            self.sounds.play("found")
            flagged = np.nonzero(self.cube.structure.flags)[0] if self.cube.structure is not None else []
            self.cube.highlight(flagged)
            self._render()

    def _heal(self) -> None:
        self.round.result = heal(self.round)
        self.step = 4
        repaired = self.round.result.repaired if self.round.result.ok else None
        if repaired is not None:
            self.cube.highlight([])
            self.cube.show_structure(build_structure(repaired, None, {}, {}), HUES["healed"])
            self.sounds.play("healed")
        else:
            self.sounds.play("wrong")
        self._render()

    # -- what the screen says ------------------------------------------------------------
    def _render(self, scanning: bool = False) -> None:
        t, lang = self.t, self.language
        for index, chip in enumerate(self.step_labels):
            chip.setVisible(self.game is None)
            active = self.step >= 1 and min(self.step - 1, 3) == index or (self.step == 0 and index == 0)
            done = self.step - 1 > index or self.step == 4
            chip.setText(f"{'✓' if done and not active else index + 1}  {t(STEPS[index])}")
            chip.setProperty("state", "active" if active else "done" if done else "")
            chip.style().unpolish(chip)
            chip.style().polish(chip)
        self.cards.setVisible(self.game is None)
        self.game_panel.setVisible(self.game is not None)
        self.board_label.setText(self._board_text())
        self.next_button.setText({0: t("Start"), 1: t("Infect it"), 2: t("Send the sonar in"), 3: t("Heal it"), 4: t("Again")}[self.step])
        self.next_button.setVisible(self.game is None)
        if self.game is not None:
            return self._render_game()
        round_ = self.round
        self.proof.setText("")
        if self.step == 0:
            self.headline.setText(t("Can you find what's hiding inside a file?"))
            self.caption.setText(t("Pick a file. We'll slip something into it, then send a sonar inside to find it and cut it out."))
        elif self.step == 1:
            self.headline.setText(t(round_.sample.title))
            self.caption.setText(t("Every dot is a slice of the file's real bytes: brighter means denser data. {size}, clean.").format(
                size=isolate(format_size(len(round_.original)), lang)))
            self.proof.setText("SHA-256  " + hashlib.sha256(round_.original).hexdigest())
        elif self.step == 2:
            grown = len(round_.infected) - len(round_.original)
            self.headline.setText(t("Infected. Can you see where?"))
            self.caption.setText(t("{what}. It's harmless filler for the demo, placed the way real tampering is. The name hasn't changed; the size grew by {size}.").format(
                what=t(FAMILY_WORDS.get(round_.family, "Something was added")), size=isolate(format_size(grown), lang)))
            self.proof.setText("SHA-256  " + hashlib.sha256(round_.infected).hexdigest())
        elif self.step == 3 and (scanning or self.cube.phase in {"drawing", "scanning", "echo", "flag"}):
            self.headline.setText(t("Sending the sonar in…"))
            self.caption.setText(t("Reading the file's structure, not guessing."))
        elif self.step == 3:
            findings = round_.report.findings
            first = findings[0] if findings else None
            self.headline.setText(t("Found it in {ms} ms").format(ms=isolate(f"{round_.seconds * 1000:.0f}", lang)))
            if first is not None:
                where = t("Bytes {start} to {end}").format(start=isolate(f"0x{first.start or 0:X}", lang), end=isolate(f"0x{first.end or 0:X}", lang))
                self.caption.setText(f"{t(first.title)} · {where}")
        elif self.step == 4:
            result = round_.result
            if not result.ok or result.repaired is None:
                self.headline.setText(t("This one can't be healed exactly"))
                self.caption.setText(t(result.message or "The repair couldn't be completed."))
                return
            exact = result.repaired == round_.original
            self.headline.setText(t("Healed. It's the original again.") if exact or same_parts(result.repaired, round_.original) else t("Healed"))
            removed = isolate(format_size(result.removed_bytes), lang)
            if exact:
                self.caption.setText(t("{size} cut out. The fingerprint matches the original byte for byte.").format(size=removed))
            else:
                self.caption.setText(t("{size} cut out. Every part matches the original.").format(size=removed))
            before, after = hashlib.sha256(round_.original).hexdigest(), hashlib.sha256(result.repaired).hexdigest()
            self.proof.setText(f"SHA-256  {before[:24]}…  {'=' if exact else '≈'}  {after[:24]}…  {'✓' if exact else ''}")
            if self.souvenir is not None:
                self.caption.setText(self.caption.text() + "  " + t("Souvenir saved: {name}").format(name=self.souvenir.name))

    # -- game --------------------------------------------------------------------------------
    def start_game(self) -> None:
        self.stop_attract()
        self.round, self.step, self.souvenir = None, 0, None
        self.cube.highlight([])
        self.cube.show_empty("#a594ff")
        self.game = {"round": 0, "score": 0, "streak": 0, "started": time.monotonic(), "answered": None, "initials": None}
        self._next_game_round()

    def _next_game_round(self) -> None:
        names, answer, trick = game_round(self.rng)
        self.game.update(names=names, answer=answer, trick=trick, answered=None, shown_at=time.monotonic())
        self.game["round"] += 1
        self._render()

    def answer(self, index: int) -> None:
        game = self.game
        if game is None or game.get("initials") is not None:
            return
        if game["answered"] is not None:
            if game["round"] >= ROUNDS:
                game["initials"] = ""
                self._render()
            else:
                self._next_game_round()
            return
        game["answered"] = index
        if index == game["answer"]:
            game["streak"] += 1
            game["score"] += 100 + max(0, int(60 - 12 * (time.monotonic() - game["shown_at"]))) + 20 * (game["streak"] - 1)
            self.sounds.play("found")
        else:
            game["streak"] = 0
            self.sounds.play("wrong")
        self._render()

    def _render_game(self) -> None:
        t, game = self.t, self.game
        self.proof.setText("")
        if game.get("initials") is not None:
            self.headline.setText(t("Score: {score}").format(score=game["score"]))
            self.caption.setText(t("Type your initials, then press Enter: {initials}").format(initials=(game["initials"] + "___")[:3]))
            for button in self.game_buttons:
                button.setVisible(False)
            return
        self.headline.setText(t("Spot the disguise · round {n} of {total}").format(n=game["round"], total=ROUNDS))
        answered = game["answered"]
        for index, (button, name) in enumerate(zip(self.game_buttons, game["names"])):
            button.setVisible(True)
            if answered is None:
                button.setText(f"{index + 1}\n{name}")
                button.setProperty("state", "")
            else:
                truth = visible(name).replace(" " * 34, " ⟦…34 spaces…⟧ ")
                button.setText(f"{'✓' if index == game['answer'] else '·'}\n{truth}")
                button.setProperty("state", "right" if index == game["answer"] else "wrong" if index == answered else "")
            button.style().unpolish(button)
            button.style().polish(button)
        if answered is None:
            self.caption.setText(t("One of these is a program pretending to be something else. Which one? Press 1, 2 or 3."))
        else:
            verdict = t("Right!") if answered == game["answer"] else t("Not this time.")
            self.caption.setText(f"{verdict} {t(TRICKS[game['trick']])}  ·  {t('Score: {score}').format(score=game['score'])}  ·  {t('Press any number to continue')}")

    def _type_initial(self, text: str) -> None:
        game = self.game
        if text and text.isalpha() and text.isascii() and len(game["initials"]) < 3:
            game["initials"] += text.upper()
            self.sounds.play("tick")
            self._render()

    def _finish_game(self) -> None:
        place = self.board.add(self.game["initials"] or "???", self.game["score"])
        self.game = None
        self.sounds.play("healed")
        self.reset()
        self.caption.setText(self.t("You placed #{place} on the board.").format(place=place))

    def _board_text(self) -> str:
        rows = self.board.load()[:5]
        if not rows:
            return ""
        lines = [self.t("Best disguise spotters")] + [f"{i}. {r['initials']}  {r['score']}" for i, r in enumerate(rows, 1)]
        return "\n".join(lines)

    # -- souvenir ----------------------------------------------------------------------
    def save_souvenir(self) -> Path | None:
        if self.step != 4 or self.round is None or self.round.result is None or not self.round.result.ok or self.data_dir is None:
            return None
        folder = self.data_dir / "exhibit" / "souvenirs"
        folder.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        card = QImage(1080, 1350, QImage.Format.Format_ARGB32)
        card.fill(QColor("#07090c"))
        painter = QPainter(card)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.drawImage(QRectF(40, 170, 1000, 760), self.cube.grab().toImage())
        brand.paint_mark(painter, QRectF(60, 50, 84, 84))
        painter.setPen(QColor("#e9eef2"))
        painter.setFont(QFont(brand.family(self.language), 40, QFont.Weight.DemiBold))
        painter.drawText(QRectF(170, 48, 860, 90), Qt.AlignmentFlag.AlignVCenter, brand.name(self.language))
        painter.setFont(QFont("Segoe UI", 30, QFont.Weight.DemiBold))
        painter.drawText(QRectF(60, 950, 960, 60), Qt.AlignmentFlag.AlignLeft, self.t("I healed {name}").format(name=self.round.sample.name))
        painter.setFont(QFont("Segoe UI", 20))
        painter.setPen(QColor("#9aa7b2"))
        lines = [self.t(FAMILY_WORDS.get(self.round.family, "Something was added")),
                 self.t("Found in {ms} ms").format(ms=f"{self.round.seconds * 1000:.0f}") + " · "
                 + self.t("{size} cut out").format(size=format_size(self.round.result.removed_bytes)),
                 datetime.now().strftime("%Y-%m-%d %H:%M")]
        for index, line in enumerate(lines):
            painter.drawText(QRectF(60, 1020 + index * 40, 960, 40), Qt.AlignmentFlag.AlignLeft, line)
        painter.setFont(QFont("Consolas", 14))
        painter.setPen(QColor(TOKENS["ok"]))
        painter.drawText(QRectF(60, 1160, 960, 30), Qt.AlignmentFlag.AlignLeft, "SHA-256 " + hashlib.sha256(self.round.result.repaired).hexdigest())
        painter.setPen(QPen(QColor(TOKENS["accent"]), 3))
        painter.drawRoundedRect(QRectF(16, 16, 1048, 1318), 28, 28)
        painter.end()
        path = folder / f"surgery-{stamp}.png"
        card.save(str(path), "PNG")
        structure = build_structure(self.round.infected, None, {}, {"entropy_boundaries": [
            {"offset_start": f.start, "offset_end": max(f.end, f.start + 1), "severity": f.severity}
            for f in self.round.report.findings if f.start is not None and f.end is not None]})
        if structure is not None:
            write_ply(structure, folder / f"surgery-{stamp}.ply")
        self.souvenir = path
        self.sounds.play("tick")
        self._render()
        return path

    # -- attract loop -------------------------------------------------------------------
    def start_attract(self) -> None:
        if self.game is not None:
            self.game = None
        self.attract = True
        self.reset()
        self.attract_timer.start(ATTRACT_STEP_MS)
        self._attract_step()

    def stop_attract(self) -> None:
        if self.attract:
            self.attract = False
            self.attract_timer.stop()
            self.reset()

    def _attract_step(self) -> None:
        if not self.attract:
            return
        if self.step == 3 and self.cube.phase != "explore":
            return  # let the sonar finish
        sounds, self.sounds.enabled = self.sounds.enabled, False  # the loop plays quietly
        try:
            self.advance()
        finally:
            self.sounds.enabled = sounds
        self.keys.setText(self.t("Press any key to try it yourself"))

    def _pressed(self, action: Callable[[], None]) -> None:
        was_attract = self.attract
        self.stop_attract()
        self.idle.start(IDLE_SECONDS * 1000)
        if not was_attract:
            action()
        if was_attract:
            self.retranslate()

    # -- input ---------------------------------------------------------------------------
    def showEvent(self, event) -> None:  # noqa: N802
        super().showEvent(event)
        self.idle.start(IDLE_SECONDS * 1000)
        self.setFocus()

    def keyPressEvent(self, event) -> None:  # noqa: N802
        key, text = event.key(), event.text()
        if key == Qt.Key.Key_Escape:
            if self.game is not None:
                self._pressed(lambda: (setattr(self, "game", None), self.reset()))
                return
            self.close()
            return
        if self.attract:  # any key hands the stand to the visitor
            self._pressed(lambda: None)
            return
        if self.game is not None and self.game.get("initials") is not None:
            self.idle.start(IDLE_SECONDS * 1000)
            if key in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
                self._finish_game()
            elif key == Qt.Key.Key_Backspace:
                self.game["initials"] = self.game["initials"][:-1]
                self._render()
            else:
                self._type_initial(text)
            return
        actions = {
            Qt.Key.Key_Space: self.advance, Qt.Key.Key_Return: self.advance, Qt.Key.Key_Enter: self.advance,
            Qt.Key.Key_G: self.start_game, Qt.Key.Key_S: self.save_souvenir,
            Qt.Key.Key_L: self.toggle_language, Qt.Key.Key_M: self.toggle_sound,
        }
        if Qt.Key.Key_1 <= key <= Qt.Key.Key_4:
            index = key - Qt.Key.Key_1
            action = (lambda: self.answer(index)) if self.game is not None else (lambda: self.choose(index))
        else:
            action = actions.get(key)
        if action is not None:
            self._pressed(action)
        else:
            super().keyPressEvent(event)

    def mousePressEvent(self, event) -> None:  # noqa: N802
        if self.attract:  # a touch screen wakes it too
            self._pressed(lambda: None)
        super().mousePressEvent(event)

    def toggle_language(self) -> None:
        self.language = "ar" if self.language == "en" else "en"
        self.retranslate()

    def toggle_sound(self) -> None:
        self.sounds.enabled = not self.sounds.enabled and bool(self.sounds.paths)

    def closeEvent(self, event) -> None:  # noqa: N802
        self.idle.stop()
        self.attract_timer.stop()
        self.cube.stop()
        self.closed.emit()
        super().closeEvent(event)


STYLE = f"""
QWidget#exhibit {{ background: #05070a; }}
QLabel {{ color: #e9eef2; background: transparent; }}
QLabel#brand {{ color: #e9eef2; }}
QLabel#step {{ color: #6d7780; font-size: 18px; padding: 8px 16px; border: 1px solid #1c232b; border-radius: 18px; }}
QLabel#step[state="active"] {{ color: #05070a; background: {TOKENS['accent']}; border-color: {TOKENS['accent']}; font-weight: 600; }}
QLabel#step[state="done"] {{ color: {TOKENS['ok']}; border-color: #1f3b33; }}
QLabel#headline {{ font-size: 52px; font-weight: 700; }}
QLabel#caption {{ color: #aab6c0; font-size: 26px; }}
QLabel#proof {{ color: {TOKENS['ok']}; font-family: Consolas, monospace; font-size: 17px; }}
QLabel#keys {{ color: #59636c; font-size: 16px; }}
QLabel#board {{ color: #aab6c0; font-size: 16px; }}
QPushButton#sample {{ color: #e9eef2; background: #0d1217; border: 1px solid #1c232b; border-radius: 22px; padding: 18px; font-size: 22px; min-height: 96px; }}
QPushButton#sample:hover {{ border-color: {TOKENS['accent']}; }}
QPushButton#sample:disabled {{ color: #3a434b; }}
QPushButton#next {{ color: #05070a; background: {TOKENS['accent']}; border: 0; border-radius: 26px; padding: 14px 34px; font-size: 24px; font-weight: 700; }}
QFrame#game {{ background: transparent; }}
QPushButton#choice {{ color: #e9eef2; background: #0d1217; border: 1px solid #1c232b; border-radius: 22px; padding: 22px; font-size: 26px; min-height: 120px; }}
QPushButton#choice[state="right"] {{ border: 2px solid {TOKENS['ok']}; color: {TOKENS['ok']}; }}
QPushButton#choice[state="wrong"] {{ border: 2px solid {TOKENS['danger']}; color: {TOKENS['danger']}; }}
"""
