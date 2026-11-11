"""The observatory: a scanned file's galaxy, over the whole window.

Opened from the result ("See its galaxy"). The galaxy forms off the UI
thread, is born in a big bang, then turns; the legend says how to read it,
"Save as wallpaper" paints it at the screen's resolution (also off the UI
thread) into Pictures\\CyberScan galaxies, and Esc or Close leaves.
"""
from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import QStandardPaths, QThread, QUrl, Qt, Signal
from PySide6.QtGui import QDesktopServices, QGuiApplication
from PySide6.QtWidgets import QHBoxLayout, QLabel, QPushButton, QVBoxLayout, QWidget

from ui import brand
from ui.copy import tr
from ui.galaxy import BANDS, Galaxy, GalaxyView, _band_image, render_wallpaper
from ui.motion import fade_in
from ui.polish import toast
from ui.theme import TOKENS

LEGEND = (
    "The core is the start of the file; the rim is its end.",
    "Blue: quiet content · white: structured · gold: scrambled or compressed.",
    "Red and amber stars: the places the scan flagged.",
)


class _Form(QThread):
    """Renders the three bands of a galaxy (the expensive part) away from the UI."""

    formed = Signal(object, int)

    def __init__(self, galaxy: Galaxy, side: int):
        super().__init__()
        self.galaxy, self.side = galaxy, side

    def run(self) -> None:
        bands = [_band_image(self.galaxy, self.side, inner, outer) for inner, outer, _speed in BANDS]
        self.formed.emit(bands, self.side)


class _Wallpaper(QThread):
    saved = Signal(object, object)  # (path | None, error | None)

    def __init__(self, galaxy: Galaxy, size, path: Path, title: str, subtitle: str, family: str):
        super().__init__()
        self.galaxy, self.size, self.path, self.title, self.subtitle, self.family = galaxy, size, path, title, subtitle, family

    def run(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            image = render_wallpaper(self.galaxy, self.size[0], self.size[1], self.title, self.subtitle, self.family)
            if not image.save(str(self.path), "PNG"):
                raise OSError("the picture could not be written")
            self.saved.emit(self.path, None)
        except Exception as exc:  # noqa: BLE001 - shown to the user
            self.saved.emit(None, exc)


def wallpaper_folder() -> Path:
    pictures = QStandardPaths.writableLocation(QStandardPaths.StandardLocation.PicturesLocation) or str(Path.home())
    return Path(pictures) / "CyberScan galaxies"


class Observatory(QWidget):
    closed = Signal()
    logged = Signal(str)

    def __init__(self, parent: QWidget, galaxy: Galaxy, name: str, language: str, describe=None):
        super().__init__(parent)
        self.galaxy, self.name, self.language = galaxy, name, language
        self.output: Path | None = None
        self._threads: list[QThread] = []
        self.setObjectName("observatory")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setStyleSheet("QWidget#observatory { background: #020205; }")
        self.setGeometry(parent.rect())
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.setLayoutDirection(Qt.LayoutDirection.RightToLeft if language == "ar" else Qt.LayoutDirection.LeftToRight)

        self.view = GalaxyView(self)
        self.view.describe = describe
        self.view.setGeometry(self.rect())

        overlay = QVBoxLayout(self)
        overlay.setContentsMargins(36, 28, 36, 26)
        top = QHBoxLayout()
        heading = QVBoxLayout()
        heading.setSpacing(4)
        self.title = QLabel(self.t("The galaxy of {name}").format(name=name))
        self.title.setStyleSheet(f"color: #f1f3f8; font-family: '{brand.family(language)}'; font-size: 28px; font-weight: 600; background: transparent;")
        self.subtitle = QLabel(self.t("No other file has this galaxy: its shape comes from the file's SHA-256 fingerprint, and every star is a real slice of its bytes."))
        self.subtitle.setWordWrap(True)
        self.subtitle.setMaximumWidth(620)
        self.subtitle.setStyleSheet("color: #9aa3b8; font-size: 14px; background: transparent;")
        heading.addWidget(self.title)
        heading.addWidget(self.subtitle)
        top.addLayout(heading)
        top.addStretch(1)
        self.save_button = QPushButton(self.t("Save as wallpaper"))
        self.save_button.setObjectName("primary")
        self.save_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.save_button.clicked.connect(self.save_wallpaper)
        self.close_button = QPushButton(self.t("Close") + "  ·  Esc")
        self.close_button.setObjectName("ghost")
        self.close_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.close_button.clicked.connect(self.close_observatory)
        top.addWidget(self.save_button, 0, Qt.AlignmentFlag.AlignTop)
        top.addWidget(self.close_button, 0, Qt.AlignmentFlag.AlignTop)
        overlay.addLayout(top)
        overlay.addStretch(1)
        self.forming = QLabel(self.t("Forming its galaxy…"))
        self.forming.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.forming.setStyleSheet("color: #c9c2ff; font-size: 16px; background: transparent;")
        overlay.addWidget(self.forming)
        overlay.addStretch(1)
        legend = QHBoxLayout()
        legend.setSpacing(22)
        self.legend_labels = []
        for line in LEGEND:
            item = QLabel(self.t(line))
            item.setWordWrap(True)
            item.setStyleSheet(f"color: #aab3c6; font-size: 13px; background: rgba(8, 9, 16, 0.6); border: 1px solid rgba(255,255,255,0.07); border-radius: 10px; padding: 8px 12px;")
            legend.addWidget(item, 1)
            self.legend_labels.append(item)
        self.hint = QLabel(self.t("Drag to orbit · scroll to zoom · point at a star to read it"))
        self.hint.setStyleSheet(f"color: {TOKENS['text_mute']}; font-size: 12px; background: transparent;")
        overlay.addLayout(legend)
        overlay.addSpacing(8)
        overlay.addWidget(self.hint, 0, Qt.AlignmentFlag.AlignHCenter)

        screen = QGuiApplication.primaryScreen()
        span = max(parent.width(), parent.height())
        if screen is not None:
            span = max(span, screen.size().height())
        side = int(min(2600, span * (screen.devicePixelRatio() if screen else 1.0) * 1.05))
        former = _Form(galaxy, side)
        former.formed.connect(self._formed)
        self._keep(former)
        former.start()

    def t(self, text: str) -> str:
        return tr(text, self.language)

    def _keep(self, thread: QThread) -> None:
        self._threads.append(thread)
        thread.finished.connect(lambda t=thread: t in self._threads and self._threads.remove(t))

    def wait(self, timeout: int = 60000) -> None:
        for thread in list(self._threads):
            thread.wait(timeout)

    def _formed(self, bands, side: int) -> None:
        from ui.galaxy import GalaxyPainter

        artist = GalaxyPainter(self.galaxy)
        artist._bands, artist._side = bands, side
        artist.prepare = lambda _side: None  # formed once, at the screen's size; scaled from then on
        self.view.artist = artist
        self.view.set_galaxy_painter(artist)
        self.forming.setVisible(False)
        self.logged.emit(f"Galaxy formed for {self.name} ({self.galaxy.arms} arms)")

    @property
    def ready(self) -> bool:
        return self.view.artist is not None

    # -- actions --------------------------------------------------------------------------
    def open(self) -> None:
        self.show()
        self.raise_()
        self.setFocus()
        fade_in(self)

    def close_observatory(self) -> None:
        self.wait()
        self.hide()
        self.closed.emit()
        self.deleteLater()

    def save_wallpaper(self) -> None:
        screen = QGuiApplication.primaryScreen()
        ratio = screen.devicePixelRatio() if screen else 1.0
        size = screen.size() if screen else None
        width, height = (int(size.width() * ratio), int(size.height() * ratio)) if size else (3840, 2160)
        width, height = max(width, 1920), max(height, 1080)
        stem = re.sub(r"[^\w.-]+", "_", Path(self.name).stem)[:60] or "file"
        path = wallpaper_folder() / f"{stem} galaxy {datetime.now():%Y-%m-%d %H%M%S}.png"
        self.save_button.setEnabled(False)
        self.save_button.setText(self.t("Saving…"))
        worker = _Wallpaper(self.galaxy, (width, height), path, self.t("The galaxy of {name}").format(name=self.name),
                            "CyberScan · SHA-256 " + self.galaxy.sha256, brand.family(self.language))
        worker.saved.connect(self._saved)
        self._keep(worker)
        worker.start()

    def _saved(self, path, error) -> None:
        self.save_button.setEnabled(True)
        self.save_button.setText(self.t("Save as wallpaper"))
        if path is None:
            toast(self, "✕  " + self.t("The wallpaper couldn't be saved.") + f" ({error})", "warn")
            return
        self.output = Path(path)
        toast(self, "✓  " + self.t("Wallpaper saved in Pictures › CyberScan galaxies"), "ok")
        self.logged.emit(f"Galaxy wallpaper saved: {path}")

    def show_folder(self) -> None:
        if self.output is not None:
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(self.output.parent)))

    # -- events ------------------------------------------------------------------------------
    def resizeEvent(self, event) -> None:  # noqa: N802
        super().resizeEvent(event)
        self.view.setGeometry(self.rect())

    def keyPressEvent(self, event) -> None:  # noqa: N802
        if event.key() == Qt.Key.Key_Escape:
            self.close_observatory()
            return
        super().keyPressEvent(event)
