"""Update check for the Windows app.

On start (and once a day while the app stays open) the app reads the small public file
https://ainex-ai.xyz/downloads/windows.json (version, file name, size, SHA-256). When it names a
newer version, the window asks the user; nothing is downloaded or installed without a click.

* Offline, blocked or a broken answer: silently nothing (the next check tries again).
* "Download update" fetches the installer to %TEMP%, checks its size and SHA-256 against
  windows.json, and only then asks a second time before starting it. The installer itself shows
  its normal wizard; it is never run silently.
* "Not now" waits for the next day; "Skip this version" stays quiet until a newer one appears.

The pure functions (``parse_version``, ``is_newer``, ``check``) have no Qt dependency so they
can be tested on their own.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import ssl
import tempfile
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from urllib.parse import urljoin, urlsplit

APP_VERSION = "2.1.0"  # keep in step with installer.iss (AppVersion)
MANIFEST_URL = "https://ainex-ai.xyz/downloads/windows.json"
ALLOWED_HOSTS = ("ainex-ai.xyz", "scan.ainex-ai.xyz", "www.ainex-ai.xyz", "cyberscan-assets.s3.eu-north-1.amazonaws.com")
CHECK_EVERY = 24 * 3600
TIMEOUT = 8
MAX_INSTALLER = 600 * 1024 * 1024
USER_AGENT = f"CyberScan-Desktop/{APP_VERSION} (update check)"


def parse_version(text: str) -> tuple[int, ...]:
    """'2.1.0' -> (2, 1, 0); anything after the numbers ('-beta') is ignored. Bad input -> ()."""
    match = re.match(r"\s*v?(\d+(?:\.\d+){0,3})", str(text or ""))
    return tuple(int(part) for part in match.group(1).split(".")) if match else ()


def is_newer(remote: str, local: str = APP_VERSION) -> bool:
    a, b = parse_version(remote), parse_version(local)
    if not a or not b:
        return False
    width = max(len(a), len(b))
    return a + (0,) * (width - len(a)) > b + (0,) * (width - len(b))


@dataclass(frozen=True)
class Update:
    version: str
    url: str
    file: str
    size: int
    sha256: str


def _trusted(url: str) -> bool:
    parts = urlsplit(url)
    return parts.scheme == "https" and (parts.hostname or "").lower() in ALLOWED_HOSTS


def _open(url: str, timeout: float = TIMEOUT):
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Cache-Control": "no-cache"})
    return urllib.request.urlopen(request, timeout=timeout, context=ssl.create_default_context())  # noqa: S310 - https only, checked


def check(manifest_url: str = MANIFEST_URL, local: str = APP_VERSION) -> Update | None:
    """The newer version described by windows.json, or None (up to date, offline, or a bad answer)."""
    try:
        with _open(manifest_url) as response:
            info = json.loads(response.read(64 * 1024).decode("utf-8"))
    except Exception:  # noqa: BLE001 - offline / DNS / TLS / JSON: the app just carries on
        return None
    if not isinstance(info, dict) or not is_newer(str(info.get("version", "")), local):
        return None
    file = os.path.basename(str(info.get("file", "")))
    url = str(info.get("url") or urljoin(manifest_url, file))
    sha = str(info.get("sha256", "")).lower()
    try:
        size = int(info.get("size", 0))
    except (TypeError, ValueError):
        size = 0
    if not file.lower().endswith(".exe") or not _trusted(url) or not re.fullmatch(r"[0-9a-f]{64}", sha):
        return None
    return Update(str(info["version"]), url, file, size, sha)


def download(update: Update, progress: Callable[[int, int], None] | None = None,
             cancelled: Callable[[], bool] = lambda: False) -> Path:
    """Fetches the installer to %TEMP%\\CyberScan-update and verifies size and SHA-256."""
    folder = Path(tempfile.gettempdir()) / "CyberScan-update"
    folder.mkdir(parents=True, exist_ok=True)
    target = folder / update.file
    partial = target.with_suffix(".part")
    digest = hashlib.sha256()
    done = 0
    with _open(update.url, timeout=30) as response, open(partial, "wb") as out:
        total = int(response.headers.get("Content-Length") or update.size or 0)
        while True:
            if cancelled():
                raise InterruptedError("cancelled")
            chunk = response.read(256 * 1024)
            if not chunk:
                break
            done += len(chunk)
            if done > MAX_INSTALLER:
                raise ValueError("The download is larger than expected.")
            digest.update(chunk)
            out.write(chunk)
            if progress:
                progress(done, total)
    if (update.size and done != update.size) or digest.hexdigest() != update.sha256:
        partial.unlink(missing_ok=True)
        raise ValueError("The downloaded file does not match the published fingerprint, so it was not kept.")
    target.unlink(missing_ok=True)
    partial.rename(target)
    return target


class UpdateState:
    """When the last check ran and which version the user chose to skip (DATA_DIR/update.json)."""

    def __init__(self, path: Path) -> None:
        self.path = path
        try:
            self.data = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(self.data, dict):
                self.data = {}
        except Exception:  # noqa: BLE001
            self.data = {}

    def due(self) -> bool:
        return time.time() - float(self.data.get("last_check", 0) or 0) >= CHECK_EVERY

    def mark_checked(self) -> None:
        self.data["last_check"] = time.time()
        self._save()

    def skipped(self, version: str) -> bool:
        return self.data.get("skip_version") == version

    def skip(self, version: str) -> None:
        self.data["skip_version"] = version
        self._save()

    def _save(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(self.data), encoding="utf-8")
        except OSError:
            pass


# ------------------------------------------------------------------ Qt glue (imported lazily)
def install_update_checker(window, data_dir: Path, language: Callable[[], str]) -> None:
    """Checks on start and again whenever 24 hours have passed while the app is open."""
    from PySide6.QtCore import QThread, QTimer, Signal
    from PySide6.QtWidgets import QMessageBox, QProgressDialog

    state = UpdateState(Path(data_dir) / "update.json")

    def t(en: str, ar: str) -> str:
        return ar if language() == "ar" else en

    class CheckThread(QThread):
        found = Signal(object)

        def run(self) -> None:
            self.found.emit(check())

    class DownloadThread(QThread):
        moved = Signal(int, int)
        finished_ok = Signal(str)
        failed = Signal(str)

        def __init__(self, update: Update) -> None:
            super().__init__()
            self.update_info = update
            self.stop = False

        def run(self) -> None:
            try:
                path = download(self.update_info, lambda a, b: self.moved.emit(a, b), lambda: self.stop)
                self.finished_ok.emit(str(path))
            except InterruptedError:
                self.failed.emit("")
            except Exception as exc:  # noqa: BLE001
                self.failed.emit(str(exc))

    threads: list[QThread] = []
    window._update_threads = threads  # keep references alive

    def ask_to_run(path: str, update: Update) -> None:
        box = QMessageBox(window)
        box.setWindowTitle("CyberScan")
        box.setText(t(f"CyberScan {update.version} is downloaded and its fingerprint checked.\n\n"
                      "Close CyberScan and start the installer now?",
                      f"تم تنزيل CyberScan {update.version} والتحقق من بصمته.\n\nهل تريد إغلاق CyberScan وتشغيل المثبّت الآن؟"))
        run = box.addButton(t("Install now", "ثبّت الآن"), QMessageBox.AcceptRole)
        box.addButton(t("Later", "لاحقاً"), QMessageBox.RejectRole)
        box.exec()
        if box.clickedButton() is run:
            os.startfile(path)  # noqa: S606 - the verified installer, after the user's confirmation
            window.close()

    def start_download(update: Update) -> None:
        dialog = QProgressDialog(t("Downloading the update…", "جارٍ تنزيل التحديث…"), t("Cancel", "إلغاء"), 0, 100, window)
        dialog.setWindowTitle("CyberScan")
        dialog.setMinimumDuration(0)
        worker = DownloadThread(update)
        threads.append(worker)
        worker.moved.connect(lambda a, b: dialog.setValue(int(a * 100 / b) if b else 0))
        dialog.canceled.connect(lambda: setattr(worker, "stop", True))

        def ok(path: str) -> None:
            dialog.close()
            ask_to_run(path, update)

        def failed(message: str) -> None:
            dialog.close()
            if message:
                QMessageBox.warning(window, "CyberScan", t("The update could not be downloaded: ", "تعذّر تنزيل التحديث: ") + message)

        worker.finished_ok.connect(ok)
        worker.failed.connect(failed)
        worker.start()

    def offer(update: Update | None) -> None:
        state.mark_checked()
        if update is None or state.skipped(update.version):
            return
        size = f" ({update.size / 1048576:.0f} MB)" if update.size else ""
        box = QMessageBox(window)
        box.setWindowTitle("CyberScan")
        box.setIcon(QMessageBox.Information)
        box.setText(t(f"A new version of CyberScan is available: {update.version}{size}.\nYou have {APP_VERSION}.",
                      f"يتوفر إصدار جديد من CyberScan: {update.version}{size}.\nلديك الإصدار {APP_VERSION}."))
        get = box.addButton(t("Download update", "نزّل التحديث"), QMessageBox.AcceptRole)
        skip = box.addButton(t("Skip this version", "تخطَّ هذا الإصدار"), QMessageBox.DestructiveRole)
        box.addButton(t("Not now", "ليس الآن"), QMessageBox.RejectRole)
        box.exec()
        if box.clickedButton() is get:
            start_download(update)
        elif box.clickedButton() is skip:
            state.skip(update.version)

    def run_check(force: bool = False) -> None:
        if not force and not state.due():
            return
        worker = CheckThread()
        threads.append(worker)
        worker.found.connect(offer)
        worker.start()

    QTimer.singleShot(8000, lambda: run_check(True))  # every start, once the window has settled
    timer = QTimer(window)
    timer.setInterval(3600 * 1000)  # hourly look; a real check only when a day has passed
    timer.timeout.connect(run_check)
    timer.start()
    window._update_timer = timer


def wait_for_threads(window) -> None:
    for thread in getattr(window, "_update_threads", []):
        if hasattr(thread, "stop"):
            thread.stop = True
        thread.wait(3000)
