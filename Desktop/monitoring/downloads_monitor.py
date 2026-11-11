from __future__ import annotations

import queue
import threading
from pathlib import Path
from typing import Callable

# Files still being written by a browser/downloader; scanning them early gives wrong results.
TEMPORARY_SUFFIXES = (".crdownload", ".part", ".partial", ".tmp", ".download", ".opdownload")


class DownloadMonitor:
    """Polls a directory and reports files that appear *after* start().

    - Files already present at start are not re-reported (the old monitor flooded the UI with
      the whole Downloads folder on first start).
    - Temporary download files are skipped until they are renamed.
    - A file is reported only once its size is stable between two polls.
    - Callback errors cannot kill the polling thread, and the monitor can be restarted.
    """

    def __init__(
        self,
        directory: str,
        callback: Callable[[str], None] | None = None,
        poll_interval: float = 2.0,
    ):
        self.directory = Path(directory)
        self.callback = callback
        self.poll_interval = poll_interval
        self.queue: queue.Queue[str] = queue.Queue()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._seen: set[str] = set()
        self._pending_sizes: dict[str, int] = {}

    def _list_files(self) -> list[Path]:
        try:
            return sorted(path for path in self.directory.iterdir() if path.is_file())
        except OSError:
            return []

    def is_running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def start(self) -> None:
        if self.is_running():
            return
        self._stop_event.clear()
        self._pending_sizes.clear()
        self._seen = {path.name for path in self._list_files()}  # baseline: ignore existing files
        self._thread = threading.Thread(target=self._loop, daemon=True, name="CyberScanDownloadMonitor")
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=max(2.0, self.poll_interval + 1.0))

    def poll_once(self) -> list[str]:
        """Run one detection pass and return newly confirmed files (also queued and passed to callback)."""
        reported: list[str] = []
        for path in self._list_files():
            name = path.name
            if name in self._seen or name.lower().endswith(TEMPORARY_SUFFIXES):
                continue
            try:
                size = path.stat().st_size
            except OSError:
                continue
            if self._pending_sizes.get(name) != size:
                self._pending_sizes[name] = size  # still changing (or first sighting): wait one more poll
                continue
            self._pending_sizes.pop(name, None)
            self._seen.add(name)
            self.queue.put(str(path))
            reported.append(str(path))
            if self.callback:
                try:
                    self.callback(str(path))
                except Exception:  # a faulty callback must not stop monitoring
                    pass
        return reported

    def _loop(self) -> None:
        while not self._stop_event.is_set():
            self.poll_once()
            self._stop_event.wait(self.poll_interval)

    def get_next(self) -> str | None:
        try:
            return self.queue.get_nowait()
        except queue.Empty:
            return None

    def manual_scan_directory(self) -> list[str]:
        return [str(path) for path in self._list_files()]
