from __future__ import annotations

import logging
import queue
import threading
from pathlib import Path
from typing import Callable

logger = logging.getLogger(__name__)


class DownloadMonitor:
    PARTIAL_SUFFIXES = (".crdownload", ".download", ".part", ".partial", ".tmp")

    def __init__(
        self,
        directory: str,
        callback: Callable[[str], None] | None = None,
        *,
        poll_interval: float = 2.0,
        stable_polls: int = 2,
    ):
        if poll_interval <= 0:
            raise ValueError("poll_interval must be positive.")
        if isinstance(stable_polls, bool) or not isinstance(stable_polls, int) or stable_polls < 1:
            raise ValueError("stable_polls must be a positive integer.")
        self.directory = Path(directory)
        self.callback = callback
        self.poll_interval = poll_interval
        self.stable_polls = stable_polls
        self.queue: queue.Queue[str] = queue.Queue()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._seen: dict[Path, tuple[int, int]] = {}
        self._pending: dict[Path, tuple[int, int, int]] = {}

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._prime_existing_files()
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def _prime_existing_files(self) -> None:
        if not self.directory.exists():
            return
        try:
            for path in self.directory.iterdir():
                if not path.is_file() or path.suffix.casefold() in self.PARTIAL_SUFFIXES:
                    continue
                try:
                    stat = path.stat()
                    self._seen[path.resolve()] = (stat.st_size, stat.st_mtime_ns)
                except OSError:
                    logger.debug("Unable to baseline existing download: %s", path, exc_info=True)
        except OSError:
            logger.exception("Unable to baseline monitored directory %s", self.directory)

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=max(2.0, self.poll_interval + 0.5))

    def _scan_once(self) -> None:
        if not self.directory.exists():
            return
        try:
            paths = sorted(self.directory.iterdir())
        except OSError:
            logger.exception("Unable to enumerate monitored directory %s", self.directory)
            return

        observed: set[Path] = set()
        for path in paths:
            if not path.is_file() or path.suffix.casefold() in self.PARTIAL_SUFFIXES:
                continue
            try:
                resolved = path.resolve()
                stat = path.stat()
            except OSError:
                logger.debug("Download is not ready for inspection: %s", path, exc_info=True)
                continue
            observed.add(resolved)
            signature = (stat.st_size, stat.st_mtime_ns)
            if self._seen.get(resolved) == signature:
                continue
            self._seen.pop(resolved, None)
            previous = self._pending.get(resolved)
            stable_count = previous[2] + 1 if previous and previous[:2] == signature else 1
            self._pending[resolved] = (signature[0], signature[1], stable_count)
            if stable_count < self.stable_polls:
                continue
            try:
                with path.open("rb") as handle:
                    handle.read(1)
                current_stat = path.stat()
            except OSError:
                logger.debug("Download is locked or not readable yet: %s", path, exc_info=True)
                self._pending[resolved] = (signature[0], signature[1], 0)
                continue
            if (current_stat.st_size, current_stat.st_mtime_ns) != signature:
                self._pending[resolved] = (
                    current_stat.st_size,
                    current_stat.st_mtime_ns,
                    0,
                )
                continue
            self._seen[resolved] = signature
            self._pending.pop(resolved, None)
            file_path = str(path)
            if self.callback:
                try:
                    self.callback(file_path)
                except Exception:
                    logger.exception("Download monitor callback failed for %s", file_path)
            else:
                self.queue.put(file_path)

        for stale_path in self._pending.keys() - observed:
            self._pending.pop(stale_path, None)

    def _loop(self) -> None:
        while not self._stop_event.is_set():
            self._scan_once()
            self._stop_event.wait(self.poll_interval)

    def get_next(self) -> str | None:
        try:
            return self.queue.get_nowait()
        except queue.Empty:
            return None

    def manual_scan_directory(self) -> list[str]:
        files: list[str] = []
        if not self.directory.exists():
            return files
        for path in sorted(self.directory.iterdir()):
            if path.is_file():
                files.append(str(path))
        return files
