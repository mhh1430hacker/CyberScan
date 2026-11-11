"""Run scans in a separate, long-lived process.

The engine is CPU-bound Python. Run in a thread of the interface process, it
holds the interpreter lock for long stretches and the window stops painting
(the UI audit measured freezes of up to 1.4 s). One worker process, started
once and kept warm, runs every scan instead; the interface only waits on a
queue, so animation never stutters.

Nothing here touches Qt, and nothing changes what the engine does: the worker
calls ``ScanService.analyze`` exactly as before and streams its progress
reports back through a queue, tagged with the scan's id.
"""
from __future__ import annotations

import multiprocessing
import os
import queue
import threading
from concurrent.futures import Future, ProcessPoolExecutor
from concurrent.futures.process import BrokenProcessPool
from typing import Any

_progress_queue: Any = None
_service: Any = None


def _init(progress_queue: Any) -> None:
    global _progress_queue
    _progress_queue = progress_queue


def _warm() -> bool:
    global _service
    from ui.scan_service import ScanService

    if _service is None:
        _service = ScanService()
    return True


def _run(scan_id: int, candidate: str, mode: str, settings: dict[str, Any]):
    _warm()

    def report(index: int, state: str, detail: str) -> None:
        _progress_queue.put((scan_id, index, state, detail))

    return _service.analyze(candidate, mode, settings, report)


def enabled() -> bool:
    """Scans run out of process unless CYBERSCAN_SCAN_IN_PROCESS=0 (tests)."""
    return os.environ.get("CYBERSCAN_SCAN_IN_PROCESS", "1").strip() not in {"0", "false", "no"}


class ScanHost:
    """The single worker process, created on first use and recreated if it dies."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._executor: ProcessPoolExecutor | None = None
        self._queue: Any = None
        self._next_id = 0
        self._pending: dict[int, list[tuple]] = {}

    def _ensure(self) -> ProcessPoolExecutor:
        with self._lock:
            if self._executor is None:
                context = multiprocessing.get_context("spawn")
                self._queue = context.Queue()
                self._executor = ProcessPoolExecutor(
                    max_workers=1, mp_context=context, initializer=_init, initargs=(self._queue,)
                )
            return self._executor

    def warm_up(self) -> None:
        """Start the process and import the engine ahead of the first scan."""
        try:
            self._ensure().submit(_warm)
        except (BrokenProcessPool, RuntimeError, OSError):
            self.reset()

    def submit(self, candidate: str, mode: str, settings: dict[str, Any]) -> tuple[int, Future]:
        executor = self._ensure()
        with self._lock:
            self._next_id += 1
            scan_id = self._next_id
        return scan_id, executor.submit(_run, scan_id, candidate, mode, settings)

    def progress(self, scan_id: int, timeout: float):
        """The next (index, state, detail) report for ``scan_id``, or None.

        Reports for other scans (a cancelled one still finishing) are kept
        for their own reader, never dropped or misdelivered.
        """
        with self._lock:
            pending = self._pending.get(scan_id)
            if pending:
                return pending.pop(0)
        try:
            item = self._queue.get(timeout=timeout)
        except (queue.Empty, OSError, EOFError, ValueError, AttributeError):
            return None
        owner, report = item[0], tuple(item[1:])
        if owner == scan_id:
            return report
        with self._lock:
            self._pending.setdefault(owner, []).append(report)
        return None

    def forget(self, scan_id: int) -> None:
        with self._lock:
            self._pending.pop(scan_id, None)

    def reset(self) -> None:
        with self._lock:
            executor, self._executor = self._executor, None
        if executor is not None:
            executor.shutdown(wait=False, cancel_futures=True)

    def shutdown(self) -> None:
        with self._lock:
            executor, self._executor = self._executor, None
        if executor is not None:
            processes = list((getattr(executor, "_processes", None) or {}).values())
            executor.shutdown(wait=False, cancel_futures=True)
            for process in processes:
                if process.is_alive():
                    process.terminate()


HOST = ScanHost()
