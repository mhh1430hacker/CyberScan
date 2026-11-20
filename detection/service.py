"""Request-level wrapper for web backends: limits, timeouts, concurrency and error envelopes.

``detection.engine`` functions are pure analysis calls: they assume their input is admissible
and they take as long as they take. A web route needs more than that, and every route would
otherwise reimplement it. ``ScanService`` adds:

* admission  — empty / oversized input is rejected before any parsing;
* concurrency — at most ``max_concurrency`` analyses run at once; extra requests wait up to
  ``queue_timeout`` seconds, then get ``busy`` (HTTP 503) instead of piling up;
* timeouts   — ``isolation="process"`` runs each analysis in a separate worker process that is
  killed on timeout (hard limit, also contains a parser crash or memory blow-up). Workers are
  started ahead of time and reused (imports, YARA and YARA-Forge rules stay loaded), recycled
  after ``max_tasks_per_worker`` analyses, and replaced after a crash or a timeout;
  ``isolation="thread"`` returns ``timeout`` on time but cannot stop the work, so the
  concurrency slot stays taken until the work really ends (no pile-up);
* errors     — every outcome is a JSON-serialisable envelope; exceptions never escape.

``isolation="auto"`` picks ``thread`` on AWS Lambda and ``process`` elsewhere. On Lambda this is a
conservative default, not a verified limitation: Lambda has no /dev/shm (so multiprocessing pools,
queues and locks fail), but the single spawn ``Process`` + ``Pipe`` used here has not been tested there.
Verify with a Lambda smoke test before setting ``CYBERSCAN_ISOLATION=process`` (detection/INTEGRATION.md §4).

Envelope::

    {"status": "ok" | "rejected" | "busy" | "timeout" | "error",
     "result": {...} | None,
     "error": {"code": str, "message": str, "en": str, "ar": str} | None,
     "elapsed_ms": int, "engine": {"version": str, "isolation": str}}
"""
from __future__ import annotations

import logging
import multiprocessing
import os
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable

ENGINE_VERSION = "2026.11.10"

# Formats with a dedicated analyzer (sniffed from content, never from the file name).
SUPPORTED_FORMATS: dict[str, str] = {
    "pdf": "PDF documents",
    "ooxml": "Office Open XML (.docx/.docm/.xlsx/.xlsm/.pptx/.pptm)",
    "word / excel / powerpoint / ole": "Legacy Office and other OLE compound files (.doc/.xls/.ppt)",
    "outlook-msg": "Outlook messages (.msg)",
    "rtf": "Rich Text Format",
    "archive": "ZIP archives (and .jar/.whl and other ZIP containers)",
    "apk": "Android packages",
    "browser-extension": "Chrome/Edge/Firefox extensions (.crx/.xpi/.zip with manifest.json)",
    "pe": "Windows executables and DLLs",
    "elf": "Linux executables",
    "image": "PNG/JPEG/GIF/BMP/TIFF/WebP (QR codes decoded when the decoder is installed)",
    "email": "Raw e-mail (.eml) and other RFC 822 text",
    "text": "Scripts and other text (tradecraft rules, links, secrets)",
}

HTTP_STATUS = {"ok": 200, "rejected": 413, "busy": 503, "timeout": 504, "error": 500}


@dataclass(frozen=True)
class ScanLimits:
    max_bytes: int = 50 * 1024 * 1024
    max_text_chars: int = 200_000
    timeout_seconds: float = 30.0
    max_concurrency: int = max(1, min(4, (os.cpu_count() or 2)))
    queue_timeout_seconds: float = 5.0
    max_tasks_per_worker: int = 200


def _default_isolation() -> str:
    if os.environ.get("CYBERSCAN_ISOLATION") in {"process", "thread"}:
        return os.environ["CYBERSCAN_ISOLATION"]
    return "thread" if os.environ.get("AWS_LAMBDA_FUNCTION_NAME") else "process"


# --------------------------------------------------------------------------- operations
# Top-level functions so a spawned child process can import and run them.

def _op_inspect(data: bytes, file_name: str) -> dict[str, Any]:
    from detection.engine import _jsonable, inspect_content, safe_file_name
    result = inspect_content(data, safe_file_name(file_name))
    result["indicators"] = [item.as_dict() for item in result["indicators"] if item.category != "privacy"]
    return _jsonable(result)


def _op_analyze_upload(data: bytes, file_name: str, settings: dict | None) -> dict[str, Any]:
    from detection.engine import analyze_upload
    return analyze_upload(data, file_name, settings)


def _op_analyze_text(value: str, settings: dict | None) -> dict[str, Any]:
    from detection.engine import analyze_text_json
    return analyze_text_json(value, settings)


_OPERATIONS: dict[str, Callable[..., dict[str, Any]]] = {
    "inspect": _op_inspect, "analyze_upload": _op_analyze_upload, "analyze_text": _op_analyze_text,
}


def _child(connection, operation: str, args: tuple) -> None:
    """One analysis in a throw-away process (kept for callers that want no warm state)."""
    try:
        connection.send(("ok", _OPERATIONS[operation](*args)))
    except Exception as exc:  # reported to the parent as an error envelope
        connection.send(("error", f"{type(exc).__name__}: {str(exc)[:300]}"))
    finally:
        connection.close()


WARM_SAMPLE = b"CyberScan worker warm-up sample: ordinary text, nothing to see here.\n"


def _warm_up() -> None:
    """Load what every analysis needs once: the engine modules, the bundled YARA rules and the
    YARA-Forge rules (deserialising 8.7 MB of compiled rules takes about a second)."""
    try:
        _op_analyze_upload(WARM_SAMPLE, "warm-up.txt", None)
        _op_inspect(WARM_SAMPLE, "warm-up.txt")
    except Exception:  # noqa: BLE001 - a warm-up problem shows up (and is reported) on the first real call
        pass


def _worker_main(connection, warm: bool = True) -> None:
    """A reusable analysis worker: warm up, say ready, then serve one request at a time."""
    if warm:
        _warm_up()
    try:
        connection.send(("ready", os.getpid()))
    except (OSError, EOFError):
        return
    while True:
        try:
            message = connection.recv()
        except (EOFError, OSError):
            break
        if message is None:
            break
        operation, args = message
        try:
            reply = ("ok", _OPERATIONS[operation](*args))
        except Exception as exc:  # reported to the parent as an error envelope
            reply = ("error", f"{type(exc).__name__}: {str(exc)[:300]}")
        try:
            connection.send(reply)
        except (OSError, EOFError):
            break
    connection.close()


class _Worker:
    """Parent-side handle of one worker process. Used by one request at a time."""

    def __init__(self, context, warm: bool = True) -> None:
        self.connection, child = context.Pipe(duplex=True)
        self.process = context.Process(target=_worker_main, args=(child, warm), daemon=True,
                                       name="cyberscan-sentinel-worker")
        try:
            self.process.start()
        finally:
            child.close()
        self.ready = False
        self.tasks = 0

    def wait_ready(self, timeout: float) -> bool:
        if self.ready:
            return True
        try:
            if self.connection.poll(timeout):
                status, _pid = self.connection.recv()
                self.ready = status == "ready"
        except (EOFError, OSError):
            self.ready = False
        return self.ready

    def alive(self) -> bool:
        return self.process.is_alive()

    def call(self, operation: str, args: tuple, timeout: float) -> tuple[str, Any]:
        self.tasks += 1
        self.connection.send((operation, args))
        if not self.connection.poll(timeout):
            return "timeout", None
        return self.connection.recv()

    def stop(self, kill: bool = False) -> None:
        try:
            if not kill and self.process.is_alive():
                self.connection.send(None)
                self.process.join(timeout=1)
        except (OSError, EOFError, ValueError):
            pass
        try:
            self.connection.close()
        except OSError:
            pass
        if self.process.is_alive():
            self.process.kill()
        self.process.join(timeout=2)


class _WorkerPool:
    """Pre-started, reusable worker processes.

    A worker is checked out for one request and checked back in when it answered normally. A
    worker that timed out, crashed or served ``max_tasks`` requests is stopped (killed when it may
    still be busy) and a replacement is started in the background, so the next request again finds
    a warm worker."""

    def __init__(self, size: int, max_tasks: int = 200, ready_timeout: float = 120.0) -> None:
        self.size = max(1, size)
        self.max_tasks = max(1, max_tasks)
        self.ready_timeout = ready_timeout
        self._context = multiprocessing.get_context("spawn")
        self._idle: list[_Worker] = []
        self._starting = 0
        self._busy = 0
        self._lock = threading.Lock()
        self._closed = False

    def _spawn_in_background(self) -> None:
        with self._lock:
            if self._closed or len(self._idle) + self._starting + self._busy >= self.size:
                return
            if self._idle or self._starting:
                return  # one warm spare is enough; more start when they are needed
            self._starting += 1

        def start() -> None:
            worker = None
            try:
                worker = _Worker(self._context)
                worker.wait_ready(self.ready_timeout)
            except OSError:
                worker = None
            finally:
                with self._lock:
                    self._starting -= 1
                    if worker is not None and worker.ready and worker.alive() and not self._closed:
                        self._idle.append(worker)
                        worker = None
            if worker is not None:
                worker.stop(kill=True)

        threading.Thread(target=start, name="cyberscan-worker-start", daemon=True).start()

    def prestart(self) -> None:
        self._spawn_in_background()

    def checkout(self, wait_for_spare: float = 0.0) -> _Worker:
        """An idle warm worker; else (after waiting up to ``wait_for_spare`` seconds for one that is
        starting) a new one."""
        deadline = time.monotonic() + wait_for_spare
        while True:
            with self._lock:
                worker = None
                while self._idle:
                    candidate = self._idle.pop()
                    if candidate.alive():
                        worker = candidate
                        break
                    candidate.stop(kill=True)
                starting = self._starting
                if worker is not None or not starting or time.monotonic() >= deadline:
                    self._busy += 1
                    break
            time.sleep(0.02)
        if worker is None:
            try:
                worker = _Worker(self._context)
            except Exception:
                with self._lock:
                    self._busy -= 1
                raise
        self._spawn_in_background()  # keep one warm spare for the next request
        return worker

    def checkin(self, worker: _Worker, healthy: bool) -> None:
        keep = healthy and worker.alive() and worker.tasks < self.max_tasks
        with self._lock:
            self._busy -= 1
            if keep and not self._closed:
                self._idle.append(worker)
                return
        worker.stop(kill=not healthy)
        self._spawn_in_background()

    def counts(self) -> dict[str, int]:
        with self._lock:
            return {"idle": len(self._idle), "starting": self._starting, "busy": self._busy}

    def shutdown(self) -> None:
        with self._lock:
            self._closed = True
            idle, self._idle = self._idle, []
        for worker in idle:
            worker.stop()


# --------------------------------------------------------------------------- service

class ScanService:
    def __init__(self, limits: ScanLimits | None = None, isolation: str = "auto"):
        self.limits = limits or ScanLimits()
        self.isolation = _default_isolation() if isolation == "auto" else isolation
        if self.isolation not in {"process", "thread"}:
            raise ValueError("isolation must be 'auto', 'process' or 'thread'")
        self._slots = threading.BoundedSemaphore(self.limits.max_concurrency)
        self._pool: _WorkerPool | None = (
            _WorkerPool(self.limits.max_concurrency, max_tasks=self.limits.max_tasks_per_worker)
            if self.isolation == "process" else None
        )

    def warm(self) -> None:
        """Start a worker process now, so the first scan does not pay for imports and rule loading.
        Returns at once; the worker warms up in the background."""
        if self._pool is not None:
            self._pool.prestart()
        else:
            threading.Thread(target=_warm_up, name="cyberscan-warm-up", daemon=True).start()

    def shutdown(self) -> None:
        if self._pool is not None:
            self._pool.shutdown()

    # -- public API --------------------------------------------------------------------------
    def inspect_upload(self, data: bytes, file_name: str) -> dict[str, Any]:
        """Content inspection only (detection.engine.inspect_content): the fast path for web tools."""
        rejected = self._admit_bytes(data)
        return rejected or self._run("inspect", (bytes(data), file_name or ""))

    def analyze_upload(self, data: bytes, file_name: str, settings: dict | None = None) -> dict[str, Any]:
        """Full pipeline (detection.engine.analyze_upload): host file analyzer + content inspection."""
        rejected = self._admit_bytes(data)
        return rejected or self._run("analyze_upload", (bytes(data), file_name or "", settings))

    def analyze_text(self, value: str, settings: dict | None = None) -> dict[str, Any]:
        """URL, message or hash (detection.engine.analyze_text_json)."""
        if not isinstance(value, str) or not value.strip():
            return self._envelope("rejected", error=("empty_input", "Enter a link, message or hash."))
        if len(value) > self.limits.max_text_chars:
            return self._envelope("rejected", error=("too_large", f"Text is longer than {self.limits.max_text_chars:,} characters."))
        return self._run("analyze_text", (value, settings))

    def describe(self) -> dict[str, Any]:
        """Static facts for a status endpoint or the upload form."""
        from detection.host import host_capabilities
        return {"engine_version": ENGINE_VERSION, "isolation": self.isolation, "max_bytes": self.limits.max_bytes,
                "timeout_seconds": self.limits.timeout_seconds, "max_concurrency": self.limits.max_concurrency,
                "supported_formats": SUPPORTED_FORMATS, "host": host_capabilities()}

    @staticmethod
    def http_status(envelope: dict[str, Any]) -> int:
        if envelope.get("status") == "rejected" and (envelope.get("error") or {}).get("code") == "empty_input":
            return 400
        return HTTP_STATUS.get(envelope.get("status", "error"), 500)

    # -- internals ---------------------------------------------------------------------------
    def _admit_bytes(self, data: Any) -> dict[str, Any] | None:
        if not isinstance(data, (bytes, bytearray, memoryview)):
            return self._envelope("rejected", error=("empty_input", "Upload body must be raw bytes."))
        if len(data) == 0:
            return self._envelope("rejected", error=("empty_input", "The uploaded file is empty."))
        if len(data) > self.limits.max_bytes:
            return self._envelope("rejected", error=("too_large", f"The file is larger than {self.limits.max_bytes:,} bytes."))
        return None

    def _envelope(self, status: str, result: dict | None = None, error: tuple[str, str] | None = None,
                  started: float | None = None) -> dict[str, Any]:
        return {
            "status": status,
            "result": result,
            "error": _error(*error) if error else None,
            "elapsed_ms": int((time.monotonic() - started) * 1000) if started else 0,
            "engine": {"version": ENGINE_VERSION, "isolation": self.isolation},
        }

    def _run(self, operation: str, args: tuple) -> dict[str, Any]:
        started = time.monotonic()
        if not self._slots.acquire(timeout=self.limits.queue_timeout_seconds):
            return self._envelope("busy", error=("busy", "The scanner is at capacity. Try again shortly."), started=started)
        if self.isolation == "process":
            try:
                status, payload = self._in_process(operation, args)
            finally:
                self._slots.release()
        else:
            status, payload = self._in_thread(operation, args)  # releases the slot itself
        if status == "ok":
            return self._envelope("ok", result=payload, started=started)
        if status == "timeout":
            return self._envelope("timeout", error=("timeout", f"The check took longer than its {self.limits.timeout_seconds:g}-second limit, so it was stopped."), started=started)
        if status == "rejected":
            return self._envelope("rejected", error=("too_large", payload), started=started)
        # The worker's own text (an exception name and message) goes to the log, never to the visitor.
        logger.warning("Sentinel %s failed: %s", operation, payload)
        if isinstance(payload, str) and payload.startswith("TimeoutError"):
            return self._envelope("timeout", error=("timeout", ""), started=started)
        return self._envelope("error", error=("analysis_failed", ""), started=started)

    def _in_process(self, operation: str, args: tuple) -> tuple[str, Any]:
        assert self._pool is not None
        try:
            # a spare that is already warming up is usually faster than a brand-new process
            worker = self._pool.checkout(wait_for_spare=self.limits.timeout_seconds)
        except OSError as exc:
            logger.warning("Could not start the analysis worker: %r", exc)
            return "error", "worker_start_failed"
        healthy = False
        try:
            if not worker.wait_ready(self._pool.ready_timeout):
                return "error", "The analysis worker did not start."
            status, payload = worker.call(operation, args, self.limits.timeout_seconds)
            if status == "timeout":
                return "timeout", None  # the worker may still be busy: it is killed below
            healthy = True
            return self._classify(status, payload)
        except (EOFError, OSError):
            return "error", f"The analysis worker stopped unexpectedly (exit code {worker.process.exitcode})."
        finally:
            self._pool.checkin(worker, healthy)

    def _in_thread(self, operation: str, args: tuple) -> tuple[str, Any]:
        outcome: dict[str, Any] = {}

        def work() -> None:
            try:
                outcome["value"] = ("ok", _OPERATIONS[operation](*args))
            except Exception as exc:
                outcome["value"] = ("error", f"{type(exc).__name__}: {str(exc)[:300]}")
            finally:
                self._slots.release()  # held until the work truly ends, even after a timeout

        worker = threading.Thread(target=work, name=f"cyberscan-{operation}", daemon=True)
        worker.start()
        worker.join(self.limits.timeout_seconds)
        if worker.is_alive():
            return "timeout", None
        return self._classify(*outcome["value"])

    @staticmethod
    def _classify(status: str, payload: Any) -> tuple[str, Any]:
        # analyze_upload enforces the host's maximum_file_size with ValueError("...maximum file size.")
        if status == "error" and isinstance(payload, str) and "maximum file size" in payload:
            return "rejected", payload
        return status, payload


logger = logging.getLogger("cyberscan.sentinel")


def _error(code: str, message: str = "") -> dict[str, str]:
    """A stable code and friendly words (English and Arabic). Python exception text never goes in
    here: ``message`` is either one of the fixed sentences below or a limit stated by this module."""
    from core.status_text import error_text  # noqa: PLC0415

    words = error_text(code)
    english = message if message and code in {"too_large", "empty_input", "busy", "timeout"} else words["en"]
    return {"code": code, "message": english, "en": english, "ar": words["ar"]}


_DEFAULT: ScanService | None = None
_DEFAULT_LOCK = threading.Lock()


def default_service() -> ScanService:
    """Process-wide service built from environment variables (see detection/INTEGRATION.md)."""
    global _DEFAULT
    with _DEFAULT_LOCK:
        if _DEFAULT is None:
            env = os.environ
            _DEFAULT = ScanService(ScanLimits(
                max_bytes=int(env.get("CYBERSCAN_MAX_BYTES", ScanLimits.max_bytes)),
                timeout_seconds=float(env.get("CYBERSCAN_TIMEOUT", ScanLimits.timeout_seconds)),
                max_concurrency=int(env.get("CYBERSCAN_CONCURRENCY", ScanLimits().max_concurrency)),
                queue_timeout_seconds=float(env.get("CYBERSCAN_QUEUE_TIMEOUT", ScanLimits.queue_timeout_seconds)),
            ))
        return _DEFAULT
