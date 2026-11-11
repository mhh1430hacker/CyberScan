"""Request-level wrapper for web backends: limits, timeouts, concurrency and error envelopes.

``detection.engine`` functions are pure analysis calls: they assume their input is admissible
and they take as long as they take. A web route needs more than that, and every route would
otherwise reimplement it. ``ScanService`` adds:

* admission  — empty / oversized input is rejected before any parsing;
* concurrency — at most ``max_concurrency`` analyses run at once; extra requests wait up to
  ``queue_timeout`` seconds, then get ``busy`` (HTTP 503) instead of piling up;
* timeouts   — ``isolation="process"`` runs each analysis in a fresh child process that is
  killed on timeout (hard limit, also contains a parser crash or memory blow-up);
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
     "error": {"code": str, "message": str} | None,
     "elapsed_ms": int, "engine": {"version": str, "isolation": str}}
"""
from __future__ import annotations

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
    try:
        connection.send(("ok", _OPERATIONS[operation](*args)))
    except Exception as exc:  # reported to the parent as an error envelope
        connection.send(("error", f"{type(exc).__name__}: {str(exc)[:300]}"))
    finally:
        connection.close()


# --------------------------------------------------------------------------- service

class ScanService:
    def __init__(self, limits: ScanLimits | None = None, isolation: str = "auto"):
        self.limits = limits or ScanLimits()
        self.isolation = _default_isolation() if isolation == "auto" else isolation
        if self.isolation not in {"process", "thread"}:
            raise ValueError("isolation must be 'auto', 'process' or 'thread'")
        self._slots = threading.BoundedSemaphore(self.limits.max_concurrency)

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
            "error": {"code": error[0], "message": error[1]} if error else None,
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
            return self._envelope("timeout", error=("timeout", f"Analysis exceeded {self.limits.timeout_seconds:g} seconds."), started=started)
        if status == "rejected":
            return self._envelope("rejected", error=("too_large", payload), started=started)
        return self._envelope("error", error=("analysis_failed", payload), started=started)

    def _in_process(self, operation: str, args: tuple) -> tuple[str, Any]:
        context = multiprocessing.get_context("spawn")
        receiver, sender = context.Pipe(duplex=False)
        process = context.Process(target=_child, args=(sender, operation, args), daemon=True)
        try:
            process.start()
        except OSError as exc:
            receiver.close()
            sender.close()
            return "error", f"Could not start the analysis worker ({type(exc).__name__})."
        sender.close()
        try:
            if not receiver.poll(self.limits.timeout_seconds):
                return "timeout", None
            status, payload = receiver.recv()
            return self._classify(status, payload)
        except (EOFError, OSError):
            return "error", f"The analysis worker stopped unexpectedly (exit code {process.exitcode})."
        finally:
            receiver.close()
            if process.is_alive():
                process.kill()
            process.join(timeout=2)

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
