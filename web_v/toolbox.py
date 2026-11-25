"""The Toolbox: the CyberScan security tools (``Tools/``) behind the web app.

The tools themselves, their metadata and their trust gate live in ``Tools/``: discovery parses
metadata without importing anything, and a tool runs only if its source hash is approved in
``Tools/registry.json`` and its input and output match the schemas it declares
(``Tools.registry.ToolRegistry``). This module adds what the registry leaves to its caller:

* **a public policy**: on the public website, three kinds of tools are neither listed nor run:
  tools that inspect the machine they run on (system-security: on a server that would be the
  server, not the visitor's computer); tools that open network connections to addresses a visitor
  types (their HTTP helper has no private-address guard, so they could be pointed inside the
  cloud); and tools that declare filesystem access (some walk a "directory" on the machine). As a
  second, independent guard, inputs that name a place on disk ("directory", "paths", "root") are
  refused for every tool. A "path" that only labels supplied content is fine and allowed.
  On the desktop, run locally, every approved tool is available.
* **input checks first**: an empty form, a missing required field or input that doesn't match the
  tool's schema is refused with HTTP 400 and plain words, before anything runs.
* **a hard time limit**: each run happens in its own process, killed when its deadline passes, so a
  slow or hostile tool can't hold the server (on AWS Lambda, one request per instance, a thread).
* **size limits** that fit where the site runs (AWS Lambda accepts at most 6 MB per request).
* **a cached catalog**, so listing tools doesn't re-parse a hundred files on every request.
"""
from __future__ import annotations

import concurrent.futures as cf
import logging
import multiprocessing
import os
import threading
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
PUBLIC_BLOCKED_CATEGORIES = {"system-security"}
PUBLIC_BLOCKED_INPUTS = {"directory", "paths", "root"}       # places on the server's disk
# System tools that can also analyse what the visitor pastes (an export, a list, a config) and open
# no connection nor folder: on the website they run on pasted content only ("source" must not be
# "local", which would read the server itself).
PUBLIC_PASTE_TOOLS = {
    "cyberscan.system.firewall-config", "cyberscan.system.installed-software", "cyberscan.system.persistence-auditor",
    "cyberscan.system.process-security", "cyberscan.system.scheduled-tasks", "cyberscan.system.config-auditor",
    "cyberscan.system.update-status",
}
PUBLIC_MAX_BODY = 5_600_000          # bytes of JSON (base64 inflates by 4/3: about 4 MB of file)
LOCAL_MAX_BODY = 70_000_000
TIMEOUT_SECONDS = 20                 # public website
LOCAL_TIMEOUT_SECONDS = 60           # the desktop / local server

_pool = cf.ThreadPoolExecutor(max_workers=3, thread_name_prefix="toolbox")   # AWS Lambda only
_slots = threading.BoundedSemaphore(3)     # tools running at once
_lock = threading.Lock()
_cache: dict[str, Any] = {"at": 0.0, "records": None}


class ToolboxError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


def _registry():
    from Tools.registry import ToolRegistry  # noqa: PLC0415 - imported on first use

    return ToolRegistry(ROOT / "Tools")


def _records() -> list:
    with _lock:
        if _cache["records"] is None or time.monotonic() - _cache["at"] > 60:
            _cache["records"] = _registry().discover()
            _cache["at"] = time.monotonic()
        return _cache["records"]


def _allowed(record, public: bool) -> bool:
    if record.status != "available" or record.metadata is None:
        return False
    if not public:
        return True
    meta = record.metadata
    if meta.processing.get("network", False) or meta.processing.get("filesystem", False):
        return False
    return meta.category.lower() not in PUBLIC_BLOCKED_CATEGORIES or meta.tool_id in PUBLIC_PASTE_TOOLS


def catalog(public: bool) -> dict[str, Any]:
    """Every tool the visitor may run here, with what the interface needs to build its form."""
    tools = []
    for rec in _records():
        if not _allowed(rec, public):
            continue
        m = rec.metadata
        tools.append({
            "id": m.tool_id, "name": m.name, "description": m.description, "category": m.category.lower(),
            "version": m.version, "input": m.input_schema, "privacy": m.privacy, "processing": m.processing,
            "paste_only": bool(public and m.tool_id in PUBLIC_PASTE_TOOLS),
        })
    tools.sort(key=lambda t: (t["category"], t["name"]))
    hidden = sum(1 for r in _records() if r.status == "available") - len(tools)
    return {"tools": tools, "hidden": hidden, "public": public, "max_body": PUBLIC_MAX_BODY if public else LOCAL_MAX_BODY}


def _meaningful(value: Any) -> bool:
    """Whether a form value says anything: not empty text, an empty list or an empty object."""
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (list, dict)):
        return any(_meaningful(item) for item in (value.values() if isinstance(value, dict) else value))
    return True


def validate_input(schema: dict[str, Any], input_data: dict[str, Any]) -> dict[str, Any]:
    """Reject an empty or malformed input before anything runs (HTTP 400, friendly words).
    Empty fields are dropped, so a blank optional box is not sent to the tool as ""."""
    cleaned = {key: value for key, value in input_data.items() if _meaningful(value)}
    properties = (schema or {}).get("properties") or {}
    if properties and not cleaned:
        raise ToolboxError(400, "Fill in the tool's input first: every field is empty.")
    missing = [key for key in (schema or {}).get("required") or [] if key not in cleaned]
    if missing:
        raise ToolboxError(400, f"Fill in the required field(s): {', '.join(missing)}.")
    from Tools.registry import _schema_errors  # noqa: PLC0415 - the registry's own schema check

    errors = _schema_errors(cleaned, schema or {"type": "object"})
    if errors:
        raise ToolboxError(400, "The input doesn't match what this tool accepts: " + "; ".join(errors[:3]))
    return cleaned


def _child(connection, tool_id: str, input_data: dict[str, Any]) -> None:
    """Runs in its own process: a slow or hostile tool can be killed without touching the server."""
    try:
        connection.send(("ok", _registry().execute(tool_id, input_data, None).as_dict()))
    except Exception as exc:  # noqa: BLE001
        connection.send(("error", type(exc).__name__))
    finally:
        connection.close()


def _isolated() -> bool:
    # AWS Lambda serves one request per instance and enforces its own timeout; elsewhere every
    # run gets its own process.
    return not os.environ.get("AWS_LAMBDA_FUNCTION_NAME") and os.environ.get("CYBERSCAN_TOOLBOX_ISOLATION") != "thread"


def _run_in_process(tool_id: str, input_data: dict[str, Any], timeout: float) -> dict[str, Any]:
    context = multiprocessing.get_context("spawn")
    receiver, sender = context.Pipe(duplex=False)
    process = context.Process(target=_child, args=(sender, tool_id, input_data), daemon=True, name="cyberscan-tool")
    try:
        process.start()
    finally:
        sender.close()
    try:
        # The server thread waits on the pipe (no Python work, the GIL is free for other requests).
        if not receiver.poll(timeout):
            raise ToolboxError(504, f"The tool took longer than {timeout:g} seconds, so it was stopped.")
        status, payload = receiver.recv()
    except (EOFError, OSError) as exc:
        raise ToolboxError(500, "The tool stopped unexpectedly.") from exc
    finally:
        receiver.close()
        if process.is_alive():
            process.kill()          # a hard stop: the tool really ends
        process.join(timeout=2)
    if status != "ok":
        raise ToolboxError(500, "The tool failed while running.")
    return payload


def run(tool_id: Any, input_data: Any, public: bool) -> dict[str, Any]:
    if not isinstance(tool_id, str) or not tool_id:
        raise ToolboxError(400, "Choose a tool first.")
    record = next((r for r in _records() if r.tool_id == tool_id), None)
    if record is None or not _allowed(record, public):
        raise ToolboxError(404 if record is None else 403, "This tool isn't available here.")
    if not isinstance(input_data, dict):
        raise ToolboxError(400, "The tool's input must be an object.")
    if public and PUBLIC_BLOCKED_INPUTS & {k for k, v in input_data.items() if _meaningful(v)}:
        raise ToolboxError(403, "Reading folders on the server isn't available on the website; paste the content instead.")
    if public and tool_id in PUBLIC_PASTE_TOOLS and str(input_data.get("source", "provided")) != "provided":
        raise ToolboxError(403, "On the website this tool reads only what you paste; reading this computer works in the desktop app.")
    input_data = validate_input(record.metadata.input_schema, input_data)
    declared = float((record.metadata.processing or {}).get("timeout_seconds") or TIMEOUT_SECONDS)
    timeout = max(1.0, min(declared, TIMEOUT_SECONDS if public else LOCAL_TIMEOUT_SECONDS))
    if not _slots.acquire(timeout=2):
        raise ToolboxError(503, "Other tools are running. Try again in a moment.")
    started = time.perf_counter()
    try:
        if _isolated():
            out = _run_in_process(tool_id, input_data, timeout)
        else:
            future = _pool.submit(_registry().execute, tool_id, input_data, None)
            try:
                out = future.result(timeout=timeout).as_dict()
            except cf.TimeoutError as exc:
                raise ToolboxError(504, f"The tool took longer than {timeout:g} seconds and was stopped waiting.") from exc
    finally:
        _slots.release()
    error = out.get("error")
    if isinstance(error, dict) and error.get("message") and out.get("status") in {"import_error", "execution_error"}:
        logging.getLogger("cyberscan.toolbox").warning("Tool %s failed: %s", tool_id, error.get("message"))
        out["error"] = {"code": error.get("code", "execution_error"), "message": "The tool failed while running."}
    out["elapsed_ms"] = round((time.perf_counter() - started) * 1000)
    return out
