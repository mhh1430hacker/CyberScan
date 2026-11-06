"""The on-device side of CyberScan Mobile.

Runs inside Pyodide (Python compiled to WebAssembly) in a Web Worker on the
phone. It uses the same engine and the same result shape as the web server,
so a phone and the desktop give the same verdict for the same file.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Callable

from config import DEFAULT_SETTINGS
from ui.scan_service import ScanService

import server  # serialize_result: one result format for server and phone
import services

_service: ScanService | None = None
WORK = Path("/tmp/cyberscan")
WORK.mkdir(parents=True, exist_ok=True)


def _settings(max_bytes: int) -> dict[str, Any]:
    # Nothing leaves the phone: public threat lookups stay off on-device.
    return {**DEFAULT_SETTINGS, "osint_enabled": False, "maximum_file_size": int(max_bytes), "analysis_timeout": 60.0}


def warm() -> str:
    """Import everything and build the engine once; returns the engine list."""
    global _service
    if _service is None:
        _service = ScanService()
    return json.dumps({"python": __import__("sys").version.split()[0]})


def scan(kind: str, value: str, display: str, max_bytes: int, progress: Callable | None = None) -> str:
    """kind: 'file' (value = path written by the worker), 'url' or 'text'."""
    warm()
    mode = {"file": "File", "url": "URL", "text": "Text"}[kind]

    def report(index: int, state: str, detail: str) -> None:
        # a JavaScript null arrives as a JsNull object, not None
        if callable(progress):
            progress(index, state, detail)

    started = time.monotonic()
    payload = _service.analyze(value, mode, _settings(max_bytes), report)
    result, raw = payload[0], payload[5]
    out = server.serialize_result(result, display, mode, raw, time.monotonic() - started)
    out["exists"] = False
    out["on_device"] = True
    return json.dumps(out, ensure_ascii=False)


def repair_open(path: str, name: str) -> str:
    data = Path(path).read_bytes()
    return json.dumps(services.repair_open(data, name, None), ensure_ascii=False)


def repair_run(session_id: str, keys_json: str) -> str:
    session = services.REPAIRS.get(session_id)
    if session is None:
        raise ValueError("This repair session has expired. Open the file again.")
    out = services.repair_run(session, json.loads(keys_json))
    if out.get("ok") and session.output is not None:
        target = WORK / f"repaired-{session_id}"
        target.write_bytes(session.output)
        out["output_path"] = str(target)
        out["output_name"] = session.output_name
    return json.dumps(out, ensure_ascii=False)
