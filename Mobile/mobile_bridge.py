"""The on-device side of CyberScan Mobile.

Runs inside Pyodide (Python compiled to WebAssembly) in a Web Worker on the
phone. It uses the same engine and the same result shape as the web server,
so a phone and the desktop give the same verdict for the same file.
"""
from __future__ import annotations

import hashlib
import json
import sys
import time
from pathlib import Path
from typing import Any, Callable

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_WEB_ROOT = _PROJECT_ROOT / "Web"
if _WEB_ROOT.is_dir():
    for _path in (_WEB_ROOT, _WEB_ROOT / "web_v"):
        if str(_path) not in sys.path:
            sys.path.insert(0, str(_path))

from config import DEFAULT_SETTINGS
from ui.scan_service import ScanService

import server  # serialize_result: one result format for server and phone
import services
from Tools.registry import ToolRegistry

_service: ScanService | None = None
WORK = Path("/tmp/cyberscan")
WORK.mkdir(parents=True, exist_ok=True)


def _settings(max_bytes: int) -> dict[str, Any]:
    # Nothing leaves the phone: public threat lookups stay off on-device.
    return {**DEFAULT_SETTINGS, "osint_enabled": False, "maximum_file_size": int(max_bytes), "analysis_timeout": 60.0}


def warm() -> str:
    """Import everything and build the engine once; returns what's on board."""
    global _service
    if _service is None:
        _service = ScanService()
    info = {"python": __import__("sys").version.split()[0]}
    try:
        import yara  # the pure-Python reader packed as yara.py
        from core.yara_engine import discover_yara_rules
        files = discover_yara_rules()
        rules = yara.compile(filepaths={p.stem: str(p) for p in files})
        info["yara"] = {"reader": getattr(yara, "__version__", "?"), "files": len(files),
                        "rules": len(list(rules)), "skipped": rules.skipped if hasattr(rules, "skipped") else []}
    except Exception as exc:  # noqa: BLE001 - shown on the Device screen, never fatal
        info["yara"] = {"error": f"{type(exc).__name__}: {exc}"}
    return json.dumps(info)


def fingerprints(data: bytes) -> dict[str, Any]:
    return {"md5": hashlib.md5(data).hexdigest(), "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}


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
    try:
        data = Path(value).read_bytes() if kind == "file" else value.encode("utf-8")
        out["fingerprints"] = fingerprints(data)
        out["kind"] = kind
    except OSError:
        pass
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


def tools_list() -> str:
    """Return shared tool metadata without importing or executing tool modules."""
    records = ToolRegistry().discover()
    return json.dumps([record.as_dict() for record in records], ensure_ascii=False)


def run_tool(tool_id: str, input_json: str, options_json: str = "null") -> str:
    """Execute one tool through the shared registry's hash and schema checks."""
    input_data = json.loads(input_json)
    options = json.loads(options_json)
    result = ToolRegistry().execute(tool_id, input_data, options)
    return json.dumps(result.as_dict(), ensure_ascii=False)
