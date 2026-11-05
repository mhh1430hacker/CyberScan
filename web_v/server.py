"""Local web API for the CyberScan web interface.

Serves the HTML/CSS/JS front end and a small JSON API around the existing
``ScanService``. Uses only the Python standard library.

Security model (this server can read local files and run scans, so any web
page the user visits must not be able to drive it):
  * binds to 127.0.0.1 only;
  * rejects requests whose Host header is not this loopback address and port
    (blocks DNS-rebinding);
  * rejects cross-origin requests (Origin must be this server);
  * every /api/ call needs a random per-launch token, which is injected only
    into the page this server serves.
"""
from __future__ import annotations

import dataclasses
import json
import mimetypes
import re
import secrets
import shutil
import sys
import tempfile
import threading
import uuid
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from config import DATA_DIR, DEFAULT_SETTINGS, REPORT_DIR  # noqa: E402
from core.models import Finding, ScanResult  # noqa: E402
from reports.exporter import export_report  # noqa: E402
from ui.persistence import LocalUiStore  # noqa: E402
from ui.scan_service import ScanService  # noqa: E402

STATIC_DIR = Path(__file__).resolve().parent / "static"
STAGES = 4
MAX_JOBS = 32
MAX_TEXT = 1024 * 1024
HISTORY_LIMIT = 200
HISTORY_DIR = Path(REPORT_DIR) / "history"

# Settings the web page may change, with their validators. Everything else in
# the shared settings file (language, monitoring, AI model…) is preserved.
EDITABLE_SETTINGS: dict[str, Any] = {
    "entropy_analysis": bool,
    "heuristic_rules": bool,
    "ml_analysis": bool,
    "osint_enabled": bool,
    "large_text": bool,
    "animated_background": bool,
    "maximum_file_size": (1 * 1024 * 1024, 200 * 1024 * 1024),
    "analysis_timeout": (5.0, 300.0),
}

# One store shared with the Qt app, so both interfaces see the same scans.
STORE = LocalUiStore(DATA_DIR / "ui_settings.json", DATA_DIR / "scan_history.json")
STORE_LOCK = threading.Lock()


def _settings_defaults() -> dict[str, Any]:
    return {**DEFAULT_SETTINGS, "ui_language": "en"}


def load_settings() -> dict[str, Any]:
    try:
        return STORE.load_settings(_settings_defaults())
    except ValueError:
        return _settings_defaults()


def public_settings() -> dict[str, Any]:
    current = load_settings()
    return {key: current[key] for key in EDITABLE_SETTINGS}


def update_settings(changes: Any) -> dict[str, Any]:
    if not isinstance(changes, dict):
        raise ValueError("expected an object")
    with STORE_LOCK:
        current = load_settings()
        for key, value in changes.items():
            rule = EDITABLE_SETTINGS.get(key)
            if rule is None:
                raise ValueError(f"{key} cannot be changed here")
            if rule is bool:
                if not isinstance(value, bool):
                    raise ValueError(f"{key} must be true or false")
            else:
                low, high = rule
                if isinstance(value, bool) or not isinstance(value, (int, float)) or not low <= value <= high:
                    raise ValueError(f"{key} must be between {low} and {high}")
                value = type(DEFAULT_SETTINGS[key])(value)
            current[key] = value
        STORE.save_settings(current)
    return public_settings()


# ---------------------------------------------------------------- history
def _report_path(record: dict[str, Any]) -> Path:
    path = Path(str(record.get("report_path", ""))).resolve()
    if path.parent != HISTORY_DIR.resolve() or not path.is_file():
        raise FileNotFoundError("The saved report is missing or outside the history folder.")
    return path


def load_history() -> list[dict[str, Any]]:
    try:
        return STORE.load_history()
    except ValueError:
        return []


def record_history(result: ScanResult, display_target: str) -> str:
    HISTORY_DIR.mkdir(parents=True, exist_ok=True)
    record_id = uuid.uuid4().hex
    report_path = HISTORY_DIR / f"scan_{record_id}.json"
    saved = dataclasses.replace(result, target=display_target)
    export_report(saved, report_path, "json")
    record = {
        "id": record_id,
        "timestamp": datetime.now().astimezone().isoformat(timespec="seconds"),
        "target": display_target,
        "classification": result.classification,
        "score": result.combined_score,
        "sha256": str(result.feature_summary.get("sha256", "")),
        "report_path": str(report_path.resolve()),
    }
    with STORE_LOCK:
        candidate = [*load_history(), record]
        try:
            STORE.save_history(candidate[-HISTORY_LIMIT:])
        except (OSError, TypeError, ValueError):
            report_path.unlink(missing_ok=True)
            raise
    for expired in candidate[:-HISTORY_LIMIT]:
        try:
            _report_path(expired).unlink()
        except OSError:
            pass
    return record_id


def history_list() -> list[dict[str, Any]]:
    return [
        {
            "id": r["id"],
            "timestamp": r["timestamp"],
            "target": r["target"],
            "classification": r["classification"],
            "score": r["score"],
            "quarantined": bool(r.get("quarantined")),
        }
        for r in reversed(load_history())
    ]


def history_open(record_id: str) -> dict[str, Any] | None:
    record = next((r for r in load_history() if r["id"] == record_id), None)
    if record is None:
        return None
    payload = json.loads(_report_path(record).read_text(encoding="utf-8"))
    result = ScanResult(
        target=str(payload.get("target", record["target"])),
        heuristic_score=int(payload.get("heuristic_score", 0)),
        ml_risk_score=payload.get("ml_risk_score"),
        combined_score=int(payload.get("combined_score", record["score"])),
        classification=str(payload.get("classification", record["classification"])),
        evidence=[
            Finding(
                str(i.get("category", "")), str(i.get("severity", "")),
                str(i.get("evidence", "")), str(i.get("explanation", "")),
                int(i.get("contribution", 0)),
            )
            for i in payload.get("evidence", []) if isinstance(i, dict)
        ],
        feature_summary=payload.get("feature_summary", {}),
        model_status=str(payload.get("model_status", "")),
        limitations=str(payload.get("limitations", "")),
        summary=str(payload.get("summary", "")),
        engine_status=payload.get("engine_status", {}),
        nextgen_analysis=payload.get("nextgen_analysis", {}),
        mitre_techniques=payload.get("mitre_techniques", []),
        osint_summary=payload.get("osint_summary", {}),
        structural_prediction=payload.get("structural_prediction", {}),
    )
    out = serialize_result(result, record["target"])
    out.update(record_id=record_id, timestamp=record["timestamp"])
    return out


def history_delete(record_id: str) -> bool:
    with STORE_LOCK:
        history = load_history()
        record = next((r for r in history if r["id"] == record_id), None)
        if record is None:
            return False
        STORE.save_history([r for r in history if r["id"] != record_id])
    try:
        _report_path(record).unlink()
    except OSError:
        pass
    return True


def _downsample(values: list[float], limit: int = 240) -> list[float]:
    if len(values) <= limit:
        return [round(float(v), 4) for v in values]
    step = len(values) / limit
    return [round(float(values[int(i * step)]), 4) for i in range(limit)]


def serialize_result(result: ScanResult, display_target: str) -> dict[str, Any]:
    nextgen = result.nextgen_analysis or {}
    prediction = result.structural_prediction or {}
    intelligence = result.osint_summary or {}
    entropy = nextgen.get("entropy_topography") or {}
    return {
        "target": display_target,
        "combined_score": result.combined_score,
        "heuristic_score": result.heuristic_score,
        "ml_risk_score": result.ml_risk_score,
        "classification": result.classification,
        "summary": result.summary,
        "limitations": result.limitations,
        "model_status": result.model_status,
        "evidence": [dataclasses.asdict(f) for f in result.evidence],
        "mitre": result.mitre_techniques,
        "yara": result.yara_matches,
        "engines": result.engine_status,
        "prediction": {
            "status": prediction.get("status"),
            "label": prediction.get("label"),
            "abstained": prediction.get("abstained", False),
        },
        "osint_status": intelligence.get("status"),
        "size": int(nextgen.get("file_size", 0) or 0),
        "entropy": {
            "trajectory": _downsample(list(entropy.get("trajectory") or [])),
            "mean": round(float(entropy.get("mean_entropy", 0.0)), 3),
            "peak": round(float(entropy.get("peak_entropy", 0.0)), 3),
            "anomalies": len(entropy.get("anomalies") or []),
        },
        "report_text": result.as_text().replace(
            f"Target: {result.target}", f"Target: {display_target}", 1
        ),
    }


class Job:
    def __init__(self) -> None:
        self.id = uuid.uuid4().hex
        self.stages = [{"state": "pending", "detail": ""} for _ in range(STAGES)]
        self.status = "running"
        self.result: dict[str, Any] | None = None
        self.error: str | None = None

    def snapshot(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "status": self.status,
            "stages": self.stages,
            "result": self.result,
            "error": self.error,
        }


class App:
    def __init__(self) -> None:
        self.token = secrets.token_urlsafe(32)
        self.jobs: dict[str, Job] = {}
        self.lock = threading.Lock()
        self.upload_root = Path(tempfile.mkdtemp(prefix="cyberscan-web-"))

    def start_job(self, candidate: str, mode: str, display: str, cleanup: Path | None) -> Job:
        job = Job()
        with self.lock:
            if len(self.jobs) >= MAX_JOBS:
                finished = [k for k, j in self.jobs.items() if j.status != "running"]
                for key in finished[: len(self.jobs) - MAX_JOBS + 1]:
                    del self.jobs[key]
            self.jobs[job.id] = job

        def progress(index: int, state: str, detail: str) -> None:
            if 0 <= index < STAGES:
                job.stages[index] = {"state": state, "detail": detail}

        def run() -> None:
            try:
                result = ScanService().analyze(candidate, mode, load_settings(), progress)[0]
                job.result = serialize_result(result, display)
                try:
                    job.result["record_id"] = record_history(result, display)
                except (OSError, TypeError, ValueError) as exc:
                    job.result["history_error"] = f"{type(exc).__name__}: {exc}"
                job.status = "done"
            except Exception as exc:  # noqa: BLE001 - reported to the page
                job.error = f"{type(exc).__name__}: {exc}"
                job.status = "failed"
            finally:
                if cleanup is not None:
                    shutil.rmtree(cleanup, ignore_errors=True)

        threading.Thread(target=run, daemon=True).start()
        return job


def make_handler(app: App, port: int) -> type[BaseHTTPRequestHandler]:
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
    allowed_origins = {f"http://{h}" for h in allowed_hosts}

    class Handler(BaseHTTPRequestHandler):
        server_version = "CyberScanWeb"
        sys_version = ""

        def log_message(self, fmt: str, *args: Any) -> None:  # quiet console
            pass

        # ---- helpers -------------------------------------------------
        def _send(self, status: int, body: bytes, ctype: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; img-src 'self' data:; style-src 'self'; "
                "script-src 'self'; connect-src 'self'; frame-ancestors 'none'",
            )
            self.end_headers()
            self.wfile.write(body)

        def _json(self, status: int, value: Any) -> None:
            self._send(status, json.dumps(value, ensure_ascii=False).encode(), "application/json; charset=utf-8")

        def _guard(self, api: bool) -> bool:
            if self.headers.get("Host", "") not in allowed_hosts:
                self._json(HTTPStatus.FORBIDDEN, {"error": "bad host"})
                return False
            origin = self.headers.get("Origin")
            if origin is not None and origin not in allowed_origins:
                self._json(HTTPStatus.FORBIDDEN, {"error": "bad origin"})
                return False
            if api and not secrets.compare_digest(
                self.headers.get("X-CyberScan-Token", ""), app.token
            ):
                self._json(HTTPStatus.UNAUTHORIZED, {"error": "bad token"})
                return False
            return True

        def _body(self, limit: int) -> bytes | None:
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = -1
            if length < 0 or length > limit:
                self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "body too large"})
                return None
            return self.rfile.read(length)

        # ---- routes --------------------------------------------------
        def do_GET(self) -> None:  # noqa: N802
            path = self.path.split("?", 1)[0]
            if path.startswith("/api/"):
                if not self._guard(api=True):
                    return
                if path == "/api/history":
                    self._json(HTTPStatus.OK, history_list())
                    return
                if path == "/api/settings":
                    self._json(HTTPStatus.OK, public_settings())
                    return
                match = re.fullmatch(r"/api/history/([0-9a-f]{32})", path)
                if match:
                    try:
                        found = history_open(match.group(1))
                    except (OSError, ValueError, TypeError) as exc:
                        self._json(HTTPStatus.GONE, {"error": str(exc)})
                        return
                    if found is None:
                        self._json(HTTPStatus.NOT_FOUND, {"error": "no such scan"})
                    else:
                        self._json(HTTPStatus.OK, found)
                    return
                match = re.fullmatch(r"/api/scan/([0-9a-f]{32})", path)
                job = app.jobs.get(match.group(1)) if match else None
                if job is None:
                    self._json(HTTPStatus.NOT_FOUND, {"error": "no such scan"})
                else:
                    self._json(HTTPStatus.OK, job.snapshot())
                return
            if not self._guard(api=False):
                return
            name = "index.html" if path in ("/", "/index.html") else path.lstrip("/")
            target = (STATIC_DIR / name).resolve()
            if STATIC_DIR not in target.parents or not target.is_file():
                self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
                return
            body = target.read_bytes()
            if name == "index.html":
                body = body.replace(b"__CYBERSCAN_TOKEN__", app.token.encode())
            ctype = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
            if ctype.startswith("text/") or ctype.endswith("javascript"):
                ctype += "; charset=utf-8"
            self._send(HTTPStatus.OK, body, ctype)

        def do_POST(self) -> None:  # noqa: N802
            if not self._guard(api=True):
                return
            path = self.path.split("?", 1)[0]
            if path == "/api/scan":
                raw = self._body(MAX_TEXT)
                if raw is None:
                    return
                try:
                    data = json.loads(raw)
                    mode = {"url": "URL", "text": "Text"}[data["mode"]]
                    value = str(data["value"]).strip()
                except (ValueError, KeyError, TypeError):
                    self._json(HTTPStatus.BAD_REQUEST, {"error": "expected {mode: url|text, value}"})
                    return
                if not value:
                    self._json(HTTPStatus.BAD_REQUEST, {"error": "empty input"})
                    return
                label = value if mode == "URL" else "Pasted text"
                job = app.start_job(value, mode, label[:300], None)
                self._json(HTTPStatus.ACCEPTED, {"id": job.id})
                return
            if path == "/api/scan/file":
                limit = int(load_settings().get("maximum_file_size", 50 * 1024 * 1024))
                raw = self._body(limit)
                if raw is None:
                    return
                from urllib.parse import unquote

                original = unquote(self.headers.get("X-Filename", "upload.bin"))
                safe = re.sub(r"[^\w.\- ]", "_", Path(original).name)[:120] or "upload.bin"
                folder = Path(tempfile.mkdtemp(dir=app.upload_root))
                file_path = folder / safe
                file_path.write_bytes(raw)
                job = app.start_job(str(file_path), "File", Path(original).name[:300], folder)
                self._json(HTTPStatus.ACCEPTED, {"id": job.id})
                return
            self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})

        def do_PUT(self) -> None:  # noqa: N802
            if not self._guard(api=True):
                return
            if self.path.split("?", 1)[0] != "/api/settings":
                self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
                return
            raw = self._body(64 * 1024)
            if raw is None:
                return
            try:
                self._json(HTTPStatus.OK, update_settings(json.loads(raw)))
            except ValueError as exc:
                self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            except OSError as exc:
                self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": str(exc)})

        def do_DELETE(self) -> None:  # noqa: N802
            if not self._guard(api=True):
                return
            match = re.fullmatch(r"/api/history/([0-9a-f]{32})", self.path.split("?", 1)[0])
            if not match:
                self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
                return
            try:
                removed = history_delete(match.group(1))
            except (OSError, ValueError) as exc:
                self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": str(exc)})
                return
            self._json(HTTPStatus.OK if removed else HTTPStatus.NOT_FOUND, {"removed": removed})

    return Handler


def create_server(port: int = 0) -> tuple[ThreadingHTTPServer, App]:
    app = App()
    server = ThreadingHTTPServer(("127.0.0.1", port), BaseHTTPRequestHandler)
    actual = server.server_address[1]
    server.RequestHandlerClass = make_handler(app, actual)
    server.daemon_threads = True
    return server, app


def cleanup(app: App) -> None:
    shutil.rmtree(app.upload_root, ignore_errors=True)
