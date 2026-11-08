"""Local web API for the CyberScan web interface.

Serves the HTML/CSS/JS front end and a JSON API around the existing engine
(``ScanService``) and the desktop app's own modules. Standard library only.

Security model (this server reads local files, quarantines and repairs them,
so no other web page the user visits may drive it):
  * binds to 127.0.0.1 only;
  * rejects requests whose Host header is not this loopback address and port
    (blocks DNS rebinding);
  * rejects cross-origin requests (Origin must be this server);
  * every /api/ call needs a random per-launch token, injected only into the
    page this server serves;
  * strict Content-Security-Policy: no inline or third-party scripts.

Public mode (CYBERSCAN_PUBLIC=1, used by web_v/lambda_function.py on AWS Lambda):
  * anyone may use it, so nothing that touches the server's own disk is
    available: no scanning by path, no native file picker, no quarantine,
    restore or reveal, no saved settings or keys, no local AI, no downloads
    watch; nothing is written to a shared history (each visitor's results
    stay in their browser);
  * scans finish inside the request (Lambda freezes background threads);
  * uploads are capped by Lambda's 6 MB request limit;
  * the Origin must be the site itself; large static files (Pyodide, the
    APK) are redirected to CYBERSCAN_ASSET_BASE (an S3 bucket).
"""
from __future__ import annotations

import base64
import dataclasses
import json
import mimetypes
import os
import re
import secrets
import shutil
import sys
import tempfile
import threading
import time
import uuid
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qs, quote, unquote

ROOT = Path(__file__).resolve().parent.parent
for entry in (ROOT, Path(__file__).resolve().parent):
    if str(entry) not in sys.path:
        sys.path.insert(0, str(entry))

from config import DATA_DIR, DEFAULT_SETTINGS, REPORT_DIR  # noqa: E402
from core.models import Finding, ScanResult  # noqa: E402
from reports.exporter import export_report  # noqa: E402
from reports.report_generator import generate_report  # noqa: E402
from ui.persistence import LocalUiStore  # noqa: E402
from ui.scan_service import ScanService  # noqa: E402

import services  # noqa: E402

STATIC_DIR = Path(__file__).resolve().parent / "static"
STAGES = 4
MAX_JOBS = 32
MAX_TEXT = 1024 * 1024
HISTORY_LIMIT = 200
HISTORY_DIR = Path(REPORT_DIR) / "history"
ID = r"([0-9a-f]{32})"

PUBLIC = os.environ.get("CYBERSCAN_PUBLIC") == "1"
ASSET_BASE = os.environ.get("CYBERSCAN_ASSET_BASE", "").rstrip("/")
PUBLIC_MAX_UPLOAD = 4 * 1024 * 1024        # Lambda accepts 6 MB per request, base64 included
PUBLIC_TIMEOUT = 50.0                      # stays under the Lambda timeout
# routes that would let a visitor reach the server's own disk or settings
# Behind CloudFront, Lambda sees its own address as Host while the browser's Origin is
# the real domain: list the site's addresses here (comma-separated), e.g.
# CYBERSCAN_SITE_ORIGINS=https://ainex-ai.xyz,https://www.ainex-ai.xyz
SITE_ORIGINS = {o.strip().rstrip("/") for o in os.environ.get("CYBERSCAN_SITE_ORIGINS", "").split(",") if o.strip()}
PUBLIC_DISABLED = {
    "history_quarantine", "history_restore", "history_reveal", "history_ai", "ai_poll", "ai_stop",
    "settings_put", "keys_put", "pick", "repair_path",
}

_MODEL_NAME = re.compile(r"^[\w.:/\-]{1,80}$")


def _is_bool(value: Any) -> bool:
    return isinstance(value, bool)


def _number(low: float, high: float) -> Callable[[Any], bool]:
    return lambda v: not isinstance(v, bool) and isinstance(v, (int, float)) and low <= v <= high


# Settings the web page may change, each with a validator. Everything else in
# the shared settings file (weights, quarantine folder, language…) is kept.
EDITABLE_SETTINGS: dict[str, Callable[[Any], bool]] = {
    "entropy_analysis": _is_bool,
    "heuristic_rules": _is_bool,
    "ml_analysis": _is_bool,
    "osint_enabled": _is_bool,
    "large_text": _is_bool,
    "animated_background": _is_bool,
    "ai_summary_enabled": _is_bool,
    "monitoring_enabled": _is_bool,
    "maximum_file_size": _number(1 * 1024 * 1024, 200 * 1024 * 1024),
    "analysis_timeout": _number(5.0, 300.0),
    "monitoring_directory": lambda v: isinstance(v, str) and 0 < len(v) < 1024,
    "ai_model": lambda v: isinstance(v, str) and bool(_MODEL_NAME.match(v)),
}

# One store shared with the desktop app, so both interfaces see the same scans.
STORE = LocalUiStore(DATA_DIR / "ui_settings.json", DATA_DIR / "scan_history.json")
STORE_LOCK = threading.Lock()
MONITOR = services.Monitor()


class ApiError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


# ---------------------------------------------------------------- settings
def _settings_defaults() -> dict[str, Any]:
    return {**DEFAULT_SETTINGS, "ui_language": "en"}


def load_settings() -> dict[str, Any]:
    if PUBLIC:
        # the same safe settings for every visitor; nothing is read from or written to disk
        return {**_settings_defaults(), "osint_enabled": False, "ai_summary_enabled": False, "monitoring_enabled": False,
                "maximum_file_size": PUBLIC_MAX_UPLOAD, "analysis_timeout": PUBLIC_TIMEOUT}
    try:
        return STORE.load_settings(_settings_defaults())
    except ValueError:
        return _settings_defaults()


def public_settings() -> dict[str, Any]:
    current = load_settings()
    out = {key: current[key] for key in EDITABLE_SETTINGS}
    out["monitor_state"] = "on" if MONITOR.monitor is not None else "off"
    out["public"] = PUBLIC
    return out


def update_settings(changes: Any) -> dict[str, Any]:
    if not isinstance(changes, dict):
        raise ApiError(400, "expected an object")
    with STORE_LOCK:
        current = load_settings()
        for key, value in changes.items():
            check = EDITABLE_SETTINGS.get(key)
            if check is None:
                raise ApiError(400, f"{key} cannot be changed here")
            if not check(value):
                raise ApiError(400, f"{key} has an invalid value")
            if isinstance(DEFAULT_SETTINGS.get(key), float):
                value = float(value)
            elif isinstance(DEFAULT_SETTINGS.get(key), int) and not isinstance(DEFAULT_SETTINGS.get(key), bool):
                value = int(value)
            current[key] = value
        folder = str(Path(current["monitoring_directory"]).expanduser())
        if current["monitoring_enabled"] and not Path(folder).is_dir():
            raise ApiError(400, "Choose a folder that exists.")
        current["monitoring_directory"] = folder
        STORE.save_settings(current)
    apply_monitor(current)
    return public_settings()


def apply_monitor(settings: dict[str, Any]) -> None:
    try:
        MONITOR.apply(bool(settings.get("monitoring_enabled")), str(settings.get("monitoring_directory", "")))
    except Exception:  # noqa: BLE001 - monitoring is optional
        pass


# ---------------------------------------------------------------- history
def _report_path(record: dict[str, Any]) -> Path:
    path = Path(str(record.get("report_path", ""))).resolve()
    if path.parent != HISTORY_DIR.resolve() or not path.is_file():
        raise ApiError(410, "The saved report is missing or outside the history folder.")
    return path


def load_history() -> list[dict[str, Any]]:
    try:
        return STORE.load_history()
    except ValueError:
        return []


def find_record(record_id: str) -> dict[str, Any]:
    record = next((r for r in load_history() if r["id"] == record_id), None)
    if record is None:
        raise ApiError(404, "no such scan")
    return record


def update_record(record_id: str, change: Callable[[dict[str, Any]], None]) -> None:
    with STORE_LOCK:
        history = load_history()
        for record in history:
            if record["id"] == record_id:
                change(record)
                break
        STORE.save_history(history)


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
        except (OSError, ApiError):
            pass
    return record_id


def result_from_record(record: dict[str, Any]) -> ScanResult:
    try:
        payload = json.loads(_report_path(record).read_text(encoding="utf-8"))
    except ValueError as exc:
        raise ApiError(410, f"The saved report can't be read: {exc}") from exc
    return ScanResult(
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
        yara_matches=payload.get("yara_matches", []),
        engine_status=payload.get("engine_status", {}),
        nextgen_analysis=payload.get("nextgen_analysis", {}),
        pe_analysis=payload.get("pe_analysis", {}),
        mitre_techniques=payload.get("mitre_techniques", []),
        osint_summary=payload.get("osint_summary", {}),
        structural_prediction=payload.get("structural_prediction", {}),
    )


def _on_disk(target: str) -> bool:
    return not target.startswith(("http://", "https://")) and Path(target).is_absolute()


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


def history_open(record_id: str) -> dict[str, Any]:
    record = find_record(record_id)
    out = serialize_result(result_from_record(record), record["target"], None, None, None)
    out.update(
        record_id=record_id,
        timestamp=record["timestamp"],
        quarantined=bool(record.get("quarantined")),
        exists=_on_disk(record["target"]) and Path(record["target"]).is_file(),
    )
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
    except (OSError, ApiError):
        pass
    return True


def history_stats() -> dict[str, Any]:
    history = load_history()
    counts = {"SUSPICIOUS": 0, "REVIEW": 0, "NO_INDICATORS_OBSERVED": 0}
    for record in history:
        if record["classification"] in counts:
            counts[record["classification"]] += 1
    return {"scans": len(history), "by_class": counts}


# ---------------------------------------------------------------- results
def _downsample(values: list[float], limit: int = 240) -> list[float]:
    if len(values) <= limit:
        return [round(float(v), 4) for v in values]
    step = len(values) / limit
    return [round(float(values[int(i * step)]), 4) for i in range(limit)]


def serialize_result(
    result: ScanResult, display_target: str, mode: str | None, raw: bytes | None, elapsed: float | None
) -> dict[str, Any]:
    nextgen = result.nextgen_analysis or {}
    prediction = result.structural_prediction or {}
    intelligence = result.osint_summary or {}
    entropy = nextgen.get("entropy_topography") or {}
    out = {
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
            "class_scores": prediction.get("class_scores") or {},
        },
        "osint_status": intelligence.get("status"),
        "osint_matches": len(intelligence.get("matches") or []),
        "size": int(nextgen.get("file_size", 0) or 0),
        "elapsed": round(elapsed, 2) if elapsed is not None else None,
        "entropy": {
            "trajectory": _downsample(list(entropy.get("trajectory") or [])),
            "mean": round(float(entropy.get("mean_entropy", 0.0)), 3),
            "peak": round(float(entropy.get("peak_entropy", 0.0)), 3),
            "anomalies": len(entropy.get("anomalies") or []),
        },
        "report_text": result.as_text().replace(f"Target: {result.target}", f"Target: {display_target}", 1),
    }
    try:
        out.update(services.present(result, display_target, mode, raw, elapsed))
    except Exception as exc:  # noqa: BLE001 - the raw result is still useful
        out["present_error"] = f"{type(exc).__name__}: {exc}"
    return out


# ---------------------------------------------------------------- scans
class Job:
    def __init__(self) -> None:
        self.id = uuid.uuid4().hex
        self.stages = [{"state": "pending", "detail": ""} for _ in range(STAGES)]
        self.status = "running"
        self.result: dict[str, Any] | None = None
        self.error: str | None = None

    def snapshot(self) -> dict[str, Any]:
        return {"id": self.id, "status": self.status, "stages": self.stages, "result": self.result, "error": self.error}


class App:
    def __init__(self) -> None:
        # Public mode runs on many short-lived instances: the page must work with any of them,
        # so the token is the same everywhere (it only stops other sites from driving the API).
        self.token = os.environ.get("CYBERSCAN_TOKEN") or ("cyberscan-public" if PUBLIC else secrets.token_urlsafe(32))
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
            started = time.monotonic()
            try:
                payload = ScanService().analyze(candidate, mode, load_settings(), progress)
                result, raw = payload[0], payload[5]
                # Uploaded copies are not where the user keeps the file: present them by name.
                shown_mode = "File" if mode == "File" else mode
                job.result = serialize_result(result, display, shown_mode, raw, time.monotonic() - started)
                if not PUBLIC:  # a public server keeps no shared history
                    try:
                        job.result["record_id"] = record_history(result, display)
                    except (OSError, TypeError, ValueError) as exc:
                        job.result["history_error"] = f"{type(exc).__name__}: {exc}"
                job.result["exists"] = cleanup is None and mode == "File"
                job.result["quarantined"] = False
                job.status = "done"
            except Exception as exc:  # noqa: BLE001 - reported to the page
                job.error = f"{type(exc).__name__}: {exc}"
                job.status = "failed"
            finally:
                if cleanup is not None:
                    shutil.rmtree(cleanup, ignore_errors=True)

        if PUBLIC:
            run()  # Lambda freezes background threads once the response is sent
        else:
            threading.Thread(target=run, daemon=True).start()
        return job


# ---------------------------------------------------------------- handler
def make_handler(app: App, port: int) -> type[BaseHTTPRequestHandler]:
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
    allowed_origins = {f"http://{h}" for h in allowed_hosts}

    class Handler(BaseHTTPRequestHandler):
        server_version = "CyberScanWeb"
        sys_version = ""
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt: str, *args: Any) -> None:  # quiet console
            pass

        # ---- plumbing ------------------------------------------------
        def _send(self, status: int, body: bytes, ctype: str, extra: dict[str, str] | None = None) -> None:
            extra = dict(extra or {})
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", extra.pop("Cache-Control", "no-store"))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            # 'wasm-unsafe-eval' only lets the page compile WebAssembly (the phone
            # app's on-device engine); it does not allow eval() of JavaScript.
            # In public mode the large files come from the asset bucket.
            assets = f" {ASSET_BASE}" if PUBLIC and ASSET_BASE else ""
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; img-src 'self' data: blob:; style-src 'self'; "
                f"script-src 'self' 'wasm-unsafe-eval'{assets}; connect-src 'self'{assets}; worker-src 'self'; manifest-src 'self'; "
                "frame-ancestors 'self'; base-uri 'none'; form-action 'self'",  # 'self': the phone app shows its privacy page in a frame
            )
            if PUBLIC:
                self.send_header("Strict-Transport-Security", "max-age=31536000")
                self.send_header("X-Frame-Options", "SAMEORIGIN")
                self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
            for key, value in extra.items():
                self.send_header(key, value)
            self.end_headers()
            if self.command != "HEAD":   # HEAD: the same headers, no body
                self.wfile.write(body)

        def _json(self, status: int, value: Any) -> None:
            self._send(status, json.dumps(value, ensure_ascii=False).encode(), "application/json; charset=utf-8")

        def _guard(self, api: bool) -> bool:
            if PUBLIC:
                # any host name AWS gives the function; the page may only be driven by itself
                host = self.headers.get("Host", "")
                origin = self.headers.get("Origin")
                forwarded = self.headers.get("X-Forwarded-Host", "")
                allowed = {f"https://{host}", f"http://{host}"} | SITE_ORIGINS
                if forwarded:
                    allowed.add(f"https://{forwarded}")
                if origin is not None and origin.rstrip("/") not in allowed:
                    self._json(HTTPStatus.FORBIDDEN, {"error": "bad origin"})
                    return False
                if api and not secrets.compare_digest(self.headers.get("X-CyberScan-Token", ""), app.token):
                    self._json(HTTPStatus.UNAUTHORIZED, {"error": "bad token"})
                    return False
                return True
            if self.headers.get("Host", "") not in allowed_hosts:
                self._json(HTTPStatus.FORBIDDEN, {"error": "bad host"})
                return False
            origin = self.headers.get("Origin")
            if origin is not None and origin not in allowed_origins:
                self._json(HTTPStatus.FORBIDDEN, {"error": "bad origin"})
                return False
            if api and not secrets.compare_digest(self.headers.get("X-CyberScan-Token", ""), app.token):
                self._json(HTTPStatus.UNAUTHORIZED, {"error": "bad token"})
                return False
            return True

        def _length(self) -> int:
            try:
                return int(self.headers.get("Content-Length", "0"))
            except ValueError:
                return -1

        def _raw_body(self, limit: int) -> bytes:
            length = self._length()
            if length < 0 or length > limit:
                # Don't read it; close the connection so it can't leak into the next request.
                self.close_connection = True
                self._consumed = True
                raise ApiError(413, "body too large")
            self._consumed = True
            return self.rfile.read(length)

        def _drain(self) -> None:
            """Keep-alive safety: a body no handler read must not become the
            start of the next request on this connection."""
            if getattr(self, "_consumed", True):
                return
            self._consumed = True
            length = self._length()
            if 0 < length <= MAX_TEXT:
                self.rfile.read(length)
            elif length != 0:
                self.close_connection = True

        def _json_body(self, limit: int = MAX_TEXT) -> Any:
            raw = self._raw_body(limit)
            if not raw:
                return {}
            try:
                return json.loads(raw)
            except ValueError as exc:
                raise ApiError(400, "invalid JSON") from exc

        def _dispatch(self, method: str) -> None:
            self._consumed = method == "GET" and self._length() <= 0
            # Drain before replying: some clients wait for the reply before sending the rest.
            original_send = type(self)._send.__get__(self, type(self))

            def send_after_drain(*args: Any, **kwargs: Any) -> None:
                self._drain()
                original_send(*args, **kwargs)

            self._send = send_after_drain  # type: ignore[method-assign]
            try:
                self._route(method)
            finally:
                self._drain()

        def _route(self, method: str) -> None:
            path, _, query = self.path.partition("?")
            if not path.startswith("/api/"):
                if method != "GET":
                    self._json(HTTPStatus.METHOD_NOT_ALLOWED, {"error": "method not allowed"})
                    return
                if self._guard(api=False):
                    self._static(path)
                return
            if not self._guard(api=True):
                return
            for route_method, pattern, handler in ROUTES:
                if route_method != method:
                    continue
                match = re.fullmatch(pattern, path)
                if match and PUBLIC and getattr(handler, "route_name", "") in PUBLIC_DISABLED:
                    self._json(HTTPStatus.FORBIDDEN, {"error": "This isn't available in the online version. Use the desktop app."})
                    return
                if match:
                    try:
                        handler(self, *match.groups(), query=parse_qs(query))
                    except ApiError as exc:
                        self._json(exc.status, {"error": str(exc)})
                    except (OSError, ValueError, RuntimeError) as exc:
                        self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": f"{type(exc).__name__}: {exc}"})
                    return
            self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})

        def do_GET(self) -> None:  # noqa: N802
            self._dispatch("GET")

        def do_POST(self) -> None:  # noqa: N802
            self._dispatch("POST")

        def do_PUT(self) -> None:  # noqa: N802
            self._dispatch("PUT")

        def do_HEAD(self) -> None:  # noqa: N802 - CDNs and download managers ask before fetching
            path = self.path.partition("?")[0]
            if path.startswith("/api/"):
                self._json(HTTPStatus.METHOD_NOT_ALLOWED, {"error": "method not allowed"})
                return
            self._dispatch("GET")

        def do_DELETE(self) -> None:  # noqa: N802
            self._dispatch("DELETE")

        def _static(self, path: str) -> None:
            name = "index.html" if path in ("/", "/index.html") else unquote(path).lstrip("/")
            if PUBLIC and ASSET_BASE and (name.startswith("pyodide/") or (name.startswith("downloads/") and name.endswith(".apk"))):
                # larger than Lambda can return (6 MB): served by the asset bucket
                if ".." in name or not re.fullmatch(r"[\w./\-]+", name):
                    self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
                    return
                self._send(HTTPStatus.FOUND, b"", "text/plain", {"Location": f"{ASSET_BASE}/{name}", "Cache-Control": "public, max-age=3600"})
                return
            target = (STATIC_DIR / name).resolve()
            if PUBLIC and not ASSET_BASE and not target.is_file() and (name.startswith("pyodide/") or name.endswith(".apk")):
                # the Lambda package doesn't contain these: say what's missing instead of a bare 404
                self._json(HTTPStatus.NOT_FOUND, {"error": "not found: set CYBERSCAN_ASSET_BASE to the S3 bucket that holds pyodide/ and downloads/"})
                return
            if target.is_dir() and STATIC_DIR in target.parents:
                if not path.endswith("/"):  # /m -> /m/ so relative links resolve
                    self._send(HTTPStatus.MOVED_PERMANENTLY, b"", "text/plain", {"Location": path + "/"})
                    return
                target = target / "index.html"
            if STATIC_DIR not in target.parents or not target.is_file():
                self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
                return
            body = target.read_bytes()
            if name == "index.html":
                body = body.replace(b"__CYBERSCAN_TOKEN__", app.token.encode())
            types = {".js": "text/javascript", ".mjs": "text/javascript", ".webmanifest": "application/manifest+json",
                     ".svg": "image/svg+xml", ".wasm": "application/wasm", ".zip": "application/zip",
                     ".vtt": "text/vtt", ".png": "image/png", ".json": "application/json",
                     ".apk": "application/vnd.android.package-archive"}
            ctype = types.get(target.suffix) or mimetypes.guess_type(target.name)[0] or "application/octet-stream"
            if ctype.startswith("text/") or ctype.endswith(("javascript", "json", "svg+xml")):
                ctype += "; charset=utf-8"
            extra = {}
            rel = target.relative_to(STATIC_DIR).as_posix()
            if PUBLIC:
                # Let the browser and the CDN (CloudFront) keep the site's files: without this every
                # visit runs the function once per file. After a deploy, invalidate "/*" in CloudFront.
                if rel == "sw.js":
                    extra["Cache-Control"] = "no-cache"
                elif rel.startswith("downloads/") or rel == "m/engine.version":
                    extra["Cache-Control"] = "public, max-age=300, s-maxage=300"
                else:
                    extra["Cache-Control"] = "public, max-age=600, s-maxage=86400, stale-while-revalidate=86400"
            elif rel.startswith("pyodide/") or rel == "m/engine.zip":
                # versioned and large: the phone downloads the engine once
                extra["Cache-Control"] = "public, max-age=31536000, immutable"
            if target.suffix == ".apk":
                # the signed Android app: always a download, never opened in the tab
                extra["Content-Disposition"] = f"attachment; filename*=UTF-8''{quote(target.name)}"
                extra["Cache-Control"] = "public, max-age=3600"
            self._send(HTTPStatus.OK, body, ctype, extra)

        # ---- scans ---------------------------------------------------
        def scan_start(self, query: dict) -> None:
            data = self._json_body()
            try:
                mode = {"url": "URL", "text": "Text", "path": "File"}[data["mode"]]
                value = str(data["value"]).strip()
            except (KeyError, TypeError) as exc:
                raise ApiError(400, "expected {mode: url|text|path, value}") from exc
            if not value:
                raise ApiError(400, "empty input")
            if mode == "File" and PUBLIC:
                raise ApiError(403, "Scanning files by path isn't available online. Upload the file instead.")
            if mode == "File":
                file_path = Path(value.strip('"')).expanduser()
                if not file_path.is_absolute() or not file_path.is_file():
                    raise ApiError(400, "That file doesn't exist.")
                value = str(file_path.resolve())
                label = value
            else:
                label = value if mode == "URL" else "Pasted text"
            job = app.start_job(value, mode, label[:1000], None)
            # public mode: the scan already finished, so the page gets the result at once
            self._json(HTTPStatus.OK if PUBLIC else HTTPStatus.ACCEPTED, job.snapshot() if PUBLIC else {"id": job.id})

        def scan_upload(self, query: dict) -> None:
            limit = int(load_settings().get("maximum_file_size", 50 * 1024 * 1024))
            raw = self._raw_body(limit)
            original = unquote(self.headers.get("X-Filename", "upload.bin"))
            safe = re.sub(r"[^\w.\- ]", "_", Path(original).name)[:120] or "upload.bin"
            folder = Path(tempfile.mkdtemp(dir=app.upload_root))
            file_path = folder / safe
            file_path.write_bytes(raw)
            job = app.start_job(str(file_path), "File", Path(original).name[:300], folder)
            self._json(HTTPStatus.OK if PUBLIC else HTTPStatus.ACCEPTED, job.snapshot() if PUBLIC else {"id": job.id})

        def scan_status(self, job_id: str, query: dict) -> None:
            job = app.jobs.get(job_id)
            if job is None:
                raise ApiError(404, "no such scan")
            self._json(HTTPStatus.OK, job.snapshot())

        # ---- history -------------------------------------------------
        def history_index(self, query: dict) -> None:
            self._json(HTTPStatus.OK, history_list())

        def history_lookup(self, query: dict) -> None:
            digest = (query.get("sha256") or [""])[0].lower()
            if not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise ApiError(400, "expected a SHA-256 fingerprint")
            matches = [
                {k: r[k] for k in ("id", "timestamp", "target", "classification", "score")}
                for r in reversed(load_history()) if str(r.get("sha256", "")).lower() == digest
            ]
            self._json(HTTPStatus.OK, {"matches": matches})

        def history_get(self, record_id: str, query: dict) -> None:
            self._json(HTTPStatus.OK, history_open(record_id))

        def history_remove(self, record_id: str, query: dict) -> None:
            removed = history_delete(record_id)
            self._json(HTTPStatus.OK if removed else HTTPStatus.NOT_FOUND, {"removed": removed})

        def history_export(self, record_id: str, query: dict) -> None:
            record = find_record(record_id)
            result = result_from_record(record)
            fmt = (query.get("format") or ["txt"])[0]
            base = re.sub(r"[^\w.\- ]", "_", Path(record["target"]).name or "scan")[:80] or "scan"
            if fmt == "json":
                body = _report_path(record).read_bytes()
                name, ctype = f"{base}.cyberscan.json", "application/json"
            else:
                body = generate_report(result).encode("utf-8")
                name, ctype = f"{base}.cyberscan.txt", "text/plain; charset=utf-8"
            self._send(HTTPStatus.OK, body, ctype, {
                "Content-Disposition": f"attachment; filename*=UTF-8''{quote(name)}",
            })

        def history_quarantine(self, record_id: str, query: dict) -> None:
            record = find_record(record_id)
            if record.get("quarantined"):
                raise ApiError(409, "Already in quarantine.")
            if not _on_disk(record["target"]) or not Path(record["target"]).is_file():
                raise ApiError(409, "The file is no longer where it was scanned.")
            sealed = services.quarantine(record["target"])
            update_record(record_id, lambda r: r.__setitem__("quarantined", sealed))
            self._json(HTTPStatus.OK, {"quarantined": True})

        def history_restore(self, record_id: str, query: dict) -> None:
            record = find_record(record_id)
            if not record.get("quarantined"):
                raise ApiError(409, "This file isn't in quarantine.")
            try:
                services.restore(record["quarantined"], record["target"])
            except FileExistsError as exc:
                raise ApiError(409, "A file with that name is already there, so nothing was restored.") from exc
            update_record(record_id, lambda r: r.pop("quarantined", None))
            self._json(HTTPStatus.OK, {"quarantined": False})

        def history_reveal(self, record_id: str, query: dict) -> None:
            record = find_record(record_id)
            if not _on_disk(record["target"]):
                raise ApiError(409, "This scan isn't a file on disk.")
            services.reveal(record["target"])
            self._json(HTTPStatus.OK, {"ok": True})

        def history_ai(self, record_id: str, query: dict) -> None:
            record = find_record(record_id)
            data = self._json_body()
            lang = "ar" if data.get("lang") == "ar" else "en"
            settings = load_settings()
            if not settings.get("ai_summary_enabled", True):
                raise ApiError(409, "AI summaries are turned off in Settings.")
            job = services.ai_start(result_from_record(record), record["target"], None, lang, settings.get("ai_model", "qwen3:8b"))
            self._json(HTTPStatus.ACCEPTED, {"id": job.id})

        def stats(self, query: dict) -> None:
            out = history_stats()
            out["rules"] = sum(
                1 for f in (ROOT / "rules").glob("*.yar") for line in f.read_text(errors="ignore").splitlines()
                if line.lstrip().startswith("rule ")
            )
            self._json(HTTPStatus.OK, out)

        # ---- AI ------------------------------------------------------
        def ai_status(self, query: dict) -> None:
            if PUBLIC:  # the AI summary needs a model on the user's own computer
                self._json(HTTPStatus.OK, {"state": "no_server", "enabled": False, "models": []})
                return
            settings = load_settings()
            status = services.ai_status(settings.get("ai_model", "qwen3:8b"))
            status["enabled"] = bool(settings.get("ai_summary_enabled", True))
            self._json(HTTPStatus.OK, status)

        def ai_poll(self, job_id: str, query: dict) -> None:
            job = services.AI_JOBS.get(job_id)
            if job is None:
                raise ApiError(404, "no such summary")
            self._json(HTTPStatus.OK, {"status": job.status, "text": job.text, "error": job.error})

        def ai_stop(self, job_id: str, query: dict) -> None:
            job = services.AI_JOBS.get(job_id)
            if job is not None:
                job.stop = True
            self._json(HTTPStatus.OK, {"stopped": True})

        # ---- settings, keys, pick, events ----------------------------
        def settings_get(self, query: dict) -> None:
            self._json(HTTPStatus.OK, public_settings())

        def settings_put(self, query: dict) -> None:
            self._json(HTTPStatus.OK, update_settings(self._json_body(64 * 1024)))

        def keys_get(self, query: dict) -> None:
            self._json(HTTPStatus.OK, services.keys_status())

        def keys_put(self, query: dict) -> None:
            data = self._json_body(16 * 1024)
            if not isinstance(data, dict):
                raise ApiError(400, "expected an object")
            try:
                self._json(HTTPStatus.OK, services.save_keys(data))
            except ValueError as exc:
                raise ApiError(400, str(exc)) from exc

        def pick(self, query: dict) -> None:
            data = self._json_body()
            kind = "folder" if data.get("kind") == "folder" else "file"
            try:
                chosen = services.pick(kind)
            except RuntimeError as exc:
                raise ApiError(409, str(exc)) from exc
            info: dict[str, Any] = {"path": chosen}
            if chosen and kind == "file" and Path(chosen).is_file():
                info.update(name=Path(chosen).name, size=Path(chosen).stat().st_size)
            self._json(HTTPStatus.OK, info)

        def events(self, query: dict) -> None:
            if PUBLIC:
                self._json(HTTPStatus.OK, {"events": [], "monitor": "off"})
                return
            try:
                since = int((query.get("since") or ["0"])[0])
            except ValueError:
                since = 0
            self._json(HTTPStatus.OK, {"events": MONITOR.since(since), "monitor": "on" if MONITOR.monitor else "off"})

        # ---- repair --------------------------------------------------
        def repair_path(self, query: dict) -> None:
            data = self._json_body()
            file_path = Path(str(data.get("path", "")).strip('"')).expanduser()
            if not file_path.is_absolute() or not file_path.is_file():
                raise ApiError(400, "That file doesn't exist.")
            if file_path.stat().st_size > services.REPAIR_MAX:
                raise ApiError(413, "This file is larger than 200 MB, which Repair doesn't handle yet.")
            self._json(HTTPStatus.OK, services.repair_open(file_path.read_bytes(), file_path.name, file_path.resolve()))

        def repair_upload(self, query: dict) -> None:
            raw = self._raw_body(PUBLIC_MAX_UPLOAD if PUBLIC else services.REPAIR_MAX)
            name = Path(unquote(self.headers.get("X-Filename", "upload.bin"))).name[:200] or "upload.bin"
            self._json(HTTPStatus.OK, services.repair_open(raw, name, None))

        def repair_run(self, session_id: str, query: dict) -> None:
            session = services.REPAIRS.get(session_id)
            if session is None:
                raise ApiError(404, "This repair session has expired. Open the file again.")
            data = self._json_body()
            keys = data.get("keys")
            if not isinstance(keys, list) or not all(isinstance(k, str) for k in keys):
                raise ApiError(400, "expected {keys: [...]}")
            try:
                out = services.repair_run(session, keys)
            except ValueError as exc:
                raise ApiError(400, str(exc)) from exc
            if PUBLIC and out.get("ok") and session.output is not None:
                # the next request may reach another instance: hand the copy over now
                out["output_b64"] = base64.b64encode(session.output).decode("ascii")
                out["output_name"] = session.output_name
            self._json(HTTPStatus.OK, out)

        def repair_download(self, session_id: str, query: dict) -> None:
            session = services.REPAIRS.get(session_id)
            if session is None or session.output is None:
                raise ApiError(404, "Nothing to download.")
            self._send(HTTPStatus.OK, session.output, "application/octet-stream", {
                "Content-Disposition": f"attachment; filename*=UTF-8''{quote(session.output_name)}",
            })

    return Handler


def _route(method: str, pattern: str, name: str) -> tuple[str, str, Callable]:
    def call(handler: Any, *groups: str, query: dict) -> None:
        getattr(handler, name)(*groups, query=query)
    call.route_name = name  # type: ignore[attr-defined]
    return method, pattern, call


ROUTES = [
    _route("POST", r"/api/scan", "scan_start"),
    _route("POST", r"/api/scan/file", "scan_upload"),
    _route("GET", rf"/api/scan/{ID}", "scan_status"),
    _route("GET", r"/api/history", "history_index"),
    _route("GET", r"/api/history/lookup", "history_lookup"),
    _route("GET", rf"/api/history/{ID}", "history_get"),
    _route("DELETE", rf"/api/history/{ID}", "history_remove"),
    _route("GET", rf"/api/history/{ID}/export", "history_export"),
    _route("POST", rf"/api/history/{ID}/quarantine", "history_quarantine"),
    _route("POST", rf"/api/history/{ID}/restore", "history_restore"),
    _route("POST", rf"/api/history/{ID}/reveal", "history_reveal"),
    _route("POST", rf"/api/history/{ID}/ai", "history_ai"),
    _route("GET", r"/api/stats", "stats"),
    _route("GET", r"/api/ai/status", "ai_status"),
    _route("GET", rf"/api/ai/{ID}", "ai_poll"),
    _route("POST", rf"/api/ai/{ID}/stop", "ai_stop"),
    _route("GET", r"/api/settings", "settings_get"),
    _route("PUT", r"/api/settings", "settings_put"),
    _route("GET", r"/api/keys", "keys_get"),
    _route("PUT", r"/api/keys", "keys_put"),
    _route("POST", r"/api/pick", "pick"),
    _route("GET", r"/api/events", "events"),
    _route("POST", r"/api/repair/path", "repair_path"),
    _route("POST", r"/api/repair/upload", "repair_upload"),
    _route("POST", rf"/api/repair/{ID}/run", "repair_run"),
    _route("GET", rf"/api/repair/{ID}/download", "repair_download"),
]


def create_server(port: int = 0) -> tuple[ThreadingHTTPServer, App]:
    app = App()
    server = ThreadingHTTPServer(("127.0.0.1", port), BaseHTTPRequestHandler)
    actual = server.server_address[1]
    server.RequestHandlerClass = make_handler(app, actual)
    server.daemon_threads = True
    services.load_keys_into_environment()
    apply_monitor(load_settings())
    return server, app


def cleanup(app: App) -> None:
    MONITOR.stop()
    shutil.rmtree(app.upload_root, ignore_errors=True)
