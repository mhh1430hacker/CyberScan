from __future__ import annotations

import http.client
import io
import json
import shutil
import sys
import threading
import zipfile
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

ROOT = Path(__file__).resolve().parents[1]
WEB_DIR = ROOT / "web_v"
if str(WEB_DIR) not in sys.path:
    sys.path.insert(0, str(WEB_DIR))

import server as web_server  # noqa: E402


class FakeDetectionService:
    class Limits:
        max_bytes = 50 * 1024 * 1024

    def __init__(self) -> None:
        self.limits = self.Limits()
        self.status = "ok"

    @staticmethod
    def _content(data: bytes, name: str) -> dict:
        suffix = Path(name).suffix.lower()
        if suffix == ".pdf":
            details = {"type": "pdf", "actions": {}, "links": []}
        elif suffix in {".docx", ".xlsx", ".pptx"}:
            details = {"type": "ooxml", "parts": 1, "vba": [], "external_links": []}
        elif suffix in {".png", ".jpg"}:
            details = {
                "type": "image",
                "qr_codes": {
                    "status": "decoded",
                    "codes": [{
                        "format": "QRCode",
                        "payload": "https://example.test/",
                        "kind": "url",
                        "risk": {"score": 0, "classification": "NO_INDICATORS_OBSERVED", "findings": []},
                    }],
                    "limitations": [],
                },
            }
        else:
            details = {"type": "zip" if data.startswith(b"PK") else "text"}
        return {
            "file_type": details["type"],
            "score": 55,
            "classification": "SUSPICIOUS",
            "evidence_agreement": "corroborated",
            "details": details,
            "findings": [{
                "category": "content",
                "severity": "high",
                "label": "Fixture finding",
                "explanation": "A test-only inspection finding.",
                "contribution": 55,
            }],
            "privacy": {},
            "analyzer_errors": [],
            "truncated_input": False,
        }

    def _result(self, data: bytes, name: str) -> dict:
        content = self._content(data, name)
        return {
            "classification": "NO_INDICATORS_OBSERVED",
            "content_analysis": content,
            "detection_summary": {
                "classification": "SUSPICIOUS",
                "needs_attention": True,
                "host_classification": "NO_INDICATORS_OBSERVED",
                "content_classification": "SUSPICIOUS",
                "content_score": 55,
                "evidence_agreement": "corroborated",
                "privacy_exposure": "none_detected",
            },
        }

    def analyze_upload(self, data: bytes, name: str, settings=None) -> dict:
        if self.status != "ok":
            return {
                "status": self.status,
                "result": None,
                "error": {"code": self.status, "message": f"test {self.status}"},
                "elapsed_ms": 3,
                "engine": {"version": "test", "isolation": "test"},
            }
        return {
            "status": "ok",
            "result": self._result(data, name),
            "error": None,
            "elapsed_ms": 3,
            "engine": {"version": "test", "isolation": "test"},
        }

    def analyze_text(self, text: str, settings=None) -> dict:
        return self.analyze_upload(text.encode(), "message.txt", settings)


@pytest.fixture
def api_server(monkeypatch, tmp_path):
    monkeypatch.setattr(web_server, "PUBLIC", False)
    monkeypatch.setattr(web_server, "MAX_ACTIVE_SCANS", 2)
    app = web_server.App()
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), web_server.BaseHTTPRequestHandler)
    httpd.RequestHandlerClass = web_server.make_handler(app, httpd.server_address[1])
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    try:
        yield app, base
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=3)
        shutil.rmtree(app.upload_root, ignore_errors=True)


def _request(app, base: str, path: str, body: bytes, headers: dict | None = None):
    request_headers = {
        "X-CyberScan-Token": app.token,
        "Content-Type": "application/octet-stream",
        **(headers or {}),
    }
    request = Request(f"{base}{path}", data=body, headers=request_headers, method="POST")
    try:
        with urlopen(request, timeout=15) as response:
            return response.status, json.loads(response.read())
    except HTTPError as error:
        return error.code, json.loads(error.read())


def _zip_bytes() -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr("note.txt", "harmless test content")
    return output.getvalue()


def test_file_tool_routes_return_unified_schema_and_qr_contract(api_server, monkeypatch):
    app, base = api_server
    scanner = FakeDetectionService()
    monkeypatch.setattr(web_server.detection_service, "default_service", lambda: scanner)

    status, pdf = _request(app, base, "/api/tools/pdf", b"%PDF-1.4\n%%EOF", {"X-Filename": "note.pdf"})
    assert status == 200
    assert pdf["status"] in {"ok", "partial"}
    assert pdf["detection_summary"]["classification"] == "SUSPICIOUS"
    assert pdf["result"]["file_name"] == "note.pdf"

    status, archive = _request(app, base, "/api/tools/archive", _zip_bytes(), {"X-Filename": "notes.zip"})
    assert status == 200
    assert archive["result"]["archive_inspection"]["entry_count"] == 1
    assert archive["result"]["sentinel_details"]["type"] == "zip"

    status, qr = _request(app, base, "/api/tools/qr", b"\x89PNG\r\n\x1a\nfixture", {"X-Filename": "code.png"})
    assert status == 200
    code = qr["result"]["codes"][0]
    assert (code["kind"], code["payload"], code["risk"]["classification"]) == (
        "url", "https://example.test/", "NO_INDICATORS_OBSERVED"
    )

    status, office = _request(app, base, "/api/tools/office", _zip_bytes(), {"X-Filename": "report.docx"})
    assert status == 200
    assert office["result"]["format"] == "ooxml"

    status, authenticity = _request(
        app, base, "/api/tools/authenticity", b"ordinary text", {"X-Filename": "invoice.pdf"}
    )
    assert status == 200
    assert authenticity["result"]["extension_mismatch"] is True
    assert authenticity["detection_summary"]["classification"] == "SUSPICIOUS"

    status, integrity = _request(
        app, base, "/api/tools/integrity", b"ordinary text", {"X-Filename": "note.txt"}
    )
    assert status == 200
    assert integrity["result"]["sha256"]
    assert integrity["result"]["status"] == "verification_incomplete"


def test_scan_upload_uses_unified_summary_and_cleans_temporary_file(api_server, monkeypatch):
    app, base = api_server
    scanner = FakeDetectionService()
    monkeypatch.setattr(web_server, "PUBLIC", True)
    monkeypatch.setattr(web_server.detection_service, "default_service", lambda: scanner)

    class LegacyScan:
        def analyze(self, *args, **kwargs):
            return object(), None, None, None, None, b"fixture"

    monkeypatch.setattr(web_server, "ScanService", LegacyScan)
    monkeypatch.setattr(
        web_server,
        "serialize_result",
        lambda *args, **kwargs: {
            "classification": "NO_INDICATORS_OBSERVED",
            "combined_score": 1,
            "evidence": [],
            "plain": {},
        },
    )

    status, body = _request(app, base, "/api/scan/file", b"scan fixture", {"X-Filename": "sample.txt"})
    assert status == 200
    assert body["status"] == "done"
    assert body["result"]["classification"] == "SUSPICIOUS"
    assert body["result"]["platform_classification"] == "NO_INDICATORS_OBSERVED"
    assert body["result"]["detection_summary"]["classification"] == "SUSPICIOUS"
    assert list(app.upload_root.iterdir()) == []

    for mode, value in (("url", "https://example.test/"), ("text", "Hello from a test")):
        status, body = _request(
            app,
            base,
            "/api/scan",
            json.dumps({"mode": mode, "value": value}).encode(),
            {"Content-Type": "application/json"},
        )
        assert status == 200
        assert body["status"] == "done"
        assert body["result"]["classification"] == "SUSPICIOUS"
        assert body["result"]["detection_summary"]["classification"] == "SUSPICIOUS"


def test_scan_routes_enforce_text_upload_timeout_and_concurrency_limits(api_server, monkeypatch):
    app, base = api_server
    scanner = FakeDetectionService()
    monkeypatch.setattr(web_server.detection_service, "default_service", lambda: scanner)

    long_text = json.dumps({"mode": "text", "value": "x" * (web_server.MAX_DETECTION_TEXT + 1)}).encode()
    status, oversized = _request(app, base, "/api/scan", long_text, {"Content-Type": "application/json"})
    assert status == 413
    assert oversized["status"] == "rejected"
    assert oversized["error"]["code"] == "too_large"
    assert oversized["detection_summary"]["classification"] == "UNKNOWN"

    scanner.status = "timeout"
    status, timed_out = _request(app, base, "/api/tools/pdf", b"%PDF-1.4", {"X-Filename": "slow.pdf"})
    assert status == 504
    assert timed_out["status"] == "timeout"
    assert timed_out["detection_summary"]["classification"] == "UNKNOWN"

    acquired_slots = []
    try:
        for _ in range(web_server.MAX_ACTIVE_SCANS):
            acquired_slots.append(app.active_scans.acquire(blocking=False))
        assert all(acquired_slots)
        status, busy = _request(
            app, base, "/api/tools/authenticity", b"x", {"X-Filename": "note.txt"}
        )
    finally:
        for acquired in acquired_slots:
            if acquired:
                app.active_scans.release()
    assert status == 503
    assert busy["status"] == "busy"
    assert busy["error"]["code"] == "busy"


def test_upload_limit_error_has_consistent_response(api_server, monkeypatch):
    app, base = api_server
    monkeypatch.setattr(web_server, "PUBLIC", True)
    monkeypatch.setattr(web_server, "PUBLIC_MAX_UPLOAD", 8)
    status, body = _request(app, base, "/api/scan/file", b"123456789", {"X-Filename": "large.txt"})
    assert status == 413
    assert body["status"] == "rejected"
    assert body["error"]["code"] == "too_large"
    assert body["result"] is None
