"""AWS Lambda entry point for the CyberScan website (Function URL or API Gateway HTTP API).

Handler: lambda_function.handler

Every Lambda event is turned into an ordinary HTTP request and handed to the same
request handler the local server uses (web_v/server.py), in its public mode:
nothing on the server's disk is reachable, nothing is kept between visitors, and
scans finish inside the request. Large static files (Pyodide, the APK) are
redirected to the asset bucket named by CYBERSCAN_ASSET_BASE.

Environment variables:
    CYBERSCAN_ASSET_BASE   https URL of the asset bucket/CDN, no trailing slash (required)
    CYBERSCAN_TOKEN        optional; any string (the page and the API must agree)
"""
from __future__ import annotations

import base64
import io
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
os.environ.setdefault("CYBERSCAN_PUBLIC", "1")
for entry in (HERE, HERE / "web_v"):
    if str(entry) not in sys.path:
        sys.path.insert(0, str(entry))

# Lambda's code folder is read-only: everything the engine writes goes to /tmp.
import config  # noqa: E402

TMP = Path(os.environ.get("CYBERSCAN_DATA", "/tmp/cyberscan"))
TMP.mkdir(parents=True, exist_ok=True)
config.DATA_DIR = TMP
config.REPORT_DIR = TMP / "reports"
config.DEFAULT_SETTINGS["quarantine_directory"] = str(TMP / "quarantine")

import server  # noqa: E402

APP = server.App()
_Handler = server.make_handler(APP, 443)


class _LambdaRequest(_Handler):  # type: ignore[misc, valid-type]
    """The real handler, reading the request from memory instead of a socket."""

    def __init__(self, raw: bytes, client: tuple[str, int]) -> None:  # noqa: D107 - no socket setup
        self.rfile = io.BytesIO(raw)
        self.wfile = io.BytesIO()
        self.client_address = client
        self.server = None
        self.request = None
        self.close_connection = True


_HOP_BY_HOP = {"connection", "keep-alive", "transfer-encoding", "upgrade", "content-length"}


def handler(event: dict, context: object = None) -> dict:
    http = (event.get("requestContext") or {}).get("http") or {}
    method = (http.get("method") or event.get("httpMethod") or "GET").upper()
    path = event.get("rawPath") or event.get("path") or "/"
    query = event.get("rawQueryString") or ""
    headers = {str(k).lower(): str(v) for k, v in (event.get("headers") or {}).items()}
    if event.get("cookies"):
        headers["cookie"] = "; ".join(event["cookies"])

    body = event.get("body") or ""
    data = base64.b64decode(body) if event.get("isBase64Encoded") else body.encode("utf-8")
    for name in list(headers):
        if name in _HOP_BY_HOP:
            del headers[name]
    headers["content-length"] = str(len(data))
    headers["connection"] = "close"

    target = path + (f"?{query}" if query else "")
    head = f"{method} {target} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in headers.items()) + "\r\n"
    request = _LambdaRequest(head.encode("latin-1", "replace") + data, (http.get("sourceIp") or "0.0.0.0", 0))
    request.handle_one_request()

    raw = request.wfile.getvalue()
    head_bytes, _, payload = raw.partition(b"\r\n\r\n")
    lines = head_bytes.decode("latin-1").split("\r\n")
    status = int(lines[0].split(" ", 2)[1]) if lines and lines[0].startswith("HTTP/") else 502
    out: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        if key.strip().lower() in _HOP_BY_HOP:
            continue
        out[key.strip()] = f"{out[key.strip()]}, {value.strip()}" if key.strip() in out else value.strip()
    return {"statusCode": status, "headers": out, "body": base64.b64encode(payload).decode("ascii"), "isBase64Encoded": True}
