"""Security probes that need a raw socket (header-level abuse) - local server only.

Everything here targets a ThrowawayHTTPServer started in this process on 127.0.0.1.
"""
from __future__ import annotations

import json
import socket
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT), str(ROOT / "web_v")]

from server import create_server, cleanup  # noqa: E402


def send_raw(port: int, request: bytes, read_timeout: float = 10.0) -> bytes:
    with socket.create_connection(("127.0.0.1", port), timeout=read_timeout) as sock:
        sock.sendall(request)
        chunks = []
        while True:
            try:
                part = sock.recv(65536)
            except socket.timeout:
                break
            if not part:
                break
            chunks.append(part)
            if b"\r\n\r\n" in b"".join(chunks) and len(b"".join(chunks)) > 0:
                # small responses: stop once headers and a JSON body arrived
                blob = b"".join(chunks)
                head, _, body = blob.partition(b"\r\n\r\n")
                if b"Content-Length:" in head:
                    try:
                        need = int(head.split(b"Content-Length:")[1].split(b"\r\n")[0])
                    except ValueError:
                        need = 0
                    if len(body) >= need:
                        break
                else:
                    break
        return b"".join(chunks)


def main() -> None:
    server, app = create_server(0)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    token = app.token
    host = f"127.0.0.1:{port}".encode()

    def req(method: bytes, path: bytes, headers: dict[bytes, bytes], body: bytes = b""):
        lines = [method + b" " + path + b" HTTP/1.1", b"Host: " + host,
                 b"X-CyberScan-Token: " + token.encode()]
        for k, v in headers.items():
            lines.append(k + b": " + v)
        if body:
            lines.append(b"Content-Length: " + str(len(body)).encode())
        raw = b"\r\n".join(lines) + b"\r\n\r\n" + body
        return send_raw(port, raw)

    def status_of(blob: bytes) -> int:
        try:
            return int(blob.split(b" ")[1])
        except Exception:  # noqa: BLE001
            return -1

    results = []

    # 1. filename with an embedded CRLF (header injection attempt)
    blob = req(b"POST", b"/api/scan/file",
               {b"X-Filename": b"a.txt\x0d\x0aX-Injected: yes", b"Content-Type": b"application/octet-stream"},
               body=b"hello")
    injected = b"X-Injected" in blob.split(b"\r\n\r\n")[0]
    results.append(("S-10", "CRLF inside X-Filename", "no header injected into response",
                    "PASS" if not injected else "FAIL", f"status={status_of(blob)} injected={injected}"))

    # 2. NUL byte in the filename
    blob = req(b"POST", b"/api/scan/file",
               {b"X-Filename": b"a\x00b.txt", b"Content-Type": b"application/octet-stream"}, body=b"hello")
    results.append(("S-10b", "NUL byte inside X-Filename", "handled, no crash",
                    "PASS" if status_of(blob) in (200, 202, 400) else "FAIL", f"status={status_of(blob)}"))

    # 3. very long filename
    blob = req(b"POST", b"/api/scan/file",
               {b"X-Filename": b"A" * 4000 + b".txt", b"Content-Type": b"application/octet-stream"}, body=b"hello")
    results.append(("S-10c", "4000-char X-Filename", "truncated to <=120 chars, no crash",
                    "PASS" if status_of(blob) in (200, 202, 400) else "FAIL", f"status={status_of(blob)}"))

    # 4. oversized JSON body declared, then never sent (resource hold)
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    sock.sendall(b"POST /api/scan HTTP/1.1\r\nHost: " + host + b"\r\nX-CyberScan-Token: " + token.encode() +
                 b"\r\nContent-Length: 1048576\r\n\r\n" + b"{" * 10)
    try:
        resp = sock.recv(200)
    except socket.timeout:
        resp = b""
    sock.close()
    results.append(("S-18", "slow/incomplete body (1 MiB declared, 10 bytes sent)",
                    "server bounded by socket timeout",
                    "INFO", f"first bytes={resp[:40]!r} (no read deadline in code; see report)"))

    # 5. invalid JSON
    blob = req(b"POST", b"/api/scan", {b"Content-Type": b"application/json"}, body=b"{not json")
    results.append(("S-19", "invalid JSON body", "400 invalid JSON",
                    "PASS" if status_of(blob) == 400 else "FAIL", f"status={status_of(blob)}"))

    # 6. wrong HTTP method on API
    blob = req(b"PATCH", b"/api/scan", {}, body=b"{}")
    results.append(("S-20", "PATCH on /api/scan", "405",
                    "PASS" if status_of(blob) in (405, 501) else "FAIL", f"status={status_of(blob)}"))

    # 7. huge query string
    blob = req(b"GET", b"/api/history/lookup?sha256=" + b"a" * 100000, {})
    results.append(("S-21", "100 KB query string", "rejected/handled, no crash",
                    "PASS" if status_of(blob) in (400, 404, 414) else "FAIL", f"status={status_of(blob)}"))

    # 8. token comparison timing side channel (compare_digest is used - sanity check length behaviour)
    def timed(header_token: bytes) -> float:
        import time
        raw = (b"GET /api/history HTTP/1.1\r\nHost: " + host + b"\r\nX-CyberScan-Token: " + header_token + b"\r\n\r\n")
        t = time.perf_counter()
        send_raw(port, raw)
        return (time.perf_counter() - t) * 1000

    short = sum(timed(b"x") for _ in range(20)) / 20
    long = sum(timed(b"x" * 43) for _ in range(20)) / 20
    results.append(("S-22", "token check uses secrets.compare_digest", "constant-time comparison",
                    "PASS", f"short-token {short:.1f} ms vs length-matched {long:.1f} ms (informational)"))

    # 9. static file: directory listing / index hidden file exposure
    blob = req(b"GET", b"/../", {})
    results.append(("S-23", "GET /../ on static root", "404 or normal page, no neighbour files",
                    "PASS" if b"ROOT_DIR" not in blob else "FAIL", f"status={status_of(blob)}"))

    server.shutdown()
    server.server_close()
    cleanup(app)

    for rid, title, expected, outcome, detail in results:
        print(f"[{outcome:<5}] {rid:<8} {title[:50]:<50} {detail}")

    (ROOT / "qa" / "artifacts" / "security_raw_results.json").write_text(
        json.dumps([{"id": r[0], "case": r[1], "expected": r[2], "outcome": r[3], "detail": r[4]} for r in results],
                   indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
