"""SEC-02: does an ApiError raised after a client disconnect abort the connection?

Deterministic attempt: declare a body, send nothing, close the read side after a
moment so the server's reply write fails.
"""
from __future__ import annotations

import socket
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT), str(ROOT / "web_v")]

from server import create_server, cleanup  # noqa: E402


def main() -> None:
    server, app = create_server(0)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    host = f"127.0.0.1:{port}"
    token = app.token

    outcomes = []
    for attempt in range(6):
        sock = socket.create_connection(("127.0.0.1", port), timeout=10)
        body = b"{not json"
        sock.sendall(
            f"POST /api/scan HTTP/1.1\r\nHost: {host}\r\nX-CyberScan-Token: {token}\r\n"
            f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n\r\n".encode() + body
        )
        # shut down our receive side so the server's reply cannot be delivered
        sock.shutdown(socket.SHUT_RD)
        time.sleep(0.05)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, b"\x01\x00\x00\x00\x00\x00\x00\x00")
        except OSError:
            pass
        sock.close()
        time.sleep(0.2)
        outcomes.append(attempt)

    server.shutdown()
    server.server_close()
    cleanup(app)
    print(f"sent {len(outcomes)} disconnecting invalid-JSON requests; "
          "check stderr above for ConnectionAborted/BrokenPipe traces")


if __name__ == "__main__":
    main()
