"""Launch the CyberScan web interface.

Opens a native window through pywebview (Windows' built-in WebView2) when it is
installed, otherwise opens the default browser.

    .venv\\Scripts\\python.exe web_v\\run.py            # window or browser
    .venv\\Scripts\\python.exe web_v\\run.py --browser  # always the browser
    .venv\\Scripts\\python.exe web_v\\run.py --port 8765 --no-open
"""
from __future__ import annotations

import argparse
import sys
import threading
import webbrowser
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from server import cleanup, create_server  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description="CyberScan web interface")
    parser.add_argument("--port", type=int, default=8765,
                        help="a fixed port keeps the installed app's address stable; 0 picks a free one")
    parser.add_argument("--browser", action="store_true", help="use the default browser")
    parser.add_argument("--no-open", action="store_true", help="only start the server")
    args = parser.parse_args()

    try:
        server, app = create_server(args.port)
    except OSError:
        print(f"Port {args.port} is busy; using a free one (the installed app won't find this one).", flush=True)
        server, app = create_server(0)
    url = f"http://127.0.0.1:{server.server_address[1]}/"
    print(f"CyberScan web interface: {url}", flush=True)

    try:
        if not args.no_open and not args.browser:
            try:
                import webview  # type: ignore[import-not-found]
            except ImportError:
                webview = None
            if webview is not None:
                threading.Thread(target=server.serve_forever, daemon=True).start()
                webview.create_window("CyberScan", url, width=1280, height=820, min_size=(380, 600))
                webview.start()
                return
        if not args.no_open:
            threading.Timer(0.4, webbrowser.open, args=(url,)).start()
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        cleanup(app)


if __name__ == "__main__":
    main()
