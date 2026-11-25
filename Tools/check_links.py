"""Crawl the local CyberScan server and check every internal link and asset.

    python tools/check_links.py                  (starts its own server on a free port)
    python tools/check_links.py --base http://127.0.0.1:8811   (uses a running one)

Starts at the site's pages (/, /app.html, /journey, /support, the trust pages, a few language
addresses), follows same-origin href/src references in HTML (and url() in the site's own CSS),
and fails (exit 1) if any of them answers with 4xx/5xx. External links are not fetched.
Standard library only.
"""
from __future__ import annotations

import argparse
import re
import sys
import threading
import urllib.error
import urllib.request
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urldefrag, urljoin, urlparse

ROOT = Path(__file__).resolve().parents[1]
START = ["/", "/app.html", "/journey", "/support", "/privacy", "/terms", "/security", "/status", "/tests", "/changelog",
         "/ar/", "/fr/", "/ar/privacy", "/sitemap.xml", "/robots.txt", "/.well-known/security.txt", "/manifest.webmanifest"]
SKIP = re.compile(r"^(mailto:|tel:|javascript:|data:|blob:|#)|/api/|\.(apk|exe)$|/pyodide/")
MAX_PAGES = 400


class Refs(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.refs: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = dict(attrs)
        for key in ("href", "src"):
            v = a.get(key)
            if v and not (tag == "link" and a.get("rel") in ("canonical", "alternate")) and not (tag == "meta"):
                self.refs.append(v)
        if tag == "meta" and a.get("property") == "og:image" and a.get("content"):
            self.refs.append(a["content"])


def fetch(url: str) -> tuple[int, str, bytes]:
    """Status, type and body; only pages and stylesheets are downloaded, other files are checked with HEAD."""
    for attempt in range(3):
        try:
            head = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "cyberscan-link-check"})
            with urllib.request.urlopen(head, timeout=30) as r:
                ctype = r.headers.get("Content-Type", "")
            if not ("text/html" in ctype or "text/css" in ctype):
                return 200, ctype, b""
            with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "cyberscan-link-check"}), timeout=30) as r:
                return r.status, r.headers.get("Content-Type", ""), r.read()
        except urllib.error.HTTPError as exc:
            return exc.code, "", b""
        except OSError:
            if attempt == 2:
                return 599, "", b""
    return 599, "", b""


def crawl(base: str) -> list[str]:
    host = urlparse(base).netloc
    seen: set[str] = set()
    queue = [(urljoin(base, p), "(start)") for p in START]
    broken: list[str] = []
    while queue and len(seen) < MAX_PAGES:
        url, origin = queue.pop(0)
        url = urldefrag(url)[0]
        if url in seen:
            continue
        seen.add(url)
        status, ctype, body = fetch(url)
        if status >= 400:
            broken.append(f"{status} {url}  (linked from {origin})")
            continue
        refs: list[str] = []
        if "text/html" in ctype:
            p = Refs()
            p.feed(body.decode("utf-8", "replace"))
            refs = p.refs
        elif "text/css" in ctype:
            css = re.sub(r"url\(\s*([\"'])data:.*?\1\s*\)", "", body.decode("utf-8", "replace"))   # inline SVGs have url(#id) inside
            refs = re.findall(r"url\(\s*['\"]?([^'\")]+)['\"]?\s*\)", css)
        for ref in refs:
            ref = ref.strip()
            if not ref or SKIP.search(ref):
                continue
            target = urljoin(url, ref)
            parsed = urlparse(target)
            # the site's own absolute addresses (canonical domain) are checked against this server
            if parsed.netloc.endswith("ainex-ai.xyz") and parsed.scheme == "https":
                target = urljoin(base, parsed.path or "/")
                parsed = urlparse(target)
            if parsed.netloc == host and target not in seen:
                queue.append((target, url))
    print(f"checked {len(seen)} URLs, {len(broken)} broken")
    return broken


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base")
    args = ap.parse_args()
    base = args.base
    server = None
    if not base:
        sys.path.insert(0, str(ROOT))
        sys.path.insert(0, str(ROOT / "web_v"))
        import os
        os.environ.setdefault("CYBERSCAN_AUTO_UPDATE", "0")
        from web_v.server import create_server
        server, _app = create_server(0)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{server.server_address[1]}"
    broken = crawl(base.rstrip("/") + "/")
    for line in broken:
        print("  " + line)
    if server:
        server.shutdown()
    sys.exit(1 if broken else 0)


if __name__ == "__main__":
    main()
