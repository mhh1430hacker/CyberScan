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
import logging
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
import assistant  # noqa: E402
import site_extras  # noqa: E402  - trust pages, per-language URLs, sitemap, security.txt, vitals/errors beacons
import visits  # noqa: E402  - the real visit counter (web_v/visits.py)
import profile_stats  # noqa: E402  - the support page's live public numbers (GET /api/profile)
try:
    import toolbox  # noqa: E402
except ImportError:   # the phone engine (m/engine.zip) carries the server's result format, not the Toolbox
    toolbox = None
from detection import service as detection_service  # noqa: E402

STATIC_DIR = Path(__file__).resolve().parent / "static"
# The ONYX team section: the team's logo (0) and the six members' photos (1-6). The files live in the
# project's team/ folder (or static/team/) under any extension: team/3.jpe, team/0.webp... The type is
# read from the file's own bytes, not its name, and only real images are served. /api/team lists them.
TEAM_DIRS = (ROOT / "team", STATIC_DIR / "team")
TEAM_FILE = re.compile(r"team/([0-6])\.([A-Za-z0-9]{1,5})")
TEAM_ORDER = (".webp", ".avif", ".png", ".jpg", ".jpeg", ".jpe", ".jfif", ".gif", ".svg")   # if a slot has several files


def _image_type(head: bytes) -> str | None:
    if head.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "image/webp"
    if head[:6] in (b"GIF87a", b"GIF89a"):
        return "image/gif"
    if head[4:8] == b"ftyp" and head[8:12] in (b"avif", b"avis"):
        return "image/avif"
    text = head.lstrip(b"\xef\xbb\xbf \t\r\n").lower()
    if text.startswith(b"<svg") or (text.startswith(b"<?xml") and b"<svg" in head.lower()):
        return "image/svg+xml"
    return None


def team_file(n: str, ext: str | None = None) -> tuple[Path, str] | None:
    """The image for slot n (0 = the logo) and its type; with ext, only that file name."""
    for folder in TEAM_DIRS:
        if not folder.is_dir():
            continue
        found = [f for f in folder.iterdir() if f.is_file() and f.stem == n and (ext is None or f.suffix[1:].lower() == ext.lower())]
        found.sort(key=lambda f: TEAM_ORDER.index(f.suffix.lower()) if f.suffix.lower() in TEAM_ORDER else 99)
        for f in found:
            with f.open("rb") as fh:
                kind = _image_type(fh.read(512))
            if kind:
                return f, kind
    return None


def team_photos() -> dict:
    out = {}
    for n in "0123456":
        hit = team_file(n)
        if hit:
            f = hit[0]
            out[n] = f"team/{n}{f.suffix.lower()}?v={int(f.stat().st_mtime)}"
    return out
STAGES = 4
MAX_JOBS = 32
MAX_TEXT = 1024 * 1024
MAX_DETECTION_TEXT = 200_000
MAX_DETECTION_UPLOAD = 50 * 1024 * 1024
MAX_ACTIVE_SCANS = max(1, min(4, int(os.environ.get("CYBERSCAN_WEB_CONCURRENCY", "2"))))
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
# Two pages from one file: the landing (index.html) and the scan app, served at /app.html and on
# any host that starts with "scan." (e.g. scan.ainex-ai.xyz). The scan page is index.html without
# the landing and its heavy scripts (particle field, film, scroll scenes…).
SCAN_URL = os.environ.get("CYBERSCAN_SCAN_URL", "app.html")    # where the landing sends people
HOME_URL = os.environ.get("CYBERSCAN_HOME_URL", "/")           # where the scan page's logo leads
JOURNEY_URL = os.environ.get("CYBERSCAN_JOURNEY_URL", "/journey")   # the File Journey (its own host on the site: j.<domain>)
LANDING_ONLY_CSS = ("landing.css", "scroll.css", "science.css", "scrolly.css", "saudi.css", "cinema.css", "team.css", "theme.css", "get-app.css", "hero-art.css",
                    "intro.css", "landing-plus.css", "origin.css")
LANDING_ONLY_JS = ("js/gl-hero.js", "js/pipeline.js", "js/film.js", "js/story.js", "js/landing.js",
                   "js/get-app.js", "js/lite.js", "js/scroll.js", "js/science.js", "js/scrolly-i18n.js", "js/scrolly.js", "js/saudi.js", "js/tilt.js", "js/tour.js", "js/team.js",
                   "js/intro-early.js", "js/intro.js", "js/landing-i18n.js", "js/live-demo.js", "js/origin.js")   # the opening sequence (#preloader) is the landing's own


def _cut(html: str, start: str, end: str) -> str:
    """Remove from the first `start` up to and including the next `end`."""
    i = html.find(start)
    if i < 0:
        return html
    j = html.find(end, i + len(start))
    return html if j < 0 else html[:i] + html[j + len(end):]


def _cut_element(html: str, start: str, tag: str = "div") -> str:
    """Remove the element that begins at the first `start`, through its own matching end tag
    (nested elements of the same name are counted, so the result stays well-formed whatever the
    markup's indentation)."""
    i = html.find(start)
    if i < 0:
        return html
    depth = 0
    for m in re.finditer(rf"<(/?){tag}\b[^>]*>", html[i:]):
        depth += -1 if m.group(1) else 1
        if depth == 0:
            return html[:i] + html[i + m.end():]
    return html


# Scripts and styles only the scan app uses (the landing page has none of their markup or events).
APP_ONLY_JS = ("js/file-tools.js", "js/repair.js", "js/scan-pro.js", "js/external-intel.js", "js/tools.js", "js/batch.js", "js/palette.js", "js/pwa.js", "js/insights.js", "js/workspace.js",
               "js/scan-center.js", "js/toolbox.js", "js/toolbox-ar.js")
APP_ONLY_CSS = ("toolbox.css",)
CANONICAL_URL = os.environ.get("CYBERSCAN_CANONICAL_URL", "").strip().rstrip("/")

# ---- static file cache: content hashes (versioned URLs, ETags) and gzip, keyed by mtime/size
_ASSETS: dict[str, tuple[int, int, str, bytes | None]] = {}
_ASSETS_LOCK = threading.Lock()
COMPRESSIBLE = ("text/", "application/javascript", "application/json", "application/manifest+json", "image/svg+xml", "application/xml")
VERSIONED = re.compile(r"_v/([0-9a-f]{10})/(.+)")    # /_v/<content hash>/<path>: a file at one exact version
BUNDLE = re.compile(r"((?:[\w-]+\+)+[\w-]+)\.css")   # a+b+c.css: those root stylesheets, joined in order
JS_BUNDLE = re.compile(r"((?:[\w-]+(?:~[\w-]+)*\+)+[\w-]+(?:~[\w-]+)*)\.js")   # js~a+js~b.js: js/a.js then js/b.js


def _asset(path: Path, compressible: bool) -> tuple[str, bytes | None]:
    """(content hash, gzip body or None) of a static file; recomputed only when the file changes.
    Large files (the phone engine, the APK) are only hashed, never kept in memory."""
    import hashlib  # noqa: PLC0415

    st = path.stat()
    key = str(path)
    hit = _ASSETS.get(key)
    if not (hit and hit[0] == st.st_mtime_ns and hit[1] == st.st_size):
        digest = hashlib.sha256(path.read_bytes()).hexdigest()[:16]
        hit = (st.st_mtime_ns, st.st_size, digest, False)   # False: not compressed yet
        with _ASSETS_LOCK:
            _ASSETS[key] = hit
    if hit[3] is False and compressible and not PUBLIC:
        gz = _gzip(path.read_bytes()) if st.st_size <= 16 * 1024 * 1024 else None
        hit = (hit[0], hit[1], hit[2], gz)
        with _ASSETS_LOCK:
            _ASSETS[key] = hit
    return hit[2], (hit[3] if compressible and hit[3] is not False else None)


def _bundle_body(names: list[str]) -> bytes | None:
    """Root stylesheets joined in order (url() paths stay valid: they are all in the same folder)."""
    files = [STATIC_DIR / n for n in names]
    if not all(re.fullmatch(r"[\w.-]+\.css", n) for n in names) or not all(f.is_file() for f in files):
        return None
    return _min_css(b"\n".join(f.read_bytes() for f in files))


def _min_css(css: bytes) -> bytes:
    """A conservative minifier: comments out, runs of whitespace folded, spaces dropped only next to
    braces, semicolons and commas (never around ':', since "a :hover" and "a:hover" differ)."""
    text = css.decode("utf-8", "replace")
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r"\s+", " ", text)
    text = re.sub(r"\s*([{};,])\s*", r"\1", text)
    return text.replace(";}", "}").strip().encode("utf-8")


def _gzip(data: bytes) -> bytes | None:
    import gzip  # noqa: PLC0415

    if len(data) <= 512:
        return None
    packed = gzip.compress(data, 6, mtime=0)
    return packed if len(packed) < len(data) else None


_BUNDLES: dict[tuple, tuple[str, bytes, str, bytes | None]] = {}


def _bundle_stamp(names: list[str]) -> str:
    import hashlib  # noqa: PLC0415

    return hashlib.sha256("".join(f"{n}:{_version_of(n)}" for n in names).encode()).hexdigest()[:10]


def _bundle(names: list[str]) -> tuple[str, bytes, str, bytes | None] | None:
    """(stamp, body, content hash, gzip) of a stylesheet bundle, rebuilt only when a part changes."""
    import hashlib  # noqa: PLC0415

    if len(names) > 60 or not all(re.fullmatch(r"[\w-]+\.css", n) and (STATIC_DIR / n).is_file() for n in names):
        return None
    key = tuple((n, (STATIC_DIR / n).stat().st_mtime_ns, (STATIC_DIR / n).stat().st_size) for n in names)
    hit = _BUNDLES.get(key)
    if hit is None:
        body = _bundle_body(names)
        if body is None:
            return None
        hit = (_bundle_stamp(names), body, hashlib.sha256(body).hexdigest()[:16], None if PUBLIC else _gzip(body))
        with _ASSETS_LOCK:
            if len(_BUNDLES) > 16:
                _BUNDLES.clear()
            _BUNDLES[key] = hit
    return hit


# ---- script bundles: the page's consecutive deferred scripts served as one file, in order.
# Deferred scripts already run one after another in document order, so joining a run of them
# changes only the number of requests. What stays a file of its own: the synchronous *-early.js
# head scripts, any file that starts with a file-level "use strict" (joined, its strictness would
# silently apply to nothing or to its neighbours), and anything that isn't a plain local .js.
# Files that are one IIFE (no top-level declarations) are wrapped in try/catch, so an error in one
# is reported but doesn't stop the scripts after it, as it wouldn't when they were separate files.
_JS_STRICT = re.compile(r'\A\ufeff?\s*(?:(?:/\*.*?\*/|//[^\n]*)\s*)*["\']use strict["\']', re.S)
_JS_IIFE = re.compile(r"\A\s*(?:(?:/\*.*?\*/|//[^\n]*)\s*)*[(!]\s*(?:async\s+)?(?:function\b|\(\s*\)\s*=>)", re.S)
_JS_TOP_DECL = re.compile(r"^(?:const|let|var|function|async function|class)\b", re.M)
_JS_TAG = re.compile(r'<script src="((?:[\w-]+/)*[\w-]+\.js)"></script>')
_JS_RUN = re.compile(r'(?:<script src="(?:[\w-]+/)*[\w-]+\.js"></script>\s*){2,}')


def _js_joinable(rel: str) -> bool:
    f = STATIC_DIR / rel
    if rel.endswith("-early.js") or not f.is_file():
        return False
    with f.open("rb") as fh:
        head = fh.read(4096).decode("utf-8", "ignore")
    return not _JS_STRICT.match(head)


def _js_part(rel: str, data: bytes) -> bytes:
    text = data.decode("utf-8").replace("\r\n", "\n").rstrip()
    if _JS_IIFE.match(text) and not _JS_TOP_DECL.search(text) and text.endswith((")();", ")()", "}();")):
        text = f"try {{\n{text}\n}} catch (e) {{ setTimeout(function () {{ throw e; }}); }}"
    return f"/* {rel} */\n{text}\n;\n".encode("utf-8")


def _js_bundle(names: list[str]) -> tuple[str, bytes, str, bytes | None] | None:
    """(stamp, body, content hash, gzip) of a script bundle, rebuilt only when a part changes."""
    import hashlib  # noqa: PLC0415

    if not 1 < len(names) <= 80 or not all(re.fullmatch(r"(?:[\w-]+/)*[\w-]+\.js", n) and _js_joinable(n) for n in names):
        return None
    key = ("js",) + tuple((n, (STATIC_DIR / n).stat().st_mtime_ns, (STATIC_DIR / n).stat().st_size) for n in names)
    hit = _BUNDLES.get(key)
    if hit is None:
        body = b"".join(_js_part(n, (STATIC_DIR / n).read_bytes()) for n in names)
        hit = (_bundle_stamp(names), body, hashlib.sha256(body).hexdigest()[:16], None if PUBLIC else _gzip(body))
        with _ASSETS_LOCK:
            if len(_BUNDLES) > 16:
                _BUNDLES.clear()
            _BUNDLES[key] = hit
    return hit


def _bundle_scripts(html: str) -> str:
    """Replace each run of plain consecutive <script src> tags with as few bundles as allowed."""
    def run(m: re.Match) -> str:
        out: list[str] = []
        group: list[str] = []

        def flush() -> None:
            built = _js_bundle(group) if len(group) > 1 else None
            if built is not None:
                out.append(f'<script src="/_v/{built[0]}/{"+".join(n[:-3].replace("/", "~") for n in group)}.js"></script>')
            else:
                out.extend(f'<script src="{n}"></script>' for n in group)
            group.clear()

        for name in _JS_TAG.findall(m.group(0)):
            if _js_joinable(name):
                group.append(name)
            else:
                flush()
                out.append(f'<script src="{name}"></script>')
        flush()
        return "\n  ".join(out) + "\n  "
    return _JS_RUN.sub(run, html)


def _version_of(rel: str) -> str | None:
    target = (STATIC_DIR / rel).resolve()
    if STATIC_DIR not in target.parents or not target.is_file():
        return None
    return _asset(target, False)[0][:10]


def _versioned_refs(html: str, defer: bool, bundle: bool) -> str:
    """Point the page's own CSS/JS at content-versioned URLs (/_v/<hash>/<file>), so they can be
    cached for a year and change URL when they change (a query string isn't enough: the documented
    CloudFront cache policy leaves it out of the cache key). Optionally let scripts download
    without blocking the page (defer keeps their order; the tiny *-early.js head scripts stay
    synchronous because they decide classes before the first paint) and serve the head's
    stylesheets as one file."""
    head_end = html.find("</head>")
    if bundle and head_end > 0:
        head = html[:head_end]
        links = re.findall(r'<link rel="stylesheet" href="([\w.-]+\.css)">', head)
        built = _bundle(links) if len(links) > 1 else None
        if built is not None:
            first = head.find(f'<link rel="stylesheet" href="{links[0]}">')
            for name in links:
                head = head.replace(f'<link rel="stylesheet" href="{name}">', "", 1)
            joined = "+".join(n[:-4] for n in links)
            stamp = built[0]
            head = head[:first] + f'<link rel="stylesheet" href="/_v/{stamp}/{joined}.css">' + head[first:]
            html = head + html[head_end:]

    if bundle and defer:
        html = _bundle_scripts(html)

    def script(m: re.Match) -> str:
        src, rest = m.group(1), m.group(2)
        v = _version_of(src) if not src.startswith(("http", "/", "_v/")) else None
        url = f"/_v/{v}/{src}" if v else src
        if defer and "defer" not in rest and "type=\"module\"" not in rest and "async" not in rest and not src.endswith("-early.js"):
            rest += " defer"
        return f'<script src="{url}"{rest}></script>'

    def link(m: re.Match) -> str:
        href = m.group(1)
        v = _version_of(href) if not href.startswith(("http", "/", "_v/")) else None
        return f'<link rel="stylesheet" href="{"/_v/" + v + "/" + href if v else href}">'

    html = re.sub(r'<script src="([^"]+\.js)"([^>]*)></script>', script, html)
    return re.sub(r'<link rel="stylesheet" href="([^"]+\.css)">', link, html)


def _head_meta(html: str, path: str = "/", lang: str | None = None) -> str:
    """Canonical address, hreflang alternates, the page's social card, JSON-LD and the shared
    accessibility / monitoring scripts (web_v/site_extras.py; the site's address defaults to
    https://ainex-ai.xyz, CYBERSCAN_CANONICAL_URL changes it)."""
    return site_extras.decorate(html, path, lang)


def landing_page(html: str) -> str:
    """The presentation site: index.html without the scan app (it lives on its own page)."""
    # the app, then its confirm dialog (the next </dialog>); the messages box after it stays
    html = _cut(html, "<!-- ===================================================== APP -->", "</dialog>")
    html = _cut_element(html, '<div id="palette"')
    html = _cut(html, '<dialog id="shortcuts"', "</dialog>")
    html = _cut_element(html, '<div id="drop-veil"')
    for js in APP_ONLY_JS:
        html = html.replace(f'<script src="{js}"></script>', "")
    for css in APP_ONLY_CSS:
        html = html.replace(f'<link rel="stylesheet" href="{css}">', "")
    # the landing's own small core instead of the scan app's script
    return html.replace('<script src="app.js"></script>', '<script src="js/site.js"></script>', 1)


_PAGES: dict[tuple, tuple[tuple, bytes]] = {}
_GZ_PAGES: dict[str, bytes] = {}   # gzip of rendered pages, by content hash


def _static_signature() -> tuple:
    """Changes whenever a file the pages reference changes (a few hundred stat calls, ~1 ms)."""
    newest, count = 0, 0
    for folder in (STATIC_DIR, STATIC_DIR / "js", STATIC_DIR / "js" / "performance"):
        try:
            with os.scandir(folder) as it:
                for entry in it:
                    if entry.is_file():
                        count += 1
                        newest = max(newest, entry.stat().st_mtime_ns)
        except OSError:
            pass
    return newest, count


def page_html(raw: bytes, token: str, scan: bool, lang: str | None = None) -> bytes:
    """The rendered page, kept until index.html or a file it references changes: rendering
    (cutting, versioning every reference) costs tens of ms of GIL time per request otherwise."""
    import hashlib  # noqa: PLC0415

    key = (hashlib.sha256(raw).digest(), token, scan, lang)
    sig = _static_signature()
    hit = _PAGES.get(key)
    if hit and hit[0] == sig:
        return hit[1]
    body = _render_page(raw, token, scan, lang)
    with _ASSETS_LOCK:
        if len(_PAGES) > 40:   # landing + scan, and the landing in each of the 30 language addresses
            _PAGES.clear()
        _PAGES[key] = (sig, body)
    return body


def _render_page(raw: bytes, token: str, scan: bool, lang: str | None = None) -> bytes:
    html = raw.decode("utf-8").replace("\r\n", "\n")   # a Windows checkout has CRLF line ends
    html = html.replace("__CYBERSCAN_TOKEN__", token).replace("__CYBERSCAN_SCAN_URL__", SCAN_URL).replace("__CYBERSCAN_HOME_URL__", HOME_URL)
    if not scan:
        html = landing_page(html.replace('href="/journey"', f'href="{JOURNEY_URL}"'))
        return _versioned_refs(_head_meta(html, "/", lang), defer=True, bundle=True).encode("utf-8")
    html = _cut(html, "<!-- ===================================================== LANDING -->", "<!-- ===================================================== APP -->")
    html = _cut_element(html, '<nav class="side-dots"', "nav")
    html = _cut_element(html, '<div id="preloader"')
    for line in ('<canvas id="gl-hero" class="gl-hero" aria-hidden="true"></canvas>', '<div class="tint" id="tint" aria-hidden="true"></div>',
                 '<div class="scroll-progress" aria-hidden="true"><i></i></div>'):
        html = html.replace(line, "")
    for css in LANDING_ONLY_CSS:
        html = html.replace(f'<link rel="stylesheet" href="{css}">', "")
    for js in LANDING_ONLY_JS:
        html = html.replace(f'<script src="{js}"></script>', "")
    # a calm working layout: its own stylesheet, no backdrop particles, grain or custom cursor
    for piece in ('<canvas id="cells" class="cells" aria-hidden="true"></canvas>', '<div class="glow-cursor" aria-hidden="true"></div>',
                  '<div class="grain" aria-hidden="true"></div>', '<div class="cursor-ring" aria-hidden="true"><span></span></div>',
                  '<div class="cursor-dot" aria-hidden="true"></div>', '<script src="js/cells.js"></script>', '<script src="js/fx.js"></script>'):
        html = html.replace(piece, "")
    html = html.replace('<link rel="stylesheet" href="a11y.css">', '<link rel="stylesheet" href="a11y.css">\n  <link rel="stylesheet" href="scan.css">\n  <link rel="stylesheet" href="workspace.css">\n  <link rel="stylesheet" href="scan-center.css">\n  <link rel="stylesheet" href="scan-pro.css">\n  <link rel="stylesheet" href="result-plus.css">\n  <link rel="stylesheet" href="scan-extras.css">\n  <link rel="stylesheet" href="layers.css">', 1)
    html = html.replace('<body class="on-landing">', '<body class="page-scan">', 1)
    html = html.replace("<title>CyberScan</title>", "<title>CyberScan · Scan</title>", 1)
    html = html.replace('<a class="skip-link" href="#top"', '<a class="skip-link" href="#app"', 1)
    html = html.replace('<a class="brand" href="#/" title="Home">', f'<a class="brand" href="{HOME_URL}" title="Home">', 1)
    return _versioned_refs(_head_meta(html, "/app.html"), defer=True, bundle=True).encode("utf-8")


PUBLIC_DISABLED = {
    "history_quarantine", "history_restore", "history_reveal", "history_ai", "ai_poll", "ai_stop",
    "settings_put", "keys_put", "pick", "repair_path", "protection_update",
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


FILE_TOOL_ROUTES = {"pdf_tool", "archive_tool", "qr_tool", "office_tool", "authenticity_tool", "integrity_tool"}
SCAN_API_ROUTES = {"scan_start", "scan_upload"} | FILE_TOOL_ROUTES


def _unknown_detection_summary(host_classification: str = "UNKNOWN") -> dict[str, Any]:
    return {
        "classification": "UNKNOWN",
        "needs_attention": True,
        "host_classification": host_classification,
        "content_classification": "UNKNOWN",
        "content_score": 0,
        "evidence_agreement": "none",
        "privacy_exposure": "unknown",
    }


def _scan_error_envelope(status: int, message: str) -> dict[str, Any]:
    if status in {
        HTTPStatus.BAD_REQUEST,
        HTTPStatus.FORBIDDEN,
        HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
        HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
        HTTPStatus.UNPROCESSABLE_ENTITY,
    }:
        state = "rejected"
        code = {
            HTTPStatus.BAD_REQUEST: "invalid_request",
            HTTPStatus.FORBIDDEN: "forbidden",
            HTTPStatus.REQUEST_ENTITY_TOO_LARGE: "too_large",
            HTTPStatus.UNSUPPORTED_MEDIA_TYPE: "unsupported_format",
            HTTPStatus.UNPROCESSABLE_ENTITY: "invalid_request",
        }[HTTPStatus(status)]
    elif status == HTTPStatus.SERVICE_UNAVAILABLE:
        state, code = "busy", "busy"
    elif status == HTTPStatus.GATEWAY_TIMEOUT:
        state, code = "timeout", "timeout"
    else:
        state, code = "error", "analysis_failed"
    from core.status_text import error_text  # noqa: PLC0415

    words = error_text({"invalid_request": "analysis_failed", "forbidden": "analysis_failed",
                        "unsupported_format": "analysis_failed"}.get(code, code))
    return {
        "status": state,
        "result": None,
        "error": {"code": code, "message": message or words["en"], "en": message or words["en"], "ar": words["ar"]},
        "elapsed_ms": 0,
        "engine": {"version": detection_service.ENGINE_VERSION, "isolation": "not_started"},
        "detection_summary": _unknown_detection_summary(),
    }


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


# What a reopened record does not take from the saved page: it belongs to the moment of opening.
VIEW_VOLATILE = ("record_id", "exists", "quarantined", "history_error", "timestamp")


def _view_path(report_path: Path) -> Path:
    """The page as it was shown, saved next to the report: scan_<id>.view.json."""
    return report_path.with_name(report_path.stem + ".view.json")


def record_history(result: ScanResult, display_target: str, shown: dict[str, Any] | None = None,
                   mode: str | None = None) -> str:
    """Save a scan: the engine report (scan_<id>.json, what exports read) and the full payload the
    page showed (scan_<id>.view.json), so a reopened record is the same result, not a rebuild."""
    HISTORY_DIR.mkdir(parents=True, exist_ok=True)
    record_id = uuid.uuid4().hex
    report_path = HISTORY_DIR / f"scan_{record_id}.json"
    saved = dataclasses.replace(result, target=display_target)
    export_report(saved, report_path, "json")
    if shown:
        view = {key: value for key, value in shown.items() if key not in VIEW_VOLATILE}
        _view_path(report_path).write_text(json.dumps(view, ensure_ascii=False), encoding="utf-8")
    record = {
        "id": record_id,
        "timestamp": datetime.now().astimezone().isoformat(timespec="seconds"),
        "target": display_target,
        "mode": mode or (shown or {}).get("mode") or "",
        "classification": (shown or {}).get("classification") or result.classification,
        "engine_classification": (shown or {}).get("platform_classification") or result.classification,
        "score": int((shown or {}).get("final_score", result.combined_score) or 0),
        "sha256": str(result.feature_summary.get("sha256", "")),
        "report_path": str(report_path.resolve()),
    }
    if shown and isinstance(shown.get("detection_summary"), dict):
        record["detection_summary"] = shown["detection_summary"]
    with STORE_LOCK:
        candidate = [*load_history(), record]
        try:
            STORE.save_history(candidate[-HISTORY_LIMIT:])
        except (OSError, TypeError, ValueError):
            report_path.unlink(missing_ok=True)
            _view_path(report_path).unlink(missing_ok=True)
            raise
    for expired in candidate[:-HISTORY_LIMIT]:
        _remove_saved(expired)
    return record_id


def _remove_saved(record: dict[str, Any]) -> None:
    try:
        path = _report_path(record)
    except (OSError, ApiError):
        return
    for item in (path, _view_path(path)):
        try:
            item.unlink(missing_ok=True)
        except OSError:
            pass


def result_from_record(record: dict[str, Any]) -> ScanResult:
    try:
        payload = json.loads(_report_path(record).read_text(encoding="utf-8"))
    except ValueError as exc:
        logging.warning("Saved report %s can't be read: %s", record.get("id"), exc)
        raise ApiError(410, "The saved report can't be read.") from exc
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
                engines=list(i.get("engines") or []), also=list(i.get("also") or []),
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
            "report": _report_available(r),
        }
        for r in reversed(load_history())
    ]


def _report_available(record: dict[str, Any]) -> bool:
    try:
        return _report_path(record).is_file()
    except (OSError, ApiError):
        return False


def _record_mode(record: dict[str, Any], result: ScanResult) -> str:
    """The input mode of a record saved before records stored it: a link, a file (it has a
    fingerprint), else text. An uploaded file's name is not a path, so the name can't tell."""
    if record.get("mode") in {"File", "URL", "Text"}:
        return record["mode"]
    target = str(record.get("target", ""))
    if target.startswith(("http://", "https://")):
        return "URL"
    if (result.feature_summary or {}).get("sha256"):
        return "File"
    return "Text"


def history_open(record_id: str, lang: str | None = None) -> dict[str, Any]:
    """The saved result. Records from this version carry the page exactly as it was shown; older
    records are rebuilt from their report (with the saved verdict) as faithfully as they allow."""
    record = find_record(record_id)
    out: dict[str, Any] | None = None
    try:
        view = _view_path(_report_path(record))
        if view.is_file():
            out = json.loads(view.read_text(encoding="utf-8"))
            out["reopened"] = "saved_view"
    except (OSError, ValueError, ApiError):
        out = None
    if out is None:
        result = result_from_record(record)
        out = serialize_result(result, record["target"], _record_mode(record, result), None, None, lang)
        out["reopened"] = "rebuilt"
        # the classification the page showed (after the content inspection) and its summary
        if isinstance(record.get("detection_summary"), dict):
            out["platform_classification"] = out.get("classification")
            out["classification"] = record.get("classification") or out.get("classification")
            out["detection_summary"] = record["detection_summary"]
            final = record["detection_summary"].get("final_score")
            out["final_score"] = out["score"] = int(final if final is not None else record.get("score", 0) or 0)
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
    _remove_saved(record)
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
    result: ScanResult, display_target: str, mode: str | None, raw: bytes | None, elapsed: float | None,
    lang: str | None = None,
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
        out.update(services.present(result, display_target, mode, raw, elapsed, lang))
    except Exception:  # noqa: BLE001 - the raw result is still useful
        logging.exception("Presenting a result failed")
        out["present_error"] = "presentation_failed"
    return out


# ---------------------------------------------------------------- scans
class Job:
    def __init__(self, accepted_at: float | None = None) -> None:
        self.id = uuid.uuid4().hex
        # end-to-end clock: from the moment the request was accepted (before the upload was read)
        self.accepted_at = accepted_at if accepted_at is not None else time.monotonic()
        self.stages = [{"state": "pending", "detail": ""} for _ in range(STAGES)]
        self.status = "running"
        self.result: dict[str, Any] | None = None
        self.error: str | None = None             # a friendly sentence, never Python exception text
        self.error_info: dict[str, Any] | None = None   # {code, message, en, ar}
        # layered analysis, streamed while it runs: {"done", "total", "cells": [{"id", "s", "st"}]}
        self.layers: dict[str, Any] | None = None

    def layer_progress(self, entry: dict[str, Any], done: int, total: int) -> None:
        if self.layers is None:
            self.layers = {"done": 0, "total": total, "cells": []}
        self.layers["cells"].append({"id": entry["id"], "s": entry.get("signal"), "st": entry.get("status")})
        self.layers["done"] = done
        self.layers["total"] = total

    def snapshot(self) -> dict[str, Any]:
        out = {"id": self.id, "status": self.status, "stages": self.stages, "result": self.result, "error": self.error}
        if self.error_info:
            out["error_info"] = self.error_info
        if self.layers is not None:
            out["layers"] = {**self.layers, "cells": list(self.layers["cells"])}
        if self.status == "running":
            out["elapsed_ms"] = int((time.monotonic() - self.accepted_at) * 1000)
        return out


def _friendly_failure(exc: BaseException) -> dict[str, Any]:
    """A stable code and words for a scan that could not produce any result (logged in full)."""
    from core.status_text import error_text  # noqa: PLC0415

    text = str(exc).lower()
    if isinstance(exc, FileNotFoundError):
        code = "not_found"
    elif isinstance(exc, PermissionError) or (isinstance(exc, OSError) and not isinstance(exc, TimeoutError)):
        code = "unreadable"
    elif isinstance(exc, TimeoutError):
        code = "timeout"
    elif isinstance(exc, ValueError) and ("limit" in text or "maximum" in text or "exceeds" in text):
        code = "too_large"
    elif isinstance(exc, ValueError) and "empty" in text:
        code = "empty_input"
    else:
        code = "analysis_failed"
    return error_text(code)


CONTENT_STATUS = {"ok": "complete", "timeout": "timeout", "busy": "busy", "rejected": "failed", "error": "failed"}


class App:
    def __init__(self) -> None:
        # Public mode runs on many short-lived instances: the page must work with any of them,
        # so the token is the same everywhere (it only stops other sites from driving the API).
        self.token = os.environ.get("CYBERSCAN_TOKEN") or ("cyberscan-public" if PUBLIC else secrets.token_urlsafe(32))
        self.jobs: dict[str, Job] = {}
        self.lock = threading.Lock()
        self.active_scans = threading.BoundedSemaphore(MAX_ACTIVE_SCANS)
        self.upload_root = Path(tempfile.mkdtemp(prefix="cyberscan-web-"))

    @staticmethod
    def warm() -> None:
        """Get the first scan's one-time costs out of the way while the server starts: a warm
        Sentinel worker process (imports, YARA and YARA-Forge rules loaded) and, in this process,
        the same rules for the host pipeline. Returns at once; both happen in the background."""
        try:
            detection_service.default_service().warm()
        except Exception:  # noqa: BLE001 - the first scan then simply pays the start-up cost
            logging.exception("Could not pre-start the Sentinel worker")

        def host() -> None:
            try:
                sample = Path(tempfile.mkdtemp(prefix="cyberscan-warm-")) / "warm-up.txt"
                sample.write_bytes(detection_service.WARM_SAMPLE)
                try:
                    ScanService().analyze(str(sample), "File", {**load_settings(), "osint_enabled": False})
                finally:
                    shutil.rmtree(sample.parent, ignore_errors=True)
            except Exception:  # noqa: BLE001
                logging.exception("Host warm-up failed")

        threading.Thread(target=host, name="cyberscan-host-warm-up", daemon=True).start()

    def start_job(
        self,
        candidate: str,
        mode: str,
        display: str,
        cleanup: Path | None,
        lang: str | None = None,
        detection_data: bytes | None = None,
        accepted_at: float | None = None,
        external: tuple[bool, str] | None = None,
    ) -> Job:
        if not self.active_scans.acquire(blocking=False):
            raise ApiError(HTTPStatus.SERVICE_UNAVAILABLE, "The scanner is at capacity. Try again shortly.")
        job = Job(accepted_at)
        with self.lock:
            if len(self.jobs) >= MAX_JOBS:
                finished = [k for k, j in self.jobs.items() if j.status != "running"]
                for key in finished[: len(self.jobs) - MAX_JOBS + 1]:
                    del self.jobs[key]
            self.jobs[job.id] = job

        def progress(index: int, state: str, detail: Any) -> None:
            # ui.scan_service sends StageText: English words plus {code, en, ar}; the page shows
            # the words in its language (``detail`` is that object; plain strings stay strings).
            if 0 <= index < STAGES:
                job.stages[index] = {"state": state, "detail": getattr(detail, "i18n", None) or str(detail),
                                     "at_ms": int((time.monotonic() - job.accepted_at) * 1000)}

        def sentinel(settings: dict[str, Any]) -> dict[str, Any]:
            """Sentinel's content inspection (its own warm worker process); never raises."""
            try:
                detector = detection_service.default_service()
                if mode == "File":
                    data = detection_data
                    if data is None:
                        file_path = Path(candidate)
                        if file_path.stat().st_size > detector.limits.max_bytes:
                            return _scan_error_envelope(
                                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                                f"The file is larger than {detector.limits.max_bytes:,} bytes for the bounded content scanner.",
                            )
                        data = file_path.read_bytes()
                    return detector.analyze_upload(data, Path(display).name or "upload.bin", settings)
                return detector.analyze_text(candidate, settings)
            except Exception:  # noqa: BLE001 - the host pipeline's result still stands
                logging.exception("Sentinel scan failed")
                return _scan_error_envelope(HTTPStatus.INTERNAL_SERVER_ERROR, "")

        def run() -> None:
            started = job.accepted_at
            timing: dict[str, int] = {"queued_ms": int((time.monotonic() - started) * 1000)}
            try:
                settings = load_settings()
                size = (len(detection_data) if detection_data is not None
                        else Path(candidate).stat().st_size if mode == "File" else None)
                empty = mode == "File" and size == 0
                # The two engines run side by side: Sentinel in its worker process, the host
                # pipeline here. Their results are joined below into one verdict.
                holder: dict[str, Any] = {}
                side: threading.Thread | None = None
                if not empty:
                    def content_side() -> None:
                        t0 = time.monotonic()
                        holder["envelope"] = sentinel(settings)
                        timing["content_ms"] = int((time.monotonic() - t0) * 1000)

                    detector = detection_service.default_service()
                    if getattr(detector, "isolation", "process") == "process":
                        side = threading.Thread(target=content_side, name="cyberscan-sentinel", daemon=True)
                        side.start()
                    else:
                        content_side()   # one process (AWS Lambda): nothing to gain from a thread
                t0 = time.monotonic()
                result: Any = None
                raw: bytes = b""
                host_failure: BaseException | None = None
                try:
                    # external intelligence (VirusTotal and the others) for this scan: on/off and why
                    host_settings = settings if external is None else {
                        **settings, "osint_enabled": external[0], "osint_off_reason": external[1]}
                    payload = ScanService().analyze(candidate, mode, host_settings, progress)
                    result, raw = payload[0], payload[5]
                except Exception as exc:  # noqa: BLE001 - Sentinel's result may still answer
                    logging.exception("Host scan failed")
                    host_failure = exc
                timing["analysis_ms"] = int((time.monotonic() - t0) * 1000)
                if side is not None:
                    side.join(timeout=float(getattr(detector.limits, "timeout_seconds", 30)) + 20)
                envelope = holder.get("envelope") or (
                    None if empty else _scan_error_envelope(HTTPStatus.GATEWAY_TIMEOUT, ""))
                sentinel_ok = bool(envelope) and envelope.get("status") == "ok" and isinstance(envelope.get("result"), dict)
                combined = envelope["result"] if sentinel_ok else {}
                if result is None:
                    # The host pipeline failed; Sentinel's host analysis (same engines) still answers.
                    if sentinel_ok and not combined.get("analysis_incomplete"):
                        result = services.scan_result_from_payload(combined, display)
                        raw = detection_data if detection_data is not None else (
                            candidate.encode("utf-8", errors="replace") if mode != "File" else b"")
                    else:
                        raise host_failure or RuntimeError("no result")
                content = combined.get("content_analysis") if sentinel_ok else None
                content = content if isinstance(content, dict) else None
                content_incomplete = (not empty) and (
                    not sentinel_ok or content is None or bool(content.get("analyzer_errors"))
                    or bool(content.get("truncated_input")))
                is_result = isinstance(result, ScanResult)
                host_incomplete = host_failure is not None or (is_result and any(
                    item.get("critical") for item in (result.feature_summary.get("analysis_incomplete") or [])))
                legacy_classification = str(result.classification) if is_result else None
                content_state = ("complete" if sentinel_ok and not content_incomplete
                                 else "partial" if sentinel_ok else CONTENT_STATUS.get(str((envelope or {}).get("status")), "failed"))
                parts: dict[str, Any] = {}
                layered: dict[str, Any] | None = None
                layer_effect: dict[str, Any] | None = None
                if is_result:
                    if empty:
                        result.classification = "EMPTY"
                    else:
                        result.engine_status["Content inspection"] = content_state
                        # ~180 independent layers over the same input (core.layers), streamed to the page
                        layered = services.run_layered(result, raw, mode, display, candidate, job.layer_progress)
                        layer_effect = services.apply_layered(
                            result, layered, content, incomplete=host_incomplete or (content_incomplete and not sentinel_ok))
                    parts = services.apply_final_verdict(
                        result, content, incomplete=host_incomplete or (content_incomplete and not sentinel_ok))
                    if content_incomplete and not empty:
                        result.feature_summary.setdefault("analysis_incomplete", []).append(
                            {"code": f"content.{content_state}", "stage": "content", **_content_words(content_state)})
                finished = time.monotonic()
                job.result = serialize_result(result, display, mode, raw, finished - started, lang)
                legacy_classification = legacy_classification or str(job.result.get("classification") or "UNKNOWN")
                if not parts:   # a stand-in result (tests): the same rule from the numbers we have
                    from detection.engine import final_verdict  # noqa: PLC0415

                    host_score = int(job.result.get("combined_score") or 0)
                    content_score = int((content or {}).get("score") or 0)
                    score, classification = final_verdict(host_score, legacy_classification, content_score,
                                                          incomplete=host_incomplete or not sentinel_ok)
                    parts = {"final_score": score, "classification": classification, "host_score": host_score,
                             "host_classification": legacy_classification, "content_score": content_score}
                summary = dict(combined.get("detection_summary") or {}) if sentinel_ok else _unknown_detection_summary(legacy_classification)
                summary.update(
                    classification=parts["classification"], final_score=parts["final_score"],
                    host_score=parts["host_score"], host_classification=parts["host_classification"],
                    content_score=parts["content_score"],
                    needs_attention=parts["classification"] not in {"NO_INDICATORS_OBSERVED", "EMPTY"},
                )
                job.result.update(
                    platform_classification=legacy_classification,
                    engine_score=parts["host_score"],
                    classification=parts["classification"],
                    combined_score=parts["final_score"],
                    final_score=parts["final_score"],
                    score=parts["final_score"],
                    detection_summary=summary,
                    content_analysis=content or {},
                    detection_engine=(envelope or {}).get("engine"),
                )
                if layered is not None:
                    job.result["layers"] = services.layered_payload(layered, layer_effect)
                if empty:
                    from core.status_text import error_text, text, verdict_text  # noqa: PLC0415

                    job.result["detection_status"] = "empty"
                    job.result["status"] = "empty"
                    job.result["verdict"] = verdict_text("EMPTY", 0)
                    job.result["outcome"] = text("empty_file", error_text("empty_file")["en"], error_text("empty_file")["ar"])
                else:
                    job.result["detection_status"] = "complete" if content_state == "complete" else (
                        "partial" if sentinel_ok else str((envelope or {}).get("status") or "error"))
                    job.result["status"] = "partial" if (content_incomplete or host_incomplete or job.result.get("incomplete")) else "complete"
                if not sentinel_ok and not empty:
                    error = (envelope or {}).get("error") or {}
                    job.result["detection_error"] = error.get("message") or _content_words(content_state)["en"]
                    job.result["detection_error_info"] = {"code": error.get("code", "analysis_failed"),
                                                          **_content_words(content_state)}
                elapsed = finished - started
                timing["total_ms"] = int(elapsed * 1000)
                job.result.update(elapsed=round(elapsed, 2), elapsed_ms=timing["total_ms"], server_elapsed_ms=timing["total_ms"],
                                  timing=timing)
                summary["elapsed_ms"] = timing["total_ms"]
                job.result["exists"] = cleanup is None and mode == "File"
                job.result["quarantined"] = False
                if not PUBLIC and is_result:  # a public server keeps no shared history
                    try:
                        job.result["record_id"] = record_history(result, display, job.result, mode)
                    except (OSError, TypeError, ValueError):
                        logging.exception("Saving the scan to history failed")
                        job.result["history_error"] = "The result couldn't be saved to history."
                job.status = "partial" if job.result["status"] == "partial" else "done"
            except Exception as exc:  # noqa: BLE001 - reported to the page in plain words
                logging.exception("Web scan job failed")
                job.error_info = _friendly_failure(exc)
                job.error = job.error_info["message"]
                job.status = "failed"
            finally:
                if cleanup is not None:
                    shutil.rmtree(cleanup, ignore_errors=True)
                self.active_scans.release()

        if PUBLIC:
            run()  # Lambda freezes background threads once the response is sent
        else:
            threading.Thread(target=run, daemon=True).start()
        return job


def _content_words(state: str) -> dict[str, Any]:
    from core.status_text import engine_text  # noqa: PLC0415

    words = engine_text("Content inspection", state)
    return {"en": words["en"], "ar": words["ar"], "state": words["state"]}


# ---------------------------------------------------------------- handler
def make_handler(app: App, port: int) -> type[BaseHTTPRequestHandler]:
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
    allowed_origins = {f"http://{h}" for h in allowed_hosts}

    class Handler(BaseHTTPRequestHandler):
        server_version = ""
        sys_version = ""
        protocol_version = "HTTP/1.1"
        # Per-connection socket timeout: an idle keep-alive connection (or a client that stops
        # sending mid-request) is closed after this long instead of holding its thread forever.
        timeout = 30

        def log_message(self, fmt: str, *args: Any) -> None:  # quiet console
            pass

        # ---- plumbing ------------------------------------------------
        def _send(self, status: int, body: bytes, ctype: str, extra: dict[str, str] | None = None) -> None:
            extra = dict(extra or {})
            self.send_response(status)
            if status != HTTPStatus.NOT_MODIFIED:   # a 304 has no body, so no length or type
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", extra.pop("Cache-Control", "no-store"))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Frame-Options", "SAMEORIGIN")   # with CSP frame-ancestors, for older browsers
            self.send_header("Cross-Origin-Opener-Policy", "same-origin")
            # the site's files are only for the site's own pages (ainex-ai.xyz and its scan./j. subdomains)
            self.send_header("Cross-Origin-Resource-Policy", "same-site")
            self.send_header("X-Permitted-Cross-Domain-Policies", "none")
            # the phone app (/m/) and the scan page ("Scan a QR code") may read QR codes with the camera;
            # nothing else asks for devices
            scan_page = getattr(self, "_scan_page", False) or self.headers.get("Host", "").startswith("scan.")
            camera = "(self)" if self.path.startswith("/m/") or scan_page else "()"
            self.send_header("Permissions-Policy", f"camera={camera}, microphone=(), geolocation=(), payment=(), usb=(), display-capture=(), browsing-topics=()")
            # 'wasm-unsafe-eval' only lets the page compile WebAssembly (the phone
            # app's on-device engine); it does not allow eval() of JavaScript.
            # In public mode the large files come from the asset bucket.
            assets = f" {ASSET_BASE}" if PUBLIC and ASSET_BASE else ""
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; img-src 'self' data: blob:; media-src 'self' blob:; style-src 'self'; "
                f"script-src 'self' 'wasm-unsafe-eval'{assets}; connect-src 'self'{assets} https://api.pwnedpasswords.com; worker-src 'self'; manifest-src 'self'; "
                # frame-src: the site's own pages (the persistent player, js/site-nav.js) and privacy-enhanced YouTube embeds
                "frame-src 'self' https://www.youtube-nocookie.com; object-src 'none'; "
                "frame-ancestors 'self'; base-uri 'none'; form-action 'self'"  # 'self': the phone app shows its privacy page in a frame
                + ("; upgrade-insecure-requests" if PUBLIC else ""),
            )
            if PUBLIC:   # HTTPS only there; the local server is plain http on the loopback
                self.send_header("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
            for key, value in extra.items():
                self.send_header(key, value)
            self.end_headers()
            if self.command != "HEAD" and status != HTTPStatus.NOT_MODIFIED:   # HEAD: the same headers, no body
                self.wfile.write(body)

        def send_response(self, code: int, message: str | None = None) -> None:
            """As the standard one, without the Server banner (it only tells scanners what runs here)."""
            self.log_request(code)
            self.send_response_only(code, message)
            self.send_header("Date", self.date_time_string())

        @property
        def _lang(self) -> str | None:
            """The visitor's language (the page sends it); results also come in it."""
            return self.headers.get("X-CyberScan-Lang")

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
            if path in ("/api/vitals", "/api/errors", "/api/health", "/api/visit", "/api/visits"):
                # no token: navigator.sendBeacon can't send headers; the Origin/Host check still applies
                if self._guard(api=False):
                    self._site_api(method, path)
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
                        body = (
                            _scan_error_envelope(exc.status, str(exc))
                            if getattr(handler, "route_name", "") in SCAN_API_ROUTES
                            else {"error": str(exc)}
                        )
                        self._json(exc.status, body)
                    except (OSError, ValueError, RuntimeError) as exc:
                        logging.exception("API route failed")
                        status = HTTPStatus.INTERNAL_SERVER_ERROR
                        body = (
                            _scan_error_envelope(status, "")
                            if getattr(handler, "route_name", "") in SCAN_API_ROUTES
                            else {"error": "Something went wrong on the server. Try again.", "code": "server_error"}
                        )
                        self._json(status, body)
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

        def _site_api(self, method: str, path: str) -> None:
            """Real-user vitals and script errors (POST, from js/vitals.js and js/errors.js) and the
            status page's health check (GET). See web_v/site_extras.py."""
            if path == "/api/health" and method == "GET":
                self._json(HTTPStatus.OK, site_extras.health())
                return
            # the real visit counter: one POST per browser session (js/visits.js), GET for the total
            if path == "/api/visits" and method == "GET":
                self._json(HTTPStatus.OK, visits.total())
                return
            if path == "/api/visit" and method == "POST":
                visits.record(self.headers.get("User-Agent", ""))
                self._send(HTTPStatus.NO_CONTENT, b"", "text/plain")
                return
            if path == "/api/visits":
                self._json(HTTPStatus.METHOD_NOT_ALLOWED, {"error": "method not allowed"})
                return
            if path == "/api/health" or method != "POST":
                self._json(HTTPStatus.METHOD_NOT_ALLOWED, {"error": "method not allowed"})
                return
            try:
                raw = self._raw_body(4096)
            except ApiError as exc:
                self._json(exc.status, {"error": str(exc)})
                return
            ok = site_extras.beacon(path.rsplit("/", 1)[1], raw)
            self._send(HTTPStatus.NO_CONTENT if ok else HTTPStatus.BAD_REQUEST, b"", "text/plain")

        def _static(self, path: str) -> None:
            # trust pages, /<lang>/ addresses, /sitemap.xml, security.txt (web_v/site_extras.py)
            self._page_lang = self._page_path = None
            extra_hit = site_extras.resolve(path)
            if extra_hit:
                kind, value = extra_hit
                if kind == "redirect":
                    self._send(HTTPStatus.MOVED_PERMANENTLY, b"", "text/plain", {"Location": value, "Cache-Control": "public, max-age=3600"})
                    return
                if kind == "body":
                    self._send(HTTPStatus.OK, value[0], value[1], {"Cache-Control": "public, max-age=3600"})
                    return
                if kind == "alias":
                    path = value
                else:
                    page_file, self._page_path, self._page_lang = value
                    path = {"index.html": "/", "journey.html": "/journey", "support.html": "/support"}.get(page_file, "/" + page_file)
            self._scan_page = path in ("/app.html", "/scan", "/scan/")
            name = "index.html" if path in ("/", "/index.html") or self._scan_page else unquote(path).lstrip("/")
            if path in ("/journey", "/journey/"):
                name = "journey.html"                      # the File Journey (journey.css, js/journey.js)
            if path in ("/support", "/support/"):
                name = "support.html"                      # support the developer (support.css, js/support.js)
            # /_v/<hash>/<file>: the page's own reference to one exact version of a file (see
            # _versioned_refs); relative URLs inside it (fonts, i18n/...) resolve under the same prefix
            version = None
            versioned = VERSIONED.fullmatch(name)
            if versioned:
                version, name = versioned.groups()
            bundle = BUNDLE.fullmatch(name)
            if bundle:
                built = _bundle([n + ".css" for n in bundle.group(1).split("+")])
                if built is None:
                    self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
                    return
                stamp, body, digest, gz = built
                fresh = version == stamp
                extra = {"Cache-Control": "public, max-age=31536000, immutable" if fresh else ("public, max-age=600" if PUBLIC else "no-cache")}
                self._send_file(body, "text/css; charset=utf-8", extra, digest, gz, None, ranges=False)
                return
            js_bundle = JS_BUNDLE.fullmatch(name) if version else None
            if js_bundle:
                built = _js_bundle([n.replace("~", "/") + ".js" for n in js_bundle.group(1).split("+")])
                if built is None:
                    self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
                    return
                stamp, body, digest, gz = built
                fresh = version == stamp
                extra = {"Cache-Control": "public, max-age=31536000, immutable" if fresh else ("public, max-age=600" if PUBLIC else "no-cache")}
                self._send_file(body, "text/javascript; charset=utf-8", extra, digest, gz, None, ranges=False)
                return
            if PUBLIC and ASSET_BASE and (name.startswith("pyodide/") or (name.startswith("downloads/") and name.endswith((".apk", ".exe")))):
                # larger than Lambda can return (6 MB): served by the asset bucket
                if ".." in name or not re.fullmatch(r"[\w./\-]+", name):
                    self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
                    return
                self._send(HTTPStatus.FOUND, b"", "text/plain", {"Location": f"{ASSET_BASE}/{name}", "Cache-Control": "public, max-age=3600"})
                return
            target = (STATIC_DIR / name).resolve()
            team = TEAM_FILE.fullmatch(name)
            if team:
                hit = team_file(team.group(1), team.group(2))
                if not hit:
                    self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
                    return
                found, ctype = hit
                # the URL carries ?v=<mtime>, so a replaced photo is a new URL
                headers = {"Cache-Control": "public, max-age=86400", "X-Content-Type-Options": "nosniff"}
                if ctype == "image/svg+xml":
                    headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'; sandbox"
                self._send(HTTPStatus.OK, found.read_bytes(), ctype, headers)
                return
            if PUBLIC and not ASSET_BASE and not target.is_file() and (name.startswith("pyodide/") or name.endswith((".apk", ".exe"))):
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
            rendered = token_page = False
            if name == "index.html" and target == STATIC_DIR / "index.html":
                host = (self.headers.get("X-Forwarded-Host") or self.headers.get("Host") or "").lower()
                scan = self._scan_page or host.startswith("scan.")
                body = page_html(target.read_bytes(), app.token, scan=scan, lang=None if scan else self._page_lang)
                rendered = token_page = True
            elif target == STATIC_DIR / "support.html":
                # the robot's brain (/api/bit) needs the page's API token
                body = target.read_bytes().replace(b"__CYBERSCAN_TOKEN__", app.token.encode())
                body = site_extras.decorate(body.decode("utf-8").replace("\r\n", "\n"), "/support", self._page_lang)
                body = _versioned_refs(body, defer=False, bundle=False).encode("utf-8")
                rendered = token_page = True
            elif self._page_path in site_extras.TRUST_PAGES and target == STATIC_DIR / site_extras.TRUST_PAGES[self._page_path]:
                # /privacy, /terms, /security, /status, /tests, /changelog (the status page reads /api/protection)
                body = target.read_bytes().decode("utf-8").replace("\r\n", "\n").replace("__CYBERSCAN_TOKEN__", app.token)
                body = _versioned_refs(site_extras.decorate(body, self._page_path, self._page_lang), defer=False, bundle=False).encode("utf-8")
                rendered = token_page = True
            elif target in (STATIC_DIR / "journey.html", STATIC_DIR / "report.html"):
                body = target.read_bytes()
                host = (self.headers.get("X-Forwarded-Host") or self.headers.get("Host") or "").lower()
                if host.startswith("j.") and re.fullmatch(r"[a-z0-9.-]+", host):
                    # on its own host (j.<domain>) the way back is the main site, not this page's root
                    body = body.replace(b'href="/"', f'href="https://{host[2:]}/"'.encode())
                html = body.decode("utf-8").replace("\r\n", "\n")
                if target == STATIC_DIR / "journey.html":
                    html = site_extras.decorate(html, "/journey", self._page_lang)
                body = _versioned_refs(html, defer=False, bundle=False).encode("utf-8")
                rendered = True
            types = {".js": "text/javascript", ".mjs": "text/javascript", ".webmanifest": "application/manifest+json",
                     ".svg": "image/svg+xml", ".wasm": "application/wasm", ".zip": "application/zip",
                     ".vtt": "text/vtt", ".png": "image/png", ".json": "application/json", ".css": "text/css",
                     ".html": "text/html", ".txt": "text/plain", ".ico": "image/x-icon", ".mp3": "audio/mpeg",
                     ".woff": "font/woff", ".woff2": "font/woff2", ".webp": "image/webp",
                     ".apk": "application/vnd.android.package-archive"}
            ctype = types.get(target.suffix) or mimetypes.guess_type(target.name)[0] or "application/octet-stream"
            if ctype.startswith("text/") or ctype.endswith(("javascript", "json", "svg+xml")):
                ctype += "; charset=utf-8"
            compressible = ctype.startswith(COMPRESSIBLE)
            if rendered:
                import hashlib  # noqa: PLC0415

                digest, mtime = hashlib.sha256(body).hexdigest()[:16], None
                gz = None
                if compressible and not PUBLIC:
                    gz = _GZ_PAGES.get(digest)
                    if gz is None:
                        gz = _gzip(body) or b""
                        if len(_GZ_PAGES) > 16:
                            _GZ_PAGES.clear()
                        _GZ_PAGES[digest] = gz
                    gz = gz or None
            else:
                body = target.read_bytes()
                digest, gz = _asset(target, compressible)
                mtime = target.stat().st_mtime
            fresh = version is not None and version == digest[:10]
            extra = {}
            rel = target.relative_to(STATIC_DIR).as_posix()
            if token_page:
                # carries the API token: never stored, except the public site's shared, well-known one,
                # which the CDN may keep briefly (browsers still check back every time)
                extra["Cache-Control"] = "public, max-age=0, must-revalidate, s-maxage=300" if PUBLIC and app.token == "cyberscan-public" else "no-store"
            elif ctype.startswith("text/html"):
                extra["Cache-Control"] = "public, max-age=0, must-revalidate, s-maxage=300" if PUBLIC else "no-cache"
            elif fresh:
                extra["Cache-Control"] = "public, max-age=31536000, immutable"   # the URL changes when the file does
            elif PUBLIC:
                # Let the browser and the CDN (CloudFront) keep the site's files: without this every
                # visit runs the function once per file. After a deploy, invalidate "/*" in CloudFront.
                if rel == "sw.js":
                    extra["Cache-Control"] = "no-cache"
                elif rel.startswith("downloads/") or rel == "m/engine.version":
                    extra["Cache-Control"] = "public, max-age=300, s-maxage=300"
                elif target.suffix.lower() in (".png", ".jpg", ".jpeg", ".jpe", ".webp", ".avif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".mp3", ".webm"):
                    # images, fonts and media rarely change: a week in the browser, a month at the CDN
                    extra["Cache-Control"] = "public, max-age=604800, s-maxage=2592000, stale-while-revalidate=86400"
                else:
                    extra["Cache-Control"] = "public, max-age=600, s-maxage=86400, stale-while-revalidate=86400"
            elif rel.startswith("pyodide/") or rel == "m/engine.zip":
                # versioned and large: the phone downloads the engine once
                extra["Cache-Control"] = "public, max-age=31536000, immutable"
            else:
                extra["Cache-Control"] = "no-cache"   # kept, but checked each time (a cheap 304)
            if target.suffix == ".apk":
                # the signed Android app: always a download, never opened in the tab
                extra["Content-Disposition"] = f"attachment; filename*=UTF-8''{quote(target.name)}"
                extra["Cache-Control"] = "public, max-age=3600"
            self._send_file(body, ctype, extra, digest, gz, mtime, ranges=not rendered)

        def _send_file(self, body: bytes, ctype: str, extra: dict[str, str], digest: str, gz: bytes | None,
                       mtime: float | None, ranges: bool) -> None:
            """A static response with validators (ETag, Last-Modified -> 304), gzip when the
            browser takes it, and byte ranges (audio and video seek with them)."""
            from email.utils import formatdate, parsedate_to_datetime  # noqa: PLC0415

            accept = (self.headers.get("Accept-Encoding") or "").lower()
            wants_range = ranges and self.headers.get("Range", "").startswith("bytes=")
            use_gz = gz is not None and not wants_range and re.search(r"\bgzip\b(?!;\s*q=0(?:\.0+)?\b)", accept) is not None
            if gz is not None:
                extra["Vary"] = "Accept-Encoding"
            if extra.get("Cache-Control") != "no-store":
                extra["ETag"] = f'"{digest}-gz"' if use_gz else f'"{digest}"'
                if mtime:
                    extra["Last-Modified"] = formatdate(mtime, usegmt=True)
                inm, ims = self.headers.get("If-None-Match"), self.headers.get("If-Modified-Since")
                unchanged = digest in inm if inm else False
                if not inm and ims and mtime:
                    try:
                        unchanged = int(mtime) <= parsedate_to_datetime(ims).timestamp()
                    except (TypeError, ValueError):
                        unchanged = False
                if unchanged:
                    self._send(HTTPStatus.NOT_MODIFIED, b"", ctype, extra)
                    return
            status = HTTPStatus.OK
            if ranges:
                extra["Accept-Ranges"] = "bytes"
            if wants_range and (not self.headers.get("If-Range") or self.headers.get("If-Range") == extra.get("ETag")):
                spec = re.fullmatch(r"bytes=(\d*)-(\d*)", self.headers["Range"].strip())
                size = len(body)
                start = end = None
                if spec and (spec.group(1) or spec.group(2)):
                    if spec.group(1):
                        start = int(spec.group(1))
                        end = min(int(spec.group(2)), size - 1) if spec.group(2) else size - 1
                    else:   # the last N bytes
                        start, end = max(0, size - int(spec.group(2))), size - 1
                if start is None or start > end or start >= size:
                    extra["Content-Range"] = f"bytes */{size}"
                    self._send(HTTPStatus.REQUESTED_RANGE_NOT_SATISFIABLE, b"", ctype, extra)
                    return
                body, status = body[start:end + 1], HTTPStatus.PARTIAL_CONTENT
                extra["Content-Range"] = f"bytes {start}-{end}/{size}"
            elif use_gz:
                body = gz
                extra["Content-Encoding"] = "gzip"
            self._send(status, body, ctype, extra)

        # ---- scans ---------------------------------------------------
        def _client(self) -> str:
            # behind CloudFront the visitor is the first X-Forwarded-For address
            forwarded = self.headers.get("X-Forwarded-For", "") if PUBLIC else ""
            return forwarded.split(",")[0].strip() or self.client_address[0]

        def _external_choice(self, requested: Any) -> tuple[bool, str]:
            """Whether this scan asks VirusTotal and the other services (fingerprint or link only).
            Website: on unless the visitor switched it off, within a per-visitor limit that protects
            the free quotas. Local app: Settings decide; the per-scan switch can only turn it off."""
            from core import external_intel  # noqa: PLC0415

            wanted = str(requested).strip().lower() not in {"0", "false", "off", "no"} if requested is not None else True
            if PUBLIC:
                if os.environ.get("CYBERSCAN_EXTERNAL_INTEL", "1") == "0":
                    return False, "disabled"
                if not wanted:
                    return False, "off_for_scan"
                if not external_intel.CLIENTS.allow(self._client()):
                    return False, "rate_limited"
                return True, ""
            if not load_settings().get("osint_enabled"):
                return False, "disabled"
            return (True, "") if wanted else (False, "off_for_scan")

        def scan_start(self, query: dict) -> None:
            accepted = time.monotonic()   # the job's end-to-end clock starts here
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
            if mode != "File" and len(value) > MAX_DETECTION_TEXT:
                raise ApiError(413, f"Text is longer than the {MAX_DETECTION_TEXT:,}-character scan limit.")
            if mode == "File":
                file_path = Path(value.strip('"')).expanduser()
                if not file_path.is_absolute() or not file_path.is_file():
                    raise ApiError(400, "That file doesn't exist.")
                value = str(file_path.resolve())
                label = value
            else:
                label = value if mode == "URL" else "Pasted text"
            external = self._external_choice(data.get("external") if isinstance(data, dict) else None)
            job = app.start_job(value, mode, label[:1000], None, self._lang, accepted_at=accepted, external=external)
            # public mode: the scan already finished, so the page gets the result at once
            self._json(HTTPStatus.OK if PUBLIC else HTTPStatus.ACCEPTED, job.snapshot() if PUBLIC else {"id": job.id})

        def scan_upload(self, query: dict) -> None:
            accepted = time.monotonic()   # before the upload is read: its transfer counts too
            limit = min(
                int(load_settings().get("maximum_file_size", MAX_DETECTION_UPLOAD)),
                MAX_DETECTION_UPLOAD,
                PUBLIC_MAX_UPLOAD if PUBLIC else MAX_DETECTION_UPLOAD,
            )
            raw = self._raw_body(limit)
            original = unquote(self.headers.get("X-Filename", "upload.bin"))
            external = self._external_choice(self.headers.get("X-CyberScan-External"))
            from detection.engine import safe_file_name
            safe = safe_file_name(original)[:120]
            folder = Path(tempfile.mkdtemp(dir=app.upload_root))
            file_path = folder / safe
            try:
                file_path.write_bytes(raw)
                job = app.start_job(
                    str(file_path), "File", Path(original).name[:300], folder, self._lang, detection_data=raw,
                    accepted_at=accepted, external=external,
                )
            except Exception:
                shutil.rmtree(folder, ignore_errors=True)
                raise
            self._json(HTTPStatus.OK if PUBLIC else HTTPStatus.ACCEPTED, job.snapshot() if PUBLIC else {"id": job.id})

        def _file_tool(self, raw: bytes, name: str, analyze: Callable[[bytes, str, dict[str, Any]], dict[str, Any]]) -> None:
            if not app.active_scans.acquire(blocking=False):
                raise ApiError(HTTPStatus.SERVICE_UNAVAILABLE, "The scanner is at capacity. Try again shortly.")
            try:
                from detection.engine import safe_file_name

                safe_name = safe_file_name(name)
                envelope = detection_service.default_service().analyze_upload(raw, safe_name, load_settings())
                status_code = detection_service.ScanService.http_status(envelope)
                if status_code != HTTPStatus.OK:
                    envelope.setdefault("detection_summary", _unknown_detection_summary())
                    self._json(status_code, envelope)
                    return

                inspection = envelope.get("result")
                if not isinstance(inspection, dict):
                    raise RuntimeError("Sentinel returned an invalid inspection result.")
                content = inspection.get("content_analysis")
                summary = inspection.get("detection_summary")
                if not isinstance(content, dict) or not isinstance(summary, dict):
                    raise RuntimeError("Sentinel returned an incomplete unified scan result.")
                result = analyze(raw, safe_name, content)
                if not isinstance(result, dict):
                    raise RuntimeError("The file analyzer returned an invalid result.")

                tool_status = str(result.get("status", ""))
                if tool_status in {"timeout", "decoder_timeout"}:
                    response_status = "timeout"
                    http_status = HTTPStatus.GATEWAY_TIMEOUT
                    error = {"code": "timeout", "message": "The format-specific inspection exceeded its time limit."}
                elif (
                    tool_status in {
                        "partial", "parser_unavailable", "parse_error", "decoder_unavailable",
                        "decoder_error", "not_decodable", "limit_exceeded", "encrypted",
                    }
                    or content.get("analyzer_errors")
                    or inspection.get("truncated_input")
                ):
                    response_status = "partial"
                    http_status = HTTPStatus.OK
                    error = {"code": "incomplete", "message": "Some inspection steps could not be completed."}
                else:
                    response_status = "ok"
                    http_status = HTTPStatus.OK
                    error = None

                self._json(http_status, {
                    "status": response_status,
                    "result": result,
                    "content_analysis": content,
                    "detection_summary": summary,
                    "error": error,
                    "elapsed_ms": envelope.get("elapsed_ms", 0),
                    "engine": envelope.get("engine"),
                })
            finally:
                app.active_scans.release()

        def pdf_tool(self, query: dict) -> None:
            from detection.engine import sniff_type

            raw = self._raw_body(min(PUBLIC_MAX_UPLOAD if PUBLIC else MAX_DETECTION_UPLOAD, 16 * 1024 * 1024))
            name = unquote(self.headers.get("X-Filename", "upload.pdf"))

            def analyze(data: bytes, safe_name: str, inspection: dict[str, Any]) -> dict[str, Any]:
                if sniff_type(data) != "pdf":
                    raise ApiError(400, "The uploaded file is not a PDF.")
                from core.pdf_scanner import analyze_pdf, assess_pdf_links

                report = analyze_pdf(data, safe_name)
                return {
                    **report,
                    "link_assessments": assess_pdf_links(report).get("link_assessments", []),
                }

            self._file_tool(raw, name, analyze)

        def archive_tool(self, query: dict) -> None:
            from detection.engine import sniff_type

            raw = self._raw_body(min(PUBLIC_MAX_UPLOAD if PUBLIC else MAX_DETECTION_UPLOAD, MAX_DETECTION_UPLOAD))
            name = unquote(self.headers.get("X-Filename", "upload.zip"))

            def analyze(data: bytes, safe_name: str, inspection: dict[str, Any]) -> dict[str, Any]:
                if Path(safe_name).suffix.lower() == ".rar":
                    raise ApiError(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "RAR inspection is not supported by the installed parsers.")
                if sniff_type(data) != "zip":
                    raise ApiError(400, "The uploaded file is not a supported ZIP-based archive.")
                from core.archive_inspector import inspect_zip

                archive = inspect_zip(data)
                return {
                    "file_name": safe_name,
                    "status": archive.status,
                    "archive_inspection": archive.as_dict(),
                    "sentinel_details": inspection.get("details") or {},
                }

            self._file_tool(raw, name, analyze)

        def qr_tool(self, query: dict) -> None:
            from detection.engine import sniff_type

            raw = self._raw_body(min(PUBLIC_MAX_UPLOAD if PUBLIC else MAX_DETECTION_UPLOAD, 8 * 1024 * 1024))
            name = unquote(self.headers.get("X-Filename", "upload-image"))

            def analyze(data: bytes, safe_name: str, inspection: dict[str, Any]) -> dict[str, Any]:
                if sniff_type(data) != "image":
                    raise ApiError(400, "The uploaded file is not a supported image.")
                details = inspection.get("details") or {}
                qr_report = details.get("qr_codes")
                if not isinstance(qr_report, dict):
                    return {
                        "status": "decoder_unavailable",
                        "file_name": safe_name,
                        "codes": [],
                        "limitations": ["The bounded content inspection did not return QR decoding results."],
                    }
                return {"file_name": safe_name, **qr_report}

            self._file_tool(raw, name, analyze)

        def office_tool(self, query: dict) -> None:
            from detection.engine import sniff_type

            raw = self._raw_body(min(PUBLIC_MAX_UPLOAD if PUBLIC else MAX_DETECTION_UPLOAD, MAX_DETECTION_UPLOAD))
            name = unquote(self.headers.get("X-Filename", "upload-office"))

            def analyze(data: bytes, safe_name: str, inspection: dict[str, Any]) -> dict[str, Any]:
                kind = sniff_type(data)
                details = inspection.get("details") or {}
                extension = Path(safe_name).suffix.lower()
                office_extensions = {
                    ".doc", ".docm", ".docx", ".dotm", ".xls", ".xlsm", ".xlsx", ".xltm",
                    ".ppt", ".pptm", ".pptx", ".potm",
                }
                if extension not in office_extensions or kind not in {"ole", "zip"}:
                    raise ApiError(400, "Upload a supported DOC, XLS, PPT, DOCX, XLSX, or PPTX document.")
                if kind == "zip" and details.get("type") != "ooxml":
                    raise ApiError(400, "The ZIP container is not a recognized Office Open XML document.")
                return {"file_name": safe_name, "format": details.get("type", kind), **details}

            self._file_tool(raw, name, analyze)

        def authenticity_tool(self, query: dict) -> None:
            from core.file_authenticity import identify_file_format

            raw = self._raw_body(min(PUBLIC_MAX_UPLOAD if PUBLIC else MAX_DETECTION_UPLOAD, MAX_DETECTION_UPLOAD))
            name = unquote(self.headers.get("X-Filename", "upload.bin"))

            def analyze(data: bytes, safe_name: str, inspection: dict[str, Any]) -> dict[str, Any]:
                return identify_file_format(data, safe_name)

            self._file_tool(raw, name, analyze)

        def integrity_tool(self, query: dict) -> None:
            raw = self._raw_body(min(PUBLIC_MAX_UPLOAD if PUBLIC else MAX_DETECTION_UPLOAD, MAX_DETECTION_UPLOAD))
            name = unquote(self.headers.get("X-Filename", "upload.bin"))

            def analyze(data: bytes, safe_name: str, inspection: dict[str, Any]) -> dict[str, Any]:
                report = services.verify_uploaded_bytes(data, max_file_size=MAX_DETECTION_UPLOAD)
                return {"file_name": safe_name, **report}

            self._file_tool(raw, name, analyze)

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
            self._json(HTTPStatus.OK, history_open(record_id, self._lang))

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

        def team(self, query: dict) -> None:
            self._send(HTTPStatus.OK, json.dumps({"photos": team_photos()}).encode(), "application/json; charset=utf-8",
                       {"Cache-Control": "no-cache"})

        def profile(self, query: dict) -> None:   # the support page's live numbers and featured video (web_v/profile_stats.py)
            self._send(HTTPStatus.OK, json.dumps(profile_stats.profile()).encode(), "application/json; charset=utf-8",
                       {"Cache-Control": "private, max-age=600"})

        # ---- the Toolbox: the security tools in Tools/ (web_v/toolbox.py) ----
        def toolbox_list(self, query: dict) -> None:
            self._json(HTTPStatus.OK, toolbox.catalog(PUBLIC))

        # ---- email analysis: a pasted raw email (headers + body), read as text, nothing fetched ----
        def email_analyze(self, query: dict) -> None:
            import email_check  # noqa: PLC0415
            data = self._json_body(email_check.MAX_RAW * 4 + 1024)
            if not isinstance(data, dict):
                raise ApiError(400, "expected {raw}")
            try:
                self._json(HTTPStatus.OK, email_check.analyze(data.get("raw")))
            except email_check.EmailError as exc:
                raise ApiError(400, str(exc)) from exc

        def toolbox_run(self, query: dict) -> None:
            data = self._json_body(toolbox.PUBLIC_MAX_BODY if PUBLIC else toolbox.LOCAL_MAX_BODY)
            if not isinstance(data, dict):
                raise ApiError(400, "expected {tool, input}")
            try:
                self._json(HTTPStatus.OK, toolbox.run(data.get("tool"), data.get("input"), PUBLIC))
            except toolbox.ToolboxError as exc:
                raise ApiError(exc.status, str(exc)) from exc

        def protection_info(self, query: dict) -> None:
            from core import protection  # noqa: PLC0415

            from core import hash_intel  # noqa: PLC0415
            from core.yara_engine import discover_yara_rules  # noqa: PLC0415
            from intel import updater  # noqa: PLC0415

            info = protection.manifest()
            from core import external_intel  # noqa: PLC0415

            keys = services.keys_status() if not PUBLIC else {}
            configured = external_intel.configured()   # keys in this process's environment (Lambda: its variables)
            online = (os.environ.get("CYBERSCAN_EXTERNAL_INTEL", "1") != "0") if PUBLIC else bool(load_settings().get("osint_enabled"))
            self._json(HTTPStatus.OK, {
                "forge": protection.forge_available(), "lists": protection.lists_available(),
                "secrets": bool(info.get("secret_rules")), "updated": info.get("updated"),
                "forge_rules": info.get("forge_rules", 0), "forge_version": info.get("forge_version", ""),
                "bundled_rules": len(discover_yara_rules()),
                "urlhaus": info.get("urlhaus", 0),
                "phishing": info.get("phishing", 0), "secret_rules": info.get("secret_rules", 0),
                "malware_hashes": hash_intel.offline_count(), "hash_sources": info.get("hash_sources", []),
                "hashes_updated": info.get("hashes_updated"), "failed": info.get("failed", []),
                "online": online, "public": PUBLIC,
                "keys": {name: bool(keys.get(name)) or bool(configured.get(service)) for name, service in (
                    ("abusech", "malwarebazaar"), ("virustotal", "virustotal"), ("otx", "otx"),
                    ("safebrowsing", "safebrowsing"), ("urlscan", "urlscan"))},
                "external": {"services": configured, "virustotal_quota": external_intel.BUCKETS["virustotal"].state()},
                "auto_update": not PUBLIC, "updater": updater.state(),
                "schedule": {"hashes_hours": updater.HASHES_EVERY, "rules_hours": updater.RULES_EVERY},
            })

        def protection_update(self, query: dict) -> None:
            from intel import updater  # noqa: PLC0415

            if updater.state()["running"]:
                self._json(HTTPStatus.ACCEPTED, updater.state())
                return
            threading.Thread(target=updater.refresh, name="intel-refresh-now", daemon=True).start()
            self._json(HTTPStatus.ACCEPTED, {**updater.state(), "running": True})

        # ---- layered analysis catalog (core.layers): names, categories, what each layer checks ----
        def layers_catalog(self, query: dict) -> None:
            from core import layers  # noqa: PLC0415

            self._json(HTTPStatus.OK, {"layers": layers.catalog(), "formula": layers.FORMULA,
                                       "categories": {k: {"en": v[0], "ar": v[1]} for k, v in layers.CATEGORIES.items()}})

        # ---- the result summary written for the reader's profile (web_v/assistant.py: summarize) ----
        def assistant_summary(self, query: dict) -> None:
            data = self._json_body(16 * 1024)
            if not isinstance(data, dict):
                raise ApiError(400, "expected {context, profile, lang}")
            forwarded = self.headers.get("X-Forwarded-For", "") if PUBLIC else ""
            client = forwarded.split(",")[0].strip() or self.client_address[0]
            # the burst guard limits model calls only: past it, the template writer answers (costs nothing)
            use_model = assistant.LIMITS.allow(client)
            model = "qwen3:8b" if PUBLIC else str(load_settings().get("ai_model", "qwen3:8b"))
            try:
                result = assistant.summarize(data.get("context"), data.get("profile"), data.get("lang"),
                                             local=not PUBLIC, client=client, ollama_model=model, use_model=use_model)
            except assistant.AskError as exc:
                raise ApiError(400, str(exc)) from exc
            self._json(HTTPStatus.OK, result)

        # ---- Ask the AI about CyberScan (web_v/assistant.py) -----------
        def assistant_ask(self, query: dict) -> None:
            data = self._json_body(16 * 1024)
            if not isinstance(data, dict):
                raise ApiError(400, "expected {question, history}")
            # behind CloudFront the visitor is the first X-Forwarded-For address
            forwarded = self.headers.get("X-Forwarded-For", "") if PUBLIC else ""
            client = forwarded.split(",")[0].strip() or self.client_address[0]
            if not assistant.LIMITS.allow(client):
                raise ApiError(429, "Too many questions at once. Please wait a minute.")
            model = "qwen3:8b" if PUBLIC else str(load_settings().get("ai_model", "qwen3:8b"))
            try:
                result = assistant.ask(data.get("question"), data.get("history"), local=not PUBLIC, client=client, ollama_model=model,
                                       context=data.get("context"))
            except assistant.AskError as exc:
                raise ApiError(400, str(exc)) from exc
            self._json(HTTPStatus.OK, result)

        # ---- Bit, the robot on the support page: a model picks its next move ----
        def bit_decide(self, query: dict) -> None:
            import bit_brain  # noqa: PLC0415
            data = self._json_body(4 * 1024)
            if not isinstance(data, dict):
                raise ApiError(400, "expected a state object")
            forwarded = self.headers.get("X-Forwarded-For", "") if PUBLIC else ""
            client = forwarded.split(",")[0].strip() or self.client_address[0]
            if not bit_brain.allowed(client):
                self._json(HTTPStatus.OK, {"source": "none", "reason": "rate"})
                return
            model = "qwen3:8b" if PUBLIC else str(load_settings().get("ai_model", "qwen3:8b"))
            self._json(HTTPStatus.OK, bit_brain.decide(data, local=not PUBLIC, ollama_model=model))

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
            self._json(HTTPStatus.OK, services.repair_open(file_path.read_bytes(), file_path.name, file_path.resolve(), self._lang))

        def repair_upload(self, query: dict) -> None:
            raw = self._raw_body(PUBLIC_MAX_UPLOAD if PUBLIC else services.REPAIR_MAX)
            name = Path(unquote(self.headers.get("X-Filename", "upload.bin"))).name[:200] or "upload.bin"
            self._json(HTTPStatus.OK, services.repair_open(raw, name, None, self._lang))

        def repair_run(self, session_id: str, query: dict) -> None:
            session = services.REPAIRS.get(session_id)
            if session is None:
                raise ApiError(404, "This repair session has expired. Open the file again.")
            data = self._json_body()
            keys = data.get("keys")
            if not isinstance(keys, list) or not all(isinstance(k, str) for k in keys):
                raise ApiError(400, "expected {keys: [...]}")
            try:
                out = services.repair_run(session, keys, load_settings())
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
    _route("POST", r"/api/tools/pdf", "pdf_tool"),
    _route("POST", r"/api/tools/archive", "archive_tool"),
    _route("POST", r"/api/tools/qr", "qr_tool"),
    _route("POST", r"/api/tools/office", "office_tool"),
    _route("POST", r"/api/tools/authenticity", "authenticity_tool"),
    _route("POST", r"/api/tools/integrity", "integrity_tool"),
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
    _route("GET", r"/api/team", "team"),
    _route("GET", r"/api/profile", "profile"),
    _route("GET", r"/api/toolbox", "toolbox_list"),
    _route("POST", r"/api/toolbox/run", "toolbox_run"),
    _route("POST", r"/api/email", "email_analyze"),
    _route("GET", r"/api/protection", "protection_info"),
    _route("POST", r"/api/protection/update", "protection_update"),
    _route("POST", r"/api/assistant", "assistant_ask"),
    _route("POST", r"/api/assistant/summary", "assistant_summary"),
    _route("GET", r"/api/layers", "layers_catalog"),
    _route("POST", r"/api/bit", "bit_decide"),
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


class WebServer(ThreadingHTTPServer):
    """One thread per connection. The listen backlog is the stdlib's 5 by default: a page opens
    dozens of connections at once, and while the accepting thread waits for the GIL (a scan is
    running) the sixth and later connections were refused, which browsers retry only after 1 s,
    2 s, 4 s ... (the stalls). A deep backlog lets them wait in the kernel instead."""
    request_queue_size = 256
    daemon_threads = True
    block_on_close = False


def create_server(port: int = 0) -> tuple[ThreadingHTTPServer, App]:
    app = App()
    # CYBERSCAN_BIND lets public mode listen on another address (e.g. 0.0.0.0 to reach it from phones
    # on the same network). The local mode reads and changes files on this computer, so it never
    # listens anywhere but the loopback address.
    bind = os.environ.get("CYBERSCAN_BIND", "127.0.0.1").strip() or "127.0.0.1"
    if bind not in ("127.0.0.1", "localhost", "::1") and not PUBLIC:
        raise SystemExit("CYBERSCAN_BIND other than 127.0.0.1 needs public mode (CYBERSCAN_PUBLIC=1).")
    server = WebServer((bind, port), BaseHTTPRequestHandler)
    actual = server.server_address[1]
    server.RequestHandlerClass = make_handler(app, actual)
    services.load_keys_into_environment()
    apply_monitor(load_settings())
    if "pytest" not in sys.modules:
        app.warm()   # a warm analysis worker and loaded rules before the first scan arrives
    if not PUBLIC and os.environ.get("CYBERSCAN_AUTO_UPDATE", "1") != "0" and "pytest" not in sys.modules:
        from intel import updater  # noqa: PLC0415

        updater.start_background()   # rules and known-malware hashes stay current while the app runs
    return server, app


def cleanup(app: App) -> None:
    MONITOR.stop()
    shutil.rmtree(app.upload_root, ignore_errors=True)
