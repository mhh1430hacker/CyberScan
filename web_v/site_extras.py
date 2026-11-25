"""The website's trust, SEO and monitoring pieces, kept out of server.py's request plumbing.

server.py calls three things from here:
  * resolve(path)      -> what a non-API GET means: a trust page (/privacy, /terms, /security,
                          /status, /tests, /changelog), a per-language address (/fr/, /ar/privacy),
                          /sitemap.xml, /.well-known/security.txt, or None (an ordinary file);
  * decorate(html, ..) -> every HTML page's head: canonical address, hreflang alternates, the
                          page's own social card, JSON-LD (as data blocks: CSP does not apply to
                          them, they are never executed) and the shared scripts (accessibility
                          panel, real-user vitals, error reports);
  * beacon(kind, raw)  -> POST /api/vitals and /api/errors: validated, no personal data, no IP,
                          appended to a capped JSONL file locally, printed to CloudWatch on Lambda.
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

STATIC_DIR = Path(__file__).resolve().parent / "static"
PUBLIC = os.environ.get("CYBERSCAN_PUBLIC") == "1"
SITE = (os.environ.get("CYBERSCAN_CANONICAL_URL", "").strip().rstrip("/") or "https://ainex-ai.xyz")
SCAN_SITE = os.environ.get("CYBERSCAN_SCAN_URL", "").strip().rstrip("/")
SCAN_SITE = SCAN_SITE if SCAN_SITE.startswith("https://") else "https://scan.ainex-ai.xyz"
CONTACT = "mahdi-alhajji@zohomail.sa"
STARTED = time.time()

# the 30 interface languages (same list as js/languages.js and ui/i18n.py)
LANGS = ("en", "ar", "zh", "es", "hi", "fr", "bn", "pt", "ru", "ur", "id", "de", "ja", "tr", "vi", "ko", "it", "fa",
         "pl", "uk", "nl", "th", "sw", "ms", "fil", "ta", "te", "mr", "gu", "pa")
RTL = {"ar", "fa", "ur"}

# address -> file, for the pages that have no file name of their own
TRUST_PAGES = {"/privacy": "privacy.html", "/terms": "terms.html", "/security": "security.html",
               "/status": "status.html", "/tests": "tests.html", "/changelog": "changelog.html"}
# every page that is listed in the sitemap and gets language addresses
SEO_PATHS = ("/", "/journey", "/support", *TRUST_PAGES)
SEO_FILES = {"/": "index.html", "/journey": "journey.html", "/support": "support.html", **TRUST_PAGES}
OG_IMAGES = {"/": "og/landing.png", "/app.html": "og/scan.png", "/journey": "og/journey.png", "/support": "og/support.png",
             "/tests": "og/tests.png", "/privacy": "og/privacy.png", "/terms": "og/privacy.png", "/security": "og/privacy.png",
             "/status": "og/tests.png", "/changelog": "og/landing.png"}
LANG_PATH = re.compile(r"/(" + "|".join(LANGS) + r")(/.*)?")


def resolve(path: str) -> tuple[str, Any] | None:
    """('page', (file, page_path, lang)) | ('redirect', url) | ('body', (bytes, ctype)) | ('alias', path) | None."""
    if path == "/sitemap.xml":
        return "body", (sitemap(), "application/xml; charset=utf-8")
    if path in ("/.well-known/security.txt", "/security.txt"):
        return "body", (security_txt(), "text/plain; charset=utf-8")
    lang = None
    m = LANG_PATH.fullmatch(path)
    if m:
        lang, rest = m.group(1), m.group(2)
        if rest is None:
            return "redirect", f"/{lang}/"
        path = rest
    page = path.rstrip("/") or "/"
    if page in TRUST_PAGES:
        return "page", (TRUST_PAGES[page], page, lang)
    if lang is None:
        return None
    if page in ("/", "/journey", "/support"):
        return "page", (SEO_FILES[page], page, lang)
    return "alias", path   # /fr/styles.css: the page's relative files, from the site root


def _lastmod(name: str) -> str:
    try:
        return datetime.fromtimestamp((STATIC_DIR / name).stat().st_mtime, timezone.utc).strftime("%Y-%m-%d")
    except OSError:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def sitemap() -> bytes:
    rows = []
    for path in SEO_PATHS:
        mod = _lastmod(SEO_FILES[path])
        prio = "1.0" if path == "/" else "0.8" if path in ("/journey", "/support", "/tests") else "0.5"
        rows.append(f"  <url><loc>{SITE}{path}</loc><lastmod>{mod}</lastmod><priority>{prio}</priority></url>")
        for code in LANGS:
            rows.append(f"  <url><loc>{SITE}/{code}{'/' if path == '/' else path}</loc><lastmod>{mod}</lastmod><priority>{prio}</priority></url>")
    rows.append(f"  <url><loc>{SCAN_SITE}/</loc><lastmod>{_lastmod('index.html')}</lastmod><priority>0.9</priority></url>")
    return ('<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
            + "\n".join(rows) + "\n</urlset>\n").encode()


def security_txt() -> bytes:
    """RFC 9116. Expires one year after the file was last changed (rebuilt on every deploy)."""
    stamp = _lastmod("security.html")
    year, rest = stamp.split("-", 1)
    expires = f"{int(year) + 1}-{rest}T00:00:00.000Z"
    return (f"Contact: mailto:{CONTACT}\nExpires: {expires}\nPolicy: {SITE}/security\nAcknowledgments: {SITE}/security#thanks\n"
            f"Preferred-Languages: en, ar\nCanonical: {SITE}/.well-known/security.txt\n").encode()


# ---------------------------------------------------------------- head decoration
def _url(path: str, lang: str | None) -> str:
    if lang:
        return f"{SITE}/{lang}{'/' if path == '/' else path}"
    return f"{SITE}{path}"


def _ld(obj: dict) -> str:
    # a data block; "</" is escaped so the JSON can never close the element early
    return '<script type="application/ld+json">' + json.dumps(obj, ensure_ascii=False).replace("</", "<\\/") + "</script>"


PERSON = {
    "@type": "Person", "@id": f"{SITE}/support#mahdi", "name": "Mahdi Hassan Al-Hajji", "alternateName": ["Mynex", "مهدي آل حاجي"],
    "url": f"{SITE}/support", "jobTitle": "Software developer and AI researcher", "email": f"mailto:{CONTACT}",
    "sameAs": ["https://github.com/mhh1430hacker", "https://www.youtube.com/@AinexTube", "https://www.kaggle.com/mhh1430hacker"],
}
PAPERS = [
    ("10.5281/zenodo.18649873", "The Ainex Singularity: A Geometric Proof of Dimensional Collapse and the Necessity of Fluid Topology"),
    ("10.5281/zenodo.18242108", "The Ainex Limit: Geometric Proof of LLM Semantic Collapse"),
    ("10.5281/zenodo.18285674", "The Ainex Structural Divergence: A Unified Mathematical Proof of Static AI Collapse versus Fluid Adaptive Systems"),
]


def json_ld(path: str) -> str:
    if path == "/":
        app = {"@context": "https://schema.org", "@type": "SoftwareApplication", "name": "CyberScan", "alternateName": "سايبر سكان",
               "url": f"{SITE}/", "applicationCategory": "SecurityApplication", "operatingSystem": "Web, Windows 10/11, Android 7+",
               "description": "Static analysis of files, links and text, explained in plain words. Nothing you check is ever run.",
               "offers": {"@type": "Offer", "price": "0", "priceCurrency": "USD"}, "inLanguage": list(LANGS),
               "image": f"{SITE}/og/landing.png", "creator": {"@type": "Organization", "name": "CyberScan team", "url": f"{SITE}/"}}
        # the developer's personal details stay on /support only, never on the product's home page
        return _ld(app)
    if path == "/support":
        graph = [PERSON] + [{"@type": "ScholarlyArticle", "headline": title, "name": title, "identifier": f"https://doi.org/{doi}",
                             "url": f"https://doi.org/{doi}", "datePublished": "2026-01", "publisher": {"@type": "Organization", "name": "Zenodo"},
                             "author": {"@id": PERSON["@id"]}, "inLanguage": "en"} for doi, title in PAPERS]
        return _ld({"@context": "https://schema.org", "@graph": graph})
    return ""


SHARED_CSS = '<link rel="stylesheet" href="a11y-panel.css">'
SHARED_JS = ('<script src="js/errors.js"></script>', '<script src="js/a11y-early.js"></script>')
SHARED_TAIL = ('<script src="js/a11y-panel.js"></script>', '<script src="js/vitals.js"></script>')


def decorate(html: str, path: str, lang: str | None = None) -> str:
    """Add the SEO head and the shared scripts to one of the site's pages (idempotent).
    path: the page's address without a language prefix ("/", "/app.html", "/privacy"...)."""
    if "data-cs-decorated" in html:
        return html
    head: list[str] = []
    if lang:
        # the language this address stands for: html lang/dir now, and js/lang-early.js tells the page's own
        # language code before any of its scripts read the saved choice
        html = re.sub(r"<html\b[^>]*>", f'<html lang="{lang}" dir="{"rtl" if lang in RTL else "ltr"}">', html, count=1)
        early = f'\n  <meta name="cyberscan-lang" content="{lang}">\n  <script src="js/lang-early.js"></script>'
        html = re.sub(r"(<head>\s*(?:<meta charset=[^>]*>)?)", lambda m: m.group(1) + early, html, count=1)
    head.append('<meta name="cyberscan-decorated" content="1" data-cs-decorated>')
    for piece in SHARED_JS:
        if piece not in html:
            head.append(piece)
    if SHARED_CSS not in html:
        head.append(SHARED_CSS)
    seo = path in SEO_FILES
    canonical = _url(path, lang) if seo else (f"{SCAN_SITE}/" if path == "/app.html" else None)
    html = re.sub(r'\s*<link rel="canonical"[^>]*>|\s*<meta property="og:url"[^>]*>', "", html)
    if canonical:
        head.append(f'<link rel="canonical" href="{canonical}">')
        head.append(f'<meta property="og:url" content="{canonical}">')
    if seo:
        head.append(f'<link rel="alternate" hreflang="x-default" href="{_url(path, None)}">')
        head += [f'<link rel="alternate" hreflang="{c}" href="{_url(path, c)}">' for c in LANGS]
    image = OG_IMAGES.get(path)
    if image and (STATIC_DIR / image).is_file():
        html = re.sub(r'\s*<meta (?:property="og:image(?::width|:height)?"|name="twitter:image")[^>]*>', "", html)
        head += [f'<meta property="og:image" content="{SITE}/{image}">', '<meta property="og:image:width" content="1200">',
                 '<meta property="og:image:height" content="630">', f'<meta name="twitter:image" content="{SITE}/{image}">']
        if 'name="twitter:card"' not in html:
            head.append('<meta name="twitter:card" content="summary_large_image">')
    ld = json_ld(path)
    if ld:
        head.append(ld)
    html = html.replace("</head>", "  " + "\n  ".join(head) + "\n</head>", 1)
    tail = [p for p in SHARED_TAIL if p not in html]
    i = html.rfind("</body>")
    if tail and i > 0:
        html = html[:i] + "  " + "\n  ".join(tail) + "\n" + html[i:]
    return html


# ---------------------------------------------------------------- real-user monitoring
_LOCK = threading.Lock()
_BUCKET = {"vitals": [0.0, 120.0], "errors": [0.0, 30.0]}   # [last refill, tokens]; per process, per minute
_RATE = {"vitals": 120.0, "errors": 30.0}
METRICS = {"LCP", "INP", "CLS", "TTFB", "FCP"}
PAGE_KEY = re.compile(r"/(?:[a-z]{2,3}/)?(?:app\.html|journey|support|privacy|terms|security|status|tests|changelog)?/?")
MAX_LOG = 2 * 1024 * 1024


def _allow(kind: str) -> bool:
    now = time.monotonic()
    with _LOCK:
        last, tokens = _BUCKET[kind]
        tokens = min(_RATE[kind], tokens + (now - last) * _RATE[kind] / 60.0)
        if tokens < 1:
            _BUCKET[kind] = [now, tokens]
            return False
        _BUCKET[kind] = [now, tokens - 1]
        return True


def _page(value: Any) -> str:
    p = str(value or "/")[:64].split("?")[0].split("#")[0]
    return p if PAGE_KEY.fullmatch(p) else "other"


def _clean(value: Any, limit: int) -> str:
    s = re.sub(r"[\x00-\x1f\x7f]", " ", str(value or ""))[:limit]
    # never keep anything that looks like a token, an email or a long number (personal data can hide in messages)
    s = re.sub(r"[\w.+-]+@[\w-]+\.[\w.]+", "[email]", s)
    s = re.sub(r"\b[A-Za-z0-9_\-]{32,}\b", "[id]", s)
    return re.sub(r"\d{6,}", "[n]", s)


def beacon(kind: str, raw: bytes) -> bool:
    """Record one beacon. False: rejected (bad shape or over the rate limit)."""
    if kind not in _BUCKET or not _allow(kind):
        return False
    try:
        data = json.loads(raw.decode("utf-8")) if raw else None
    except (UnicodeDecodeError, ValueError):
        return False
    if not isinstance(data, dict):
        return False
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if kind == "vitals":
        items = data.get("m")
        if not isinstance(items, list) or not 0 < len(items) <= 8:
            return False
        rows = []
        for it in items:
            if not isinstance(it, dict) or it.get("n") not in METRICS or not isinstance(it.get("v"), (int, float)):
                continue
            v = float(it["v"])
            if not 0 <= v <= (10 if it["n"] == "CLS" else 120000):
                continue
            rows.append({"n": it["n"], "v": round(v, 4 if it["n"] == "CLS" else 0)})
        if not rows:
            return False
        rec = {"t": stamp, "page": _page(data.get("p")), "m": rows, "nav": _clean(data.get("nav"), 16),
               "dev": "mobile" if data.get("mob") else "desktop"}
    else:
        rec = {"t": stamp, "page": _page(data.get("p")), "msg": _clean(data.get("msg"), 300),
               "src": _clean(str(data.get("src", "")).split("?")[0], 160),
               "line": int(data["line"]) if isinstance(data.get("line"), int) and 0 <= data["line"] < 10**7 else None,
               "col": int(data["col"]) if isinstance(data.get("col"), int) and 0 <= data["col"] < 10**7 else None,
               "type": "rejection" if data.get("type") == "rejection" else "error"}
    line = json.dumps(rec, ensure_ascii=False)
    if PUBLIC:
        print(f"CS_{kind.upper()} {line}", flush=True)   # CloudWatch Logs
        return True
    import config  # noqa: PLC0415 - Lambda and tests may change config.DATA_DIR after import

    folder = Path(config.DATA_DIR) / "rum"
    target = folder / f"{kind}.jsonl"
    with _LOCK:
        folder.mkdir(parents=True, exist_ok=True)
        if target.is_file() and target.stat().st_size > MAX_LOG:   # capped: keep the newer half
            keep = target.read_bytes()[-MAX_LOG // 2:]
            target.write_bytes(keep[keep.find(b"\n") + 1:])
        with target.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    return True


# ---------------------------------------------------------------- health
def health() -> dict[str, Any]:
    version, commit, released = "", "", ""
    try:
        log = json.loads((STATIC_DIR / "data" / "changelog.json").read_text(encoding="utf-8"))
        top = (log.get("releases") or [{}])[0]
        version, commit, released = top.get("version", ""), top.get("commit", ""), top.get("date", "")
    except (OSError, ValueError):
        pass
    return {"ok": True, "version": os.environ.get("CYBERSCAN_VERSION") or version, "commit": commit, "released": released,
            "started": datetime.fromtimestamp(STARTED, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "uptime_s": int(time.time() - STARTED), "mode": "online (AWS Lambda)" if PUBLIC else "local",
            "time": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
