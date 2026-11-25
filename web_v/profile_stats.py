"""Live public numbers for the support page (GET /api/profile).

Fetches, with short timeouts and in parallel, and caches for six hours:
  * Zenodo: unique views and unique downloads of the three Ainex papers;
  * GitHub: public repositories, followers and the stars of the public repositories;
  * YouTube: the latest video of the @AinexTube channel (its id, title and date from the channel's
    public RSS feed) and its thumbnail, embedded as a data: URI so the visitor's browser makes no
    request to YouTube until they press play.
Any source that fails keeps its last good value, or the fixed numbers checked by hand
(FALLBACK), so the page always has something true to show. Nothing here needs a key.
"""
from __future__ import annotations

import base64
import json
import re
import tempfile
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, wait
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

TTL = 6 * 3600                      # six hours
FAIL_TTL = 15 * 60                  # after a failed refresh, try again in a quarter of an hour
TIMEOUT = 3.5                       # per request (seconds)
DEADLINE = 5.0                      # the whole refresh
UA = "CyberScan-profile/1.0 (+https://ainex-ai.xyz)"

PAPERS = ("18649873", "18242108", "18285674")
GITHUB_USER = "mhh1430hacker"
YT_HANDLE = "AinexTube"
YT_CHANNEL = "UCtYhRqqklUkoGw4f1ZRFkdg"   # resolved from https://www.youtube.com/@AinexTube (canonical link), 2026-11-22

# checked by hand on 2026-11-21 (the numbers printed in support.html)
FALLBACK: dict[str, Any] = {
    "papers": {
        "18649873": {"views": 724, "downloads": 395},
        "18242108": {"views": 380, "downloads": 123},
        "18285674": {"views": 106, "downloads": 58},
    },
    "github": {"repos": 17, "followers": 1, "stars": None},
    "video": {"id": "BMldxyd71ws", "title": "CyberScan IN 1 MINUTE", "published": "2026-11-18T16:46:55+00:00", "thumb": None},
}

_lock = threading.Lock()
_cache: dict[str, Any] = {"at": 0.0, "ok": 0.0, "data": None}
_CACHE_FILE = Path(tempfile.gettempdir()) / "cyberscan-profile-cache.json"
_VIDEO_ID = re.compile(r"^[A-Za-z0-9_-]{11}$")
_CHANNEL_ID = re.compile(r"^UC[A-Za-z0-9_-]{22}$")


def _get(url: str, limit: int = 2_000_000, accept: str = "application/json") -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": accept, "Accept-Language": "en"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:  # noqa: S310 - fixed https URLs only
        return resp.read(limit + 1)[:limit]


def _zenodo(rec: str) -> dict[str, int]:
    stats = json.loads(_get(f"https://zenodo.org/api/records/{rec}")).get("stats") or {}
    return {"views": int(stats["unique_views"]), "downloads": int(stats["unique_downloads"])}


def _github() -> dict[str, Any]:
    user = json.loads(_get(f"https://api.github.com/users/{GITHUB_USER}"))
    out: dict[str, Any] = {"repos": int(user["public_repos"]), "followers": int(user["followers"]), "stars": None}
    try:
        repos = json.loads(_get(f"https://api.github.com/users/{GITHUB_USER}/repos?per_page=100&type=owner"))
        out["stars"] = sum(int(r.get("stargazers_count") or 0) for r in repos if isinstance(r, dict) and not r.get("fork"))
    except (OSError, ValueError, KeyError, TypeError):
        pass
    return out


def _channel_id() -> str:
    """The channel id behind the @handle (the page's canonical link), or the known one."""
    try:
        page = _get(f"https://www.youtube.com/@{YT_HANDLE}", limit=1_500_000, accept="text/html").decode("utf-8", "ignore")
        m = re.search(r'<link rel="canonical" href="https://www\.youtube\.com/channel/(UC[A-Za-z0-9_-]{22})"', page) \
            or re.search(r'"externalId":"(UC[A-Za-z0-9_-]{22})"', page)
        if m and _CHANNEL_ID.match(m.group(1)):
            return m.group(1)
    except OSError:
        pass
    return YT_CHANNEL


def _youtube() -> dict[str, Any]:
    cid = _channel_id()
    xml = _get(f"https://www.youtube.com/feeds/videos.xml?channel_id={cid}", accept="application/atom+xml")
    ns = {"a": "http://www.w3.org/2005/Atom", "yt": "http://www.youtube.com/xml/schemas/2015"}
    root = ElementTree.fromstring(xml)  # noqa: S314 - YouTube's own feed, small, no DTD
    best = None
    for entry in root.findall("a:entry", ns):
        vid = (entry.findtext("yt:videoId", "", ns) or "").strip()
        if not _VIDEO_ID.match(vid):
            continue
        link = entry.find("a:link", ns)
        short = link is not None and "/shorts/" in (link.get("href") or "")
        item = {"id": vid, "title": (entry.findtext("a:title", "", ns) or "").strip()[:160],
                "published": (entry.findtext("a:published", "", ns) or "").strip()[:40], "short": short}
        if best is None:
            best = item
        if not short:                      # the latest full video is featured; a Short only if there is nothing else
            best = item
            break
    if not best:
        raise ValueError("no video in the feed")
    best.pop("short", None)
    best["thumb"] = None
    try:
        img = _get(f"https://i.ytimg.com/vi/{best['id']}/hqdefault.jpg", limit=400_000, accept="image/jpeg")
        if img[:3] == b"\xff\xd8\xff":
            best["thumb"] = "data:image/jpeg;base64," + base64.b64encode(img).decode("ascii")
    except OSError:
        pass
    best["channel"] = cid
    return best


def _load_file() -> None:
    if _cache["data"] is not None:
        return
    try:
        saved = json.loads(_CACHE_FILE.read_text("utf-8"))
        if isinstance(saved, dict) and isinstance(saved.get("data"), dict):
            _cache.update(at=float(saved.get("at", 0)), ok=float(saved.get("ok", 0)), data=saved["data"])
    except (OSError, ValueError):
        pass


def _refresh() -> None:
    prev = _cache["data"] or json.loads(json.dumps(FALLBACK))
    data = json.loads(json.dumps(prev))
    live: dict[str, bool] = {}
    pool = ThreadPoolExecutor(max_workers=6)
    jobs = {pool.submit(_zenodo, rec): ("paper", rec) for rec in PAPERS}
    jobs[pool.submit(_github)] = ("github", "")
    jobs[pool.submit(_youtube)] = ("video", "")
    done, _ = wait(jobs, timeout=DEADLINE)
    for fut in done:
        kind, key = jobs[fut]
        try:
            value = fut.result()
        except Exception:  # noqa: BLE001 - any failure of one source keeps its last good value
            continue
        if kind == "paper":
            data["papers"][key] = value
            live[f"paper:{key}"] = True
        elif kind == "github":
            data["github"] = value
            live["github"] = True
        else:
            if not value.get("thumb") and prev.get("video", {}).get("id") == value["id"]:
                value["thumb"] = prev["video"].get("thumb")
            data["video"] = value
            live["video"] = True
    pool.shutdown(wait=False, cancel_futures=True)
    now = time.time()
    data["live"] = sorted(live)
    _cache["data"] = data
    _cache["at"] = now
    if live:
        _cache["ok"] = now
        data["checked"] = int(now)
        try:
            _CACHE_FILE.write_text(json.dumps({"at": now, "ok": now, "data": data}), "utf-8")
        except OSError:
            pass


def profile() -> dict[str, Any]:
    """The numbers, refreshed when older than six hours (a quarter of an hour after a failure)."""
    with _lock:
        _load_file()
        age = time.time() - _cache["at"]
        stale = _cache["data"] is None or age > TTL or (_cache["ok"] < _cache["at"] and age > FAIL_TTL)
        if stale:
            _refresh()
        data = json.loads(json.dumps(_cache["data"]))
    papers = data["papers"]
    data["totals"] = {
        "papers": len(PAPERS),
        "views": sum(int(papers[p]["views"]) for p in PAPERS),
        "downloads": sum(int(papers[p]["downloads"]) for p in PAPERS),
    }
    data.setdefault("checked", None)
    data["ttl"] = TTL
    return data
