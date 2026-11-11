"""Deciding whether one file on disk is a threat, fast enough for whole-drive scans.

Each file is first sorted by what it really is (its first bytes, not its name). Kinds that
can carry code (programs, scripts, Office and PDF documents, archives, shortcuts, and any
file whose name hides what it is) go through the full CyberScan engine: heuristics, YARA,
YARA-Forge, the PE anatomy, the structural model. Plain media and text skip it. Verdicts
are cached by SHA-256, so a second scan only looks at what changed.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

from config import DATA_DIR, DEFAULT_SETTINGS

CACHE_PATH = Path(DATA_DIR) / "shield_cache.json"
ENGINE_VERSION = "1"

CODE_EXT = {
    ".exe", ".dll", ".scr", ".com", ".pif", ".cpl", ".sys", ".msi", ".msp", ".ocx", ".drv", ".efi",
    ".ps1", ".psm1", ".psd1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".bat", ".cmd",
    ".lnk", ".url", ".reg", ".inf", ".jar", ".apk", ".py", ".pyw", ".sh", ".elf", ".dmg", ".appx", ".msix",
    ".doc", ".docm", ".docx", ".dot", ".dotm", ".xls", ".xlsm", ".xlsb", ".xlsx", ".xlam", ".ppt", ".pptm", ".pptx",
    ".rtf", ".pdf", ".one", ".chm", ".iso", ".img", ".vhd", ".vhdx", ".zip", ".rar", ".7z", ".cab", ".gz", ".tar",
    ".svg", ".html", ".htm", ".xhtml", ".mht", ".eml", ".msg", ".xll", ".wll", ".application", ".gadget", ".scf",
}
MAGIC = (
    (b"MZ", "pe"), (b"\x7fELF", "elf"), (b"PK\x03\x04", "zip"), (b"\xd0\xcf\x11\xe0", "ole"), (b"%PDF", "pdf"),
    (b"Rar!", "rar"), (b"7z\xbc\xaf", "7z"), (b"MSCF", "cab"), (b"#!", "script"), (b"{\\rtf", "rtf"),
    (b"L\x00\x00\x00\x01\x14\x02\x00", "lnk"), (b"\xca\xfe\xba\xbe", "macho"), (b"\xcf\xfa\xed\xfe", "macho"),
    (b"dex\n", "dex"),
)
MEDIA_EXT = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".heic", ".mp3", ".mp4", ".mkv", ".avi", ".mov",
             ".wav", ".flac", ".ogg", ".m4a", ".wmv", ".ttf", ".otf", ".woff", ".woff2", ".ico", ".psd", ".raw", ".tif", ".tiff"}
SKIP_DIRS = {"$recycle.bin", "system volume information", "winsxs", "node_modules", ".git", "__pycache__",
             ".venv", "venv", "site-packages", "servicing", "installer"}

_cache: dict[str, Any] | None = None
_cache_lock = threading.Lock()
_cache_dirty = 0
_local = threading.local()


def _load_cache() -> dict[str, Any]:
    global _cache
    with _cache_lock:
        if _cache is None:
            try:
                data = json.loads(CACHE_PATH.read_text(encoding="utf-8"))
                _cache = data if isinstance(data, dict) and data.get("v") == ENGINE_VERSION else {"v": ENGINE_VERSION}
            except (OSError, ValueError):
                _cache = {"v": ENGINE_VERSION}
        return _cache


def flush_cache() -> None:
    global _cache_dirty
    with _cache_lock:
        if _cache is None or not _cache_dirty:
            return
        _cache_dirty = 0
        if len(_cache) > 60000:   # keep the newest entries
            items = sorted(((k, v) for k, v in _cache.items() if k != "v"), key=lambda kv: kv[1].get("t", 0))[-40000:]
            _cache.clear()
            _cache.update(items)
            _cache["v"] = ENGINE_VERSION
        data = json.dumps(_cache, separators=(",", ":"))
    try:
        CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        tmp = CACHE_PATH.with_suffix(".tmp")
        tmp.write_text(data, encoding="utf-8")
        tmp.replace(CACHE_PATH)
    except OSError:
        pass


def _remember(digest: str, verdict: dict[str, Any]) -> None:
    global _cache_dirty
    cache = _load_cache()
    with _cache_lock:
        cache[digest] = {**verdict, "t": int(time.time())}
        _cache_dirty += 1
        dirty = _cache_dirty
    if dirty >= 50:
        flush_cache()


def excluded(path: Path, patterns: list[str]) -> bool:
    text = str(path).casefold()
    for raw in patterns:
        pattern = os.path.expandvars(raw).strip().strip('"').casefold()
        if not pattern:
            continue
        if any(ch in pattern for ch in "*?["):
            if fnmatch(text, pattern):
                return True
        elif text == pattern.rstrip("\\/") or text.startswith(pattern.rstrip("\\/") + os.sep):
            return True
    return False


def sniff(head: bytes) -> str:
    for magic, kind in MAGIC:
        if head.startswith(magic):
            return kind
    stripped = head.lstrip()[:200].lower()
    if stripped.startswith((b"<html", b"<!doctype html", b"<script", b"<svg", b"<?xml")):
        return "markup"
    return ""


def _service():
    service = getattr(_local, "service", None)
    if service is None:
        from ui.scan_service import ScanService  # noqa: PLC0415

        service = _local.service = ScanService()
    return service


def threshold(sensitivity: str) -> int:
    return {"low": 70, "normal": 50, "high": 35}.get(sensitivity, 50)


def inspect(path: Path, options: dict[str, Any] | None = None) -> dict[str, Any]:
    """Look at one file. Returns {status: clean|threat|review|skipped|error, ...}."""
    options = options or {}
    max_bytes = int(options.get("max_mb", 50)) * 1024 * 1024
    try:
        stat = path.stat()
    except OSError as exc:
        return {"status": "error", "reason": type(exc).__name__}
    if stat.st_size == 0:
        return {"status": "skipped", "reason": "empty"}
    if stat.st_size > max_bytes:
        return {"status": "skipped", "reason": "too_large"}
    try:
        with path.open("rb") as handle:
            head = handle.read(4096)
    except OSError as exc:
        return {"status": "error", "reason": type(exc).__name__}
    kind = sniff(head)
    ext = path.suffix.casefold()
    risky = bool(kind) or ext in CODE_EXT
    if not risky:
        # media, text, data: nothing that runs, unless the name lies about it (checked above via magic)
        return {"status": "clean", "kind": kind or "data", "deep": False}
    if kind in ("zip", "rar", "7z", "cab") and not options.get("archives", True) and ext not in (".docx", ".xlsx", ".pptx", ".jar", ".apk"):
        return {"status": "skipped", "reason": "archive_off"}

    try:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        return {"status": "error", "reason": type(exc).__name__}
    cache_key = f"{digest}:{options.get('heuristics', 'normal')}"
    cached = _load_cache().get(cache_key)
    if cached:
        return {**cached, "sha256": digest, "cached": True}

    settings = {**DEFAULT_SETTINGS, "osint_enabled": False, "maximum_file_size": max_bytes,
                "analysis_timeout": float(options.get("timeout", 30.0))}
    try:
        result = _service().analyze(str(path), "File", settings, None)[0]
    except Exception as exc:  # noqa: BLE001 - one unreadable file must not stop a scan
        return {"status": "error", "reason": f"{type(exc).__name__}", "sha256": digest}
    score = int(result.combined_score)
    limit = threshold(options.get("heuristics", "normal"))
    top = sorted(result.evidence, key=lambda f: -int(f.contribution or 0))[:3]
    names = [m.get("rule_name", "") for m in (result.yara_matches or []) if isinstance(m, dict)][:4]
    if score >= limit:
        status = "threat"
    elif score > 0 and result.classification != "NO_INDICATORS_OBSERVED":
        status = "review"
    else:
        status = "clean"
    verdict = {
        "status": status, "score": score, "classification": result.classification, "kind": kind or ext.lstrip("."),
        "deep": True, "rules": names,
        "reasons": [f"{f.category}: {f.evidence}"[:200] for f in top if int(f.contribution or 0) > 0],
        "name": _threat_name(result, kind or ext.lstrip(".")) if status != "clean" else "",
    }
    _remember(cache_key, verdict)
    return {**verdict, "sha256": digest}


def _threat_name(result: Any, kind: str) -> str:
    """A short label in the style antivirus products use, built only from what was found."""
    for match in result.yara_matches or []:
        if isinstance(match, dict) and match.get("rule_name"):
            return str(match["rule_name"])[:80]
    cats = [str(f.category) for f in result.evidence if int(f.contribution or 0) > 0]
    family = cats[0].replace(" ", "") if cats else "Suspicious"
    platform = {"pe": "Win32", "elf": "Linux", "macho": "MacOS", "dex": "Android", "pdf": "PDF", "ole": "Office",
                "zip": "Archive", "lnk": "LNK", "script": "Script"}.get(kind, kind.upper() or "File")
    return f"{platform}:{family}-gen"[:80]


def walk(roots: list[Path], exclusions: list[str], stop: Any = None, max_depth: int | None = None):
    """Yield every regular file under the roots, skipping excluded and system-noise folders."""
    seen: set[str] = set()
    for root in roots:
        if root.is_file():
            if not excluded(root, exclusions):
                yield root
            continue
        stack = [(root, 0)]
        while stack:
            if stop is not None and stop():
                return
            folder, depth = stack.pop()
            try:
                key = str(folder.resolve()).casefold()
            except OSError:
                continue
            if key in seen:
                continue
            seen.add(key)
            try:
                entries = list(os.scandir(folder))
            except OSError:
                continue
            for entry in entries:
                try:
                    if entry.is_symlink():
                        continue
                    path = Path(entry.path)
                    if entry.is_dir(follow_symlinks=False):
                        if entry.name.casefold() in SKIP_DIRS or excluded(path, exclusions):
                            continue
                        if max_depth is None or depth < max_depth:
                            stack.append((path, depth + 1))
                    elif entry.is_file(follow_symlinks=False):
                        if not excluded(path, exclusions):
                            yield path
                except OSError:
                    continue
