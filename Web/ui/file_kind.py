"""What kind of target the user gave us, and the colour that travels with it.

Every target gets one *kind* (program, script, document, archive, media, text,
link, indicator, file). The kind's hue follows the target everywhere it
appears: the drop lens, the scan journey, the result and the history rail.
Hues are deliberately kept away from the verdict colours (green, amber, red),
so a file's colour never reads as a judgement about it.

Pure Python: no Qt, no detection logic. The kind is a presentation label read
from the name or the input mode; it never changes how a target is analysed.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
from urllib.parse import urlsplit


@dataclass(frozen=True)
class FileKind:
    key: str
    label: str  # English source text; translated by ui.copy
    hue: str
    icon: str  # key in ui.icons.ICONS


KINDS: dict[str, FileKind] = {
    "program": FileKind("program", "Program", "#a78bfa", "program"),
    "script": FileKind("script", "Script", "#22d3ee", "script"),
    "document": FileKind("document", "Document", "#60a5fa", "document"),
    "archive": FileKind("archive", "Archive", "#e879f9", "archive"),
    "media": FileKind("media", "Image or media", "#f472b6", "media"),
    "text": FileKind("text", "Text file", "#5eead4", "textfile"),
    "file": FileKind("file", "File", "#94a3b8", "file"),
    "url": FileKind("url", "Link", "#818cf8", "link"),
    "indicator": FileKind("indicator", "Indicator", "#38bdf8", "tag"),
}

_EXTENSIONS = {
    "program": {"exe", "dll", "sys", "scr", "com", "msi", "cpl", "ocx", "drv", "efi", "elf", "so", "dylib", "apk", "app"},
    "script": {"ps1", "psm1", "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "py", "sh", "pl", "rb", "lnk", "reg", "jar"},
    "document": {"pdf", "doc", "docx", "docm", "dot", "dotm", "xls", "xlsx", "xlsm", "xlsb", "ppt", "pptx", "pptm", "rtf", "odt", "ods", "odp", "one", "pub"},
    "archive": {"zip", "rar", "7z", "gz", "tgz", "tar", "bz2", "xz", "iso", "img", "cab", "vhd", "vhdx"},
    "media": {"png", "jpg", "jpeg", "gif", "bmp", "webp", "svg", "ico", "tif", "tiff", "mp3", "wav", "flac", "ogg", "mp4", "mkv", "avi", "mov", "webm"},
    "text": {"txt", "log", "md", "csv", "json", "xml", "yaml", "yml", "ini", "cfg", "conf", "html", "htm", "eml"},
}

_URL = re.compile(r"^https?://", re.IGNORECASE)
_PATHLIKE = re.compile(r"^(?:[a-zA-Z]:[\\/]|\\\\|/|~[\\/]|\.{1,2}[\\/])")


def kind_for_name(name: str) -> FileKind:
    """Kind from the last extension (so ``invoice.pdf.exe`` is a program)."""
    suffix = PureWindowsPath(name).suffix.lstrip(".").lower()
    for key, extensions in _EXTENSIONS.items():
        if suffix in extensions:
            return KINDS[key]
    return KINDS["file"]


def kind_for_target(target: str, mode: str) -> FileKind:
    if mode == "URL":
        return KINDS["url"]
    if mode == "File":
        return kind_for_name(target)
    return KINDS["indicator"]


def extension_of(name: str) -> str:
    return PureWindowsPath(name).suffix.lstrip(".").upper()


def detect_mode(text: str) -> str:
    """Which input mode a typed or pasted target belongs to.

    ``URL`` for http(s) links, ``File`` for anything that is or looks like a
    filesystem path, otherwise ``Indicator / text`` (hashes, domains, IPs,
    free text). A path that does not exist is still ``File`` so the user is
    told the file is missing instead of having the path scanned as text.
    """
    value = text.strip().strip('"')
    if not value:
        return "File"
    if _URL.match(value):
        return "URL"
    if _PATHLIKE.match(value):
        return "File"
    try:
        if Path(value).is_file():
            return "File"
    except (OSError, ValueError):
        pass
    return "Indicator / text"


def display_name(target: str, mode: str) -> str:
    """How a target is named on screen. File names pass through
    ``ui.names.visible``: a hidden direction character never gets to reorder
    the name the user reads."""
    from ui.names import visible

    if mode == "File":
        return visible(PureWindowsPath(target).name or target)
    if mode == "URL":
        parts = urlsplit(target)
        return (parts.hostname or target) + (parts.path if parts.path not in {"", "/"} else "")
    return target
