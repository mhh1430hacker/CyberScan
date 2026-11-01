"""The truth about a file name, before anything shows it.

Attackers disguise programs with their names:

* **Hidden direction characters.** U+202E (right-to-left override) and its
  relatives make ``holiday‮gnp.exe`` *display* as ``holidayexe.png``. Every
  name shown by the interface goes through ``visible`` first, which replaces
  each such character with a visible marker, so the screen never helps the
  disguise. (MITRE ATT&CK T1036.002.)
* **Double extensions.** ``invoice.pdf.exe`` relies on the reader stopping at
  ``.pdf``. ``double_extension`` reports the decoy and the real type.
* **Shortening.** Cutting a long name in the middle hides exactly the part
  that matters. ``elide`` always keeps the whole ending (both extensions of a
  double extension) and shortens the start of the name instead.

Pure Python; presentation only. It never changes what is scanned.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import PureWindowsPath

# Bidirectional controls and invisible marks that can reorder or hide text.
HIDDEN = {
    "‪": "LRE", "‫": "RLE", "‬": "PDF", "‭": "LRO", "‮": "RLO",
    "⁦": "LRI", "⁧": "RLI", "⁨": "FSI", "⁩": "PDI",
    "‎": "LRM", "‏": "RLM", "؜": "ALM",
    "​": "ZWSP", "‌": "ZWNJ", "‍": "ZWJ", "﻿": "BOM",
}
# What a program or script may be: an ending that runs when opened.
RUNS = {
    "exe", "scr", "com", "pif", "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "ps1",
    "msi", "cpl", "lnk", "jar", "dll", "reg", "application", "gadget", "msc", "url",
}
# What people trust on sight.
LOOKS_HARMLESS = {
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "csv", "odt",
    "jpg", "jpeg", "png", "gif", "bmp", "webp", "mp3", "mp4", "mov", "avi", "wav", "zip", "rar", "html", "htm",
}


@dataclass(frozen=True)
class NameTruth:
    raw: str
    shown: str  # safe to display: hidden characters made visible, left-to-right
    hidden: tuple[str, ...]  # names of hidden characters found (e.g. ("RLO",))
    real_extension: str  # lower case, no dot; "" if none
    decoy_extension: str  # the harmless-looking extension before the real one, if any

    @property
    def disguised(self) -> bool:
        return bool(self.hidden) or bool(self.decoy_extension)

    @property
    def runs(self) -> bool:
        return self.real_extension in RUNS


def _clean(name: str) -> str:
    return "".join(character for character in name if character not in HIDDEN)


def visible(name: str) -> str:
    """The name with every hidden character shown as ⟦RLO⟧-style markers."""
    if not any(character in HIDDEN for character in name):
        return name
    return "".join(f"⟦{HIDDEN[c]}⟧" if c in HIDDEN else c for c in name)


def inspect(name: str) -> NameTruth:
    base = PureWindowsPath(name).name or name
    hidden = tuple(dict.fromkeys(HIDDEN[c] for c in base if c in HIDDEN))
    clean = _clean(base)
    parts = clean.split(".")
    real = parts[-1].lower() if len(parts) > 1 else ""
    decoy = ""
    if len(parts) > 2 and real in RUNS:
        candidate = parts[-2].lower().strip()
        if candidate in LOOKS_HARMLESS:
            decoy = candidate
    # Trailing spaces or dots before the real extension are another way to push it out of view.
    if len(parts) > 2 and real in RUNS and parts[-2].endswith((" ", " ")):
        decoy = decoy or parts[-2].strip().lower() or "space"
    return NameTruth(name, visible(base), hidden, real, decoy)


def tail(shown: str) -> str:
    """The ending of an (already ``visible``) name that must never be cut:
    from the first hidden-character marker if there is one, else the whole
    double extension, else the real extension."""
    marker = shown.find("⟦")
    if marker >= 0:
        return shown[marker:]
    pieces = shown.split(".")
    if len(pieces) < 2:
        return ""
    keep = 2 if len(pieces) > 2 and inspect(shown).decoy_extension else 1
    return "." + ".".join(pieces[-keep:])


def elide_to_width(shown: str, width: float, advance) -> str:
    """Shorten ``shown`` to ``width`` (measured by ``advance(text)``), cutting
    the start of the name and keeping ``tail`` whole."""
    if advance(shown) <= width:
        return shown
    end = tail(shown)
    head = shown[: len(shown) - len(end)] if end else shown
    room = width - advance(end) - advance("…")
    while head and advance(head) > room:
        head = head[:-1]
    return (head.rstrip() + "…" + end) if head else ("…" + end if end else shown[:1] + "…")


def elide(name: str, limit: int) -> str:
    """``elide_to_width`` with characters as the unit (for plain text)."""
    return elide_to_width(visible(name), limit, len)
