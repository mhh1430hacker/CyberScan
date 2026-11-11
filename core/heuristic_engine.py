# Claude (AI assistant, Anthropic) worked on this file, 2026-11-06: layered de-obfuscation views, UTF-16LE/BE, short Base64, tab/space letters, whole-file strings, stricter credential-URL rule.
from __future__ import annotations

import base64
import binascii
import re
from typing import Any


POWER_SHELL_PATTERNS = [
    (r"powershell\s+.*(-e|-enc|-encodedcommand)", 48, "Encoded PowerShell execution"),
    (r"invoke-expression|iex\s", 35, "In-memory script execution"),
    (r"downloadstring\(|downloadfile\(", 35, "Remote payload download behavior"),
    (r"base64.*(powershell|cmd|curl)", 30, "Obfuscated command execution"),
]

# Built-in Windows tools as ransomware and intruders use them ("living off the
# land"; see the LOLBAS project). Each alone can be ordinary administration,
# so the weights stay at review level unless several meet.
SYSTEM_TOOL_PATTERNS = [
    (r"vssadmin(\.exe)?\s+delete\s+shadows", 45, "Deletes backup copies (shadow copies)"),
    (r"wmic(\.exe)?\s+shadowcopy\s+delete", 45, "Deletes backup copies (shadow copies)"),
    (r"bcdedit(\.exe)?\s+/set\s+\S+\s+recoveryenabled\s+no", 40, "Turns off Windows recovery"),
    (r"certutil(\.exe)?\s+-urlcache\s+(-split\s+)?-f\s+https?://", 35, "Downloads a file with certutil"),
    (r"mshta(\.exe)?\s+(vbscript|javascript):", 35, "Runs script through mshta"),
    (r"reg(\.exe)?\s+add\s+\S*\\currentversion\\run", 25, "Starts itself with Windows (Run key)"),
    (r"schtasks(\.exe)?\s+/create\b", 20, "Creates a scheduled task"),
    (r"virtualalloc.{0,40}writeprocessmemory.{0,40}createremotethread", 35, "Process-injection API names together"),
]

URL_PATTERNS = [
    (r"https?://\d{1,3}(?:\.\d{1,3}){3}", 30, "Direct IPv4 URL host"),
    # Bounded on both sides: "t.co" must not match inside words such as "chat.com".
    (r"(?<![\w.-])(?:bit\.ly|tinyurl\.com|t\.co|is\.gd|rb\.gy|cutt\.ly)(?=[/\s\"'<>)\]]|$)", 20, "URL shortener domain"),
    (r"discordapp\.com/attachments|api\.telegram\.org/bot", 35, "Webhook or bot API exfiltration link"),
    # user[:password]@host, in URL characters only: "[^/\s@]*" spanned binary bytes and
    # fired on audio files whose metadata held an unrelated "http://" and a later "@".
    (r"https?://[A-Za-z0-9._~%!$&'()*+,;=:-]{1,128}@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}", 15, "Embedded credential marker in URL"),
]

# 16 characters encode 12 bytes: short commands such as "wmic shadowcopy delete" (32 characters
# of Base64) must be reachable. A token only matters if its decoding then matches an indicator.
_BASE64 = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
MAX_BASE64_TOKENS = 2000
# Text with a space after every character ("c m d   / c"): every other character is a space,
# and an original space shows as three. Six or more such pairs; ordinary prose has none.
_SPACED = re.compile(r"(?:[^\r\n][ \t]){6,}[^\r\n]?")
# UTF-16 text inside otherwise 8-bit content: printable characters each followed by a zero byte
# (little-endian, as Windows writes it) or preceded by one (big-endian).
_UTF16_RUN = re.compile("(?:[\\x20-\\x7e]\\x00){6,}")
_UTF16BE_RUN = re.compile("(?:\\x00[\\x20-\\x7e]){6,}")
_CONCAT = re.compile(r"[\"']\s*\+\s*[\"']")
MAX_VIEW_CHARACTERS = 3_000_000
# Separator between pieces taken from different places: like a C string terminator, it keeps
# "VirtualAlloc\0WriteProcessMemory" matchable (``.`` matches it) without inventing new words.
PIECE_SEPARATOR = "\x00"


def _undo_utf16(text: str) -> str | None:
    """UTF-16 text decoded as Latin-1 ("p\\0o\\0w\\0..."), even a short phrase."""
    runs = _UTF16_RUN.findall(text) + _UTF16BE_RUN.findall(text)
    return PIECE_SEPARATOR.join(run.replace(chr(0), "") for run in runs) if runs else None


def _undo_escapes(text: str) -> str | None:
    """cmd's escape character between letters: p^o^w^e^r^s^h^e^l^l."""
    return text.replace("^", "") if "^" in text else None


def _undo_spacing(text: str) -> str | None:
    """p o w e r s h e l l: keep every other character."""
    return _SPACED.sub(lambda m: m.group(0)[::2], text) if _SPACED.search(text) else None


def _undo_concatenation(text: str) -> str | None:
    """"power" + "shell"."""
    return _CONCAT.sub("", text) if _CONCAT.search(text) else None


def _undo_base64(text: str) -> str | None:
    decoded = []
    for token in _BASE64.findall(text)[:MAX_BASE64_TOKENS]:
        try:
            raw = base64.b64decode(token + "=" * (-len(token) % 4), validate=False)
        except (binascii.Error, ValueError):
            continue
        piece = raw.decode("utf-16-le", "ignore") if raw[1:2] == b"\x00" else raw.decode("latin-1")
        if sum(32 <= ord(c) < 127 for c in piece) >= 0.8 * max(1, len(piece)):
            decoded.append(piece)
    return "\n".join(decoded) if decoded else None


UNDO = (
    ("UTF-16", _undo_utf16),
    ("escape characters", _undo_escapes),
    ("spaced letters", _undo_spacing),
    ("joined strings", _undo_concatenation),
    ("Base64", _undo_base64),
)
MAX_LAYERS = 2  # tricks stacked on each other: "p ^ o ^ w ..." is escapes, then spacing
MAX_VIEWS = 16


def _views(text: str) -> list[tuple[str, str]]:
    """The same content as an attacker might hide it, each view undoing one or more tricks.

    Tricks stack (escape characters, then a space after every character), so the
    undo steps are applied to each other's output too, up to ``MAX_LAYERS``
    deep. Returned as (name, text); the first is the content as it is.
    """
    views = [("as written", text[:MAX_VIEW_CHARACTERS])]
    seen = {views[0][1]}
    frontier = list(views)
    for _layer in range(MAX_LAYERS):
        following = []
        for name, value in frontier:
            for step, undo in UNDO:
                if len(views) >= MAX_VIEWS:
                    return views
                undone = undo(value)
                if undone is None:
                    continue
                undone = undone[:MAX_VIEW_CHARACTERS]
                if undone in seen:
                    continue
                seen.add(undone)
                view = (step if name == "as written" else f"{name}, then {step}", undone)
                views.append(view)
                following.append(view)
        frontier = following
    return views


_ASCII_STRING = re.compile(rb"[\x20-\x7e\t]{6,}")
_UTF16_STRING = re.compile(rb"(?:[\x20-\x7e]\x00){6,}")
_UTF16BE_STRING = re.compile(rb"(?:\x00[\x20-\x7e]){6,}")
MAX_TAIL_STRING_CHARACTERS = 2_000_000
CHUNK_CHARACTERS = 1024
CHUNK_OVERLAP = 256  # longer than any indicator pattern, so none is cut in two everywhere


def strings_beyond(data: bytes, start: int, budget: int = MAX_TAIL_STRING_CHARACTERS) -> tuple[str, dict[str, int | bool]]:
    """Printable strings (ASCII and UTF-16LE, 6+ characters) from ``data[start:]``.

    Reading only a file's first bytes lets anyone hide an indicator by putting
    megabytes of padding in front of it. Its strings, like the ``strings`` tool
    shows them, cover the whole file at a fraction of its size. Long runs are cut
    into overlapping chunks and every repeated chunk is kept once, so filler text
    repeated to fill the budget ("lorem ipsum " x 1,000,000) collapses to a few
    chunks instead of pushing real text out. Distinct junk can still fill it, and
    ``truncated`` then says so.
    """
    seen: set[bytes] = set()
    pieces: list[str] = []
    used = 0
    truncated = False
    tail = data[start:]
    for pattern, encoding, unit in ((_ASCII_STRING, "latin-1", 1), (_UTF16_STRING, "utf-16-le", 2), (_UTF16BE_STRING, "utf-16-be", 2)):
        for match in pattern.finditer(tail):
            raw = match.group(0)
            size, step = CHUNK_CHARACTERS * unit, (CHUNK_CHARACTERS - CHUNK_OVERLAP) * unit
            chunks = [raw] if len(raw) <= size else [raw[at:at + size] for at in range(0, len(raw) - CHUNK_OVERLAP * unit, step)]
            for chunk in chunks:
                if chunk in seen:
                    continue
                seen.add(chunk)
                piece = chunk.decode(encoding, "replace")
                if used + len(piece) > budget:
                    truncated = True
                    break
                pieces.append(piece)
                used += len(piece) + 1
            if truncated:
                break
        if truncated:
            break
    return PIECE_SEPARATOR.join(pieces), {"start": start, "strings": len(pieces), "characters": used, "truncated": truncated}


def _mostly_text(text: str) -> bool:
    sample = text[:8192]
    if not sample or chr(0) in sample:  # binary content is not prose, whatever its letters
        return False
    if sample.lstrip().startswith(("%PDF", "{\\rtf", "<?xml", "<svg", "<!DOCTYPE", "<html")):
        return False  # document syntax is full of capitals by design (/Type /Font, <!DOCTYPE)
    printable = sum(1 for c in sample if c in "\t\r\n" or 32 <= ord(c) < 127 or ord(c) >= 160)
    return printable / len(sample) >= 0.95


def evaluate_heuristics(target: str, file_name: str | None = None) -> dict[str, Any]:
    score = 0
    findings: list[dict[str, Any]] = []
    text = (target or "").strip()

    if not text:
        return {"score": 0, "findings": findings}

    seen: set[str] = set()
    hidden = False
    for view_name, view in _views(text):
        for patterns, severity in ((POWER_SHELL_PATTERNS, "high"), (SYSTEM_TOOL_PATTERNS, "high"), (URL_PATTERNS, "medium")):
            for pattern, contribution, label in patterns:
                if label in seen:
                    continue
                if re.search(pattern, view, re.IGNORECASE):
                    seen.add(label)
                    score += contribution
                    shown = label if view_name == "as written" else f"{label} (hidden by {view_name})"
                    hidden = hidden or view_name != "as written"
                    findings.append({"severity": severity, "label": shown, "contribution": contribution})
    if hidden:
        # Hiding an indicator is itself a signal: harmless content has no reason to.
        score += 15
        findings.append({"severity": "high", "label": "Indicator hidden by encoding", "contribution": 15})

    if file_name:
        lower_name = file_name.lower()
        if lower_name.endswith((".exe", ".dll", ".scr", ".bat", ".cmd", ".vbs", ".ps1")):
            # Being a program is a fact, not a warning: shown, but it adds nothing.
            findings.append({"severity": "info", "label": "Executable file extension", "contribution": 0})
        if re.search(r"\.(pdf|doc|docx|jpg|png|txt)\.(exe|bat|vbs|ps1|scr)$", lower_name):
            score += 55
            findings.append({"severity": "high", "label": "Double extension spoofing", "contribution": 55})

    if "powershell" in text.lower() and "-enc" in text.lower():
        score += 12
        findings.append({"severity": "high", "label": "Base64 encoded PowerShell", "contribution": 12})

    if len(text) > 120 and not re.match(r"https?://", text) and _mostly_text(text):
        uppercase = sum(1 for c in text if c.isupper())
        if uppercase > 0.3 * len(text):
            score += 10
            findings.append({"severity": "low", "label": "Unusual capitalization pattern", "contribution": 10})

    score = max(0, min(100, int(score)))
    return {"score": score, "findings": findings}
