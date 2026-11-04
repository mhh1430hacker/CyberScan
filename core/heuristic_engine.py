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
    (r"https?://[^/\s@]*@", 15, "Embedded credential marker in URL"),
]

_BASE64 = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
# Single characters each followed by one space, at least three in a row: "r e g", "c m d . e x e".
# Collapsing only matters if a real indicator then appears, so ordinary text is not affected.
_SPACED = re.compile(r"(?<!\S)(?:\S ){2,}\S(?!\S)")
# UTF-16 text inside otherwise 8-bit content: printable characters each followed by a zero byte.
_UTF16_RUN = re.compile("(?:[\\x20-\\x7e]\\x00){6,}")
_CONCAT = re.compile(r"[\"']\s*\+\s*[\"']")
MAX_VIEW_CHARACTERS = 400_000


def _views(text: str) -> list[tuple[str, str]]:
    """The same content as an attacker might hide it: each view undoes one trick.

    Returned as (name, text); the first is the content as it is.
    """
    views = [("as written", text)]
    runs = _UTF16_RUN.findall(text)  # UTF-16 text decoded as Latin-1, even a short phrase
    if runs:
        views.append(("UTF-16", "\n".join(run.replace(chr(0), "") for run in runs)))
    if "^" in text:  # cmd's escape character between letters: p^o^w^e^r^s^h^e^l^l
        views.append(("escape characters", text.replace("^", "")))
    if _SPACED.search(text):  # p o w e r s h e l l
        views.append(("spaced letters", _SPACED.sub(lambda m: m.group(0).replace(" ", ""), text)))
    if _CONCAT.search(text):  # "power" + "shell"
        views.append(("joined strings", _CONCAT.sub("", text)))
    decoded = []
    for token in _BASE64.findall(text)[:50]:
        try:
            raw = base64.b64decode(token + "=" * (-len(token) % 4), validate=False)
        except (binascii.Error, ValueError):
            continue
        piece = raw.decode("utf-16-le", "ignore") if raw[1:2] == b"\x00" else raw.decode("latin-1")
        if sum(32 <= ord(c) < 127 for c in piece) >= 0.8 * max(1, len(piece)):
            decoded.append(piece)
    if decoded:
        views.append(("Base64", "\n".join(decoded)))
    return [(name, value[:MAX_VIEW_CHARACTERS]) for name, value in views]


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
