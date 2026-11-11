from __future__ import annotations

import re
from typing import Any

# (pattern, contribution, label, explanation)
POWER_SHELL_PATTERNS = [
    (
        r"powershell(?:\.exe)?\s+(?:[^\r\n]*?\s)?-e(?:nc(?:odedcommand)?)?\b",
        60,
        "Encoded PowerShell execution",
        "PowerShell is invoked with an encoded-command switch, a common way to hide the executed script.",
    ),
    (
        r"\binvoke-expression\b|\biex[\s(]",
        # 25, not 35: IEX alone is common in legitimate tooling (npm, Git, Visual Studio launchers ship it).
        # Combined with a download primitive it still reaches SUSPICIOUS.
        25,
        "In-memory script execution",
        "Invoke-Expression/IEX executes a string as code, often used to run downloaded or decoded payloads.",
    ),
    (
        r"\bdownloadstring\(|\bdownloadfile\(",
        35,
        "Remote payload download behavior",
        "The content calls a .NET download primitive that fetches remote data.",
    ),
    (
        r"base64.*(?:powershell|cmd|curl)",
        30,
        "Obfuscated command execution",
        "Base64 data appears next to a command interpreter reference.",
    ),
]

URL_PATTERNS = [
    (
        r"https?://\d{1,3}(?:\.\d{1,3}){3}(?![\d.])",
        30,
        "Direct IPv4 URL host",
        "The URL points at a raw IP address instead of a domain name.",
    ),
    (
        r"\b(?:bit\.ly|tinyurl\.com|t\.co|is\.gd|rb\.gy|cutt\.ly)/",
        20,
        "URL shortener domain",
        "A URL shortener hides the real destination.",
    ),
    (
        r"discordapp\.com/attachments|api\.telegram\.org/bot",
        35,
        "Webhook or bot API exfiltration link",
        "The link targets a chat-platform endpoint that is frequently abused for payload hosting or data exfiltration.",
    ),
    (
        # user-info section of a URL: scheme://user[:pass]@host
        r"https?://[^/\s@]+@[^/\s]+",
        15,
        "Embedded credential marker in URL",
        "The URL embeds a user-info section, a trick used to disguise the real host.",
    ),
]

EXECUTABLE_EXTENSIONS = (".exe", ".dll", ".scr", ".bat", ".cmd", ".vbs", ".ps1")
DOUBLE_EXTENSION_RE = re.compile(r"\.(pdf|doc|docx|xls|xlsx|ppt|jpg|jpeg|png|txt)\.(exe|bat|cmd|vbs|ps1|scr)$")


def evaluate_heuristics(
    target: str,
    file_name: str | None = None,
    *,
    scan_content: bool = False,
) -> dict[str, Any]:
    """Score text against transparent rules.

    ``scan_content`` is used for text decoded from file bytes: prose-oriented
    rules (such as the capitalization check) are skipped because they are
    meaningless on binary data.
    """
    score = 0
    findings: list[dict[str, Any]] = []
    text = (target or "").strip()

    def add(severity: str, label: str, contribution: int, explanation: str) -> None:
        nonlocal score
        score += contribution
        findings.append({"severity": severity, "label": label, "contribution": contribution, "explanation": explanation})

    if text:
        for pattern, contribution, label, explanation in POWER_SHELL_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                add("high", label, contribution, explanation)

        for pattern, contribution, label, explanation in URL_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                add("medium", label, contribution, explanation)

        if not scan_content and len(text) > 120 and not re.match(r"https?://", text):
            uppercase = sum(1 for c in text if c.isupper())
            if uppercase > 0.3 * len(text):
                add("low", "Unusual capitalization pattern", 10, "More than 30% of a long string is upper case.")

    if file_name:
        lower_name = file_name.lower()
        if DOUBLE_EXTENSION_RE.search(lower_name):
            add("high", "Double extension spoofing", 55, "A document-like extension is followed by an executable extension.")
        if lower_name.endswith(EXECUTABLE_EXTENSIONS):
            add("medium", "Executable file extension", 18, "The file extension is associated with executable content.")

    return {"score": max(0, min(100, int(score))), "findings": findings}
