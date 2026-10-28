from __future__ import annotations

import os
import re
from typing import Any


POWER_SHELL_PATTERNS = [
    (r"powershell\s+.*(-e|-enc|-encodedcommand)", 48, "Encoded PowerShell execution"),
    (r"invoke-expression|iex\s", 35, "In-memory script execution"),
    (r"downloadstring\(|downloadfile\(", 35, "Remote payload download behavior"),
    (r"base64.*(powershell|cmd|curl)", 30, "Obfuscated command execution"),
]

URL_PATTERNS = [
    (r"https?://\d{1,3}(?:\.\d{1,3}){3}", 30, "Direct IPv4 URL host"),
    (r"(?:bit\.ly|tinyurl\.com|t\.co|is\.gd|rb\.gy|cutt\.ly)", 20, "URL shortener domain"),
    (r"discordapp\.com/attachments|api\.telegram\.org/bot", 35, "Webhook or bot API exfiltration link"),
    (r"https?://[^/\s@]*@", 15, "Embedded credential marker in URL"),
]


def evaluate_heuristics(target: str, file_name: str | None = None) -> dict[str, Any]:
    score = 0
    findings: list[dict[str, Any]] = []
    text = (target or "").strip()

    if not text:
        return {"score": 0, "findings": findings}

    for pattern, contribution, label in POWER_SHELL_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            score += contribution
            findings.append({"severity": "high", "label": label, "contribution": contribution})

    for pattern, contribution, label in URL_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            score += contribution
            findings.append({"severity": "medium", "label": label, "contribution": contribution})

    if file_name:
        lower_name = file_name.lower()
        if lower_name.endswith((".exe", ".dll", ".scr", ".bat", ".cmd", ".vbs", ".ps1")):
            score += 18
            findings.append({"severity": "medium", "label": "Executable file extension", "contribution": 18})
        if re.search(r"\.(pdf|doc|docx|jpg|png|txt)\.(exe|bat|vbs|ps1|scr)$", lower_name):
            score += 55
            findings.append({"severity": "high", "label": "Double extension spoofing", "contribution": 55})

    if "powershell" in text.lower() and "-enc" in text.lower():
        score += 12
        findings.append({"severity": "high", "label": "Base64 encoded PowerShell", "contribution": 12})

    if len(text) > 120 and not re.match(r"https?://", text):
        uppercase = sum(1 for c in text if c.isupper())
        if uppercase > 0.3 * len(text):
            score += 10
            findings.append({"severity": "low", "label": "Unusual capitalization pattern", "contribution": 10})

    score = max(0, min(100, int(score)))
    return {"score": score, "findings": findings}
