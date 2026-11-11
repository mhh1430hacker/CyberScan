"""Exposed secret and sensitive-data discovery.

Findings are *privacy* evidence: they describe what would leak if the content were shared,
not whether it is malicious, so they never raise the threat score (see DECISIONS D-003).
Matched values are redacted before they leave this module.
"""
from __future__ import annotations

import math
import re
from typing import Any

from detection.common import Indicator, redact

CATEGORY = "privacy"
MAX_SECRET_FINDINGS = 50

# (identifier, label, severity, compiled pattern, value group)
_RULES: list[tuple[str, str, str, re.Pattern[str], int]] = [
    ("private_key", "Private key block", "critical",
     re.compile(r"-----BEGIN ((?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?)-----"), 1),
    ("aws_access_key_id", "AWS access key ID", "high",
     re.compile(r"\b((?:AKIA|ASIA|ABIA|ACCA|A3T[A-Z0-9])[A-Z0-9]{16})\b"), 1),
    ("aws_secret_access_key", "AWS secret access key", "critical",
     re.compile(r"(?i)aws.{0,20}?(?:secret|private).{0,20}?[\"'=:\s]\s*[\"']?([A-Za-z0-9/+]{40})(?![A-Za-z0-9/+])"), 1),
    ("github_token", "GitHub token", "high",
     re.compile(r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255})\b"), 1),
    ("gitlab_token", "GitLab personal access token", "high", re.compile(r"\b(glpat-[A-Za-z0-9_\-]{20,})\b"), 1),
    ("slack_token", "Slack token", "high", re.compile(r"\b(xox[abposr]-[A-Za-z0-9-]{10,250})\b"), 1),
    ("slack_webhook", "Slack incoming webhook", "medium",
     re.compile(r"(https://hooks\.slack\.com/services/T[A-Za-z0-9_]{6,}/B[A-Za-z0-9_]{6,}/[A-Za-z0-9_]{20,})"), 1),
    ("discord_webhook", "Discord webhook", "medium",
     re.compile(r"(https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d{15,22}/[A-Za-z0-9_\-]{50,100})"), 1),
    ("telegram_bot_token", "Telegram bot token", "high", re.compile(r"\b(\d{8,10}:AA[A-Za-z0-9_\-]{33})\b"), 1),
    ("google_api_key", "Google API key", "medium", re.compile(r"\b(AIza[0-9A-Za-z_\-]{35})(?![0-9A-Za-z_\-])"), 1),
    ("stripe_secret_key", "Stripe live secret key", "critical", re.compile(r"\b((?:sk|rk)_live_[0-9A-Za-z]{24,99})\b"), 1),
    ("openai_api_key", "OpenAI API key", "high",
     re.compile(r"\b(sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}T3BlbkFJ[A-Za-z0-9_\-]{20,})\b"), 1),
    ("anthropic_api_key", "Anthropic API key", "high", re.compile(r"\b(sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_\-]{80,120})\b"), 1),
    ("sendgrid_api_key", "SendGrid API key", "high", re.compile(r"\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b"), 1),
    ("twilio_api_key", "Twilio API key", "medium", re.compile(r"\b(SK[0-9a-fA-F]{32})\b"), 1),
    ("npm_token", "npm access token", "high", re.compile(r"\b(npm_[A-Za-z0-9]{36})\b"), 1),
    ("jwt", "JSON Web Token", "medium",
     re.compile(r"\b(eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{16,})\b"), 1),
    ("connection_string", "Database/broker URL with embedded password", "high",
     re.compile(r"\b((?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?|mssql|sqlserver)://"
                r"[^\s:/@\"']{1,64}:[^\s@/\"']{3,128}@[^\s/\"']{3,253})"), 1),
]

_GENERIC_ASSIGNMENT = re.compile(
    r"""(?ix)
    \b(?P<name>[a-z0-9_.\-]{0,32}(?:password|passwd|pwd|secret|api[_\-]?key|apikey|access[_\-]?token|auth[_\-]?token|client[_\-]?secret|private[_\-]?key))\b
    ["']?\s*(?:=|:|=>)\s*
    (?P<quote>["'])(?P<value>[^"'\s]{8,200})(?P=quote)
    """
)
_PLACEHOLDER = re.compile(
    r"(?i)^(?:x{4,}|\*{4,}|\.{3,}|<.*>|\{\{.*\}\}|\$\{.*\}|%\(.*\)s|your[_\-]|changeme|change_me|example|"
    r"placeholder|redacted|dummy|sample|test|password|secret|null|none|undefined|todo|fixme|replace)"
)
_CARD_CANDIDATE = re.compile(r"(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])")


def _shannon(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    return -sum((count / len(value)) * math.log2(count / len(value)) for count in counts.values())


def _luhn_valid(digits: str) -> bool:
    total = 0
    for index, char in enumerate(reversed(digits)):
        value = int(char)
        if index % 2 == 1:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def _card_brand(digits: str) -> str | None:
    if re.match(r"4\d{12}(?:\d{3}){0,2}$", digits):
        return "Visa"
    if re.match(r"(?:5[1-5]\d{2}|2(?:2[2-9]\d|[3-6]\d{2}|7[01]\d|720))\d{12}$", digits):
        return "Mastercard"
    if re.match(r"3[47]\d{13}$", digits):
        return "American Express"
    if re.match(r"6(?:011|5\d{2})\d{12,15}$", digits):
        return "Discover"
    return None


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def scan_secrets(text: str, *, max_findings: int = MAX_SECRET_FINDINGS) -> dict[str, Any]:
    """Find credentials and payment-card numbers in text. Values are redacted in the output."""
    content = text or ""
    indicators: list[Indicator] = []
    seen: set[tuple[str, str]] = set()
    covered: list[tuple[int, int]] = []

    def record(kind: str, label: str, severity: str, value: str, start: int, explanation: str) -> None:
        key = (kind, value)
        if key in seen or len(indicators) >= max_findings:
            return
        seen.add(key)
        indicators.append(Indicator(
            CATEGORY, severity, label, explanation, 0,
            {"type": kind, "redacted": redact(value), "line": _line_number(content, start)},
        ))

    for kind, label, severity, pattern, group in _RULES:
        for match in pattern.finditer(content):
            value = match.group(group)
            if kind == "jwt" and _PLACEHOLDER.search(value):
                continue
            covered.append(match.span())
            record(kind, label, severity, value, match.start(),
                   f"A {label.lower()} appears in the content; anyone who receives this content can use it. "
                   "Revoke and rotate it if it is real.")

    for match in _GENERIC_ASSIGNMENT.finditer(content):
        value = match.group("value")
        if any(start <= match.start("value") < end for start, end in covered):
            continue
        if _PLACEHOLDER.search(value) or _shannon(value) < 3.0:
            continue
        # Values that are references, not secrets: env lookups, file paths, URLs without credentials.
        if value.startswith(("$", "%", "/", "./", "http://", "https://", "os.environ", "process.env")):
            continue
        name = match.group("name")
        record("generic_secret", "Hard-coded credential", "medium", value, match.start(),
               f"'{name}' is assigned a literal value that looks like a real credential (high character entropy).")

    for match in _CARD_CANDIDATE.finditer(content):
        digits = re.sub(r"[ -]", "", match.group(0))
        if not 13 <= len(digits) <= 19 or len(set(digits)) < 2 or not _luhn_valid(digits):
            continue
        brand = _card_brand(digits)
        if brand is None:
            continue
        record("payment_card", f"Payment card number ({brand})", "high", digits, match.start(),
               "A Luhn-valid payment card number is present. Card data must not be stored or shared in clear text.")

    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    worst = max((severity_rank[item.severity] for item in indicators), default=0)
    exposure = ["none", "low", "moderate", "high", "critical"][worst]
    return {
        "exposure_level": exposure,
        "count": len(indicators),
        "truncated": len(indicators) >= max_findings,
        "indicators": indicators,
        "findings": [
            {"type": item.data["type"], "label": item.label, "severity": item.severity,
             "redacted": item.data["redacted"], "line": item.data["line"], "explanation": item.explanation}
            for item in indicators
        ],
    }
