"""Personal-data detectors shared by tools 072, 073, 076 and 079.

Every detector validates beyond the pattern where a checksum or structure exists (Luhn for cards and
Saudi IDs, mod-97 for IBAN, area/group/serial rules for US SSNs, prefix rules for UK NINOs), and
weaker patterns (phone numbers, passports, dates of birth) need a nearby keyword. Results are masked.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any

from security_toolkit.core import line_of

EMAIL = re.compile(r"(?<![\w.+-])([A-Za-z0-9][A-Za-z0-9._%+-]{0,63})@((?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,24})(?![\w-])")
# not preceded by a digit, '-' or '.', so the fractional digits of floats (0.1234567890123456) are not "card numbers"
CARD = re.compile(r"(?<![\d.-])(?:\d[ -]?){12,18}\d(?![\d-])")
IBAN = re.compile(r"\b([A-Z]{2}\d{2}(?: ?[A-Z0-9]){11,30})\b")
SSN = re.compile(r"(?<![\d-])(\d{3})-(\d{2})-(\d{4})(?![\d-])")
SAUDI_ID = re.compile(r"(?<!\d)([12]\d{9})(?!\d)")
NINO = re.compile(r"\b([A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z] ?\d{2} ?\d{2} ?\d{2} ?[A-D])\b")
PHONE = re.compile(r"(?<![\w+])(\+\d{1,3}[ .-]?(?:\(\d{1,4}\)[ .-]?)?\d{2,4}(?:[ .-]?\d{2,4}){1,3}|\(\d{3}\) ?\d{3}-\d{4}|05\d{8})(?![\w])")
IPV4 = re.compile(r"(?<![\d.])((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})(?![\d.])")
DOB = re.compile(r"(?i)\b(?:d\.?o\.?b\.?|date of birth|birth ?date|born(?: on)?|تاريخ الميلاد)\b\W{0,5}(\d{1,4}[./-]\d{1,2}[./-]\d{1,4})")
PASSPORT = re.compile(r"(?i)\b(?:passport(?: no\.?| number| #)?|جواز(?: السفر)?)\W{0,5}([A-Z]{1,2}\d{6,8})\b")
IBAN_LENGTHS = {"AD": 24, "AE": 23, "AT": 20, "BE": 16, "BH": 22, "CH": 21, "DE": 22, "DK": 18, "EG": 29, "ES": 24, "FI": 18,
                "FR": 27, "GB": 22, "GR": 27, "IE": 22, "IT": 27, "JO": 30, "KW": 30, "LU": 20, "NL": 18, "NO": 15, "OM": 23,
                "PL": 28, "PT": 25, "QA": 29, "SA": 24, "SE": 24, "TR": 26}
LABELS = {"email": "Email address", "payment_card": "Payment card number", "iban": "IBAN bank account", "us_ssn": "US Social Security number",
          "saudi_id": "Saudi national ID / Iqama number", "uk_nino": "UK National Insurance number", "phone": "Phone number",
          "ip_address": "Public IP address", "date_of_birth": "Date of birth", "passport": "Passport number"}
SEVERITY = {"payment_card": "high", "us_ssn": "high", "saudi_id": "high", "uk_nino": "high", "passport": "high", "iban": "medium",
            "date_of_birth": "medium", "email": "low", "phone": "low", "ip_address": "info"}
DOCUMENTATION_DOMAINS = ("example.com", "example.org", "example.net", "example.test", "test", "localhost", "invalid")


def luhn(digits: str) -> bool:
    total = 0
    for index, char in enumerate(reversed(digits)):
        value = int(char)
        if index % 2:
            value = value * 2 - 9 if value > 4 else value * 2
        total += value
    return total % 10 == 0


def iban_valid(value: str) -> bool:
    compact = value.replace(" ", "")
    expected = IBAN_LENGTHS.get(compact[:2])
    if expected and len(compact) != expected:
        return False
    rearranged = compact[4:] + compact[:4]
    try:
        number = int("".join(str(int(ch, 36)) for ch in rearranged))
    except ValueError:
        return False
    return number % 97 == 1


def _mask(kind: str, value: str) -> str:
    if kind == "email":
        user, _, domain = value.partition("@")
        return f"{user[:1]}***@{domain}"
    digits = re.sub(r"\D", "", value)
    if kind in ("payment_card", "iban", "saudi_id", "us_ssn", "phone"):
        return f"…{value.replace(' ', '')[-4:]} ({len(digits) if kind != 'iban' else len(value.replace(' ', ''))} chars)"
    if kind == "ip_address":
        return ".".join(value.split(".")[:2]) + ".x.x"
    return value[:1] + "…" + value[-1:] if len(value) > 2 else "**"


def find(text: str, *, kinds: set[str] | None = None, max_items: int = 1000) -> list[dict[str, Any]]:
    """[{kind, label, severity, line, masked}] for each validated personal-data item (unique by kind+value)."""
    found: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: str, value: str, offset: int) -> None:
        if (kinds and kind not in kinds) or (kind, value) in seen or len(found) >= max_items:
            return
        seen.add((kind, value))
        found.append({"kind": kind, "label": LABELS[kind], "severity": SEVERITY[kind], "line": line_of(text, offset),
                      "masked": _mask(kind, value)})

    for m in EMAIL.finditer(text):
        domain = m.group(2).lower()
        if not domain.endswith(DOCUMENTATION_DOMAINS) and not re.search(r"\.(?:png|jpe?g|gif|svg|webp|css|js)$", domain):
            add("email", m.group(0), m.start())
    for m in CARD.finditer(text):
        digits = re.sub(r"[ -]", "", m.group(0))
        if 13 <= len(digits) <= 19 and len(set(digits)) >= 2 and luhn(digits) and re.match(r"^(?:4|5[1-5]|2[2-7]|3[47]|6(?:011|5))", digits):
            add("payment_card", digits, m.start())
    for m in IBAN.finditer(text):
        if iban_valid(m.group(1)):
            add("iban", m.group(1).replace(" ", ""), m.start())
    for m in SSN.finditer(text):
        area, group, serial = m.groups()
        if area not in ("000", "666") and not area.startswith("9") and group != "00" and serial != "0000":
            add("us_ssn", m.group(0), m.start())
    for m in SAUDI_ID.finditer(text):
        window = text[max(0, m.start() - 60):m.start()].lower()
        if luhn(m.group(1)) and re.search(r"(?:national|id|iqama|هوية|إقامة|اقامة|سجل)", window):
            add("saudi_id", m.group(1), m.start())
    for m in NINO.finditer(text):
        compact = m.group(1).replace(" ", "")
        if compact[:2] not in ("BG", "GB", "NK", "KN", "TN", "NT", "ZZ"):
            add("uk_nino", compact, m.start())
    for m in PHONE.finditer(text):
        digits = re.sub(r"\D", "", m.group(1))
        window = text[max(0, m.start() - 40):m.start()].lower()
        if 9 <= len(digits) <= 15 and (m.group(1).startswith(("+", "(")) or re.search(r"(?:phone|tel|mobile|cell|جوال|هاتف)", window)):
            add("phone", m.group(1), m.start())
    for m in IPV4.finditer(text):
        try:
            ip = ipaddress.ip_address(m.group(1))
        except ValueError:
            continue
        if ip.is_global:
            add("ip_address", m.group(1), m.start())
    for m in DOB.finditer(text):
        add("date_of_birth", m.group(1), m.start(1))
    for m in PASSPORT.finditer(text):
        add("passport", m.group(1), m.start(1))
    return found


def summarize(items: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        counts[item["kind"]] = counts.get(item["kind"], 0) + 1
    return counts
