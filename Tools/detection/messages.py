"""Email and SMS fraud analysis.

Combines three independent views of a message:
  * social-engineering language (urgency, credential/OTP requests, payment pressure, lures),
  * every link in the message, scored by ``detection.url_intel``,
  * email header consistency (display-name spoofing, Reply-To mismatch, SPF/DKIM/DMARC results)
    when raw headers are present.

The language patterns are English plus a small set of common Arabic phrases (the UI ships in both).
"""
from __future__ import annotations

import re
from email import policy
from email.parser import HeaderParser
from email.utils import getaddresses, parseaddr
from typing import Any

from detection.common import MAX_URLS_PER_INPUT, Indicator, fuse, heuristic_dicts
from detection.url_intel import BRANDS, OFFICIAL_DOMAINS, analyze_url_intel, extract_urls, registrable_domain

CATEGORY = "social_engineering"

# (label, severity, contribution, explanation, patterns)
_LANGUAGE_RULES: list[tuple[str, str, int, str, list[str]]] = [
    ("Urgency or threat language", "low", 15,
     "The message pressures the reader to act quickly or threatens loss of access.",
     [r"\burgent(?:ly)?\b", r"\bimmediate(?:ly)?\b", r"\bwithin (?:24|48|12) ?(?:hours|hrs|h)\b", r"\bfinal (?:notice|warning|reminder)\b",
      r"\b(?:account|card|access|service)s? (?:(?:has|have|will) been |is |are |will be )?(?:suspended|locked|blocked|disabled|closed|restricted|deactivated|terminated)\b",
      r"\bunusual (?:sign[- ]?in )?activity\b", r"\bact now\b", r"\bexpires? (?:today|soon|in \d+)", r"\blast chance\b",
      r"عاجل", r"فورا|فوراً", r"تم (?:إيقاف|تعليق|حظر|تجميد) (?:حسابك|بطاقتك)", r"خلال 24 ساعة"]),
    ("Credential or verification request", "medium", 30,
     "The message asks the reader to verify an account or enter credentials, a core phishing behaviour.",
     [r"\b(?:verify|confirm|validate|update|re-?activate|unlock|restore) (?:your |the )?(?:account|identity|password|login|details|information|payment (?:details|method)|billing)\b",
      r"\b(?:enter|provide|submit|re-?enter|type) (?:your |the )?(?:password|pin|passcode|login|credentials|card (?:number|details)|cvv|ssn|social security)\b",
      r"\blog ?in (?:to|at) (?:verify|confirm|avoid|restore)\b", r"\bsign[- ]?in to (?:verify|confirm|avoid|restore)\b",
      r"تحديث (?:بيانات|معلومات) (?:حسابك|بطاقتك)", r"تأكيد (?:حسابك|هويتك|بياناتك)", r"أدخل (?:كلمة المرور|رمز)"]),
    ("Request to share a one-time code", "high", 45,
     "The message asks the reader to send or share a one-time code. Legitimate services never ask for this.",
     [r"\b(?:send|share|forward|reply with|tell us|give us|read (?:out|back)) (?:me |us )?(?:the |your |this )?(?:\d-digit )?(?:otp|one[- ]time (?:password|code|pin)|verification code|security code|auth(?:entication)? code|code (?:you|we) (?:just )?(?:received|sent))\b",
      r"(?:أرسل|ارسل|شارك)(?:\s+\S+){0,2}\s+(?:رمز التحقق|الرمز|كود التفعيل)"]),
    ("Payment or gift-card pressure", "medium", 25,
     "The message requests payment through channels favoured by fraudsters (gift cards, crypto, wire, small 'fees').",
     [r"\bgift ?cards?\b", r"\b(?:itunes|google play|steam|amazon) (?:gift )?cards?\b", r"\b(?:bitcoin|btc|usdt|crypto(?:currency)?) (?:wallet|address|payment)\b",
      r"\bwire transfer\b", r"\bwestern union\b", r"\bmoneygram\b", r"\b(?:pay|settle) (?:a |the )?(?:small |customs |delivery |processing |release )?fee\b",
      r"\bunpaid (?:toll|invoice|bill|balance|fee)\b", r"\boutstanding (?:balance|payment|toll)\b", r"\brefund (?:is )?(?:pending|available|waiting)\b",
      r"رسوم (?:التوصيل|الجمارك|الشحن)", r"بطاقة (?:هدايا|ايتونز)"]),
    ("Prize, lottery or inheritance lure", "medium", 25,
     "Unexpected winnings or inheritance are classic advance-fee fraud lures.",
     [r"\byou(?:'ve| have)? (?:won|been selected)\b", r"\bcongratulations[,!]? you\b", r"\bclaim (?:your|the) (?:prize|reward|winnings|gift|refund)\b",
      r"\blottery\b", r"\binheritance\b", r"\bbeneficiary\b.*\bfund", r"\bunclaimed (?:funds|prize|package)\b",
      r"(?:ربحت|فزت) ب", r"مبروك.{0,20}(?:فزت|ربحت)", r"(?:استلام|استلم) (?:جائزتك|الجائزة)"]),
    ("Parcel delivery lure", "medium", 20,
     "Fake delivery-failure notices are one of the most common SMS scams.",
     [r"\b(?:package|parcel|shipment|delivery)\b.{0,60}\b(?:on hold|held|could not be delivered|undeliverable|failed|pending|suspended|rescheduled?|redeliver(?:y)?|address (?:is )?incomplete)\b",
      r"\bredeliver(?:y)?\b", r"(?:شحنتك|طردك).{0,40}(?:معلق|لم يتم|فشل)"]),
    ("Authority impersonation", "low", 10,
     "The message invokes a tax office, police, court or government agency.",
     [r"\b(?:irs|hmrc|tax (?:office|authority|refund)|police|court|customs|ministry of|government) \b", r"\barrest warrant\b", r"\blegal action\b"]),
]
_COMPILED_RULES = [(label, severity, weight, explanation, [re.compile(p, re.IGNORECASE) for p in patterns])
                   for label, severity, weight, explanation, patterns in _LANGUAGE_RULES]

# Phrases that appear in *legitimate* OTP notifications and should neutralise the OTP-sharing rule.
_SAFE_OTP_PHRASES = re.compile(
    r"(?i)\b(?:do not|don't|never) (?:share|give|send|tell)\b|لا (?:تشارك|تعطي|ترسل)")

_HEADER_HINT = re.compile(r"(?im)^(?:from|to|subject|received|return-path|reply-to|message-id|authentication-results):")


def _looks_like_email(text: str) -> bool:
    return len(_HEADER_HINT.findall(text[:20000])) >= 2


def _domain_of(address: str) -> str:
    address = (address or "").strip().lower()
    return registrable_domain(address.rsplit("@", 1)[1]) if "@" in address else ""


def _header_checks(raw: str, add) -> dict[str, Any]:
    header_block = raw.split("\n\n", 1)[0] if "\n\n" in raw else raw.split("\r\n\r\n", 1)[0]
    try:
        headers = HeaderParser(policy=policy.compat32).parsestr(header_block[:100000], headersonly=True)
    except Exception:  # malformed headers are reported, not raised
        add("low", "Malformed email headers", 5, "The email headers could not be parsed cleanly.")
        return {}

    display_name, from_address = parseaddr(str(headers.get("From", "")))
    from_domain = _domain_of(from_address)
    summary: dict[str, Any] = {"from": from_address, "from_domain": from_domain, "display_name": display_name}

    lowered_name = display_name.lower()
    squashed_name = re.sub(r"[\s._-]+", "", lowered_name)
    claimed = [brand for brand in BRANDS
               if re.search(rf"\b{re.escape(brand)}\b", lowered_name) or (len(brand) >= 5 and brand in squashed_name)]
    if claimed and from_domain and from_domain not in OFFICIAL_DOMAINS:
        add("high", "Sender display name impersonates a brand", 45,
            f"The display name '{display_name}' claims to be {claimed[0]}, but the address is at '{from_domain}'.")
    if "@" in display_name:
        shown_domain = _domain_of(display_name.strip("\"' <>"))
        if shown_domain and from_domain and shown_domain != from_domain:
            add("high", "Display name shows a different email address", 40,
                f"The display name shows an address at '{shown_domain}', but the message is from '{from_domain}'.")

    reply_domains = {_domain_of(addr) for _, addr in getaddresses([str(headers.get("Reply-To", ""))]) if addr}
    reply_domains.discard("")
    if from_domain and reply_domains and from_domain not in reply_domains:
        add("medium", "Reply-To differs from sender", 20,
            f"Replies would go to {', '.join(sorted(reply_domains))} instead of the sender's domain '{from_domain}'.")
    _, return_path = parseaddr(str(headers.get("Return-Path", "")))
    return_domain = _domain_of(return_path)
    if from_domain and return_domain and return_domain != from_domain:
        add("low", "Envelope sender differs from From", 5,
            f"The bounce address is at '{return_domain}' (common for mailing services; weak signal on its own).")

    auth_results = " ".join(str(value) for value in headers.get_all("Authentication-Results", []) or []).lower()
    received_spf = " ".join(str(value) for value in headers.get_all("Received-SPF", []) or []).lower()
    failures = {mech for mech in ("spf", "dkim", "dmarc")
                if re.search(rf"\b{mech}\s*=\s*(?:fail|softfail|permerror)\b", auth_results)}
    if re.match(r"\s*(?:fail|softfail)\b", received_spf):
        failures.add("spf")
    failures = sorted(failures)
    if failures:
        weight = 40 if "dmarc" in failures else 25
        add("high" if weight >= 40 else "medium", "Email authentication failed", weight,
            f"The receiving server recorded {', '.join(f.upper() for f in failures)} failure; the sender address may be forged.")
    summary["authentication_failures"] = failures
    return summary


def analyze_message(text: str, *, max_urls: int = MAX_URLS_PER_INPUT) -> dict[str, Any]:
    content = (text or "")[:200_000]
    indicators: list[Indicator] = []

    def add(severity: str, label: str, contribution: int, explanation: str, category: str = CATEGORY, **data: Any) -> None:
        if any(item.label == label for item in indicators):
            return
        indicators.append(Indicator(category, severity, label, explanation, contribution, data))

    email_headers: dict[str, Any] = {}
    if _looks_like_email(content):
        email_headers = _header_checks(content, lambda *a, **k: add(*a, category="email_headers", **k))

    otp_safe = bool(_SAFE_OTP_PHRASES.search(content))
    for label, severity, weight, explanation, patterns in _COMPILED_RULES:
        if label == "Request to share a one-time code" and otp_safe:
            continue
        hits = [match.group(0) for pattern in patterns for match in [pattern.search(content)] if match]
        if hits:
            add(severity, label, weight, explanation, matched=hits[:3])

    links: list[dict[str, Any]] = []
    for url in extract_urls(content, limit=max_urls):
        analysis = analyze_url_intel(url)
        links.append({
            "url": url[:500], "score": analysis["score"], "classification": analysis["classification"],
            "registrable_domain": analysis.get("registrable_domain"),
            "findings": [item["label"] for item in analysis["findings"]],
        })
    worst = max(links, key=lambda item: item["score"], default=None)
    if worst and worst["score"] > 0:
        add("high" if worst["score"] >= 50 else "medium" if worst["score"] >= 25 else "low",
            "Suspicious link in message", min(70, worst["score"]),
            f"The link to '{worst['registrable_domain'] or worst['url'][:80]}' scored {worst['score']}/100 "
            f"({'; '.join(worst['findings'][:3])}).", category="phishing", url=worst["url"])

    # Lures that also carry a link are the actionable form of the scam.
    lure_labels = {"Credential or verification request", "Payment or gift-card pressure",
                   "Prize, lottery or inheritance lure", "Parcel delivery lure"}
    if links and any(item.label in lure_labels for item in indicators) and any(item.label == "Urgency or threat language" for item in indicators):
        add("medium", "Urgent call to action with link", 20,
            "Urgency, a lure and a link appear together: the typical structure of a phishing message.")

    fused = fuse(indicators)
    return {
        **fused,
        "is_email": bool(email_headers),
        "email_headers": email_headers,
        "links": links,
        "indicators": indicators,
        "findings": heuristic_dicts(indicators),
    }
