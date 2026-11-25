"""Email analysis for the scan page: paste a whole raw email (headers and body) and get a phishing read.

What it does, all from the pasted text (nothing is fetched, no link is opened, no attachment is run):

* the identity headers: From (display name and address), Reply-To, Return-Path, To, Subject, Date,
  Message-ID;
* the delivery path: each ``Received`` hop (from, by, when), oldest first;
* the receiving server's authentication verdicts: SPF, DKIM and DMARC from ``Authentication-Results``
  and ``Received-SPF``, plus the domain a ``DKIM-Signature`` claims;
* every link in the body (text and HTML), with an HTML link whose visible text shows a different
  address than it really goes to;
* attachment names, declared types and sizes (risky types and double extensions are flagged);
* the phishing analysis itself reuses the engine's message analysis (``detection.messages``: language
  lures, header consistency, every link scored by ``detection.url_intel``) and adds the checks above.

The score fuses all indicators the same way the rest of CyberScan's message checks do (noisy-OR, each
indicator a weight from 0 to 100); the verdict follows the site's bands (0 none, 1-49 review,
50+ suspicious). It is evidence, not a probability.
"""
from __future__ import annotations

import re
from email import policy
from email.message import EmailMessage, Message
from email.parser import Parser
from email.utils import parseaddr, parsedate_to_datetime
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urlparse

from detection.common import Indicator, noisy_or
from detection.messages import analyze_message
from detection.url_intel import registrable_domain

MAX_RAW = 1_000_000            # characters of pasted email
MAX_LINKS = 40
MAX_HOPS = 15
RISKY_EXT = {
    "exe", "scr", "com", "pif", "bat", "cmd", "js", "jse", "vbs", "vbe", "wsf", "wsh", "hta", "ps1", "msi", "msix", "jar",
    "lnk", "iso", "img", "vhd", "vhdx", "cpl", "reg", "html", "htm", "svg", "one", "xll", "appx",
}
MACRO_EXT = {"docm", "xlsm", "pptm", "dotm", "xltm", "xlam", "ppam"}
ARCHIVE_EXT = {"zip", "rar", "7z", "gz", "tar", "cab", "ace"}
_HEADER_LINE = re.compile(r"(?im)^(?:from|to|subject|received|return-path|reply-to|message-id|authentication-results|date|dkim-signature):")
_URL = re.compile(r"https?://[^\s<>\"')\]]{3,2000}", re.IGNORECASE)


class EmailError(ValueError):
    """The pasted text can't be analysed as an email (shown to the visitor)."""


def looks_like_email(text: str) -> bool:
    return len(_HEADER_LINE.findall(text[:20000])) >= 2


def _domain(address: str) -> str:
    address = (address or "").strip().lower()
    return registrable_domain(address.rsplit("@", 1)[1]) if "@" in address else ""


def _clip(value: Any, limit: int = 300) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    return text if len(text) <= limit else text[: limit - 1] + "…"


# ------------------------------------------------------------------ headers
def _received(msg: Message) -> list[dict[str, str]]:
    hops = []
    for value in (msg.get_all("Received") or [])[:MAX_HOPS * 2]:
        text = re.sub(r"\s+", " ", str(value))
        part, _, when = text.rpartition(";") if ";" in text else (text, "", "")
        source = re.search(r"\bfrom\s+(\S+)(?:\s+\(([^)]*)\))?", part, re.IGNORECASE)
        by = re.search(r"\bby\s+(\S+)", part, re.IGNORECASE)
        ip = re.search(r"\[(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f:]{3,})\]", part, re.IGNORECASE)
        stamp = ""
        try:
            stamp = parsedate_to_datetime(when.strip()).isoformat() if when.strip() else ""
        except (TypeError, ValueError, IndexError):
            stamp = _clip(when, 60)
        hops.append({"from": _clip(source.group(1) if source else "", 120), "by": _clip(by.group(1) if by else "", 120),
                     "ip": ip.group(1) if ip else "", "when": stamp})
    hops.reverse()                     # the first Received header is the last hop: show the path in order
    return hops[:MAX_HOPS]


def _auth(msg: Message) -> dict[str, dict[str, str]]:
    results = " ; ".join(str(v) for v in (msg.get_all("Authentication-Results") or [])).lower()
    out: dict[str, dict[str, str]] = {}
    for mech in ("spf", "dkim", "dmarc"):
        match = re.search(rf"\b{mech}\s*=\s*([a-z]+)", results)
        detail = ""
        if match:
            tail = results[match.end(): match.end() + 160]
            detail_match = re.search(r"(?:header\.(?:from|d|i)|smtp\.(?:mailfrom|helo))\s*=\s*([^\s;]+)", tail)
            detail = detail_match.group(1) if detail_match else ""
        out[mech] = {"result": match.group(1) if match else "none", "detail": _clip(detail, 120)}
    received_spf = " ".join(str(v) for v in (msg.get_all("Received-SPF") or [])).strip().lower()
    if received_spf and out["spf"]["result"] == "none":
        out["spf"] = {"result": received_spf.split()[0].strip(";:"), "detail": ""}
    signature = " ".join(str(v) for v in (msg.get_all("DKIM-Signature") or []))
    d = re.search(r"\bd\s*=\s*([^;\s]+)", signature)
    out["dkim"]["signed_by"] = d.group(1).lower() if d else ""
    return out


# ------------------------------------------------------------------ body: links and attachments
class _Anchors(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str]] = []
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "a":
            self._href = dict(attrs).get("href") or ""
            self._text = []

    def handle_data(self, data: str) -> None:
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "a" and self._href is not None:
            self.links.append((self._href.strip(), " ".join("".join(self._text).split())))
            self._href = None


def _parts(msg: Message) -> tuple[list[str], list[str], list[dict[str, Any]]]:
    texts, htmls, attachments = [], [], []
    for part in (msg.walk() if msg.is_multipart() else [msg]):
        if part.is_multipart():
            continue
        name = part.get_filename()
        disposition = str(part.get("Content-Disposition", "")).lower()
        ctype = part.get_content_type()
        if name or disposition.startswith("attachment"):
            try:
                payload = part.get_payload(decode=True) or b""
            except Exception:  # noqa: BLE001 - a broken part is listed, not raised
                payload = b""
            attachments.append({"name": _clip(name or "(unnamed)", 200), "type": ctype, "size": len(payload)})
            continue
        if ctype not in ("text/plain", "text/html"):
            continue
        try:
            payload = part.get_payload(decode=True)
            charset = part.get_content_charset() or "utf-8"
            body = payload.decode(charset, "replace") if isinstance(payload, bytes) else str(part.get_payload())
        except (LookupError, AssertionError):
            body = str(part.get_payload())
        (htmls if ctype == "text/html" else texts).append(body[:500_000])
    return texts, htmls, attachments


def _links(texts: list[str], htmls: list[str]) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    seen: dict[str, dict[str, str]] = {}
    mismatched = []
    for html in htmls:
        parser = _Anchors()
        try:
            parser.feed(html)
        except Exception:  # noqa: BLE001
            pass
        for href, text in parser.links:
            if not href.lower().startswith(("http://", "https://")):
                continue
            seen.setdefault(href, {"url": href[:500], "text": _clip(text, 120)})
            shown = _URL.search(text) or re.search(r"\b(?:www\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)+\.[a-z]{2,}\b", text, re.IGNORECASE)
            if shown:
                shown_host = urlparse(shown.group(0) if "://" in shown.group(0) else "http://" + shown.group(0)).hostname or ""
                real_host = urlparse(href).hostname or ""
                if shown_host and real_host and registrable_domain(shown_host) != registrable_domain(real_host):
                    mismatched.append({"shown": _clip(shown_host, 120), "real": _clip(real_host, 120)})
        for url in _URL.findall(re.sub(r"<[^>]+>", " ", html)):
            seen.setdefault(url.rstrip(".,;:"), {"url": url.rstrip(".,;:")[:500], "text": ""})
    for text in texts:
        for url in _URL.findall(text):
            seen.setdefault(url.rstrip(".,;:"), {"url": url.rstrip(".,;:")[:500], "text": ""})
    return list(seen.values())[:MAX_LINKS], mismatched[:10]


def _attachment_risk(name: str) -> tuple[str, int, str] | None:
    lower = name.lower().strip()
    parts = lower.rsplit(".", 2)
    ext = parts[-1] if len(parts) > 1 else ""
    if len(parts) == 3 and ext in RISKY_EXT and len(parts[-2]) <= 5 and parts[-2].isalnum():
        return "high", 50, f"'{name}' hides a .{ext} file behind a second extension (.{parts[-2]})."
    if ext in RISKY_EXT:
        return "high", 40, f"'{name}' is a type that can run code or open a page when opened (.{ext})."
    if ext in MACRO_EXT:
        return "medium", 30, f"'{name}' is an Office file that can contain macros (.{ext})."
    if ext in ARCHIVE_EXT:
        return "low", 10, f"'{name}' is an archive; what's inside wasn't checked here. Scan it as a file."
    return None


# ------------------------------------------------------------------ entry point
def _band(score: int) -> str:
    return "SUSPICIOUS" if score >= 50 else "REVIEW" if score > 0 else "NO_INDICATORS_OBSERVED"


def analyze(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, str) or not raw.strip():
        raise EmailError("Paste a whole email first, with its headers.")
    if len(raw) > MAX_RAW:
        raise EmailError("This email is too long to analyse here (1 MB of text at most).")
    text = raw.replace("\r\n", "\n").lstrip()
    if not looks_like_email(text):
        raise EmailError("This doesn't look like a raw email: include the headers (From:, To:, Subject:, Received: …). "
                         "In most mail apps: “Show original” or “View source”.")
    msg: Message = Parser(policy=policy.compat32).parsestr(text)

    display, address = parseaddr(str(msg.get("From", "")))
    _, reply = parseaddr(str(msg.get("Reply-To", "")))
    _, return_path = parseaddr(str(msg.get("Return-Path", "")))
    headers = {
        "from": _clip(address, 200), "display_name": _clip(display, 200), "from_domain": _domain(address),
        "reply_to": _clip(reply, 200), "return_path": _clip(return_path, 200), "to": _clip(msg.get("To", ""), 200),
        "subject": _clip(msg.get("Subject", ""), 300), "date": _clip(msg.get("Date", ""), 80), "message_id": _clip(msg.get("Message-ID", ""), 200),
    }
    hops = _received(msg)
    auth = _auth(msg)
    texts, htmls, attachments = _parts(msg)
    links, mismatched = _links(texts, htmls)

    # the engine's own message analysis: headers, language lures, every link scored
    body = "\n".join(texts) or re.sub(r"<[^>]+>", " ", "\n".join(htmls))
    header_block = text.split("\n\n", 1)[0]
    engine = analyze_message(header_block + "\n\n" + body + "\n" + "\n".join(item["url"] for item in links))
    indicators: list[Indicator] = list(engine["indicators"])

    def add(category: str, severity: str, label: str, weight: int, explanation: str) -> None:
        if not any(item.label == label for item in indicators):
            indicators.append(Indicator(category, severity, label, explanation, weight, {}))

    for item in mismatched[:1]:
        add("phishing", "high", "Link text shows a different address", 45,
            f"A link shows '{item['shown']}' but really goes to '{item['real']}'.")
    risky = [(a, r) for a in attachments for r in [_attachment_risk(a["name"])] if r]
    risky.sort(key=lambda pair: -pair[1][1])
    if risky:
        attachment, (severity, weight, why) = risky[0]
        add("attachment", severity, "Risky attachment", weight, why)
    if all(auth[m]["result"] == "none" for m in ("spf", "dkim", "dmarc")):
        add("email_headers", "info", "No authentication results", 0,
            "The pasted headers carry no SPF, DKIM or DMARC verdicts, so the sender can't be checked. "
            "Paste the full original from your mail app.")
    elif auth["dmarc"]["result"] == "pass" and auth["spf"]["result"] in ("pass", "none") and auth["dkim"]["result"] in ("pass", "none"):
        add("email_headers", "info", "Sender authentication passed", 0,
            "The receiving server checked the sender's domain (SPF/DKIM/DMARC) and it passed. That proves the domain, "
            "not that the message is honest.")
    signed_by = auth["dkim"].get("signed_by", "")
    if signed_by and headers["from_domain"] and registrable_domain(signed_by) != headers["from_domain"] and auth["dkim"]["result"] != "fail":
        add("email_headers", "low", "Signed by a different domain", 5,
            f"The DKIM signature is from '{signed_by}', not the sender's domain '{headers['from_domain']}' (normal for mailing services).")

    scoring = [i for i in indicators if i.contribution > 0]
    score = int(round(noisy_or(i.contribution for i in scoring))) if scoring else 0
    score = max(0, min(100, score))
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings = sorted(({"label": i.label, "severity": i.severity, "category": i.category, "weight": int(i.contribution),
                        "explanation": _clip(i.explanation, 400)} for i in indicators),
                      key=lambda f: (-f["weight"], rank.get(f["severity"], 5)))
    link_scores = {item["url"]: item for item in engine.get("links", [])}
    for link in links:
        scored = link_scores.get(link["url"]) or {}
        link["score"] = int(scored.get("score") or 0)
        link["domain"] = scored.get("registrable_domain") or registrable_domain(urlparse(link["url"]).hostname or "")
        link["flags"] = [_clip(x, 80) for x in (scored.get("findings") or [])[:3]]
    for attachment in attachments:
        risk = _attachment_risk(attachment["name"])
        attachment["risk"] = risk[0] if risk else "none"
    return {
        "score": score, "classification": _band(score), "evidence_agreement": engine.get("evidence_agreement", "none"),
        "headers": headers, "received": hops, "auth": auth, "links": links, "link_text_mismatch": mismatched,
        "attachments": attachments[:30], "findings": findings[:30],
        "note": "Static analysis of the pasted text: no link was opened and no attachment was run. The score is weighted evidence, not a probability.",
    }
