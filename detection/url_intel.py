"""Offline URL and phishing intelligence.

Everything here is computed from the URL string alone: no DNS, no HTTP, no reputation
feeds. That keeps analysis private and deterministic, and it also bounds what can be
claimed: a clean result means "no static red flags", not "the site is safe".

Registrable-domain extraction uses a small built-in list of multi-label public suffixes
instead of the full Public Suffix List, so it is an approximation for rare suffixes.
"""
from __future__ import annotations

import ipaddress
import re
import unicodedata
from typing import Any
from urllib.parse import parse_qsl, unquote, urlsplit

from detection.common import MAX_URL_LENGTH, Indicator, fuse, heuristic_dicts

CATEGORY = "phishing"

# Multi-label public suffixes common enough to matter. Anything else is treated as a single label.
MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "co.kr", "or.kr", "co.in", "net.in", "org.in", "gov.in",
    "com.br", "net.br", "org.br", "gov.br", "com.mx", "com.ar", "com.co", "com.pe", "com.ve",
    "co.nz", "org.nz", "co.za", "org.za", "com.sg", "com.my", "com.hk", "com.tw", "com.cn", "net.cn",
    "org.cn", "com.tr", "gov.tr", "com.sa", "gov.sa", "com.eg", "com.pk", "com.ng", "co.id",
    "com.ph", "com.vn", "co.th", "co.il", "com.ua", "com.pl", "co.ke", "com.qa", "com.kw",
    "com.bh", "com.om", "co.ae", "gov.ae", "ac.ae",
}

# Brand -> official registrable domains. A brand name inside any *other* registrable domain is
# what impersonation looks like. Keep entries to widely phished brands with distinctive names.
BRANDS: dict[str, set[str]] = {
    "paypal": {"paypal.com", "paypal.me", "paypalobjects.com"},
    "apple": {"apple.com", "icloud.com", "apple.news", "cdn-apple.com"},
    "icloud": {"icloud.com", "apple.com"},
    "microsoft": {"microsoft.com", "microsoftonline.com", "live.com", "office.com", "office365.com",
                  "outlook.com", "windows.net", "azure.com", "sharepoint.com", "msn.com", "bing.com",
                  "msauth.net", "msftauth.net", "microsoft365.com"},
    "office365": {"office365.com", "office.com", "microsoft.com"},
    "outlook": {"outlook.com", "live.com", "office.com", "microsoft.com"},
    "onedrive": {"onedrive.com", "live.com", "microsoft.com", "sharepoint.com"},
    "sharepoint": {"sharepoint.com", "microsoft.com"},
    "google": {"google.com", "googleapis.com", "gstatic.com", "googleusercontent.com", "youtube.com",
               "gmail.com", "goo.gl", "g.co", "withgoogle.com", "google.dev", "blogspot.com"},
    "gmail": {"gmail.com", "google.com"},
    "amazon": {"amazon.com", "amazonaws.com", "amazon.co.uk", "amazon.de", "amazon.fr", "amazon.it",
               "amazon.es", "amazon.ca", "amazon.co.jp", "amazon.in", "amazon.com.au", "amazon.ae",
               "amazon.sa", "amazon.eg", "amazon.com.br", "amazon.com.mx", "amazon.nl", "amazon.se",
               "amazon.pl", "amazon.com.tr", "amazon.sg", "a2z.com", "media-amazon.com", "aws.amazon.com"},
    "netflix": {"netflix.com", "nflxext.com", "nflximg.net", "nflxvideo.net"},
    "facebook": {"facebook.com", "fb.com", "fbcdn.net", "facebook.net", "meta.com"},
    "instagram": {"instagram.com", "cdninstagram.com"},
    "whatsapp": {"whatsapp.com", "whatsapp.net", "wa.me"},
    "linkedin": {"linkedin.com", "licdn.com", "lnkd.in"},
    "twitter": {"twitter.com", "x.com", "t.co", "twimg.com"},
    "dropbox": {"dropbox.com", "dropboxusercontent.com", "db.tt"},
    "docusign": {"docusign.com", "docusign.net"},
    "adobe": {"adobe.com", "adobelogin.com", "acrobat.com", "typekit.net"},
    "steam": {"steampowered.com", "steamcommunity.com", "steamstatic.com"},
    "steampowered": {"steampowered.com"},
    "steamcommunity": {"steamcommunity.com"},
    "binance": {"binance.com", "binance.us", "bnbstatic.com"},
    "coinbase": {"coinbase.com"},
    "metamask": {"metamask.io"},
    "chase": {"chase.com", "jpmorganchase.com"},
    "wellsfargo": {"wellsfargo.com"},
    "bankofamerica": {"bankofamerica.com", "bofa.com"},
    "hsbc": {"hsbc.com", "hsbc.co.uk", "hsbc.com.hk", "hsbc.ae"},
    "barclays": {"barclays.co.uk", "barclays.com"},
    "dhl": {"dhl.com", "dhl.de", "dhl.co.uk"},
    "fedex": {"fedex.com"},
    "usps": {"usps.com"},
    "aramex": {"aramex.com"},
    "ebay": {"ebay.com", "ebay.co.uk", "ebay.de", "ebaystatic.com"},
    "walmart": {"walmart.com"},
    "spotify": {"spotify.com", "scdn.co"},
    "telegram": {"telegram.org", "t.me", "telegram.me"},
    "discord": {"discord.com", "discord.gg", "discordapp.com", "discordapp.net"},
    "roblox": {"roblox.com", "rbxcdn.com"},
    "github": {"github.com", "githubusercontent.com", "github.io", "githubassets.com"},
    "yahoo": {"yahoo.com", "yimg.com"},
    "stcpay": {"stcpay.com.sa"},
    "alrajhi": {"alrajhibank.com.sa"},
    "emiratesnbd": {"emiratesnbd.com"},
}

# Short brand names collide with ordinary words and are only matched as whole tokens.
SHORT_BRAND_MIN_LENGTH = 5

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "rb.gy", "cutt.ly", "goo.gl", "ow.ly", "buff.ly",
    "shorturl.at", "tiny.cc", "s.id", "v.gd", "t.ly", "rebrand.ly", "bl.ink", "short.io", "lnkd.in",
    "qrco.de", "u.to", "clck.ru", "shorturl.asia",
}

# TLDs that are disproportionately represented in abuse reports. Weak signal on its own.
ABUSED_TLDS = {
    "zip", "mov", "top", "xyz", "tk", "ml", "ga", "cf", "gq", "work", "click", "link", "country",
    "kim", "rest", "cam", "icu", "buzz", "surf", "monster", "sbs", "cfd", "quest", "support",
    "lol", "cyou", "bond", "shop", "online", "site", "live", "info",
}

# Free hosting / tunnelling platforms commonly used to stand up phishing pages quickly.
FREE_HOSTING_SUFFIXES = (
    "pages.dev", "workers.dev", "web.app", "firebaseapp.com", "glitch.me", "ngrok-free.app", "ngrok.io",
    "ngrok.app", "trycloudflare.com", "000webhostapp.com", "weebly.com", "wixsite.com", "netlify.app",
    "vercel.app", "herokuapp.com", "repl.co", "replit.dev", "github.io", "blogspot.com", "sites.google.com",
    "ipfs.io", "dweb.link", "r2.dev", "onrender.com", "surge.sh", "webflow.io", "framer.app",
)

DANGEROUS_DOWNLOAD_EXTENSIONS = {
    ".exe", ".scr", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".hta", ".wsf",
    ".lnk", ".jar", ".apk", ".iso", ".img", ".vhd", ".vhdx", ".dll", ".cpl", ".msix", ".appx", ".reg",
}
ARCHIVE_DOWNLOAD_EXTENSIONS = {".zip", ".rar", ".7z", ".tar", ".gz", ".cab", ".ace"}

REDIRECT_PARAMETERS = {
    "url", "u", "redirect", "redirect_uri", "redirect_url", "redirecturl", "next", "goto", "go", "dest",
    "destination", "return", "returnurl", "return_to", "continue", "target", "rurl", "out", "link", "to",
    "r", "q", "uri", "forward", "jump",
}

CREDENTIAL_KEYWORDS = (
    "login", "log-in", "signin", "sign-in", "logon", "verify", "verification", "account", "update",
    "secure", "security", "wallet", "banking", "password", "passwd", "webscr", "confirm", "unlock",
    "suspended", "billing", "invoice", "authenticate", "auth", "recover", "2fa", "otp", "kyc", "seed",
)

BRAND_KEYWORD_SUFFIXES = (
    "login", "signin", "secure", "verify", "account", "accounts", "support", "update", "id", "service",
    "services", "help", "online", "auth", "billing", "pay", "payment", "wallet", "team", "security",
    "alert", "alerts", "center", "centre", "web", "app", "mail", "portal", "customer", "care",
)

# Homoglyphs that render (nearly) identically to Latin letters, plus common digit swaps.
CONFUSABLES = {
    # Cyrillic
    "а": "a", "в": "b", "с": "c", "ԁ": "d", "е": "e", "һ": "h", "і": "i", "ј": "j", "к": "k",
    "ӏ": "l", "м": "m", "о": "o", "р": "p", "ԛ": "q", "г": "r", "ѕ": "s", "т": "t", "у": "y",
    "х": "x", "ԝ": "w", "ь": "b", "ո": "n", "ս": "u",
    # Greek
    "α": "a", "β": "b", "ε": "e", "η": "n", "ι": "i", "κ": "k", "ν": "v", "ο": "o", "ρ": "p",
    "τ": "t", "υ": "u", "χ": "x", "γ": "y", "ω": "w",
    # Latin look-alikes
    "ı": "i", "ɡ": "g", "ɑ": "a", "ǀ": "l", "ł": "l", "ø": "o", "đ": "d", "ħ": "h",
}
DIGIT_SWAPS = {"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g", "@": "a", "$": "s"}
SEQUENCE_SWAPS = (("rn", "m"), ("vv", "w"), ("cl", "d"), ("nn", "m"))

URL_IN_TEXT_RE = re.compile(
    r"""(?ix)
    \b(
        (?:https?|hxxps?|ftp)://[^\s<>"'`]+                          # explicit scheme (incl. defanged hxxp)
      | www\.[^\s<>"'`]+                                             # www. without scheme
      | (?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,24}|xn--[a-z0-9-]{2,59})
        /[^\s<>"'`]*                                                 # bare domain followed by a path
    )
    """
)


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def registrable_domain(host: str) -> str:
    labels = [label for label in host.strip(".").split(".") if label]
    if len(labels) <= 2:
        return ".".join(labels)
    if ".".join(labels[-2:]) in MULTI_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _public_suffix(domain: str) -> str:
    labels = domain.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_LABEL_SUFFIXES:
        return ".".join(labels[-2:])
    return labels[-1] if labels else ""


def _decode_idna(host: str) -> str:
    """Return the Unicode form of a punycode host; fall back to the input on malformed labels."""
    decoded_labels = []
    for label in host.split("."):
        if label.startswith("xn--"):
            try:
                decoded_labels.append(label[4:].encode("ascii").decode("punycode"))
                continue
            except (UnicodeError, ValueError):
                pass
        decoded_labels.append(label)
    return ".".join(decoded_labels)


def _scripts(text: str) -> set[str]:
    scripts: set[str] = set()
    for char in text:
        if char.isascii() or not char.isalpha():
            if char.isalpha():
                scripts.add("LATIN")
            continue
        name = unicodedata.name(char, "")
        scripts.add(name.split(" ")[0] if name else "UNKNOWN")
    return scripts


def skeleton(text: str) -> str:
    """Map a label to the ASCII string it visually imitates (confusables + digit swaps)."""
    normalized = unicodedata.normalize("NFKC", text.lower())
    mapped = "".join(CONFUSABLES.get(char, char) for char in normalized)
    mapped = "".join(DIGIT_SWAPS.get(char, char) for char in mapped)
    for sequence, replacement in SEQUENCE_SWAPS:
        mapped = mapped.replace(sequence, replacement)
    return mapped


def damerau_levenshtein(a: str, b: str, max_distance: int = 3) -> int:
    """Optimal-string-alignment distance with an early exit once ``max_distance`` is exceeded."""
    if abs(len(a) - len(b)) > max_distance:
        return max_distance + 1
    previous_previous: list[int] | None = None
    previous = list(range(len(b) + 1))
    for i, char_a in enumerate(a, start=1):
        current = [i] + [0] * len(b)
        for j, char_b in enumerate(b, start=1):
            cost = 0 if char_a == char_b else 1
            current[j] = min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + cost)
            if previous_previous is not None and i > 1 and j > 1 and char_a == b[j - 2] and a[i - 2] == char_b:
                current[j] = min(current[j], previous_previous[j - 2] + 1)
        if min(current) > max_distance:
            return max_distance + 1
        previous_previous, previous = previous, current
    return previous[-1]


def _parse_ip_host(host: str) -> ipaddress._BaseAddress | None:
    """Recognise dotted, IPv6, and obfuscated (decimal / hex / octal) IPv4 host forms."""
    candidate = host.strip("[]")
    try:
        return ipaddress.ip_address(candidate)
    except ValueError:
        pass
    # Integer forms: http://3232235777/ or http://0xC0A80001/
    try:
        if re.fullmatch(r"0x[0-9a-f]{1,8}", candidate):
            return ipaddress.IPv4Address(int(candidate, 16))
        if re.fullmatch(r"\d{8,10}", candidate) and int(candidate) <= 0xFFFFFFFF:
            return ipaddress.IPv4Address(int(candidate))
    except ValueError:
        return None
    # Dotted parts with hex/octal components: http://0x7f.0.0.1/ or http://0177.0.0.1/
    parts = candidate.split(".")
    if 2 <= len(parts) <= 4 and all(re.fullmatch(r"0x[0-9a-f]+|0[0-7]*|[1-9]\d*", part) for part in parts):
        try:
            values = [int(part, 16) if part.startswith("0x") else int(part, 8) if len(part) > 1 and part.startswith("0") else int(part) for part in parts]
            if all(value <= 255 for value in values[:-1]) and values[-1] < 256 ** (5 - len(values)):
                number = 0
                for value in values[:-1]:
                    number = number * 256 + value
                number = number * 256 ** (5 - len(values)) + values[-1]
                return ipaddress.IPv4Address(number)
        except ValueError:
            return None
    return None


def extract_urls(text: str, limit: int = 25) -> list[str]:
    """Pull URL-like strings out of free text, refanging ``hxxp`` and ``[.]`` notation."""
    refanged = (text or "").replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")
    found: list[str] = []
    for match in URL_IN_TEXT_RE.finditer(refanged):
        url = match.group(1).rstrip(".,;:!?)]}'\"")
        url = re.sub(r"^hxxp", "http", url, flags=re.IGNORECASE)
        if url not in found:
            found.append(url)
        if len(found) >= limit:
            break
    return found


# ---------------------------------------------------------------------------
# Brand impersonation
# ---------------------------------------------------------------------------

OFFICIAL_DOMAINS = frozenset(domain for officials in BRANDS.values() for domain in officials)
_PHISH_CONTEXT_WORDS = frozenset(BRAND_KEYWORD_SUFFIXES) | frozenset(CREDENTIAL_KEYWORDS)


def _collapse_repeats(text: str) -> str:
    return re.sub(r"(.)\1+", r"\1", text)


def _brand_checks(host: str, domain: str, add) -> str | None:
    """Return the impersonated brand, if any, after adding the relevant indicator.

    Checks run strongest-first. Plain edit distance is deliberately restricted (long
    brands, same first letter, medium severity) because short brand names sit one edit
    away from ordinary words (binance/finance, discord/discard).
    """
    if not domain or domain in OFFICIAL_DOMAINS:
        return None
    domain_label = domain.split(".")[0]
    subdomain_part = host[: -len(domain)].rstrip(".") if host.endswith(domain) else ""
    domain_tokens = [token for token in re.split(r"[-_.\d]+", domain_label) if token]
    label_skeleton = skeleton(domain_label)
    skeleton_tokens = [token for token in re.split(r"[-_.]+", label_skeleton) if token]
    has_context_word = any(token in _PHISH_CONTEXT_WORDS for token in domain_tokens)

    def report(severity: str, label: str, weight: int, explanation: str, brand: str) -> str:
        add(severity, label, weight, explanation, brand=brand)
        return brand

    for brand in BRANDS:
        # 1. Brand glued to a phishing keyword: paypalsecure.com, appleid-verify.com
        for word in BRAND_KEYWORD_SUFFIXES:
            if brand + word in domain_tokens or word + brand in domain_tokens:
                return report("high", "Brand impersonation in domain name", 55,
                              f"The domain '{domain}' joins the brand '{brand}' with '{word}'; it is not an official {brand} domain.", brand)
        # 2. Brand as a whole token: secure-paypal.net (strong) or apple-recipes.com (weak on its own).
        if brand in domain_tokens and domain_label != brand:
            if has_context_word:
                return report("high", "Brand impersonation in domain name", 55,
                              f"The domain '{domain}' combines the brand '{brand}' with account/security wording; "
                              f"it is not an official {brand} domain.", brand)
            return report("medium", "Brand name inside unrelated domain", 30,
                          f"The domain '{domain}' contains the brand '{brand}' but is not an official {brand} domain.", brand)
        # 3. Exact brand label on a TLD the brand does not use: paypal.top
        if domain_label == brand:
            suffix = _public_suffix(domain)
            if suffix in ABUSED_TLDS:
                return report("high", "Brand name on unusual TLD", 45,
                              f"'{domain}' uses the brand name '{brand}' on the .{suffix} TLD, which is not one of its official domains.", brand)
            continue  # brand.<ccTLD> is often a legitimate regional site; do not guess.
        # 4. Homoglyph / digit-swap skeleton equals the brand: paypa1.com, аpple.com, rnicrosoft.com
        if label_skeleton == brand or brand in skeleton_tokens:
            return report("high", "Lookalike (homoglyph) domain", 60,
                          f"'{domain}' visually imitates '{brand}' using look-alike characters.", brand)
        # 5. Doubled-letter typo: paypall.com, gooogle.com
        if len(brand) >= SHORT_BRAND_MIN_LENGTH:
            for candidate in {domain_label, *domain_tokens}:
                if candidate != brand and _collapse_repeats(candidate) == _collapse_repeats(brand):
                    return report("high", "Typosquatting domain", 50,
                                  f"'{domain}' repeats or drops a letter of the brand '{brand}'.", brand)
        # 6. Edit distance, long brands only. Weak alone; corroborated by keywords/TLD signals.
        if len(brand) >= 7:
            allowed = 2 if len(brand) >= 10 else 1
            for candidate in {domain_label, *domain_tokens}:
                if (candidate != brand and candidate[:1] == brand[:1]
                        and abs(len(candidate) - len(brand)) <= allowed
                        and damerau_levenshtein(candidate, brand, allowed) <= allowed):
                    return report("medium", "Possible typosquatting domain", 30,
                                  f"'{domain}' is within {allowed} character edit(s) of the brand '{brand}'.", brand)
        # 7. Brand in a subdomain of an unrelated registrable domain: paypal.com.account-check.xyz
        if subdomain_part:
            sub_tokens = [token for token in re.split(r"[-_.\d]+", subdomain_part) if token]
            if brand in sub_tokens or (len(brand) >= SHORT_BRAND_MIN_LENGTH and brand in skeleton(subdomain_part)):
                return report("high", "Brand name in subdomain of unrelated domain", 55,
                              f"The host '{host}' places '{brand}' in a subdomain, but the real registered domain is '{domain}'.", brand)
    return None


# ---------------------------------------------------------------------------
# Main analysis
# ---------------------------------------------------------------------------

def analyze_url_intel(url: str, *, _depth: int = 0) -> dict[str, Any]:
    raw = (url or "").strip()
    indicators: list[Indicator] = []

    def add(severity: str, label: str, contribution: int, explanation: str, **data: Any) -> None:
        if any(item.label == label for item in indicators):
            return
        indicators.append(Indicator(CATEGORY, severity, label, explanation, contribution, data))

    result: dict[str, Any] = {
        "url": raw[:2048],
        "scheme": None,
        "host": None,
        "unicode_host": None,
        "registrable_domain": None,
        "impersonated_brand": None,
        "embedded_urls": [],
    }

    if not raw:
        return _finish(result, indicators)
    # Refang defanged indicators shared by analysts: hxxp://evil[.]com
    raw = re.sub(r"^hxxp", "http", raw, flags=re.IGNORECASE).replace("[.]", ".").replace("[:]", ":")

    if len(raw) > MAX_URL_LENGTH:
        add("low", "Excessively long URL", 10, f"The URL is {len(raw):,} characters long; long URLs are used to hide the real destination.")
        raw = raw[:MAX_URL_LENGTH]
    elif len(raw) > 200:
        add("low", "Very long URL", 5, f"The URL is {len(raw)} characters long.")

    if re.search(r"[\x00-\x1f\x7f]", raw):
        add("medium", "Control characters in URL", 20, "The URL contains control characters, which can confuse parsers and users.")

    scheme_match = re.match(r"^([a-zA-Z][a-zA-Z0-9+.-]*):", raw)
    scheme = scheme_match.group(1).lower() if scheme_match else ""
    if scheme in {"javascript", "vbscript"}:
        add("high", "Script URL scheme", 60, f"The '{scheme}:' scheme runs code when the link is opened.")
        result["scheme"] = scheme
        return _finish(result, indicators)
    if scheme == "data":
        mime = raw[5:60].split(";")[0].split(",")[0].lower()
        severity, weight = ("high", 50) if "html" in mime or "script" in mime or "svg" in mime else ("medium", 25)
        add(severity, "Data URL", weight, f"The link embeds its own content ({mime or 'unknown type'}) instead of pointing to a site; "
            "data: URLs are used to render phishing pages without a hosting domain.")
        result["scheme"] = scheme
        return _finish(result, indicators)
    if scheme == "file":
        add("medium", "Local/UNC file link", 25, "file: links open local or network (SMB) paths and can leak credentials over SMB.")
    if not scheme or "//" not in raw[: len(scheme) + 3]:
        if scheme in {"mailto", "tel", "sms"}:
            result["scheme"] = scheme
            return _finish(result, indicators)
        raw = "http://" + raw.lstrip("/")
        scheme = "http"

    try:
        parts = urlsplit(raw)
        host = (parts.hostname or "").rstrip(".")
        port = parts.port
    except ValueError as exc:
        add("medium", "Malformed URL", 20, f"The URL could not be parsed ({exc}); malformed URLs are used to evade filters.")
        return _finish(result, indicators)

    result["scheme"] = parts.scheme.lower()
    if not host:
        add("low", "URL without host", 5, "The URL has no host component.")
        return _finish(result, indicators)

    if "%" in (parts.netloc or ""):
        host = unquote(host).lower()
        add("medium", "Percent-encoded host", 25, "The host name is percent-encoded, which hides the real destination from readers.")
    result["host"] = host

    # User-info trick: https://www.paypal.com@evil.example/
    if parts.username is not None or "@" in (parts.netloc or ""):
        userinfo = (parts.netloc or "").rsplit("@", 1)[0]
        userinfo_lower = userinfo.lower()
        names_brand = any(brand in userinfo_lower for brand in BRANDS) or any(d in userinfo_lower for d in OFFICIAL_DOMAINS)
        weight = 60 if names_brand else 40 if "." in userinfo else 15
        add("high" if weight >= 40 else "medium", "Embedded credential marker in URL", weight,
            f"Everything before '@' ('{userinfo[:60]}') is ignored by the browser; the real host is '{host}'.")

    if port is not None and port not in (80, 443, 8080, 8443):
        add("low", "Non-standard port", 10, f"The URL uses port {port}.")

    ip_value = _parse_ip_host(host)
    if ip_value is not None:
        canonical = str(ip_value)
        obfuscated = canonical != host.strip("[]")
        if obfuscated:
            add("high", "Obfuscated IP address host", 45,
                f"The host '{host}' is an encoded form of the IP address {canonical}; this is used to evade URL filters.")
        else:
            add("medium", "Direct IPv4 URL host" if ip_value.version == 4 else "Direct IPv6 URL host", 30,
                "The URL points at a raw IP address instead of a domain name.")
        if ip_value.is_private or ip_value.is_loopback or ip_value.is_link_local:
            add("info", "Internal network address", 0, f"{canonical} is a private, loopback or link-local address.")
        result["registrable_domain"] = canonical
        _path_checks(parts, add, _depth)
        return _finish(result, indicators, embedded=_embedded(parts, _depth))

    unicode_host = _decode_idna(host)
    result["unicode_host"] = unicode_host
    domain = registrable_domain(host)
    result["registrable_domain"] = domain
    unicode_domain = registrable_domain(unicode_host)

    if unicode_host != host or not host.isascii():
        scripts = _scripts(unicode_domain.replace(".", ""))
        if len(scripts - {"UNKNOWN"}) > 1:
            add("high", "Mixed-script domain (homograph)", 55,
                f"The domain '{unicode_domain}' mixes characters from {', '.join(sorted(scripts))}; "
                "this is the classic IDN homograph trick.")
        else:
            add("low", "Internationalized domain name", 5, f"The host decodes to '{unicode_host}'.")

    brand = _brand_checks(unicode_host.lower(), unicode_domain.lower(), add)
    if brand is None and unicode_domain != domain:
        brand = _brand_checks(host, domain, add)
    result["impersonated_brand"] = brand

    host_lower = host.lower()
    if domain in URL_SHORTENERS or host_lower in URL_SHORTENERS:
        add("medium", "URL shortener domain", 20, "A URL shortener hides the real destination.")

    if host_lower.endswith(("discordapp.com", "discord.com")) and "/attachments/" in (parts.path or "") \
            or host_lower == "api.telegram.org" and (parts.path or "").startswith("/bot") \
            or "/api/webhooks/" in (parts.path or "") and host_lower.endswith(("discord.com", "discordapp.com")):
        add("medium", "Webhook or bot API exfiltration link", 35,
            "The link targets a chat-platform endpoint that is frequently abused for payload hosting or data exfiltration.")

    suffix = _public_suffix(domain)
    if suffix in ABUSED_TLDS and not brand:
        add("low", "Frequently abused TLD", 10, f"The .{suffix} TLD is over-represented in abuse reports. This is a weak signal on its own.")

    free_host = next((item for item in FREE_HOSTING_SUFFIXES if host_lower == item or host_lower.endswith("." + item)), None)
    if free_host:
        add("low", "Free hosting or tunnel platform", 10,
            f"The page is hosted on {free_host}, where anyone can publish a site in minutes.")

    subdomain_labels = host_lower[: -len(domain)].rstrip(".").split(".") if host_lower.endswith(domain) and host_lower != domain else []
    if len(subdomain_labels) >= 4:
        add("low", "Deep subdomain nesting", 10, f"The host has {len(subdomain_labels)} subdomain levels.")
    if len(host_lower) > 60:
        add("low", "Very long host name", 10, f"The host name is {len(host_lower)} characters long.")
    domain_label = unicode_domain.split(".")[0]
    if domain_label.count("-") >= 3:
        add("low", "Many hyphens in domain", 10, f"'{unicode_domain}' contains {domain_label.count('-')} hyphens.")
    if re.search(r"\d{4,}", domain_label) and not brand:
        add("low", "Long digit run in domain", 5, f"'{domain}' contains a long run of digits.")

    keyword_source = (host_lower + " " + unquote(parts.path or "") + " " + unquote(parts.query or "")).lower()
    keywords = sorted({word for word in CREDENTIAL_KEYWORDS if re.search(rf"(?<![a-z]){re.escape(word)}(?![a-z])", keyword_source)})
    official = any(domain in officials for officials in BRANDS.values())
    if keywords and not official:
        weight = 15 if (brand or free_host or suffix in ABUSED_TLDS) else 8
        add("low", "Credential-harvesting keywords", weight,
            f"The URL contains account/credential wording ({', '.join(keywords[:5])}).", keywords=keywords[:10])
        if parts.scheme.lower() == "http":
            add("low", "Credential wording without TLS", 10, "A login-style URL uses plain http.")

    _path_checks(parts, add, _depth)
    return _finish(result, indicators, embedded=_embedded(parts, _depth))


def _path_checks(parts, add, depth: int) -> None:
    path = unquote(parts.path or "").lower()
    extension = "." + path.rsplit(".", 1)[-1] if "." in path.rsplit("/", 1)[-1] else ""
    if extension in DANGEROUS_DOWNLOAD_EXTENSIONS:
        add("medium", "Direct download of executable content", 25,
            f"The link points directly at a '{extension}' file, which runs code when opened.")
    elif extension in ARCHIVE_DOWNLOAD_EXTENSIONS:
        add("low", "Direct archive download", 5, f"The link downloads a '{extension}' archive.")
    encoded = len(re.findall(r"%[0-9a-fA-F]{2}", parts.path or ""))
    if encoded >= 10 and encoded * 3 > 0.3 * max(1, len(parts.path or "")):
        add("low", "Heavily percent-encoded path", 10, "Much of the path is percent-encoded, which hides its content.")


def _embedded(parts, depth: int) -> list[dict[str, Any]]:
    """Find URLs smuggled in query parameters (open redirects) and analyze them one level deep."""
    embedded: list[dict[str, Any]] = []
    try:
        pairs = parse_qsl(parts.query or "", keep_blank_values=False)
    except ValueError:
        return embedded
    if parts.fragment and "=" in parts.fragment:
        try:
            pairs += parse_qsl(parts.fragment)
        except ValueError:
            pass
    for name, value in pairs[:50]:
        value = value.strip()
        if not re.match(r"^(?:https?:)?//[^/\s]+", value, re.IGNORECASE):
            continue
        if name.lower() not in REDIRECT_PARAMETERS and not value.lower().startswith(("http://", "https://")):
            continue
        target = value if value.lower().startswith("http") else "http:" + value
        nested = analyze_url_intel(target, _depth=depth + 1) if depth < 2 else None
        embedded.append({"parameter": name, "url": target[:2048], "analysis": nested})
        if len(embedded) >= 5:
            break
    return embedded


def _finish(result: dict[str, Any], indicators: list[Indicator], embedded: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    if embedded:
        result["embedded_urls"] = embedded
        outer_domain = result.get("registrable_domain")
        for item in embedded:
            nested = item.get("analysis") or {}
            nested_domain = nested.get("registrable_domain")
            if nested_domain and nested_domain != outer_domain:
                if not any(existing.label == "Embedded redirect target" for existing in indicators):
                    indicators.append(Indicator(
                        CATEGORY, "medium", "Embedded redirect target",
                        f"The '{item['parameter']}' parameter forwards to '{nested_domain}', a different site (possible open redirect).",
                        15, {"target": item["url"][:300]},
                    ))
            if nested.get("score", 0) >= 30:
                indicators.append(Indicator(
                    CATEGORY, "high" if nested["score"] >= 50 else "medium", "Suspicious redirect destination",
                    f"The embedded destination '{nested_domain or item['url'][:80]}' scored {nested['score']}/100: "
                    + "; ".join(sub["label"] for sub in nested.get("findings", [])[:3]) + ".",
                    min(60, int(nested["score"] * 0.8)), {"target": item["url"][:300]},
                ))
    fused = fuse(indicators)
    result.update(fused)
    result["indicators"] = indicators
    result["findings"] = heuristic_dicts(indicators)
    return result
