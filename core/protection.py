"""Open-source protection data, used by the scans when it is present.

    YARA-Forge     thousands of curated YARA rules from public rule sets, run with YARA-X
                   (VirusTotal's YARA engine); each rule keeps its own licence and author
    URLhaus        live malware download links (abuse.ch, CC0), via the urlhaus-filter mirror
    Phishing.Database  active phishing domains (MIT)
    gitleaks       patterns for API keys, tokens and private keys (MIT)

The data is downloaded and prepared by intel/fetch.py into intel/data/ (the website build
does this on every deploy; CYBERSCAN_INTEL_DIR points elsewhere). Without it, or without
the yara-x package, these checks are skipped and every scan works as before. The lookalike
checks (punycode, brand names in the wrong domain) need no data and always run.
"""
from __future__ import annotations

import gzip
import json
import math
import os
import re
import sys
import threading
import unicodedata
import warnings
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]

# In PyInstaller bundle, data files are extracted to sys._MEIPASS
if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
    DATA = Path(sys._MEIPASS) / "intel" / "data"
else:
    DATA = Path(os.environ.get("CYBERSCAN_INTEL_DIR") or ROOT / "intel" / "data")

_lock = threading.Lock()

# YARA-Forge rules carry a score (65-100 in the core set): how strongly a match means "malicious".
FORGE_MIN_SCORE = 70


def _read_lines(name: str) -> list[str]:
    path = DATA / name
    if not path.exists():
        return []
    with gzip.open(path, "rt", encoding="utf-8") as fh:
        return [line.strip() for line in fh if line.strip()]


def manifest() -> dict[str, Any]:
    try:
        return json.loads((DATA / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


# ---------------------------------------------------------------- YARA-Forge (files)
@lru_cache(maxsize=1)
def _forge() -> Any:
    try:
        import yara_x  # noqa: PLC0415 - optional dependency
    except Exception:  # noqa: BLE001
        return None
    path = DATA / "forge.yarx"
    if not path.exists():
        return None
    try:
        with _lock, path.open("rb") as fh:
            return yara_x.Rules.deserialize_from(fh)
    except Exception:  # noqa: BLE001 - rules built by another yara-x version: skip them
        return None


def forge_available() -> bool:
    return _forge() is not None


def forge_scan(data: bytes, timeout_seconds: int = 10) -> dict[str, Any]:
    """Matches in the same shape core/yara_engine.py reports them."""
    rules = _forge()
    if rules is None:
        return {"available": False, "matches": [], "rules_loaded": 0, "error": None}
    import yara_x  # noqa: PLC0415

    scanner = yara_x.Scanner(rules)
    scanner.set_timeout(max(1, int(timeout_seconds)))
    try:
        results = scanner.scan(data)
    except Exception as exc:  # noqa: BLE001 - a timeout must not lose the rest of the scan
        return {"available": True, "matches": [], "rules_loaded": manifest().get("forge_rules", 0),
                "error": f"YARA-Forge: {type(exc).__name__}"}
    matches = []
    for rule in results.matching_rules:
        meta: dict[str, Any] = {}
        for key, value in rule.metadata:
            meta.setdefault(key, value)   # rules list several hashes; the first of each is enough
        score = int(meta.get("score", 75) or 75)
        if score < FORGE_MIN_SCORE:
            continue
        author = str(meta.get("author", "") or "").strip()
        description = str(meta.get("description", "") or "A YARA-Forge rule matched.").strip()
        strings = []
        for pattern in rule.patterns:
            for hit in pattern.matches[:2]:
                strings.append(f"0x{hit.offset:x}:{pattern.identifier}")
        matches.append({
            "rule_name": rule.identifier,
            "tags": list(rule.tags),
            # the rule licences (DRL 1.1, CC BY-SA) ask for the author to be credited with each match
            "description": f"{description} (YARA-Forge rule by {author})" if author else f"{description} (YARA-Forge)",
            "matched_strings": strings[:6],
            "meta": {"source": "YARA-Forge", "score": score, "author": author,
                     "reference": str(meta.get("reference", "") or ""), "license": str(meta.get("license", "") or "")},
        })
    matches.sort(key=lambda m: -m["meta"]["score"])
    return {"available": True, "matches": matches[:12], "rules_loaded": manifest().get("forge_rules", 0), "error": None}


# ---------------------------------------------------------------- links
# Second-level suffixes under which the registered name is the third label (example.co.uk).
_SLD = {"co", "com", "net", "org", "gov", "edu", "ac", "or", "ne", "go", "gob", "nic", "mil", "sch", "ltd", "plc", "info", "biz"}

# Brands phishing pages imitate most, with the domains they really use.
BRANDS: dict[str, tuple[str, ...]] = {
    "paypal": ("paypal.com", "paypal.me"), "apple": ("apple.com", "icloud.com"), "icloud": ("icloud.com",),
    "microsoft": ("microsoft.com", "live.com", "office.com", "microsoftonline.com", "azure.com"),
    "office365": ("office.com", "microsoft.com"), "outlook": ("outlook.com", "live.com", "office.com"),
    "google": ("google.com", "gmail.com", "youtube.com", "goo.gl", "googleusercontent.com"),
    "gmail": ("gmail.com", "google.com"), "facebook": ("facebook.com", "fb.com", "fb.me"),
    "instagram": ("instagram.com",), "whatsapp": ("whatsapp.com", "whatsapp.net", "wa.me"),
    "netflix": ("netflix.com",), "amazon": ("amazon.com", "amazon.sa", "amazon.ae", "amazon.co.uk", "amazon.de", "amazonaws.com", "aws.amazon.com"),
    "binance": ("binance.com",), "coinbase": ("coinbase.com",), "metamask": ("metamask.io",),
    "dhl": ("dhl.com", "dhl.de"), "fedex": ("fedex.com",), "aramex": ("aramex.com",), "usps": ("usps.com",),
    "linkedin": ("linkedin.com",), "dropbox": ("dropbox.com",), "docusign": ("docusign.com", "docusign.net"),
    "adobe": ("adobe.com",), "steam": ("steampowered.com", "steamcommunity.com"), "roblox": ("roblox.com",),
    "telegram": ("telegram.org", "t.me"), "tiktok": ("tiktok.com",), "snapchat": ("snapchat.com",),
    "twitter": ("twitter.com", "x.com", "t.co"), "discord": ("discord.com", "discord.gg", "discordapp.com"),
    "github": ("github.com", "github.io", "githubusercontent.com"), "yahoo": ("yahoo.com",),
    "alrajhi": ("alrajhibank.com.sa",), "alrajhibank": ("alrajhibank.com.sa",), "absher": ("absher.sa",),
    "stcpay": ("stcpay.com.sa",), "mada": ("mada.com.sa",), "snb": ("alahli.com", "snb.com"),
    "chase": ("chase.com",), "wellsfargo": ("wellsfargo.com",), "hsbc": ("hsbc.com", "hsbc.co.uk"),
    "visa": ("visa.com",), "mastercard": ("mastercard.com",), "ebay": ("ebay.com",), "walmart": ("walmart.com",),
}
# Characters from other scripts that look like Latin letters (Unicode confusables, most used).
_CONFUSABLE = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s", "һ": "h",
    "ԁ": "d", "ɡ": "g", "ո": "n", "ս": "u", "ⅼ": "l", "ӏ": "l", "ı": "i", "ɑ": "a", "ο": "o", "ν": "v", "τ": "t",
    "κ": "k", "α": "a", "ρ": "p", "ε": "e", "ω": "w", "в": "b", "м": "m", "н": "h", "т": "t", "к": "k",
    "0": "o", "1": "l", "3": "e", "5": "s", "7": "t", "@": "a", "$": "s",
})


_BAIT = {"com", "net", "org", "login", "signin", "secure", "verify", "account", "accounts", "update", "support",
         "wallet", "auth", "billing", "payment", "confirm", "unlock", "recovery", "webscr"}


def registered_domain(host: str) -> str:
    labels = host.strip(".").split(".")
    if len(labels) >= 3 and labels[-2] in _SLD and len(labels[-1]) == 2:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _official(host: str, domains: tuple[str, ...]) -> bool:
    return any(host == d or host.endswith("." + d) for d in domains)


def _skeleton(text: str) -> str:
    text = unicodedata.normalize("NFKC", text.lower()).translate(_CONFUSABLE)
    return text.replace("rn", "m").replace("vv", "w")


def _edit1(a: str, b: str) -> bool:
    """True when a and b differ by one edit (insert, delete, replace or swap of neighbours)."""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        diff = [i for i in range(len(a)) if a[i] != b[i]]
        return len(diff) == 1 or (len(diff) == 2 and diff[1] == diff[0] + 1 and a[diff[0]] == b[diff[1]] and a[diff[1]] == b[diff[0]])
    if len(a) > len(b):
        a, b = b, a
    return any(a == b[:i] + b[i + 1:] for i in range(len(b)))


@lru_cache(maxsize=1)
def _phishing() -> frozenset[str]:
    return frozenset(_read_lines("phishing-domains.txt.gz"))


@lru_cache(maxsize=1)
def _urlhaus() -> tuple[frozenset[str], frozenset[str]]:
    urls, hosts = set(), set()
    for line in _read_lines("urlhaus.txt.gz"):
        (urls if "/" in line else hosts).add(line)
    return frozenset(urls), frozenset(hosts)


def lists_available() -> bool:
    return (DATA / "phishing-domains.txt.gz").exists() or (DATA / "urlhaus.txt.gz").exists()


def _finding(severity: str, label: str, contribution: int, detail: str) -> dict[str, Any]:
    return {"severity": severity, "label": label, "contribution": contribution, "detail": detail}


def check_url(url: str) -> list[dict[str, Any]]:
    """Threat-list matches and lookalike signs for one web address."""
    text = (url or "").strip()
    if not re.match(r"(?i)^https?://", text):
        return []
    try:
        parts = urlsplit(text)
        raw_host = (parts.hostname or "").rstrip(".")
    except ValueError:
        return []
    if not raw_host:
        return []
    findings: list[dict[str, Any]] = []
    try:
        host = raw_host.encode("idna").decode("ascii").lower() if not raw_host.isascii() else raw_host.lower()
    except UnicodeError:
        host = raw_host.lower()
    try:
        shown = host.encode("ascii").decode("idna") if "xn--" in host else host
    except UnicodeError:
        shown = host
    path = unquote(parts.path or "/")

    # --- threat lists
    urls, hosts = _urlhaus()
    key = (host + path).lower().rstrip("/")
    if key.removeprefix("www.") in urls or (key + ("?" + parts.query if parts.query else "")).removeprefix("www.") in urls:
        findings.append(_finding("high", "Known malware download link (URLhaus)", 95,
                                 "This exact address is listed by URLhaus (abuse.ch) as serving malware right now."))
    elif host in hosts or host.removeprefix("www.") in hosts:
        findings.append(_finding("high", "Known malware host (URLhaus)", 90,
                                 f"{shown} is listed by URLhaus (abuse.ch) as a site that serves malware."))
    phishing = _phishing()
    if phishing:
        labels = host.split(".")
        for i in range(len(labels) - 1):
            candidate = ".".join(labels[i:])
            if candidate in phishing:
                findings.append(_finding("high", "Known phishing site (Phishing.Database)", 90,
                                         f"{candidate} is on the Phishing.Database list of active phishing sites."))
                break

    # --- lookalikes (no data needed)
    registered = registered_domain(host)
    name = registered.split(".")[0]
    is_ip = bool(re.fullmatch(r"[\d.]+|[0-9a-f:]+", host))
    if not is_ip:
        if "xn--" in host:
            skeleton = _skeleton(shown)
            mimic = next((b for b, ds in BRANDS.items() if any(_skeleton(d) in skeleton or b in skeleton for d in ds)
                          and not _official(host, ds)), None)
            if mimic:
                findings.append(_finding("high", f"Lookalike letters imitating {BRANDS[mimic][0]}", 70,
                                         f"The address is written with letters from other alphabets ({shown}) that look like {BRANDS[mimic][0]}: a classic phishing trick."))
            else:
                findings.append(_finding("info", "International (punycode) domain name", 5,
                                         f"The domain uses non-Latin letters: {shown}. Usually fine, but check it is the site you expect."))
        skel_name = _skeleton(name)
        sub_words = set(re.split(r"[.\-_]", host.removesuffix(registered)))
        name_words = set(name.split("-"))
        for brand, domains in BRANDS.items():
            if _official(host, domains) or any(_official(d, (registered,)) for d in domains):
                continue
            if skel_name == brand and name != brand:          # paypa1, rnicrosoft, gооgle
                findings.append(_finding("high", f"Lookalike of {domains[0]}", 60,
                                         f"{registered} is written to look like {domains[0]} (swapped look-alike characters)."))
                break
            if len(brand) >= 6 and _edit1(name, brand):        # paypall, gooogle, micosoft
                findings.append(_finding("medium", f"Possible misspelling of {domains[0]}", 35,
                                         f"{registered} is one letter away from {domains[0]}: a common way to imitate a real site."))
                break
            # paypal-secure.com, or paypal.com.login.example.net
            if (brand in name_words and len(name_words) > 1) or (brand in sub_words and sub_words & _BAIT):
                findings.append(_finding("medium", f"Uses the name {brand} on another site", 35,
                                         f"The address mentions {brand}, but the site is really {registered}, not {domains[0]}."))
                break
    return findings


def url_list_status(url: str) -> dict[str, Any]:
    """Was this link checked against the threat lists, and what did they say? (offline, no network)

    ``{"checked": bool, "urlhaus": "listed_url" | "listed_host" | "not_listed" | "unavailable",
    "phishing": "listed" | "not_listed" | "unavailable", "listed": bool, "updated": str,
    "host": str}``"""
    text = (url or "").strip()
    out: dict[str, Any] = {"checked": False, "urlhaus": "unavailable", "phishing": "unavailable", "listed": False,
                           "updated": str(manifest().get("updated", "") or ""), "host": ""}
    if not re.match(r"(?i)^https?://", text):
        return out
    try:
        parts = urlsplit(text)
        raw_host = (parts.hostname or "").rstrip(".")
    except ValueError:
        return out
    if not raw_host:
        return out
    try:
        host = raw_host.encode("idna").decode("ascii").lower() if not raw_host.isascii() else raw_host.lower()
    except UnicodeError:
        host = raw_host.lower()
    out["host"] = host
    urls, hosts = _urlhaus()
    if urls or hosts:
        key = (host + unquote(parts.path or "/")).lower().rstrip("/")
        if key.removeprefix("www.") in urls or (key + ("?" + parts.query if parts.query else "")).removeprefix("www.") in urls:
            out["urlhaus"] = "listed_url"
        elif host in hosts or host.removeprefix("www.") in hosts:
            out["urlhaus"] = "listed_host"
        else:
            out["urlhaus"] = "not_listed"
    phishing = _phishing()
    if phishing:
        labels = host.split(".")
        out["phishing"] = "listed" if any(".".join(labels[i:]) in phishing for i in range(len(labels) - 1)) else "not_listed"
    out["checked"] = out["urlhaus"] != "unavailable" or out["phishing"] != "unavailable"
    out["listed"] = out["urlhaus"].startswith("listed") or out["phishing"] == "listed"
    return out


# ---------------------------------------------------------------- secrets in text
@lru_cache(maxsize=1)
def _secret_rules() -> tuple[list[dict[str, Any]], list[re.Pattern[str]], tuple[str, ...]]:
    try:
        spec = json.loads((DATA / "secrets.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return [], [], ()
    rules = []
    warnings.simplefilter("ignore", FutureWarning)   # Go-style character classes ("[[" ) are fine
    for rule in spec.get("rules", []):
        try:
            rule = dict(rule)
            rule["re"] = re.compile(rule["regex"])
            rule["allow_re"] = [re.compile(p) for p in rule.get("allow_regexes", [])]
            rules.append(rule)
        except re.error:
            continue
    allow = []
    for pattern in spec.get("allow_regexes", []):
        try:
            allow.append(re.compile(pattern))
        except re.error:
            continue
    return rules, allow, tuple(s.lower() for s in spec.get("stopwords", []))


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = {c: text.count(c) for c in set(text)}
    return -sum(n / len(text) * math.log2(n / len(text)) for n in counts.values())


def _mask(secret: str) -> str:
    return secret[:4] + "…" + secret[-2:] if len(secret) > 10 else secret[:2] + "…"


def find_secrets(text: str, limit: int = 8) -> list[dict[str, Any]]:
    """API keys, tokens and private keys in pasted text (gitleaks rules). Values are masked."""
    rules, allow, stopwords = _secret_rules()
    if not rules or not text:
        return []
    text = text[:2_000_000]
    lower = text.lower()
    found: list[dict[str, Any]] = []
    seen: set[str] = set()
    for rule in rules:
        keywords = rule.get("keywords") or []
        if keywords and not any(k in lower for k in keywords):
            continue
        for match in rule["re"].finditer(text):
            group = rule.get("group") or 0
            secret = match.group(group) if group and group <= (match.re.groups or 0) else next(
                (g for g in match.groups() if g), match.group(0))
            if not secret or secret in seen:
                continue
            if rule.get("entropy") and _entropy(secret) < float(rule["entropy"]):
                continue
            low = secret.lower()
            if any(w in low for w in stopwords) or any(p.search(secret) for p in allow + rule["allow_re"]):
                continue
            seen.add(secret)
            found.append(_finding(
                "medium", f"Exposed secret: {rule['title']}", 30,
                f"{rule['description']} Found: {_mask(secret)}. If this is real, revoke it and make a new one.",
            ))
            break
        if len(found) >= limit:
            break
    return found


def status() -> dict[str, str]:
    info = manifest()
    out = {}
    if forge_available():
        out["YARA-Forge"] = f"{info.get('forge_rules', '?')} rules ({info.get('forge_version', '')})".strip()
    if lists_available():
        out["Threat lists"] = f"URLhaus {info.get('urlhaus', 0)}, phishing {info.get('phishing', 0)} ({info.get('updated', '')})"
    if _secret_rules()[0]:
        out["Secret patterns"] = f"gitleaks {len(_secret_rules()[0])} rules"
    if info.get("malware_hashes"):
        out["Hash database"] = f"{info['malware_hashes']:,} known-malware hashes ({info.get('hashes_updated', '')})"
    return out


def reload() -> None:
    """Forget the loaded data so the next scan reads the files the updater just replaced."""
    for cached in (_forge, _phishing, _urlhaus, _secret_rules):
        cached.cache_clear()
