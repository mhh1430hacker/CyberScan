"""Secret and credential detection shared by tools 074, 075, 076, 079, 083, 090, 095, 097, 098.

Builds on the frozen engine's ``detection.secrets.scan_secrets`` (provider tokens, private keys,
connection strings, generic hard-coded credentials, payment cards; values already redacted there)
and adds only formats the engine does not cover. No value ever leaves this module unmasked: results
carry a masked preview and, for supplementary rules, a SHA-256 fingerprint for de-duplication.
Nothing is validated against a provider: a match is a possible exposure, not a confirmed live key.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import re
from typing import Any

from security_toolkit.core import line_of, mask, shannon_entropy

try:
    from detection.secrets import scan_secrets as _engine_scan
except Exception:  # pragma: no cover
    _engine_scan = None

CATEGORY_OF = {
    "private_key": "private_key", "payment_card": "payment_card", "connection_string": "credential",
    "generic_secret": "credential", "slack_webhook": "webhook", "discord_webhook": "webhook",
}

# (type, label, category, severity, pattern, value group)
SUPPLEMENTARY = [
    ("pypi_token", "PyPI API token", "api_key", "high", re.compile(r"\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,})"), 1),
    ("huggingface_token", "Hugging Face token", "api_key", "high", re.compile(r"\b(hf_[A-Za-z0-9]{34,40})\b"), 1),
    ("digitalocean_token", "DigitalOcean token", "api_key", "high", re.compile(r"\b(do[opr]_v1_[a-f0-9]{64})\b"), 1),
    ("shopify_token", "Shopify access token", "api_key", "high", re.compile(r"\b(shp(?:at|ss|ca|pa)_[a-fA-F0-9]{32})\b"), 1),
    ("mailgun_key", "Mailgun API key", "api_key", "medium", re.compile(r"\b(key-[0-9a-f]{32})\b"), 1),
    ("databricks_token", "Databricks token", "api_key", "high", re.compile(r"\b(dapi[0-9a-f]{32}(?:-\d)?)\b"), 1),
    ("square_token", "Square access token", "api_key", "high", re.compile(r"\b(sq0atp-[0-9A-Za-z_\-]{22}|EAAA[0-9A-Za-z_\-]{60})\b"), 1),
    ("azure_storage_key", "Azure storage account key", "api_key", "critical",
     re.compile(r"(?i)AccountKey\s*=\s*([A-Za-z0-9+/]{86}==)"), 1),
    ("azure_sas", "Azure shared access signature", "api_key", "medium", re.compile(r"[?&](sig=[A-Za-z0-9%+/]{40,}={0,2})"), 1),
    ("gcp_service_account", "Google service-account private key", "private_key", "critical",
     re.compile(r'"type"\s*:\s*"service_account"[\s\S]{0,2000}?"private_key"\s*:\s*"(-----BEGIN[^"]{40,})"'), 1),
    ("bearer_header", "Bearer token in an Authorization header", "api_key", "medium",
     re.compile(r"(?i)\bAuthorization\s*[:=]\s*[\"']?Bearer\s+([A-Za-z0-9\-._~+/]{20,}=*)"), 1),
    ("basic_auth_header", "Basic-auth credentials in an Authorization header", "credential", "high",
     re.compile(r"(?i)\bAuthorization\s*[:=]\s*[\"']?Basic\s+([A-Za-z0-9+/]{8,}={0,2})"), 1),
    ("url_credentials", "Password embedded in a URL", "credential", "high",
     re.compile(r"\b(?:https?|ftp|ssh|git|smtp|ldap)://[^\s:/@\"']{1,64}:([^\s@/\"']{3,128})@[\w.\-]+"), 1),
    ("netrc_password", ".netrc password", "credential", "high", re.compile(r"(?i)\bmachine\s+\S+\s+login\s+\S+\s+password\s+(\S+)"), 1),
    ("htpasswd_hash", "htpasswd password hash", "credential", "medium",
     re.compile(r"(?m)^[\w.\-]{1,64}:(\$apr1\$[./0-9A-Za-z]{1,8}\$[./0-9A-Za-z]{22}|\$2[aby]\$\d\d\$[./0-9A-Za-z]{53}|\{SHA\}[A-Za-z0-9+/]{27}=)$"), 1),
    ("unattend_password", "Windows unattend.xml password", "credential", "high",
     re.compile(r"(?is)<(?:AdministratorPassword|Password)>\s*<Value>([^<]{3,256})</Value>"), 1),
    ("net_use_password", "Password on a 'net use' command line", "credential", "high",
     re.compile(r"(?i)\bnet\s+use\s+\S+\s+(?!/)(\S{3,128})\s+/user:"), 1),
    ("npmrc_auth", "npm registry auth token", "api_key", "high", re.compile(r"(?i)_authToken\s*=\s*([A-Za-z0-9\-_.]{20,})"), 1),
]
PLACEHOLDER = re.compile(r"(?i)^(?:x{4,}|\*{3,}|<[^>]*>|\{\{.*\}\}|\$\{.*\}|%\w+%|your[_\-]?|changeme|change_me|example|placeholder|"
                         r"redacted|dummy|sample|password|secret|null|none|undefined|todo|fixme|replace|test(?:ing)?|\.{3,})")
TEST_PATH = re.compile(r"(?i)(?:^|/)(?:tests?|spec|__tests__|fixtures?|examples?|samples?|mocks?|testdata|docs?)(?:/|$)|\.(?:md|rst|txt)$|"
                       r"(?:_test|\.test|\.spec|_spec)\.\w+$")


def fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()[:16]


def _basic_has_password(value: str) -> bool:
    try:
        decoded = base64.b64decode(value + "=" * (-len(value) % 4)).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return False
    user, sep, password = decoded.partition(":")
    return bool(sep and user and password)


def scan(text: str, *, max_items: int = 200) -> list[dict[str, Any]]:
    """All secrets in ``text``: [{type, label, category, severity, line, masked, fingerprint, placeholder}]."""
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    if _engine_scan is not None:
        result = _engine_scan(text, max_findings=max_items)
        for item in result["findings"]:
            category = CATEGORY_OF.get(item["type"], "api_key")
            key = (item["type"], item["redacted"])
            if key in seen:
                continue
            seen.add(key)
            out.append({"type": item["type"], "label": item["label"], "category": category, "severity": item["severity"],
                        "line": item["line"], "masked": item["redacted"], "fingerprint": fingerprint(f"{item['type']}:{item['redacted']}"),
                        "placeholder": False, "source": "detection.secrets"})
    for kind, label, category, severity, pattern, group in SUPPLEMENTARY:
        for match in pattern.finditer(text):
            value = match.group(group)
            if kind == "basic_auth_header" and not _basic_has_password(value):
                continue
            placeholder = bool(PLACEHOLDER.search(value)) or (category == "credential" and kind not in ("htpasswd_hash",)
                                                              and len(value) < 32 and shannon_entropy(value) < 2.0)
            key = (kind, fingerprint(value))
            if key in seen:
                continue
            seen.add(key)
            out.append({"type": kind, "label": label, "category": category, "severity": severity,
                        "line": line_of(text, match.start(group)), "masked": mask(value), "fingerprint": fingerprint(value),
                        "placeholder": placeholder, "source": "security_toolkit"})
            if len(out) >= max_items:
                return out
    return out


def is_test_path(path: str) -> bool:
    return bool(TEST_PATH.search(path.replace("\\", "/")))
