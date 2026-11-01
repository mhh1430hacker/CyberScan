"""Things a link's own address gives away, read from the text alone.

Not a verdict and nothing online: plain facts anyone could check by reading
the address carefully, said out loud because people don't.

* A well-known brand in the address that is not the site's real owner
  (``login-microsoft.secure-verify.example.com`` belongs to example.com).
* A bare IP address instead of a name.
* ``user@host`` addresses, where everything before ``@`` is decoration.
* Internationalised (``xn--``) names that can imitate other letters.
"""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

# Distinctive names only: common words ("live", "office") would cry wolf.
BRANDS = (
    "microsoft", "outlook", "onedrive", "apple", "icloud", "google", "gmail", "youtube",
    "paypal", "amazon", "facebook", "instagram", "whatsapp", "netflix", "linkedin", "dropbox", "docusign",
    "adobe", "binance", "coinbase", "steamcommunity", "roblox", "discord", "epicgames", "fortnite",
    "telegram", "twitter", "tiktok", "snapchat", "fedex", "aramex", "stcpay", "alrajhi",
)
# Second-level labels that belong to the country code, not to the owner (co.uk, com.sa ...).
_SHARED_SECOND = {"co", "com", "org", "net", "gov", "edu", "ac", "sch", "ltd", "plc"}
_LABEL = re.compile(r"[a-z0-9]+")


def owner(host: str) -> str:
    """The registrable part of a host name (approximate, no suffix list)."""
    labels = host.lower().strip(".").split(".")
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in _SHARED_SECOND:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def hints(url: str) -> list[tuple[str, dict[str, str]]]:
    """(English template, values) pairs: the caller translates the template,
    then fills it in. Empty when nothing stands out."""
    try:
        parts = urlsplit(url.strip())
    except ValueError:
        return []
    host = (parts.hostname or "").lower()
    if not host:
        return []
    found: list[str] = []
    if parts.username:
        found.append("Everything before the @ in this address is decoration; the link really goes to {host}.")
    try:
        ipaddress.ip_address(host)
        found.append("This link uses a bare number ({host}) instead of a site name. Real services rarely do that.")
        return [(text, {"host": host}) for text in found]
    except ValueError:
        pass
    if "xn--" in host:
        found.append("This address uses letters from other alphabets that can imitate familiar ones.")
    real = owner(host)
    real_name = real.split(".")[0]
    words = set(_LABEL.findall(host[: len(host) - len(real)]))
    words |= set(_LABEL.findall(real_name)) - {real_name}
    mentioned = next((brand for brand in BRANDS if brand in words and brand != real_name), "")
    if mentioned:
        found.append("The address mentions “{brand}”, but the site really belongs to {owner}.")
    return [(text, {"host": host, "owner": real, "brand": mentioned}) for text in found]
