"""Passive DNS lookups for the network tools (dnspython), with an offline record source.

Tools accept DNS data in two ways:
  * ``records``: ``{"example.com": {"TXT": ["v=spf1 -all"], "MX": ["10 mx.example.com."]}, ...}``,
    analysed offline, no network;
  * live lookups of the requested names only, through ``lookup()``. Tests replace ``lookup`` so no
    test ever queries a real resolver.
"""
from __future__ import annotations

import os
import re
from typing import Any

from security_toolkit.core import Context, ToolInputError, Unavailable

HOSTNAME = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$")


class LookupFailed(Exception):
    """The resolver could not answer (timeout, SERVFAIL, network unreachable)."""


def live_lookup_disabled() -> bool:
    """True when live DNS is switched off for this process (offline/test environments).

    Set ``CYBERSCAN_DISABLE_LIVE_LOOKUPS=1`` to keep every tool offline: live
    lookups then fail immediately as an unavailable service instead of waiting
    for resolver timeouts that depend on the machine's network.
    """
    return os.environ.get("CYBERSCAN_DISABLE_LIVE_LOOKUPS", "").strip().lower() in {"1", "true", "yes", "on"}


def normalize_domain(value: str) -> str:
    domain = (value or "").strip().rstrip(".").lower()
    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ToolInputError("The domain is not a valid internationalized name.") from exc
    if not HOSTNAME.match(domain) or "." not in domain:
        raise ToolInputError("Provide a fully qualified domain name such as example.com.")
    return domain


def _txt(rdata: Any) -> str:
    return b"".join(rdata.strings).decode("utf-8", errors="replace")


def lookup(name: str, rtype: str, *, timeout: float, nameserver: str | None = None) -> list[str]:
    """Return presentation-format answers; [] for NXDOMAIN / no data. Raises LookupFailed or Unavailable."""
    if live_lookup_disabled():
        raise LookupFailed("live lookups are disabled (CYBERSCAN_DISABLE_LIVE_LOOKUPS)")
    try:
        import dns.exception
        import dns.resolver
    except ImportError as exc:  # pragma: no cover - dnspython is installed in the test environment
        raise Unavailable("dnspython is required for live DNS lookups (pip install dnspython).") from exc
    resolver = dns.resolver.Resolver(configure=nameserver is None)
    if nameserver:
        resolver.nameservers = [nameserver]
    resolver.lifetime = max(0.5, timeout)
    resolver.timeout = max(0.5, min(timeout, 3.0))
    try:
        answer = resolver.resolve(name, rtype, raise_on_no_answer=False)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers) as exc:
        if isinstance(exc, dns.resolver.NXDOMAIN):
            return []
        raise LookupFailed("no nameserver answered") from exc
    except dns.exception.Timeout as exc:
        raise LookupFailed("timeout") from exc
    except dns.exception.DNSException as exc:
        raise LookupFailed(type(exc).__name__) from exc
    if answer.rrset is None:
        return []
    if rtype == "TXT":
        return [_txt(r) for r in answer.rrset]
    return [r.to_text() for r in answer.rrset]


class RecordSource:
    """Answers queries from supplied records, or live, recording what could not be resolved."""

    def __init__(self, ctx: Context, records: dict[str, Any] | None, *, live: bool, nameserver: str | None) -> None:
        self.ctx = ctx
        self.live = live
        self.nameserver = nameserver
        self.records: dict[str, dict[str, list[str]]] = {}
        self.failed: list[str] = []
        for owner, types in (records or {}).items():
            if not isinstance(types, dict):
                raise ToolInputError("records must map owner names to {TYPE: [values]} objects.")
            entry = self.records.setdefault(str(owner).rstrip(".").lower(), {})
            for rtype, values in types.items():
                if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
                    raise ToolInputError(f"records['{owner}']['{rtype}'] must be a list of strings.")
                entry[str(rtype).upper()] = list(values)[:200]
        if not self.records and not live:
            raise ToolInputError("Provide 'records' to analyse offline, or set 'resolve': true for live lookups.")

    def get(self, name: str, rtype: str) -> list[str] | None:
        """Answers, [] when absent, None when the lookup failed (unknown)."""
        name = name.rstrip(".").lower()
        if not self.live:
            # A supplied owner name is taken as complete: types not listed for it are absent.
            # An owner that was not supplied at all is unknown, and its checks are skipped.
            if name not in self.records:
                self.ctx.limit(f"No records were supplied for {name}; checks that need them were skipped.")
                return None
            return list(self.records[name].get(rtype, []))
        if name in self.records and rtype in self.records[name]:
            return list(self.records[name][rtype])
        self.ctx.check()
        try:
            return lookup(name, rtype, timeout=min(5.0, self.ctx.deadline.remaining()), nameserver=self.nameserver)
        except LookupFailed as exc:
            self.failed.append(f"{rtype} {name}: {exc}")
            self.ctx.limit(f"Live lookup failed for {rtype} {name} ({exc}); that check is incomplete.", partial=True)
            return None


def source_from_input(ctx: Context, input_data: dict[str, Any]) -> RecordSource:
    live = bool(input_data.get("resolve"))
    nameserver = input_data.get("nameserver")
    if nameserver is not None and not re.fullmatch(r"[0-9a-fA-F:.]{2,45}", str(nameserver)):
        raise ToolInputError("nameserver must be an IP address.")
    ctx.input_kind = "live-dns" if live else "records"
    return RecordSource(ctx, input_data.get("records"), live=live, nameserver=nameserver)


def fetch_rrsets(zone: str, rtype: str, *, nameserver: str | None, timeout: float):
    """Live: (rrset, rrsig_rrset) for name/rtype queried with the DO bit, unvalidated. Tests replace this."""
    import dns.flags
    import dns.message
    import dns.query
    import dns.rdatatype
    import dns.resolver

    server = nameserver or dns.resolver.get_default_resolver().nameservers[0]
    query = dns.message.make_query(zone, rtype, want_dnssec=True)
    response, _ = dns.query.udp_with_fallback(query, server, timeout=timeout)
    rrset = sig = None
    for item in response.answer:
        if item.rdtype == dns.rdatatype.from_text(rtype):
            rrset = item
        elif item.rdtype == dns.rdatatype.RRSIG and item.covers == dns.rdatatype.from_text(rtype):
            sig = item
    return rrset, sig
