"""Flow-record analytics shared by tools 056 (packet metadata) and 060 (network anomalies).

A flow is ``{ts, src, dst, sport, dport, proto, bytes_out, bytes_in, packets, syn_only, dns_query}``;
missing fields default to 0/None. All detections are statistical heuristics over the supplied
window of traffic: they point at behaviour worth reviewing, not at confirmed compromise.
"""
from __future__ import annotations

import ipaddress
import math
import statistics
from collections import Counter, defaultdict
from typing import Any, Iterable

from security_toolkit.core import Context, shannon_entropy

CLEARTEXT_PORTS = {21: "FTP", 23: "Telnet", 80: "HTTP", 110: "POP3", 143: "IMAP", 161: "SNMP", 389: "LDAP",
                   512: "rexec", 513: "rlogin", 514: "rsh/syslog", 1883: "MQTT", 5900: "VNC", 69: "TFTP"}
REMOTE_ADMIN_PORTS = {22: "SSH", 23: "Telnet", 3389: "RDP", 5900: "VNC", 5985: "WinRM", 5986: "WinRM-TLS"}


INTERNAL_NETWORKS = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "fc00::/7", "fe80::/10", "::1/128"))


def is_internal(address: str) -> bool:
    """RFC 1918, CGNAT, loopback, link-local and IPv6 ULA. Unlike ``ip.is_private`` this excludes the
    documentation and benchmarking ranges, which are not part of anyone's internal network."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return any(ip.version == net.version and ip in net for net in INTERNAL_NETWORKS)


def normalize(raw: dict[str, Any]) -> dict[str, Any] | None:
    try:
        flow = {
            "ts": float(raw.get("ts") or 0),
            "src": str(raw.get("src") or raw.get("id.orig_h") or ""),
            "dst": str(raw.get("dst") or raw.get("id.resp_h") or ""),
            "sport": int(raw.get("sport") or raw.get("id.orig_p") or 0),
            "dport": int(raw.get("dport") or raw.get("id.resp_p") or 0),
            "proto": str(raw.get("proto") or "tcp").lower(),
            "bytes_out": int(float(raw.get("bytes_out") or raw.get("orig_bytes") or 0)),
            "bytes_in": int(float(raw.get("bytes_in") or raw.get("resp_bytes") or 0)),
            "packets": int(float(raw.get("packets") or 1)),
            "syn_only": bool(raw.get("syn_only")) or str(raw.get("conn_state", "")) in ("S0", "REJ"),
            "dns_query": raw.get("dns_query") or raw.get("query"),
            "dns_queries": [str(q) for q in (raw.get("dns_queries") or [])][:1000],
        }
    except (TypeError, ValueError):
        return None
    return flow if flow["src"] and flow["dst"] else None


def _mad_outliers(values: dict[str, float], threshold: float = 6.0) -> list[tuple[str, float, float]]:
    if len(values) < 5:
        return []
    numbers = list(values.values())
    median = statistics.median(numbers)
    mad = statistics.median(abs(v - median) for v in numbers) or 0.0
    out = []
    for key, value in values.items():
        if mad == 0:
            score = math.inf if value > median * 10 and value > 0 else 0.0
        else:
            score = 0.6745 * (value - median) / mad
        if score >= threshold:
            out.append((key, value, score))
    return out


def analyze(ctx: Context, flows: Iterable[dict[str, Any]], *, include_cleartext: bool = True) -> dict[str, Any]:
    flows = [f for f in flows if f]
    by_src_ports: dict[tuple[str, str], set[int]] = defaultdict(set)
    syn_ports: dict[tuple[str, str], set[int]] = defaultdict(set)
    fanout: dict[str, set[str]] = defaultdict(set)
    out_bytes: dict[str, float] = defaultdict(float)
    pair_bytes: dict[tuple[str, str], int] = defaultdict(int)
    times: dict[tuple[str, str, int], list[float]] = defaultdict(list)
    dns_names: dict[str, set[str]] = defaultdict(set)
    port_count = Counter()
    for index, f in enumerate(flows):
        if index % 2000 == 0:
            ctx.check()
        key = (f["src"], f["dst"])
        by_src_ports[key].add(f["dport"])
        if f["syn_only"]:
            syn_ports[key].add(f["dport"])
        fanout[f["src"]].add(f["dst"])
        out_bytes[f["src"]] += f["bytes_out"]
        if is_internal(f["src"]) and not is_internal(f["dst"]):
            pair_bytes[key] += f["bytes_out"]
        times[(f["src"], f["dst"], f["dport"])].append(f["ts"])
        port_count[f["dport"]] += 1
        for query in ([f["dns_query"]] if f.get("dns_query") else []) + f.get("dns_queries", []):
            name = str(query).rstrip(".").lower()
            parts = name.split(".")
            base = ".".join(parts[-2:]) if len(parts) >= 2 else name
            dns_names[base].add(name)

    if include_cleartext:
        for (src, dst), ports in by_src_ports.items():
            for port in sorted(ports & set(CLEARTEXT_PORTS)):
                ctx.finding(f"cleartext.{CLEARTEXT_PORTS[port].lower()}", f"Cleartext protocol: {CLEARTEXT_PORTS[port]}",
                            "medium" if port in (21, 23, 110, 143, 513, 512) else "low",
                            f"Traffic on port {port} ({CLEARTEXT_PORTS[port]}) is normally unencrypted; credentials and data can be read on the path.",
                            location=f"{src} -> {dst}:{port}", recommendation="Use the encrypted variant (SFTP/SSH/HTTPS/IMAPS...).")

    for (src, dst), ports in syn_ports.items():
        if len(ports) >= 20:
            ctx.finding("scan.ports", "Port-scan pattern", "high",
                        f"{src} sent connection attempts without completing handshakes to {len(ports)} ports on {dst}.",
                        location=f"{src} -> {dst}", evidence=f"ports {sorted(ports)[:15]}…")
    for src, destinations in fanout.items():
        if len(destinations) >= 50:
            ctx.finding("scan.hosts", "Host sweep / high fan-out", "medium",
                        f"{src} contacted {len(destinations)} distinct hosts in the analysed window.", location=src)

    for src, value, score in _mad_outliers({k: v for k, v in out_bytes.items() if is_internal(k)}):
        ctx.finding("volume.outlier", "Unusual outbound volume", "medium",
                    f"{src} sent {int(value):,} bytes, far above the other internal hosts (robust z-score {score if score != math.inf else 'inf'}).",
                    location=src)
    for (src, dst), total in pair_bytes.items():
        if total >= 100 * 1024 * 1024:
            ctx.finding("volume.large-egress", "Large transfer to one external host", "medium",
                        f"{src} sent {total / 1048576:.0f} MiB to {dst}; check whether that destination is expected.",
                        location=f"{src} -> {dst}")

    for (src, dst, port), stamps in times.items():
        if len(stamps) < 8 or is_internal(dst):
            continue
        stamps.sort()
        gaps = [b - a for a, b in zip(stamps, stamps[1:]) if b > a]
        if len(gaps) < 7:
            continue
        mean = statistics.mean(gaps)
        cv = statistics.pstdev(gaps) / mean if mean else 1.0
        if mean >= 5 and cv < 0.1:
            ctx.finding("beacon.periodic", "Periodic beacon-like connections", "medium",
                        f"{src} connected to {dst}:{port} {len(stamps)} times every {mean:.1f}s (variation {cv:.0%}). "
                        "Malware check-ins look like this, but so do update and monitoring agents.",
                        location=f"{src} -> {dst}:{port}")

    for base, names in dns_names.items():
        long_labels = [n for n in names if max((len(p) for p in n.split(".")), default=0) >= 40]
        random_labels = [n for n in names if shannon_entropy(n.split(".")[0]) >= 3.8 and len(n.split(".")[0]) >= 20]
        if len(names) >= 30 and (len(long_labels) + len(random_labels)) >= 10:
            ctx.finding("dns.tunnel", "DNS tunnelling pattern", "high",
                        f"{len(names)} distinct names under {base}, many with long or random-looking labels: typical of data carried in DNS queries.",
                        location=base, evidence=sorted(names)[0])

    rare = sorted(p for p, n in port_count.items() if n == 1 and p > 1024 and p not in (8080, 8443))
    return {"flows": len(flows), "hosts": len(fanout), "rare_high_ports": rare[:50], "top_ports": port_count.most_common(10)}
