"""Network tools: Wi-Fi security, DNS integrity ("Real Site"), the devices on your own
network, and the programs on this computer that accept connections.

The device sweep only looks at the local network this computer is on (the /24 of its own
address): it reads the ARP table, pings each address once and tries a short list of
well-known ports on the devices that answered, to tell you which ones expose services
that are often left open by mistake (Telnet, SMB, RDP, UPnP…).
"""
from __future__ import annotations

import ipaddress
import json
import re
import socket
import ssl
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from . import core, system, winutil

# ---------------------------------------------------------------- Wi-Fi
def wifi_status() -> dict[str, Any]:
    code, out = winutil.run(["netsh", "wlan", "show", "interfaces"], timeout=10)
    if code != 0 or "SSID" not in out:
        return {"connected": False, "risk": "ok"}
    fields: dict[str, str] = {}
    for line in out.splitlines():
        if ":" in line:
            key, _, value = line.partition(":")
            fields.setdefault(key.strip().lower(), value.strip())
    auth = fields.get("authentication", "")
    cipher = fields.get("cipher", "")
    ssid = fields.get("ssid", "")
    low = auth.lower()
    if "open" in low or not auth:
        risk, reason = "bad", "open"
    elif "wep" in low or cipher.lower() in ("wep", "tkip"):
        risk, reason = "bad", "weak_cipher"
    elif "wpa3" in low:
        risk, reason = "ok", "wpa3"
    elif "wpa2" in low:
        risk, reason = "ok", "wpa2"
    else:
        risk, reason = "warn", "old_wpa"
    return {"connected": True, "ssid": ssid, "auth": auth, "cipher": cipher, "signal": fields.get("signal", ""),
            "risk": risk, "reason": reason, "band": fields.get("band", ""), "radio": fields.get("radio type", "")}


# ---------------------------------------------------------------- DNS integrity
CHECK_DOMAINS = ("www.google.com", "www.paypal.com", "login.microsoftonline.com", "www.facebook.com",
                 "www.apple.com", "www.amazon.com", "github.com", "www.wikipedia.org")
DOH = "https://cloudflare-dns.com/dns-query?name={}&type=A"


def _doh(name: str) -> set[str]:
    req = urllib.request.Request(DOH.format(name), headers={"accept": "application/dns-json"})
    with urllib.request.urlopen(req, timeout=6, context=ssl.create_default_context()) as res:  # noqa: S310 - fixed https URL
        data = json.loads(res.read())
    return {a["data"] for a in data.get("Answer", []) if a.get("type") == 1}


def _system(name: str) -> set[str]:
    try:
        return {i[4][0] for i in socket.getaddrinfo(name, 443, socket.AF_INET)}
    except OSError:
        return set()


def _tls_ok(name: str, ip: str) -> bool:
    """Does the address the system gave really hold a valid certificate for the name?"""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((ip, 443), timeout=5) as sock, ctx.wrap_socket(sock, server_hostname=name):
            return True
    except (OSError, ssl.SSLError):
        return False


def dns_servers() -> list[str]:
    data = winutil.powershell_json(
        "Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object ServerAddresses | "
        "Select-Object InterfaceAlias,ServerAddresses | ConvertTo-Json -Compress")
    servers: list[str] = []
    for item in winutil.as_list(data):
        if isinstance(item, dict):
            servers += [s for s in winutil.as_list(item.get("ServerAddresses")) if isinstance(s, str)]
    return list(dict.fromkeys(servers))


def dns_check(quick: bool = False) -> dict[str, Any]:
    """Compare what this computer's DNS answers with DNS over HTTPS, and confirm any
    difference with a TLS handshake (CDNs legitimately give different addresses; a
    hijacked answer can't present the site's certificate)."""
    domains = CHECK_DOMAINS[:4] if quick else CHECK_DOMAINS
    rows = []
    for name in domains:
        local = _system(name)
        try:
            remote = _doh(name)
        except Exception:  # noqa: BLE001
            remote = set()
        status = "ok"
        if not local:
            status = "unresolved"
        elif remote and not (local & remote):
            status = "ok" if all(_tls_ok(name, ip) for ip in list(local)[:2]) else "bad"
        rows.append({"domain": name, "system": sorted(local), "doh": sorted(remote), "status": status})
    hosts = system.hosts_tampering()
    bad = [r for r in rows if r["status"] == "bad"]
    status = "bad" if bad or hosts else ("warn" if all(not r["doh"] for r in rows) else "ok")
    return {"status": status, "rows": rows, "servers": dns_servers(), "hosts": hosts, "checked": time.time()}


# ---------------------------------------------------------------- devices on the network
PORTS = {21: "FTP", 22: "SSH", 23: "Telnet", 53: "DNS", 80: "HTTP", 139: "NetBIOS", 443: "HTTPS", 445: "SMB",
         554: "RTSP", 1900: "UPnP", 3389: "RDP", 5000: "UPnP", 5900: "VNC", 8080: "HTTP-alt", 8443: "HTTPS-alt", 9100: "Printer"}
RISKY_PORTS = {21, 23, 445, 3389, 5900, 139}
# a few common vendor prefixes (OUI) to label devices; unknown stays unknown
OUI = {
    "00:1A:11": "Google", "3C:5A:B4": "Google", "F4:F5:D8": "Google", "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi",
    "00:17:88": "Philips Hue", "EC:FA:BC": "Espressif (IoT)", "24:0A:C4": "Espressif (IoT)", "A4:CF:12": "Espressif (IoT)",
    "00:1B:63": "Apple", "F0:18:98": "Apple", "AC:BC:32": "Apple", "3C:22:FB": "Apple", "28:6C:07": "Xiaomi",
    "64:09:80": "Xiaomi", "00:50:56": "VMware", "08:00:27": "VirtualBox", "00:15:5D": "Hyper-V", "E0:63:DA": "Ubiquiti",
    "B0:BE:76": "TP-Link", "50:C7:BF": "TP-Link", "C0:25:E9": "TP-Link", "00:1E:58": "D-Link", "14:CC:20": "TP-Link",
    "00:24:D4": "Freebox", "FC:EC:DA": "Ubiquiti", "00:04:20": "Slim Devices", "00:0C:29": "VMware", "30:B5:C2": "TP-Link",
    "70:4F:57": "TP-Link", "BC:D0:74": "Apple", "8C:85:90": "Apple", "00:26:AB": "Seiko Epson", "00:1E:0B": "HP",
    "3C:D9:2B": "HP", "00:21:5A": "HP", "A0:CE:C8": "Ce Link", "44:65:0D": "Amazon", "F0:27:2D": "Amazon",
    "74:C2:46": "Amazon", "00:FC:8B": "Amazon", "5C:AA:FD": "Sonos", "B8:E9:37": "Sonos", "00:09:B0": "Onkyo",
    "D8:31:34": "Roku", "AC:3A:7A": "Roku", "00:12:FB": "Samsung", "8C:77:12": "Samsung", "F8:04:2E": "Samsung",
    "CC:6E:A4": "Samsung", "34:CE:00": "Xiaomi", "48:A9:8A": "Routerboard", "4C:5E:0C": "Routerboard", "E8:48:B8": "TP-Link",
}


def local_network() -> tuple[str, ipaddress.IPv4Network] | None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 9))   # no packet is sent: this only picks the outgoing interface
            ip = s.getsockname()[0]
    except OSError:
        return None
    addr = ipaddress.IPv4Address(ip)
    if not addr.is_private:
        return None
    return ip, ipaddress.IPv4Network(f"{ip}/24", strict=False)


def gateway() -> str:
    code, out = winutil.run(["route", "print", "0.0.0.0"], timeout=8)
    match = re.search(r"0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)", out)
    return match.group(1) if match else ""


def arp_table() -> dict[str, str]:
    code, out = winutil.run(["arp", "-a"], timeout=10)
    table = {}
    for ip, mac in re.findall(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f]{2}(?:-[0-9a-f]{2}){5})\s+dynamic", out, re.I):
        table[ip] = mac.upper().replace("-", ":")
    return table


def _ping(ip: str) -> bool:
    code, _ = winutil.run(["ping", "-n", "1", "-w", "400", ip] if winutil.IS_WINDOWS else ["ping", "-c", "1", "-W", "1", ip], timeout=3)
    return code == 0


def _open(ip: str, port: int) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=0.5):
            return True
    except OSError:
        return False


def _name(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return ""


def network_scan() -> core.Job:
    if core.running("network_scan"):
        raise RuntimeError("A network scan is already running.")

    def work(job: core.Job) -> dict[str, Any]:
        found = local_network()
        if found is None:
            raise RuntimeError("This computer isn't on a private network.")
        me, net = found
        gw = gateway()
        wifi = wifi_status()
        hosts = [str(h) for h in net.hosts()]
        alive: set[str] = set()
        job.detail = "sweep"
        with ThreadPoolExecutor(max_workers=48) as pool:
            for i, (ip, up) in enumerate(zip(hosts, pool.map(_ping, hosts))):
                if up:
                    alive.add(ip)
                job.progress = 0.6 * (i + 1) / len(hosts)
                if job.cancel:
                    return {}
        arp = arp_table()
        alive |= {ip for ip in arp if ipaddress.IPv4Address(ip) in net}
        alive.add(me)
        devices = []
        job.detail = "ports"
        ordered = sorted(alive, key=lambda x: ipaddress.IPv4Address(x))
        for i, ip in enumerate(ordered):
            if job.cancel:
                break
            with ThreadPoolExecutor(max_workers=16) as pool:
                states = list(pool.map(lambda p: _open(ip, p), PORTS))
            open_ports = [p for p, s in zip(PORTS, states) if s]
            mac = arp.get(ip, "")
            issues = [p for p in open_ports if p in RISKY_PORTS and ip != me]
            if ip == gw and 80 in open_ports and 443 not in open_ports:
                issues.append("router_http")
            device = {"ip": ip, "mac": mac, "vendor": OUI.get(mac[:8], ""), "name": _name(ip),
                      "ports": [{"port": p, "service": PORTS[p]} for p in open_ports],
                      "role": "this" if ip == me else ("router" if ip == gw else "device"),
                      "risk": "bad" if any(isinstance(x, int) and x in (23, 21, 5900) for x in issues) else ("warn" if issues else "ok"),
                      "issues": issues}
            devices.append(device)
            job.items.append(device)
            job.progress = 0.6 + 0.4 * (i + 1) / len(ordered)
        risky = sum(1 for d in devices if d["risk"] != "ok") + (1 if wifi.get("risk") == "bad" else 0)
        core.EVENTS.add("network", "medium" if risky else "info", "network_done", net.with_prefixlen, issues=risky)
        return {"network": net.with_prefixlen, "me": me, "gateway": gw, "wifi": wifi, "devices": devices, "issues": risky}

    return core.start_job("network_scan", work)


# ---------------------------------------------------------------- listening programs
def listening() -> list[dict[str, Any]]:
    """Programs on this computer that accept connections, and from where."""
    code, out = winutil.run(["netstat", "-ano", "-p", "TCP"], timeout=15)
    code6, out6 = winutil.run(["netstat", "-ano", "-p", "TCPv6"], timeout=15)
    rows = []
    for line in (out + "\n" + out6).splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[0] == "TCP" and parts[3] == "LISTENING":
            local = parts[1]
            host, _, port = local.rpartition(":")
            rows.append({"address": host.strip("[]"), "port": int(port), "pid": int(parts[4])})
    procs = {p["pid"]: p for p in system.processes()}
    out_rows = {}
    for r in rows:
        p = procs.get(r["pid"], {})
        exposed = r["address"] not in ("127.0.0.1", "::1")
        key = (r["port"], r["pid"])
        if key in out_rows:
            out_rows[key]["exposed"] = out_rows[key]["exposed"] or exposed
            continue
        out_rows[key] = {"port": r["port"], "pid": r["pid"], "name": p.get("name", ""), "path": p.get("path", ""),
                         "exposed": exposed, "service": PORTS.get(r["port"], ""),
                         "risk": "warn" if exposed and r["port"] in RISKY_PORTS else "ok"}
    return sorted(out_rows.values(), key=lambda x: (not x["exposed"], x["port"]))


def firewall_rules_for(program: str) -> list[dict[str, Any]]:
    data = winutil.powershell_json(
        "Get-NetFirewallApplicationFilter | Where-Object { $_.Program -eq $P.p } | Get-NetFirewallRule | "
        "Select-Object DisplayName,Direction,Action,Enabled | ConvertTo-Json -Compress", params={"p": program})
    return [r for r in winutil.as_list(data) if isinstance(r, dict)]


def block_program(program: str) -> dict[str, Any]:
    """Add Windows Firewall rules that stop one program from connecting (in and out)."""
    if not program or not program.lower().endswith(".exe"):
        raise ValueError("Choose a program (.exe).")
    ok, message = winutil.elevated(
        "New-NetFirewallRule -DisplayName ('CyberScan block ' + (Split-Path $P.p -Leaf)) -Direction Outbound -Program $P.p -Action Block | Out-Null;"
        "New-NetFirewallRule -DisplayName ('CyberScan block ' + (Split-Path $P.p -Leaf)) -Direction Inbound -Program $P.p -Action Block | Out-Null",
        {"p": program})
    if ok:
        core.EVENTS.add("firewall", "info", "app_blocked", program)
    return {"ok": ok, "message": message if not ok else ""}


def unblock_program(program: str) -> dict[str, Any]:
    ok, message = winutil.elevated(
        "Get-NetFirewallRule -DisplayName ('CyberScan block ' + (Split-Path $P.p -Leaf)) | Remove-NetFirewallRule", {"p": program})
    return {"ok": ok, "message": message if not ok else ""}


def blocked_programs() -> list[str]:
    data = winutil.powershell_json(
        "Get-NetFirewallRule -DisplayName 'CyberScan block *' | Get-NetFirewallApplicationFilter | "
        "Select-Object -ExpandProperty Program -Unique | ConvertTo-Json -Compress")
    return [p for p in winutil.as_list(data) if isinstance(p, str)]


def firewall_status() -> dict[str, Any]:
    return {"profiles": system.firewall_profiles(), "listening": listening(), "blocked": blocked_programs(),
            "admin": winutil.is_admin()}


# ---------------------------------------------------------------- remote access
REMOTE_TOOLS = {"anydesk.exe": "AnyDesk", "teamviewer.exe": "TeamViewer", "tv_w32.exe": "TeamViewer",
                "rustdesk.exe": "RustDesk", "screenconnect.clientservice.exe": "ScreenConnect", "vncserver.exe": "VNC",
                "winvnc.exe": "VNC", "tvnserver.exe": "TightVNC", "remoting_host.exe": "Chrome Remote Desktop",
                "ammyy_admin.exe": "Ammyy Admin", "supremo.exe": "Supremo", "splashtopstreamer.exe": "Splashtop",
                "logmein.exe": "LogMeIn", "atera_agent.exe": "Atera", "netsupport.exe": "NetSupport", "client32.exe": "NetSupport"}


def remote_access() -> dict[str, Any]:
    rdp = winutil.reg_read("HKLM", r"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections")
    nla = winutil.reg_read("HKLM", r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", "UserAuthentication")
    port = winutil.reg_read("HKLM", r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", "PortNumber")
    assist = winutil.reg_read("HKLM", r"SYSTEM\CurrentControlSet\Control\Remote Assistance", "fAllowToGetHelp")
    tools = []
    for p in system.processes():
        label = REMOTE_TOOLS.get(p["name"].lower())
        if label:
            tools.append({"name": label, "pid": p["pid"], "path": p["path"]})
    failed = None
    if winutil.is_admin():
        data = winutil.powershell_json(
            "(Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625;StartTime=(Get-Date).AddDays(-1)} -MaxEvents 500 | Measure-Object).Count | ConvertTo-Json")
        failed = data if isinstance(data, int) else None
    return {"rdp": rdp == 0, "nla": nla == 1, "port": port, "assistance": assist == 1,
            "tools": list({t["name"]: t for t in tools}.values()), "failed_logons_24h": failed, "admin": winutil.is_admin()}
