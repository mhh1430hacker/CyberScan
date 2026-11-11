"""The computer's own security settings, running programs and startup items.

Every check reads the real state from Windows (registry, Defender, firewall, update
history) and says how sure it is: ``ok``, ``warn``, ``bad`` or ``unknown`` when Windows
would not tell us. A check that can be fixed names the fix; fixes that change system
settings ask Windows for administrator rights (the UAC prompt) first.
"""
from __future__ import annotations

import os
import re
import time
from pathlib import Path
from typing import Any

from . import winutil
from .winutil import as_list, reg_read, reg_values

# ---------------------------------------------------------------- processes
_PROC_SCRIPT = (
    "Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine,"
    "@{n='Created';e={if($_.CreationDate){$_.CreationDate.ToString('o')}}} | ConvertTo-Json -Compress -Depth 2"
)


def processes() -> list[dict[str, Any]]:
    data = winutil.powershell_json(_PROC_SCRIPT, timeout=40)
    out = []
    for p in as_list(data):
        if not isinstance(p, dict):
            continue
        out.append({"pid": p.get("ProcessId"), "ppid": p.get("ParentProcessId"), "name": p.get("Name") or "",
                    "path": p.get("ExecutablePath") or "", "cmd": (p.get("CommandLine") or "")[:2000],
                    "created": p.get("Created") or ""})
    return out


def signatures(paths: list[str]) -> dict[str, dict[str, str]]:
    """Authenticode status and signer for each path (one PowerShell call)."""
    paths = [p for p in dict.fromkeys(paths) if p and Path(p).is_file()][:400]
    if not paths:
        return {}
    data = winutil.powershell_json(
        "$P | ForEach-Object { $s = Get-AuthenticodeSignature -LiteralPath $_; "
        "[pscustomobject]@{p=$_; s=[string]$s.Status; n=if($s.SignerCertificate){$s.SignerCertificate.GetNameInfo('SimpleName',$false)}else{''}} } "
        "| ConvertTo-Json -Compress", timeout=120, params=paths)  # type: ignore[arg-type]
    return {d["p"]: {"status": d.get("s", ""), "signer": d.get("n", "")} for d in as_list(data) if isinstance(d, dict) and d.get("p")}


# ---------------------------------------------------------------- startup items
RUN_KEYS = [
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKLM", r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
]


def command_target(command: str) -> str:
    """The program a startup command runs."""
    command = os.path.expandvars(command.strip())
    if command.startswith('"'):
        end = command.find('"', 1)
        return command[1:end] if end > 0 else command.strip('"')
    match = re.match(r"(.+?\.(?:exe|com|bat|cmd|vbs|js|ps1|scr|lnk|dll))\b", command, re.I)
    return match.group(1) if match else command.split(" ")[0]


def autoruns() -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for root, key in RUN_KEYS:
        for name, value in reg_values(root, key).items():
            if isinstance(value, str) and value:
                items.append({"where": f"{root}\\{key}", "name": name, "command": value, "path": command_target(value),
                              "kind": "registry", "removable": root == "HKCU"})
    for folder_key in ("startup", "common_startup"):
        folder = winutil.known_folder(folder_key)
        if folder.is_dir():
            for entry in folder.iterdir():
                if entry.name.lower() == "desktop.ini":
                    continue
                items.append({"where": str(folder), "name": entry.name, "command": str(entry), "path": str(entry),
                              "kind": "folder", "removable": folder_key == "startup"})
    tasks = winutil.powershell_json(
        "Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\\Microsoft\\*' -and $_.State -ne 'Disabled' } | "
        "ForEach-Object { foreach($a in $_.Actions){ if($a.Execute){ [pscustomobject]@{n=$_.TaskName; p=$_.TaskPath; "
        "e=$a.Execute; a=$a.Arguments} } } } | ConvertTo-Json -Compress", timeout=60)
    for t in as_list(tasks):
        if isinstance(t, dict) and t.get("e"):
            command = f'"{t["e"]}" {t.get("a") or ""}'.strip()
            items.append({"where": f"Task Scheduler {t.get('p', '')}", "name": t.get("n", ""), "command": command,
                          "path": os.path.expandvars(str(t["e"]).strip('"')), "kind": "task", "removable": False})
    return items


def assess_autoruns(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    sigs = signatures([i["path"] for i in items])
    risky_dirs = ("\\temp\\", "\\appdata\\local\\temp", "\\downloads\\", "\\public\\", "\\$recycle.bin", "\\programdata\\")
    for item in items:
        sig = sigs.get(item["path"], {})
        item["signature"] = sig.get("status", "")
        item["signer"] = sig.get("signer", "")
        reasons = []
        low = item["command"].lower()
        if any(d in item["path"].lower() for d in risky_dirs):
            reasons.append("runs_from_temp")
        if re.search(r"-e(nc|ncodedcommand)?\s+[a-z0-9+/=]{20,}", low) or "frombase64string" in low:
            reasons.append("encoded_command")
        if re.search(r"(mshta|wscript|cscript|regsvr32|rundll32)\b.*(http|javascript:|vbscript:)", low):
            reasons.append("lolbin_remote")
        if item["path"] and not Path(item["path"]).exists() and item["kind"] != "task":
            reasons.append("missing_file")
        if sig and sig.get("status") not in ("Valid", "") and Path(item["path"]).suffix.lower() in (".exe", ".dll", ".scr"):
            reasons.append("unsigned")
        item["reasons"] = reasons
        item["risk"] = "bad" if {"encoded_command", "lolbin_remote"} & set(reasons) or (
            "runs_from_temp" in reasons and "unsigned" in reasons) else ("warn" if reasons else "ok")
    return items


def remove_autorun(where: str, name: str) -> None:
    """Remove a startup entry the current user owns (HKCU Run keys, the user's Startup folder)."""
    for root, key in RUN_KEYS:
        if root == "HKCU" and where == f"{root}\\{key}":
            if not winutil.reg_delete(root, key, name):
                raise OSError("Windows refused to remove it.")
            return
    folder = winutil.known_folder("startup")
    if Path(where) == folder:
        target = folder / name
        if target.parent != folder or not target.exists():
            raise FileNotFoundError(name)
        # keep a copy so the change can be undone by hand
        backup = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "CyberScan" / "startup-removed"
        backup.mkdir(parents=True, exist_ok=True)
        target.replace(backup / f"{int(time.time())}-{name}")
        return
    raise PermissionError("This entry needs administrator rights to change; use Task Manager's Startup tab.")


# ---------------------------------------------------------------- security checks
def _check(cid: str, status: str, detail: str = "", fix: str = "", admin: bool = False, value: Any = None) -> dict[str, Any]:
    return {"id": cid, "status": status, "detail": detail, "fix": fix, "admin": admin, "value": value}


def defender() -> dict[str, Any]:
    data = winutil.powershell_json(
        "Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,"
        "BehaviorMonitorEnabled,IoavProtectionEnabled,AntivirusSignatureAge,IsTamperProtected,QuickScanAge,"
        "AntivirusSignatureLastUpdated | ConvertTo-Json -Compress", timeout=30)
    return data if isinstance(data, dict) else {}


def firewall_profiles() -> list[dict[str, Any]]:
    data = winutil.powershell_json("Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction | ConvertTo-Json -Compress")
    out = []
    for p in as_list(data):
        if isinstance(p, dict):
            enabled = p.get("Enabled")
            out.append({"name": p.get("Name", ""), "enabled": enabled in (True, 1, "True"),
                        "inbound": {0: "NotConfigured", 2: "Allow", 4: "Block"}.get(p.get("DefaultInboundAction"), str(p.get("DefaultInboundAction")))})
    if not out:
        code, text = winutil.run(["netsh", "advfirewall", "show", "allprofiles", "state"])
        for name, state in re.findall(r"(\w+) Profile Settings:.*?State\s+(ON|OFF)", text, re.S | re.I):
            out.append({"name": name, "enabled": state.upper() == "ON", "inbound": ""})
    return out


def antivirus_products() -> list[dict[str, Any]]:
    """Antivirus products registered with Windows Security Center, and whether each is on."""
    data = winutil.powershell_json(
        "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | "
        "Select-Object displayName,productState | ConvertTo-Json -Compress")
    out = []
    for p in as_list(data):
        if isinstance(p, dict) and isinstance(p.get("productState"), int):
            state = p["productState"]
            out.append({"name": p.get("displayName", ""), "on": (state >> 12) & 0xF == 1,
                        "up_to_date": state & 0xFF == 0})
    return out


def security_checks() -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    others = [p for p in antivirus_products() if p["on"] and "defender" not in p["name"].lower()]
    d = defender()
    if others:
        # another antivirus is active: Windows turns Defender's real-time part off on purpose
        names = ", ".join(p["name"] for p in others)
        stale = [p["name"] for p in others if not p["up_to_date"]]
        checks.append(_check("antivirus", "ok", names, value=names))
        checks.append(_check("defender_sigs", "warn" if stale else "ok", ", ".join(stale), "", value=0))
    elif d:
        rt = bool(d.get("RealTimeProtectionEnabled"))
        age = d.get("AntivirusSignatureAge")
        checks.append(_check("defender_rt", "ok" if rt else "bad", "", "" if rt else "defender_on", admin=True, value=rt))
        if isinstance(age, int):
            checks.append(_check("defender_sigs", "ok" if age <= 3 else ("warn" if age <= 10 else "bad"), str(age),
                                 "" if age <= 3 else "defender_update", value=age))
        checks.append(_check("tamper", "ok" if d.get("IsTamperProtected") else "warn", "", "" if d.get("IsTamperProtected") else "open_security"))
    else:
        checks.append(_check("defender_rt", "unknown", "", "open_security"))
    profiles = firewall_profiles()
    if profiles:
        off = [p["name"] for p in profiles if not p["enabled"]]
        checks.append(_check("firewall", "bad" if off else "ok", ", ".join(off), "firewall_on" if off else "", admin=True, value=not off))
    else:
        checks.append(_check("firewall", "unknown", "", "open_firewall"))
    lua = reg_read("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA")
    prompt = reg_read("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "ConsentPromptBehaviorAdmin")
    if lua == 0:
        checks.append(_check("uac", "bad", "off", "open_uac"))
    else:
        checks.append(_check("uac", "warn" if prompt == 0 else "ok", "silent" if prompt == 0 else "", "open_uac" if prompt == 0 else ""))
    smart = reg_read("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer", "SmartScreenEnabled")
    policy = reg_read("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\System", "EnableSmartScreen")
    if policy == 0 or (isinstance(smart, str) and smart.lower() == "off"):
        checks.append(_check("smartscreen", "bad", "off", "open_smartscreen"))
    else:
        checks.append(_check("smartscreen", "ok"))
    sb = reg_read("HKLM", r"SYSTEM\CurrentControlSet\Control\SecureBoot\State", "UEFISecureBootEnabled")
    checks.append(_check("secure_boot", "ok" if sb == 1 else ("warn" if sb == 0 else "unknown")))
    hvci = reg_read("HKLM", r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity", "Enabled")
    checks.append(_check("memory_integrity", "ok" if hvci == 1 else "warn", "", "" if hvci == 1 else "open_core_isolation"))
    ppl = reg_read("HKLM", r"SYSTEM\CurrentControlSet\Control\Lsa", "RunAsPPL")
    checks.append(_check("lsa", "ok" if ppl in (1, 2) else "warn", "", "" if ppl in (1, 2) else "open_core_isolation"))
    code, out = winutil.powershell("(New-Object -ComObject Shell.Application).NameSpace('C:').Self.ExtendedProperty('System.Volume.BitLockerProtection')")
    bl = out.strip()
    checks.append(_check("encryption", "ok" if bl in ("1", "3", "5") else ("warn" if bl == "2" else "unknown"), bl,
                         "open_encryption" if bl == "2" else ""))
    last = winutil.powershell_json(
        "Get-HotFix | Where-Object InstalledOn | Sort-Object InstalledOn -Descending | Select-Object -First 1 "
        "@{n='d';e={$_.InstalledOn.ToString('yyyy-MM-dd')}},HotFixID | ConvertTo-Json -Compress", timeout=40)
    if isinstance(last, dict) and last.get("d"):
        try:
            days = int((time.time() - time.mktime(time.strptime(last["d"], "%Y-%m-%d"))) // 86400)
        except ValueError:
            days = -1
        checks.append(_check("updates", "ok" if 0 <= days <= 40 else ("warn" if days <= 90 else "bad"), last["d"],
                             "" if 0 <= days <= 40 else "open_update", value=days))
    else:
        checks.append(_check("updates", "unknown", "", "open_update"))
    rdp = reg_read("HKLM", r"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections")
    nla = reg_read("HKLM", r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", "UserAuthentication")
    if rdp == 0:
        checks.append(_check("rdp", "warn" if nla == 1 else "bad", "nla" if nla == 1 else "no_nla", "rdp_off", admin=True))
    else:
        checks.append(_check("rdp", "ok"))
    smb1 = reg_read("HKLM", r"SYSTEM\CurrentControlSet\Services\mrxsmb10", "Start")
    checks.append(_check("smb1", "bad" if smb1 in (1, 2, 3) else "ok", "", "smb1_off" if smb1 in (1, 2, 3) else "", admin=True))
    auto = reg_read("HKLM", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "AutoAdminLogon")
    stored = reg_read("HKLM", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "DefaultPassword")
    checks.append(_check("autologon", "bad" if str(auto) == "1" and stored else ("warn" if str(auto) == "1" else "ok"), "",
                         "open_signin" if str(auto) == "1" else ""))
    hosts = hosts_tampering()
    checks.append(_check("hosts", "bad" if hosts else "ok", ", ".join(hosts[:5]), "hosts_fix" if hosts else "", admin=True, value=hosts))
    usb = reg_read("HKLM", r"SYSTEM\CurrentControlSet\Services\USBSTOR", "Start")
    checks.append(_check("usb_autorun", "ok" if reg_read("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoDriveTypeAutoRun") in (255, 0xFF, 145, 0x91) else "warn",
                         "", "autorun_off", admin=True, value=usb))
    return checks


SENSITIVE_HOSTS = ("google.com", "microsoft.com", "windowsupdate.com", "paypal.com", "facebook.com", "apple.com",
                   "amazon.com", "bank", "login", "live.com", "office.com", "github.com", "virustotal.com",
                   "avast.com", "kaspersky", "eset.com", "malwarebytes", "bitdefender", "norton", "mcafee")


def hosts_entries() -> list[tuple[str, str]]:
    path = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "drivers" / "etc" / "hosts"
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    out = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        parts = line.split()
        if len(parts) >= 2:
            for host in parts[1:]:
                out.append((parts[0], host.lower()))
    return out


def hosts_tampering() -> list[str]:
    """Host names of well-known sites that the hosts file sends somewhere else. Pointing a
    security vendor at 0.0.0.0 is what malware does to stop updates; pointing a bank at
    another address is how pharming works."""
    sink = ("127.0.0.1", "0.0.0.0", "::1", "::")
    defence = ("avast", "kaspersky", "eset", "malwarebytes", "bitdefender", "norton", "mcafee", "virustotal",
               "windowsupdate", "update.microsoft", "defender", "sophos", "trendmicro")
    bad = []
    for ip, host in hosts_entries():
        if host in ("localhost", "localhost.localdomain") or host.endswith(".local"):
            continue
        redirected = ip not in sink and any(s in host for s in SENSITIVE_HOSTS)   # pharming
        silenced = ip in sink and any(s in host for s in defence)                 # stops security updates
        if redirected or silenced:
            bad.append(host)
    return bad


FIX_URIS = {
    "open_security": "windowsdefender:", "open_firewall": "windowsdefender://network", "open_update": "ms-settings:windowsupdate",
    "open_uac": "ms-settings:about", "open_smartscreen": "windowsdefender://appbrowser",
    "open_core_isolation": "windowsdefender://coreisolation", "open_encryption": "ms-settings:deviceencryption",
    "open_signin": "ms-settings:signinoptions", "open_privacy_camera": "ms-settings:privacy-webcam",
    "open_privacy_mic": "ms-settings:privacy-microphone", "open_wifi": "ms-settings:network-wifi",
    "open_startup": "ms-settings:startupapps", "open_remote": "ms-settings:remotedesktop",
}

FIX_SCRIPTS = {
    "defender_on": "Set-MpPreference -DisableRealtimeMonitoring $false -DisableBehaviorMonitoring $false -DisableIOAVProtection $false",
    "defender_update": "Update-MpSignature",
    "firewall_on": "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True",
    "rdp_off": "Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections -Value 1",
    "rdp_nla": "Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name UserAuthentication -Value 1",
    "smb1_off": "Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\mrxsmb10' -Name Start -Value 4",
    "autorun_off": "New-Item 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' -Force | Out-Null; "
                   "Set-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' -Name NoDriveTypeAutoRun -Value 255 -Type DWord",
    "hosts_fix": "$h=\"$env:SystemRoot\\System32\\drivers\\etc\\hosts\"; Copy-Item $h \"$h.cyberscan.bak\" -Force; "
                 "$bad=@($P); (Get-Content $h) | Where-Object { $l=$_; -not ($bad | Where-Object { $l -match ('\\s' + [regex]::Escape($_) + '(\\s|$)') -and $l -notmatch '^\\s*#' }) } | Set-Content $h -Encoding ASCII",
    "usb_block": "Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR' -Name Start -Value 4",
    "usb_allow": "Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR' -Name Start -Value 3",
    "cfa_on": "Set-MpPreference -EnableControlledFolderAccess Enabled; foreach($f in $P){ Add-MpPreference -ControlledFolderAccessProtectedFolders $f }",
    "cfa_off": "Set-MpPreference -EnableControlledFolderAccess Disabled",
    "boot_scan": "Start-MpWDOScan",
}


def fix(fix_id: str, params: Any = None) -> dict[str, Any]:
    if fix_id in FIX_URIS:
        return {"ok": winutil.open_uri(FIX_URIS[fix_id]), "opened": True}
    script = FIX_SCRIPTS.get(fix_id)
    if script is None:
        raise ValueError("unknown fix")
    if fix_id == "hosts_fix" and params is None:
        params = hosts_tampering()
    ok, message = winutil.elevated(script, params if params is not None else None)
    return {"ok": ok, "message": "cancelled" if message == "cancelled" else ("" if ok else message[-300:]), "admin": True}


def usb_storage_blocked() -> bool | None:
    value = reg_read("HKLM", r"SYSTEM\CurrentControlSet\Services\USBSTOR", "Start")
    return None if value is None else value == 4


def controlled_folder_access() -> str:
    code, out = winutil.powershell("(Get-MpPreference).EnableControlledFolderAccess")
    return {"0": "off", "1": "on", "2": "audit"}.get(out.strip(), "unknown")
