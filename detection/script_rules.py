"""Script and command-line tradecraft rules.

Complements ``core.heuristic_engine`` (PowerShell download/IEX patterns) with living-off-the-land
binaries, persistence, defence evasion, ransomware precursors and miners. Each rule needs a
specific command shape, not a bare keyword, to keep false positives on documentation low.
"""
from __future__ import annotations

import re
from typing import Any

from detection.host import core_content_findings

# (label, severity, contribution, explanation, pattern)
_RULES: list[tuple[str, str, int, str, str]] = [
    ("Script host creates a shell object", "medium", 30,
     "Script creates WScript.Shell / Shell.Application, which can run arbitrary commands.",
     r"(?:ActiveXObject|CreateObject|GetObject)\s*\(\s*[\"'](?:WScript\.Shell|Shell\.Application|Schedule\.Service)[\"']"),
    ("certutil used to download or decode", "high", 45,
     "certutil is abused to download files or decode base64 payloads (T1140 / T1105).",
     r"\bcertutil(?:\.exe)?\b[^\r\n]{0,80}\s[-/](?:urlcache|decode|decodehex)\b"),
    ("mshta runs remote or inline script", "high", 45,
     "mshta executes HTML applications from a URL or inline script (T1218.005).",
     r"\bmshta(?:\.exe)?\s+(?:[\"']?(?:https?:|vbscript:|javascript:))"),
    ("regsvr32 scriptlet execution", "high", 50,
     "regsvr32 /i:<url> scrobj.dll (\"Squiblydoo\") runs remote scriptlets (T1218.010).",
     r"\bregsvr32(?:\.exe)?\b[^\r\n]{0,80}/i:\s*[\"']?https?://"),
    ("rundll32 runs script or remote code", "high", 40,
     "rundll32 invoking javascript:/url.dll or a remote path is a known proxy-execution trick (T1218.011).",
     r"\brundll32(?:\.exe)?\b[^\r\n]{0,60}(?:javascript:|url\.dll,|\\\\\\\\\S+\\\S+\.dll)"),
    ("bitsadmin file transfer", "medium", 30, "bitsadmin /transfer downloads files in the background (T1197).",
     r"\bbitsadmin(?:\.exe)?\b[^\r\n]{0,40}/transfer\b"),
    ("Run-key persistence", "high", 40, "A registry Run/RunOnce key is written so a program starts at every logon (T1547.001).",
     r"(?:reg(?:\.exe)?\s+add|New-ItemProperty|Set-ItemProperty|RegWrite)[^\r\n]{0,120}\\CurrentVersion\\Run(?:Once)?\b"),
    ("Scheduled task created", "medium", 25, "A scheduled task is created for execution or persistence (T1053.005).",
     r"\bschtasks(?:\.exe)?\s+/create\b|\bRegister-ScheduledTask\b"),
    ("Shadow copy deletion", "high", 55, "Deleting volume shadow copies prevents recovery; a ransomware precursor (T1490).",
     r"\bvssadmin(?:\.exe)?\s+delete\s+shadows\b|\bwmic(?:\.exe)?\s+shadowcopy\s+delete\b|\bwbadmin\s+delete\s+catalog\b|"
     r"Win32_ShadowCopy[^\r\n]{0,60}\.Delete"),
    ("Boot recovery disabled", "high", 45, "bcdedit is used to disable Windows recovery, a ransomware precursor (T1490).",
     r"\bbcdedit(?:\.exe)?\b[^\r\n]{0,40}(?:recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)"),
    ("Security tooling disabled", "high", 45, "The script turns off Microsoft Defender or firewall protection (T1562.001).",
     r"Set-MpPreference[^\r\n]{0,60}-Disable(?:RealtimeMonitoring|BehaviorMonitoring|IOAVProtection|ScriptScanning)\s+\$?true|"
     r"Add-MpPreference[^\r\n]{0,30}-ExclusionPath|netsh\s+(?:adv)?firewall\s+set\s+[^\r\n]{0,40}state\s+off"),
    ("Event logs cleared", "high", 40, "Clearing event logs removes evidence (T1070.001).",
     r"\bwevtutil(?:\.exe)?\s+cl\b|\bClear-EventLog\b"),
    ("Execution policy bypass with hidden window", "medium", 25,
     "PowerShell runs hidden with the execution policy bypassed, a common launcher pattern.",
     r"powershell(?:\.exe)?[^\r\n]{0,80}-(?:ep|exec(?:utionpolicy)?)\s+bypass[^\r\n]{0,80}-w(?:indowstyle)?\s+h(?:idden)?|"
     r"powershell(?:\.exe)?[^\r\n]{0,80}-w(?:indowstyle)?\s+h(?:idden)?[^\r\n]{0,80}-(?:ep|exec(?:utionpolicy)?)\s+bypass"),
    ("Reflective .NET assembly load", "high", 40, "An assembly is loaded from bytes in memory, avoiding files on disk (T1620).",
     r"\[(?:System\.)?Reflection\.Assembly\]::Load\s*\(|\bAssembly\.Load\s*\(\s*(?:\[Convert\]::FromBase64String|\$)"),
    ("AMSI bypass", "critical", 70, "The script tampers with the Antimalware Scan Interface to blind security products.",
     r"AmsiUtils|amsiInitFailed|AmsiScanBuffer"),
    ("Credential dumping tooling", "critical", 70, "References to credential-dumping tools or LSASS memory dumping (T1003).",
     r"\bsekurlsa::|\blsadump::|Invoke-Mimikatz|comsvcs(?:\.dll)?[, \t]+#?(?:MiniDump|24)[ \t]+[\d$%]|procdump[^\r\n]{0,40}lsass"),
    ("Cryptominer pool protocol", "high", 45, "A stratum mining-pool URL indicates cryptocurrency mining (T1496).",
     r"\bstratum\+(?:tcp|ssl|tls)://"),
    ("Reverse shell one-liner", "critical", 70, "A shell is connected to a remote socket, giving an attacker interactive control.",
     r"\bbash\s+-i\s+>&\s*/dev/tcp/|\bnc(?:at)?\s+(?:-e|-c)\s+/bin/(?:ba)?sh|"
     r"socket\.socket\([^)]*\)[^\r\n]{0,200}(?:dup2|subprocess)[^\r\n]{0,200}/bin/(?:ba)?sh|"
     r"New-Object\s+(?:System\.)?Net\.Sockets\.TCPClient\s*\([^)]*\)[^\r\n]{0,400}(?:iex|Invoke-Expression)"),
    ("Download piped to shell", "high", 45, "Remote content is downloaded and executed directly by a shell.",
     r"\b(?:curl|wget)\b[^\r\n|]{0,200}\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b"),
    ("Linux persistence or preload hijack", "high", 40, "Writes to ld.so.preload, cron or shell start-up files for persistence or rootkit loading.",
     r"/etc/ld\.so\.preload|echo[^\r\n]{0,200}>>\s*(?:/etc/crontab|/var/spool/cron|~?/?\.bashrc)"),
]
# ``\s`` would match the newlines that separate strings extracted from binaries, letting a rule
# stitch unrelated strings together; whitespace inside a command therefore means spaces/tabs only.
_COMPILED = [(label, severity, weight, explanation, re.compile(pattern.replace(r"\s", r"[ \t]"), re.IGNORECASE))
             for label, severity, weight, explanation, pattern in _RULES]


def scan_command_text(text: str) -> list[dict[str, Any]]:
    """Run the tradecraft rules only (no core heuristics)."""
    findings = []
    for label, severity, weight, explanation, pattern in _COMPILED:
        match = pattern.search(text)
        if match:
            findings.append({"label": label, "severity": severity, "contribution": weight, "explanation": explanation,
                             "matched": match.group(0)[:120]})
    return findings


def scan_script_text(text: str) -> list[dict[str, Any]]:
    """Core heuristic content rules plus the tradecraft rules, for script files found in containers."""
    content = (text or "")[:500_000]
    core = core_content_findings(content)
    return core + scan_command_text(content)
