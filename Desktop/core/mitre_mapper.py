from __future__ import annotations

from typing import Any, Iterable

# Lower-case indicator fragment -> (technique id, technique name).
# Matching is "fragment appears inside the indicator" only; the old reverse test
# ("indicator appears inside the fragment") mapped unrelated short words such as "process".
MITRE_RULES = {
    "powershell": ("T1059.001", "PowerShell"),
    "encoded powershell": ("T1059.001", "PowerShell"),
    "obfuscated command": ("T1027", "Obfuscated Files or Information"),
    "obfuscat": ("T1027", "Obfuscated Files or Information"),
    "high entropy": ("T1027.002", "Software Packing"),
    "packed": ("T1027.002", "Software Packing"),
    "double extension": ("T1036.007", "Masquerading: Double File Extension"),
    "header mismatch": ("T1036.008", "Masquerading: Masquerade File Type"),
    "in-memory script execution": ("T1059", "Command and Scripting Interpreter"),
    "remote payload download": ("T1105", "Ingress Tool Transfer"),
    "downloadstring": ("T1105", "Ingress Tool Transfer"),
    "webhook or bot api": ("T1567", "Exfiltration Over Web Service"),
    "shadow copy deletion": ("T1490", "Inhibit System Recovery"),
    "vssadmin delete shadows": ("T1490", "Inhibit System Recovery"),
    "virtualalloc": ("T1055", "Process Injection"),
    "writeprocessmemory": ("T1055", "Process Injection"),
    "createremotethread": ("T1055", "Process Injection"),
    "queueuserapc": ("T1055.004", "Asynchronous Procedure Call"),
    "process injection": ("T1055", "Process Injection"),
    "remote thread": ("T1055", "Process Injection"),
    "suspicious import api": ("T1055", "Process Injection"),
    "suspicious pe imports": ("T1055", "Process Injection"),
    "isdebuggerpresent": ("T1622", "Debugger Evasion"),
    "setwindowshookex": ("T1056.004", "Credential API Hooking"),
    # detection/ package labels
    "capability: process injection": ("T1055", "Process Injection"),
    "capability: process hollowing": ("T1055.012", "Process Hollowing"),
    "capability: keylogging": ("T1056.001", "Keylogging"),
    "capability: downloader": ("T1105", "Ingress Tool Transfer"),
    "capability: screen capture": ("T1113", "Screen Capture"),
    "credential theft indicators": ("T1555.003", "Credentials from Web Browsers"),
    "known packer": ("T1027.002", "Software Packing"),
    "vba macro": ("T1059.005", "Visual Basic"),
    "macro with dangerous": ("T1059.005", "Visual Basic"),
    "auto-executing macro": ("T1204.002", "User Execution: Malicious File"),
    "xlm) macro": ("T1059.005", "Visual Basic"),
    "remote template injection": ("T1221", "Template Injection"),
    "dde field": ("T1559.002", "Dynamic Data Exchange"),
    "dde link": ("T1559.002", "Dynamic Data Exchange"),
    "pdf auto-executes javascript": ("T1059.007", "JavaScript"),
    "pdf contains javascript": ("T1059.007", "JavaScript"),
    "pdf launch action": ("T1204.002", "User Execution: Malicious File"),
    "equation editor object": ("T1203", "Exploitation for Client Execution"),
    "ole2link object": ("T1203", "Exploitation for Client Execution"),
    "embedded executable": ("T1204.002", "User Execution: Malicious File"),
    "pdf embeds an executable": ("T1204.002", "User Execution: Malicious File"),
    "external object loaded on open": ("T1221", "Template Injection"),
    "unc or file path reference": ("T1187", "Forced Authentication"),
    "suspicious link in": ("T1566.002", "Phishing: Spearphishing Link"),
    "brand impersonation": ("T1566.002", "Phishing: Spearphishing Link"),
    "lookalike (homoglyph) domain": ("T1566.002", "Phishing: Spearphishing Link"),
    "typosquatting domain": ("T1566.002", "Phishing: Spearphishing Link"),
    "password-protected archive with executables": ("T1027.013", "Encrypted/Encoded File"),
    "password-protected office document": ("T1027.013", "Encrypted/Encoded File"),
    "certutil used": ("T1140", "Deobfuscate/Decode Files or Information"),
    "mshta runs": ("T1218.005", "Mshta"),
    "regsvr32 scriptlet": ("T1218.010", "Regsvr32"),
    "rundll32 runs": ("T1218.011", "Rundll32"),
    "bitsadmin file transfer": ("T1197", "BITS Jobs"),
    "run-key persistence": ("T1547.001", "Registry Run Keys / Startup Folder"),
    "scheduled task created": ("T1053.005", "Scheduled Task"),
    "boot recovery disabled": ("T1490", "Inhibit System Recovery"),
    "security tooling disabled": ("T1562.001", "Impair Defenses: Disable or Modify Tools"),
    "amsi bypass": ("T1562.001", "Impair Defenses: Disable or Modify Tools"),
    "event logs cleared": ("T1070.001", "Clear Windows Event Logs"),
    "reflective .net assembly load": ("T1620", "Reflective Code Loading"),
    "credential dumping tooling": ("T1003", "OS Credential Dumping"),
    "cryptominer pool protocol": ("T1496", "Resource Hijacking"),
    "download piped to shell": ("T1105", "Ingress Tool Transfer"),
    "linux persistence or preload": ("T1574.006", "Dynamic Linker Hijacking"),
    "script host creates a shell object": ("T1059.005", "Visual Basic"),
}


def map_findings_to_mitre(
    findings: Iterable[str] | None = None,
    yara_matches: Iterable[dict[str, Any]] | None = None,
    pe_summary: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    indicators: list[str] = []
    if findings:
        indicators.extend(findings)
    if yara_matches:
        for match in yara_matches:
            indicators.append(match.get("rule_name", ""))
            indicators.extend(match.get("tags", []))
            indicators.append(match.get("description", ""))
    if pe_summary and pe_summary.get("suspicious_imports"):
        indicators.extend(pe_summary.get("suspicious_imports", []))

    by_technique: dict[str, dict[str, Any]] = {}
    for indicator in indicators:
        if not indicator:
            continue
        normalized = str(indicator).lower()
        for fragment, (technique_id, technique_name) in MITRE_RULES.items():
            if fragment not in normalized:
                continue
            entry = by_technique.setdefault(
                technique_id, {"id": technique_id, "name": technique_name, "evidence": []}
            )
            if str(indicator) not in entry["evidence"]:
                entry["evidence"].append(str(indicator))

    if not by_technique:
        return [{"id": "N/A", "name": "No mapped ATT&CK technique", "evidence": []}]
    return list(by_technique.values())
