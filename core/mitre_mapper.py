from __future__ import annotations

from typing import Any, Iterable

MITRE_RULES = {
    "powershell": ("T1059.001", "PowerShell"),
    "encoded powershell": ("T1059.001", "PowerShell"),
    "obfuscated powershell": ("T1059.001", "PowerShell"),
    "shadow copy deletion": ("T1490", "Inhibit System Recovery"),
    "vssadmin delete shadows": ("T1490", "Inhibit System Recovery"),
    "virtualalloc": ("T1055", "Process Injection"),
    "writeprocessmemory": ("T1055", "Process Injection"),
    "createremotethread": ("T1055", "Process Injection"),
    "isdebuggerpresent": ("T1622", "Debugger Evasion"),
    "process injection": ("T1055", "Process Injection"),
    "remote thread": ("T1055", "Process Injection"),
    "suspicious import api": ("T1055", "Process Injection"),
    "entropy discontinuity": ("T1027", "Obfuscated Files or Information"),
    "high entropy": ("T1027", "Obfuscated Files or Information"),
    "anti-disassembly": ("T1027", "Obfuscated Files or Information"),
    "xor decryption": ("T1027", "Obfuscated Files or Information"),
    "api hashing": ("T1027", "Obfuscated Files or Information"),
    "structural obfuscation": ("T1027", "Obfuscated Files or Information"),
    "getsysteminfo": ("T1082", "System Information Discovery"),
    "getcomputername": ("T1082", "System Information Discovery"),
    "globalmemorystatusex": ("T1082", "System Information Discovery"),
    "getversionex": ("T1082", "System Information Discovery"),
}


def map_findings_to_mitre(
    findings: Iterable[str] | None = None,
    yara_matches: Iterable[dict[str, Any]] | None = None,
    pe_summary: dict[str, Any] | None = None,
) -> list[dict[str, str | list[str]]]:
    seen: set[str] = set()
    results: list[dict[str, str | list[str]]] = []
    combined = []

    if findings:
        combined.extend(findings)
    if yara_matches:
        for match in yara_matches:
            combined.append(match.get("rule_name", ""))
            combined.extend(match.get("tags", []))
            combined.append(match.get("description", ""))
    if pe_summary and pe_summary.get("suspicious_imports"):
        combined.extend(pe_summary.get("suspicious_imports", []))
    if pe_summary:
        combined.extend(pe_summary.get("import_names", []))
        cfg = pe_summary.get("cfg_topology", {})
        if isinstance(cfg, dict):
            combined.extend(cfg.get("detected_patterns", []))

    for indicator in combined:
        if not indicator:
            continue
        normalized = str(indicator).lower()
        for key, (technique_id, technique_name) in MITRE_RULES.items():
            if key in normalized or normalized in key:
                technique_key = f"{technique_id}:{technique_name}"
                if technique_key in seen:
                    continue
                seen.add(technique_key)
                results.append({
                    "id": technique_id,
                    "name": technique_name,
                    "evidence": [str(indicator)],
                })

    if not results:
        return [{"id": "N/A", "name": "No mapped ATT&CK technique", "evidence": []}]
    return results
