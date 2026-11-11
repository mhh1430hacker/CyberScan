from __future__ import annotations

from pathlib import Path
from typing import Any

try:
    import pefile
except Exception:  # pragma: no cover - optional dependency
    pefile = None

from core.entropy import shannon_entropy

from detection.executables import CAPABILITIES

# Kept for backward compatibility (callers may import it). Membership alone is no longer evidence:
# IsDebuggerPresent, OpenProcess and CreateProcessW are imported by the MSVC runtime and ordinary
# programs. ``suspicious_imports`` below lists only APIs that complete a capability combination.
SUSPICIOUS_IMPORTS = {
    "VirtualAlloc",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "CreateToolhelp32Snapshot",
    "IsDebuggerPresent",
    "NtAllocateVirtualMemory",
    "SetWindowsHookEx",
    "QueueUserAPC",
    "OpenProcess",
    "CreateProcessA",
    "CreateProcessW",
}


def capability_imports(import_names: set[str], exported_names: set[str] | None = None) -> tuple[list[str], list[str]]:
    """Return (capabilities, APIs) for every capability whose required API groups are all present.

    A DLL that *exports* these APIs (kernel32, kernelbase, ntdll) is their provider, not a user of them.
    """
    capabilities, apis = [], set()
    if exported_names and exported_names & {api for groups, *_ in CAPABILITIES.values() for group in groups for api in group}:
        return [], []
    for name, (groups, *_rest) in CAPABILITIES.items():
        matched = [group & import_names for group in groups]
        if all(matched):
            capabilities.append(name)
            for group in matched:
                apis.update(group)
    return capabilities, sorted(apis)


def normalize_import_name(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("latin-1", errors="ignore")
    return str(value)


def analyze_pe_file(file_path: str | Path) -> dict[str, Any]:
    path = Path(file_path)
    if not path.exists():
        return {
            "status": "missing",
            "is_pe": False,
            "risk_score": 0,
            "findings": [],
            "error": f"File not found: {path}",
        }

    if pefile is None:
        return {
            "status": "dependency_missing",
            "is_pe": False,
            "risk_score": 0,
            "findings": [],
            "error": "pefile is not installed. PE analysis is unavailable.",
        }

    try:
        pe = pefile.PE(str(path))
    except Exception as exc:
        return {
            "status": "not_pe",
            "is_pe": False,
            "risk_score": 0,
            "findings": [],
            "error": f"Not a valid PE binary or parsing failed: {exc}",
        }

    sections: list[dict[str, Any]] = []
    high_entropy_sections: list[str] = []
    suspicious_imports: list[str] = []

    for section in getattr(pe, "sections", []):
        section_name = section.Name.decode("ascii", errors="ignore").rstrip("\x00")
        data = section.get_data() or b""
        entropy = shannon_entropy(data)
        if entropy > 7.0:
            high_entropy_sections.append(section_name)
        sections.append({
            "name": section_name,
            "virtual_size": section.Misc_VirtualSize,
            "raw_size": section.SizeOfRawData,
            "entropy": entropy,
            "high_entropy": entropy > 7.0,
        })

    import_names: list[str] = []
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        for imp in entry.imports or []:
            api_name = normalize_import_name(getattr(imp, "name", None))
            if not api_name:
                continue
            import_names.append(api_name)

    exported = {
        symbol.name.decode("latin-1", "ignore")
        for symbol in getattr(getattr(pe, "DIRECTORY_ENTRY_EXPORT", None), "symbols", [])[:20000]
        if symbol.name
    }
    capabilities, suspicious_imports = capability_imports(set(import_names), exported)
    risk_score = 0
    findings: list[str] = []
    if suspicious_imports:
        risk_score += 35
        findings.append(f"Import combinations implement: {', '.join(c.replace('_', ' ') for c in capabilities)}.")
    if high_entropy_sections:
        risk_score += 20
        findings.append("High-entropy PE sections detected.")
    if getattr(pe, "OPTIONAL_HEADER", None) is not None:
        if getattr(pe.OPTIONAL_HEADER, "Subsystem", 0) == 3:
            risk_score += 5
            findings.append("Console subsystem is present; not inherently malicious, but recorded for review.")
    risk_score = max(0, min(100, risk_score))

    return {
        "status": "ok",
        "is_pe": True,
        "risk_score": risk_score,
        "findings": findings,
        "suspicious_imports": suspicious_imports,
        "capabilities": capabilities,
        "import_names": sorted(set(import_names)),
        "section_count": len(sections),
        "high_entropy_sections": high_entropy_sections,
        "sections": sections,
        "header_summary": {
            "machine": getattr(getattr(pe, "FILE_HEADER", None), "Machine", None),
            "number_of_sections": getattr(getattr(pe, "FILE_HEADER", None), "NumberOfSections", None),
            "timestamp": getattr(getattr(pe, "FILE_HEADER", None), "TimeDateStamp", None),
        },
        "error": None,
    }
