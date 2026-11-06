from __future__ import annotations

from pathlib import Path
from typing import Any

try:
    import pefile
except Exception:  # pragma: no cover - optional dependency
    pefile = None

from core.entropy import shannon_entropy

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
CFG_ANALYSIS_LIMIT = 1_048_576


def _empty_cfg_summary(status: str) -> dict[str, Any]:
    return {
        "status": status,
        "basic_block_count": 0,
        "cyclomatic_complexity": 0,
        "graph_density": 0.0,
        "branching_ratio": 0.0,
        "instruction_count": 0,
        "edge_count": 0,
        "detected_patterns": [],
    }


def normalize_import_name(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("latin-1", errors="ignore")
    return str(value)


VERSION_INFO_KEYS = ("FileDescription", "ProductName", "CompanyName", "InternalName", "OriginalFilename")


def read_version_info(pe: Any) -> dict[str, str]:
    """What the program says it is: the StringFileInfo fields of its version resource."""
    claims: dict[str, str] = {}
    for file_info in getattr(pe, "FileInfo", None) or []:
        for entry in file_info if isinstance(file_info, list) else [file_info]:
            for table in getattr(entry, "StringTable", None) or []:
                for key, value in (getattr(table, "entries", None) or {}).items():
                    name = normalize_import_name(key)
                    if name in VERSION_INFO_KEYS and name not in claims:
                        raw = value if isinstance(value, bytes) else str(value).encode("utf-8", "replace")
                        text = raw.decode("utf-8", errors="replace").strip("\x00 ")[:256]
                        if text:
                            claims[name] = text
    return claims


def analyze_pe_file(file_path: str | Path, data: bytes | None = None) -> dict[str, Any]:
    path = Path(file_path)
    if data is None and not path.exists():
        return {
            "status": "missing",
            "is_pe": False,
            "risk_score": 0,
            "findings": [],
            "cfg_topology": _empty_cfg_summary("unavailable"),
            "error": f"File not found: {path}",
        }

    if pefile is None:
        return {
            "status": "dependency_missing",
            "is_pe": False,
            "risk_score": 0,
            "findings": [],
            "cfg_topology": _empty_cfg_summary("dependency_missing"),
            "error": "pefile is not installed. PE analysis is unavailable.",
        }

    try:
        pe = pefile.PE(data=data) if data is not None else pefile.PE(str(path))
    except Exception as exc:
        return {
            "status": "not_pe",
            "is_pe": False,
            "risk_score": 0,
            "findings": [],
            "cfg_topology": _empty_cfg_summary("not_pe"),
            "error": f"Not a valid PE binary or parsing failed: {exc}",
        }

    file_bytes = data
    sections: list[dict[str, Any]] = []
    high_entropy_sections: list[str] = []
    suspicious_imports: list[str] = []

    for section in getattr(pe, "sections", []):
        section_name = section.Name.decode("ascii", errors="ignore").rstrip("\x00")
        section_data = section.get_data() or b""
        entropy = shannon_entropy(section_data)
        raw_offset = int(getattr(section, "PointerToRawData", 0))
        raw_size = int(getattr(section, "SizeOfRawData", 0))
        raw_end = raw_offset + len(section_data)
        raw_range_verified = bool(
            file_bytes is not None
            and raw_offset >= 0
            and raw_end <= len(file_bytes)
            and len(section_data) == raw_size
            and memoryview(file_bytes)[raw_offset:raw_end] == section_data
        )
        if entropy > 7.0:
            high_entropy_sections.append(section_name)
        sections.append({
            "name": section_name,
            "virtual_size": section.Misc_VirtualSize,
            "raw_size": raw_size,
            "raw_data_length": len(section_data),
            "raw_offset": raw_offset,
            "virtual_address": int(section.VirtualAddress),
            "executable": bool(int(getattr(section, "Characteristics", 0)) & 0x20000000),
            "raw_range_verified": raw_range_verified,
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
            if api_name.casefold() in {item.casefold() for item in SUSPICIOUS_IMPORTS}:
                suspicious_imports.append(api_name)

    executable_sections = [
        section for section in getattr(pe, "sections", [])
        if int(getattr(section, "Characteristics", 0)) & 0x20000000
    ]
    cfg_topology = _empty_cfg_summary("no_executable_sections")
    if executable_sections:
        try:
            entrypoint = int(getattr(getattr(pe, "OPTIONAL_HEADER", None), "AddressOfEntryPoint", 0))
            entrypoint_sections = [
                section for section in executable_sections
                if int(section.VirtualAddress) <= entrypoint <
                int(section.VirtualAddress) + max(int(section.Misc_VirtualSize), int(section.SizeOfRawData))
            ]
            code_section = entrypoint_sections[0] if entrypoint_sections else max(
                executable_sections,
                key=lambda section: int(section.SizeOfRawData),
            )
            code_sample = (code_section.get_data() or b"")[:CFG_ANALYSIS_LIMIT]
            from core.nextgen_engine import NextGenCyberEngine

            decoded_cfg = NextGenCyberEngine.extract_cfg_topology(code_sample)
            block_count = int(decoded_cfg.get("basic_block_count", 0))
            instruction_count = int(decoded_cfg.get("instruction_count", 0))
            edge_count = int(decoded_cfg.get("edge_count", 0))
            cfg_topology = {
                "status": "ok" if decoded_cfg.get("disassembly_available") else "decoder_unavailable",
                "basic_block_count": block_count,
                "cyclomatic_complexity": int(decoded_cfg.get("cyclomatic_complexity", 0)),
                "graph_density": float(decoded_cfg.get("graph_density", 0.0)),
                "branching_ratio": min(1.0, edge_count / max(1, block_count * 2)),
                "instruction_count": instruction_count,
                "edge_count": edge_count,
                "detected_patterns": list(decoded_cfg.get("detected_patterns", [])),
            }
        except (ImportError, OSError, ValueError):
            cfg_topology = _empty_cfg_summary("decoder_unavailable")

    risk_score = 0
    findings: list[str] = []
    if suspicious_imports:
        risk_score += 35
        findings.append("Suspicious PE import API usage detected.")
    if high_entropy_sections:
        risk_score += 20
        findings.append("High-entropy PE sections detected.")
    if cfg_topology["detected_patterns"]:
        risk_score += 15
        findings.append("Executable-section structural obfuscation indicators detected.")
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
        "suspicious_imports": sorted(set(suspicious_imports)),
        "import_names": sorted(set(import_names)),
        "import_count": len(set(import_names)),
        "section_count": len(sections),
        "high_entropy_sections": high_entropy_sections,
        "sections": sections,
        "cfg_topology": cfg_topology,
        "header_summary": {
            "machine": getattr(getattr(pe, "FILE_HEADER", None), "Machine", None),
            "number_of_sections": getattr(getattr(pe, "FILE_HEADER", None), "NumberOfSections", None),
            "timestamp": getattr(getattr(pe, "FILE_HEADER", None), "TimeDateStamp", None),
            "subsystem": getattr(getattr(pe, "OPTIONAL_HEADER", None), "Subsystem", None),
        },
        "version_info": read_version_info(pe),
        "error": None,
    }
