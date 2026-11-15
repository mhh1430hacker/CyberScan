"""Structural analysis of PE (Windows) and ELF (Linux) executables.

Import analysis is capability-based: an API only counts when it appears in a combination
that implements a behaviour (e.g. remote allocation + remote write + remote thread). Single
APIs such as ``IsDebuggerPresent`` or ``CreateProcessW`` are imported by the Microsoft C
runtime and ordinary applications, so they are never evidence on their own.
"""
from __future__ import annotations

import re
import struct
import time
from typing import Any, Callable

from core.entropy import shannon_entropy

try:
    import pefile
except Exception:  # pragma: no cover - optional dependency
    pefile = None

AddFn = Callable[..., None]

_SCN_MEM_EXECUTE = 0x20000000
_SCN_MEM_WRITE = 0x80000000
_SCN_CNT_CODE = 0x00000020

PACKER_SECTIONS = {
    "upx0": "UPX", "upx1": "UPX", "upx2": "UPX", ".aspack": "ASPack", ".adata": "ASPack", ".petite": "Petite",
    ".nsp0": "NsPack", ".nsp1": "NsPack", ".mpress1": "MPRESS", ".mpress2": "MPRESS", ".themida": "Themida",
    ".winlice": "WinLicense", ".vmp0": "VMProtect", ".vmp1": "VMProtect", ".vmp2": "VMProtect", ".enigma1": "Enigma",
    ".enigma2": "Enigma", "pec2": "PECompact", "pec2to": "PECompact", ".packed": "generic packer", ".perplex": "Perplex",
    ".yp": "Y0da", "fsg!": "FSG", ".mew": "MEW", "kkrunchy": "kkrunchy", ".boom": "The Boomerang",
}

# Capability -> (required groups; every group must contribute >= 1 API), severity, weight, explanation
CAPABILITIES: dict[str, tuple[list[set[str]], str, int, str]] = {
    "process_injection": (
        [{"VirtualAllocEx", "NtAllocateVirtualMemory", "ZwAllocateVirtualMemory", "NtMapViewOfSection", "ZwMapViewOfSection"},
         {"WriteProcessMemory", "NtWriteVirtualMemory", "ZwWriteVirtualMemory", "NtMapViewOfSection"},
         {"CreateRemoteThread", "CreateRemoteThreadEx", "NtCreateThreadEx", "RtlCreateUserThread", "QueueUserAPC",
          "NtQueueApcThread", "SetThreadContext", "NtSetContextThread", "ResumeThread"}],
        "high", 35, "Imports the full allocate / write / execute API set used to inject code into other processes (T1055).",
    ),
    "process_hollowing": (
        [{"NtUnmapViewOfSection", "ZwUnmapViewOfSection"}, {"SetThreadContext", "NtSetContextThread", "Wow64SetThreadContext"},
         {"WriteProcessMemory", "NtWriteVirtualMemory"}],
        "high", 35, "Imports unmap + write + thread-context APIs, the signature of process hollowing (T1055.012).",
    ),
    "keylogging": (
        [{"SetWindowsHookExA", "SetWindowsHookExW"}, {"GetAsyncKeyState", "GetKeyboardState", "CallNextHookEx"},
         {"GetForegroundWindow", "GetWindowTextA", "GetWindowTextW"}],
        "low", 15, "Keyboard hooking plus active-window tracking is the core of a keylogger (T1056.001); "
        "accessibility and hotkey tools use the same APIs.",
    ),
    "downloader": (
        [{"URLDownloadToFileA", "URLDownloadToFileW", "URLDownloadToCacheFileA", "URLDownloadToCacheFileW"},
         {"WinExec", "ShellExecuteA", "ShellExecuteW", "ShellExecuteExA", "ShellExecuteExW", "CreateProcessA", "CreateProcessW"}],
        "medium", 30, "Downloads a file from a URL and can execute it (T1105).",
    ),
    "screen_capture": (
        [{"BitBlt"}, {"GetDC", "GetWindowDC", "CreateCompatibleDC"}, {"GetDesktopWindow"}],
        "info", 5, "Captures the desktop image (T1113). Also used by legitimate screenshot and remote-support tools.",
    ),
}

ANTI_ANALYSIS_APIS = {"IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess", "OutputDebugStringA",
                      "OutputDebugStringW", "NtSetInformationThread", "GetTickCount64", "QueryPerformanceCounter"}

CREDENTIAL_STRINGS = [rb"\\Google\\Chrome\\User Data", rb"Login Data", rb"\\Mozilla\\Firefox\\Profiles", rb"logins\.json",
                      rb"wallet\.dat", rb"\\Exodus\\", rb"\\Telegram Desktop\\tdata", rb"\\Electrum\\wallets",
                      rb"key4\.db", rb"\\Microsoft\\Edge\\User Data"]


def _ascii_and_wide(data: bytes) -> bytes:
    """Printable ASCII plus UTF-16LE strings (as ASCII) for pattern matching inside binaries."""
    wide = b"\n".join(match.replace(b"\x00", b"") for match in re.findall(rb"(?:[\x20-\x7e]\x00){5,}", data[:16 * 1024 * 1024]))
    return data + b"\n" + wide


def _credential_theft(data: bytes, imports: set[str], add: AddFn) -> None:
    corpus = _ascii_and_wide(data)
    hits = sorted({pattern.decode().replace("\\\\", "\\").replace("\\.", ".") for pattern in CREDENTIAL_STRINGS if re.search(pattern, corpus, re.IGNORECASE)})
    if len(hits) >= 2 and ({"CryptUnprotectData"} & imports or b"CryptUnprotectData" in corpus or b"sqlite" in corpus.lower()):
        add("high", "Browser/wallet credential theft indicators", 50,
            f"References browser or wallet credential stores ({', '.join(hits[:4])}) together with decryption/database access; "
            "this is the profile of information-stealer malware (T1555.003).", category="capability", paths=hits[:10])


def _exported_names(pe) -> set[str]:
    try:
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
    except Exception:
        return set()
    exports = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    return {symbol.name.decode("latin-1", "ignore") for symbol in getattr(exports, "symbols", [])[:20000] if symbol.name}


def inspect_pe(data: bytes, add: AddFn, *, file_size: int | None = None) -> dict[str, Any]:
    if pefile is None:
        return {"type": "pe", "status": "dependency_missing"}
    try:
        pe = pefile.PE(data=data, fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"], pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_TLS"],
        ])
    except Exception as exc:
        add("medium", "Malformed PE file", 20, f"The executable header is corrupt or deliberately malformed ({type(exc).__name__}).")
        return {"type": "pe", "status": "malformed"}

    details: dict[str, Any] = {"type": "pe", "status": "ok"}
    imports: set[str] = set()
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        for item in entry.imports or []:
            if item.name:
                imports.add(item.name.decode("latin-1", errors="ignore"))
    details["import_count"] = len(imports)
    is_dotnet = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress != 0 if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > 14 else False
    details["dotnet"] = is_dotnet
    is_dll = bool(pe.FILE_HEADER.Characteristics & 0x2000)
    details["is_dll"] = is_dll

    # Sections
    entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    sections = []
    entry_section = None
    packers: set[str] = set()
    for index, section in enumerate(pe.sections):
        name = section.Name.rstrip(b"\x00").decode("latin-1", errors="replace")
        raw = section.get_data()[: 8 * 1024 * 1024] if section.SizeOfRawData else b""
        characteristics = section.Characteristics
        info = {
            "name": name, "entropy": shannon_entropy(raw) if raw else 0.0, "raw_size": section.SizeOfRawData,
            "virtual_size": section.Misc_VirtualSize,
            "executable": bool(characteristics & _SCN_MEM_EXECUTE), "writable": bool(characteristics & _SCN_MEM_WRITE),
        }
        sections.append(info)
        if name.lower() in PACKER_SECTIONS:
            packers.add(PACKER_SECTIONS[name.lower()])
        start, size = section.VirtualAddress, max(section.Misc_VirtualSize, section.SizeOfRawData)
        if start <= entry_point < start + size:
            entry_section = (index, info)
    details["sections"] = sections
    if b"UPX!" in data[:4096] and "UPX" not in packers:
        packers.add("UPX")

    if packers:
        add("medium", "Known packer or protector", 25,
            f"Section names identify {', '.join(sorted(packers))}. Packing hides code from static analysis; it is also used by some "
            "legitimate software, so treat it as context.", category="structural", packers=sorted(packers))
    wx = [item["name"] for item in sections if item["executable"] and item["writable"]]
    if wx:
        add("medium", "Writable and executable section", 20,
            f"Section(s) {', '.join(wx[:3])} are both writable and executable, which self-modifying and unpacking code needs.",
            category="structural")
    if entry_point and not is_dotnet and not is_dll:
        if entry_section is None:
            add("medium", "Entry point outside all sections", 30,
                "The program starts executing at an address that no section covers, a hallmark of crafted or packed binaries.",
                category="structural")
        elif not entry_section[1]["executable"]:
            add("medium", "Entry point in non-executable section", 25,
                f"Execution starts in section '{entry_section[1]['name']}', which is not marked executable.", category="structural")
        elif entry_section[0] == len(sections) - 1 and len(sections) > 2 and not packers:
            add("low", "Entry point in last section", 10,
                f"Execution starts in the last section ('{entry_section[1]['name']}'), a common layout for packers and file infectors.",
                category="structural")
    high_entropy_code = [item for item in sections if item["executable"] and item["entropy"] > 7.2 and item["raw_size"] > 4096]

    # Imports
    dynamic_resolution = {"LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW", "LdrLoadDll"} & imports \
        and {"GetProcAddress", "LdrGetProcedureAddress"} & imports
    if not is_dotnet and not is_dll:
        if not imports:
            add("low", "No import table", 10, "The executable imports nothing, so it must resolve every API itself at run time.",
                category="structural")
        elif len(imports) <= 6 and dynamic_resolution and (high_entropy_code or packers):
            add("medium", "Minimal imports with dynamic API resolution", 25,
                f"Only {len(imports)} imports, including LoadLibrary/GetProcAddress, alongside packed or high-entropy code: "
                "the real import table is hidden.", category="structural")
    triggered: dict[str, list[str]] = {}
    exported = _exported_names(pe) if is_dll else set()
    details["api_provider"] = bool(exported & {api for groups, *_ in CAPABILITIES.values() for group in groups for api in group})
    for capability, (groups, severity, weight, explanation) in CAPABILITIES.items():
        if details["api_provider"]:
            break  # kernel32/kernelbase/ntdll-style DLLs implement these APIs; importing them is plumbing, not intent
        matched = [sorted(group & imports) for group in groups]
        if all(matched):
            apis = sorted({api for group in matched for api in group})
            triggered[capability] = apis
            add(severity, f"Capability: {capability.replace('_', ' ')}", weight, explanation + f" APIs: {', '.join(apis[:6])}.",
                category="capability", apis=apis)
    details["capabilities"] = triggered
    details["anti_analysis_apis"] = sorted(ANTI_ANALYSIS_APIS & imports)
    _credential_theft(data, imports, add)

    # Header facts
    timestamp = pe.FILE_HEADER.TimeDateStamp
    details["timestamp"] = timestamp
    if timestamp > time.time() + 86400 * 2 and timestamp < 0xFFFFFFFF:
        add("info", "Compile timestamp in the future", 0, "The PE timestamp is in the future; it was forged or is a reproducible-build hash.",
            category="structural")
    tls = getattr(pe, "DIRECTORY_ENTRY_TLS", None)
    if tls is not None and getattr(tls.struct, "AddressOfCallBacks", 0):
        details["tls_callbacks"] = True
        # Context only: the MSVC runtime registers TLS callbacks for thread_local data in ordinary programs.
        add("info", "TLS callbacks", 0, "TLS callbacks run before the entry point; also used by anti-debugging code.", category="structural")
    security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4] if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > 4 else None
    details["authenticode_present"] = bool(security_dir and security_dir.VirtualAddress and security_dir.Size)
    overlay_offset = pe.get_overlay_data_start_offset()
    if overlay_offset is not None and file_size:
        details["overlay_bytes"] = max(0, file_size - overlay_offset)
    pe.close()
    return details


# ---------------------------------------------------------------------------
# ELF
# ---------------------------------------------------------------------------

_ELF_TYPES = {1: "relocatable", 2: "executable", 3: "shared-object", 4: "core"}
_ELF_MACHINES = {3: "x86", 8: "MIPS", 20: "PowerPC", 40: "ARM", 62: "x86-64", 183: "AArch64", 243: "RISC-V"}


def inspect_elf(data: bytes, add: AddFn) -> dict[str, Any]:
    if len(data) < 52:
        add("low", "Truncated ELF file", 10, "The ELF header is incomplete.", category="structural")
        return {"type": "elf", "status": "truncated"}
    elf_class, endian = data[4], data[5]
    prefix = "<" if endian == 1 else ">"
    try:
        e_type, e_machine = struct.unpack_from(prefix + "HH", data, 16)
        if elf_class == 2:
            e_shoff = struct.unpack_from(prefix + "Q", data, 0x28)[0]
            e_shnum = struct.unpack_from(prefix + "H", data, 0x3C)[0]
        else:
            e_shoff = struct.unpack_from(prefix + "I", data, 0x20)[0]
            e_shnum = struct.unpack_from(prefix + "H", data, 0x30)[0]
    except struct.error:
        add("medium", "Malformed ELF header", 20, "The ELF header could not be parsed.", category="structural")
        return {"type": "elf", "status": "malformed"}
    details = {"type": "elf", "status": "ok", "class": "64-bit" if elf_class == 2 else "32-bit",
               "elf_type": _ELF_TYPES.get(e_type, str(e_type)), "machine": _ELF_MACHINES.get(e_machine, str(e_machine))}
    if b"UPX!" in data[:8192] or b"$Info: This file is packed with the UPX" in data[:65536]:
        add("medium", "Known packer or protector", 25, "The ELF binary is UPX-packed, common for IoT malware and miners.",
            category="structural", packers=["UPX"])
    if e_shnum == 0 or e_shoff == 0:
        add("medium", "ELF without section headers", 20,
            "Section headers are missing; they are not needed to run, and stripping them defeats many analysis tools.",
            category="structural")
    elif e_shoff >= len(data) and len(data) >= 1_000_000:
        details["section_headers_beyond_read_window"] = True
    return details
