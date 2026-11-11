"""PE (Windows executable) regions, read with pefile from bytes only.

Headers, the section table, every section's raw data, the entry point's
file offset, import/export tables, every resource data leaf, the
Authenticode certificate table, and the overlay (bytes past the last
section that are not the certificate).

Disarmed or malformed files are not patched to make them parse: if pefile
rejects the bytes, the error is recorded and the map keeps what was read.
"""
from __future__ import annotations

import numpy as np
import pefile

from repair_engine.regions import RegionMap

_DIRECTORIES = {
    "IMAGE_DIRECTORY_ENTRY_EXPORT": "pe_exports",
    "IMAGE_DIRECTORY_ENTRY_IMPORT": "pe_imports",
    "IMAGE_DIRECTORY_ENTRY_RESOURCE": "pe_resources",
    "IMAGE_DIRECTORY_ENTRY_DEBUG": "pe_debug",
    "IMAGE_DIRECTORY_ENTRY_TLS": "pe_tls",
    "IMAGE_DIRECTORY_ENTRY_BASERELOC": "pe_relocations",
}
_SECURITY = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
_EXECUTE = 0x20000000
_MAX_RESOURCES = 4096


def parse_pe(data: bytes, regions: RegionMap) -> None:
    regions.format = "pe"
    try:
        pe = pefile.PE(data=data, fast_load=True)
    except pefile.PEFormatError as exc:
        regions.errors.append(f"pe: {exc}")
        return
    try:
        _headers(pe, regions)
        sections = _sections(pe, regions)
        _entry_point(pe, regions, sections)
        _directories(pe, regions)
        _certificate_and_overlay(pe, data, regions)
    except Exception as exc:  # noqa: BLE001 - malformed input must never stop the map
        regions.errors.append(f"pe: {type(exc).__name__}: {exc}")
    finally:
        pe.close()


def _headers(pe: pefile.PE, regions: RegionMap) -> None:
    lfanew = int(pe.DOS_HEADER.e_lfanew)
    regions.add(0, 64, "pe_dos_header")
    if lfanew > 64:
        regions.add(64, lfanew, "pe_dos_stub")
    optional = lfanew + 4 + 20
    table = optional + int(pe.FILE_HEADER.SizeOfOptionalHeader)
    regions.add(lfanew, optional, "pe_file_header")
    regions.add(optional, table, "pe_optional_header", checksum=int(pe.OPTIONAL_HEADER.CheckSum))
    regions.add(table, table + 40 * len(pe.sections), "pe_section_table", count=len(pe.sections))


def _sections(pe: pefile.PE, regions: RegionMap) -> list[tuple[int, int, int]]:
    """Adds each section's raw data; returns (index, start, end) for the ones in the file."""
    found = []
    for number, section in enumerate(pe.sections):
        start = int(section.PointerToRawData)
        size = int(section.SizeOfRawData)
        name = section.Name.rstrip(b"\x00").decode("latin-1")
        if size == 0:
            continue
        index = regions.add(
            start,
            start + size,
            "pe_section",
            name=name,
            number=number,
            virtual_address=int(section.VirtualAddress),
            virtual_size=int(section.Misc_VirtualSize),
            characteristics=int(section.Characteristics),
            executable=bool(section.Characteristics & _EXECUTE),
            entropy=_entropy(pe.__data__[start:start + size]),
        )
        if index is not None:
            found.append((index, start, start + size))
    return found


def _entropy(chunk: bytes) -> float:
    if not chunk:
        return 0.0
    counts = np.bincount(np.frombuffer(chunk, dtype=np.uint8), minlength=256)
    share = counts[counts > 0] / len(chunk)
    return round(float(-(share * np.log2(share)).sum()), 3)


def _entry_point(pe: pefile.PE, regions: RegionMap, sections: list[tuple[int, int, int]]) -> None:
    rva = int(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    if rva == 0:
        return
    try:
        offset = int(pe.get_offset_from_rva(rva))
    except Exception:  # noqa: BLE001 - an entry point outside every section is itself a finding
        regions.errors.append(f"pe: entry point RVA 0x{rva:X} maps to no file offset")
        return
    parent = next((index for index, start, end in sections if start <= offset < end), 0)
    regions.add(offset, offset + 1, "pe_entry_point", parent=parent, rva=rva, in_section=parent != 0)


def _directories(pe: pefile.PE, regions: RegionMap) -> None:
    for name, kind in _DIRECTORIES.items():
        entry = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY[name]]
        rva, size = int(entry.VirtualAddress), int(entry.Size)
        if rva == 0 or size == 0:
            continue
        try:
            offset = int(pe.get_offset_from_rva(rva))
        except Exception:  # noqa: BLE001
            regions.errors.append(f"pe: {kind} RVA 0x{rva:X} maps to no file offset")
            continue
        parent = regions.add(offset, offset + size, kind, rva=rva)
        if kind == "pe_resources" and parent is not None:
            _resource_leaves(pe, regions, parent)


def _resource_leaves(pe: pefile.PE, regions: RegionMap, parent: int) -> None:
    try:
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
    except Exception as exc:  # noqa: BLE001
        regions.errors.append(f"pe: resources: {exc}")
        return
    root = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
    if root is None:
        return
    count = 0
    stack = [(entry, (_resource_name(entry),)) for entry in root.entries]
    while stack and count < _MAX_RESOURCES:
        entry, path = stack.pop()
        directory = getattr(entry, "directory", None)
        if directory is not None:
            stack.extend((child, path + (_resource_name(child),)) for child in directory.entries)
            continue
        data = getattr(entry, "data", None)
        if data is None:
            continue
        count += 1
        rva, size = int(data.struct.OffsetToData), int(data.struct.Size)
        try:
            offset = int(pe.get_offset_from_rva(rva))
        except Exception:  # noqa: BLE001
            continue
        regions.add(offset, offset + size, "pe_resource", parent=parent, path="/".join(path))


def _resource_name(entry) -> str:
    if getattr(entry, "name", None) is not None:
        return str(entry.name)
    resource_id = getattr(entry, "id", None)
    return pefile.RESOURCE_TYPE.get(resource_id, str(resource_id)) if resource_id is not None else "?"


def _certificate_and_overlay(pe: pefile.PE, data: bytes, regions: RegionMap) -> None:
    size = len(data)
    image_end = int(pe.OPTIONAL_HEADER.SizeOfHeaders)
    for section in pe.sections:
        if section.SizeOfRawData:
            image_end = max(image_end, int(section.PointerToRawData) + int(section.SizeOfRawData))
    image_end = min(image_end, size)
    # The certificate table's "address" is a file offset, not an RVA.
    security = pe.OPTIONAL_HEADER.DATA_DIRECTORY[_SECURITY]
    certificate = None
    if security.VirtualAddress and security.Size:
        start = int(security.VirtualAddress)
        certificate = (start, start + int(security.Size))
        regions.add(*certificate, "pe_certificate")
    cursor = image_end
    for start, end in sorted([certificate] if certificate else []):
        if start > cursor:
            regions.add(cursor, start, "pe_overlay")
        cursor = max(cursor, end)
    if cursor < size:
        regions.add(cursor, size, "pe_overlay")
