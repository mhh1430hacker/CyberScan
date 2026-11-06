"""Where a PE file keeps what, read straight from its headers (no pefile, no execution).

Shared by the orbit transforms (``ml.orbit``) and the counterfactual audit
(``ml.counterfactual``), which both need byte ranges, not a full parse.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

IMAGE_SCN_MEM_EXECUTE = 0x20000000
MAX_SECTIONS = 96


@dataclass(frozen=True)
class Section:
    name: str
    header_offset: int  # where its 40-byte entry sits in the section table
    raw_start: int
    raw_end: int
    executable: bool

    @property
    def kind(self) -> str:
        if self.executable:
            return "code"
        if self.name.lower().startswith(".rsrc"):
            return "resource"
        return "data"


@dataclass(frozen=True)
class PELayout:
    pe_offset: int
    timestamp_offset: int
    checksum_offset: int
    header_end: int
    sections: tuple[Section, ...]
    overlay_start: int | None  # None when nothing follows the last section
    rich_header: tuple[int, int] | None  # compiler fingerprint between DOS stub and PE header


def parse_layout(data: bytes) -> PELayout | None:
    """Byte ranges of a PE file's parts, or None when ``data`` is not a well-formed PE."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    pe_offset = int.from_bytes(data[0x3C:0x40], "little")
    if pe_offset < 0x40 or pe_offset + 24 > len(data) or data[pe_offset:pe_offset + 4] != b"PE\0\0":
        return None
    coff = pe_offset + 4
    section_count = min(struct.unpack_from("<H", data, coff + 2)[0], MAX_SECTIONS)
    optional_size = struct.unpack_from("<H", data, coff + 16)[0]
    optional = coff + 20
    table = optional + optional_size
    if optional_size < 68 or table + 40 * section_count > len(data):
        return None
    sections = []
    for index in range(section_count):
        entry = table + 40 * index
        name = data[entry:entry + 8].rstrip(b"\0").decode("latin-1")
        raw_size, raw_offset = struct.unpack_from("<II", data, entry + 16)
        characteristics = struct.unpack_from("<I", data, entry + 36)[0]
        start, end = raw_offset, min(len(data), raw_offset + raw_size)
        if raw_size and start < end:
            sections.append(Section(name, entry, start, end, bool(characteristics & IMAGE_SCN_MEM_EXECUTE)))
    last = max((section.raw_end for section in sections), default=table + 40 * section_count)
    rich = None
    marker = data.find(b"Rich", 0x80, pe_offset)
    if marker != -1:
        rich = (0x80, min(pe_offset, marker + 8))
    return PELayout(
        pe_offset=pe_offset,
        timestamp_offset=coff + 4,
        checksum_offset=optional + 64,
        header_end=table + 40 * section_count,
        sections=tuple(sections),
        overlay_start=last if last < len(data) else None,
        rich_header=rich,
    )
