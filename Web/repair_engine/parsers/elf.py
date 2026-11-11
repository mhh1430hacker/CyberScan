"""ELF regions from bytes: header, program/section header tables, segments,
named sections, the entry point's file offset, and the overlay."""
from __future__ import annotations

import struct

from repair_engine.regions import RegionMap

_NOBITS = 8
_PT_LOAD = 1
_MAX_ENTRIES = 4096
_SEGMENT_TYPES = {0: "NULL", 1: "LOAD", 2: "DYNAMIC", 3: "INTERP", 4: "NOTE", 6: "PHDR", 7: "TLS"}


def parse_elf(data: bytes, regions: RegionMap) -> None:
    regions.format = "elf"
    try:
        _parse(data, regions)
    except (struct.error, IndexError, ValueError) as exc:
        regions.errors.append(f"elf: {type(exc).__name__}: {exc}")


def _parse(data: bytes, regions: RegionMap) -> None:
    if len(data) < 16:
        raise ValueError("truncated identification")
    wide = data[4] == 2
    order = "<" if data[5] != 2 else ">"
    if wide:
        head = struct.unpack_from(order + "HHIQQQIHHHHHH", data, 16)
    else:
        head = struct.unpack_from(order + "HHIIIIIHHHHHH", data, 16)
    _type, machine, _version, entry, phoff, shoff, _flags, ehsize, phentsize, phnum, shentsize, shnum, shstrndx = head
    regions.add(0, ehsize, "elf_header", wide=wide, machine=machine)
    covered = ehsize
    segments = []
    if phoff and phnum and phentsize:
        phnum = min(phnum, _MAX_ENTRIES)
        regions.add(phoff, phoff + phentsize * phnum, "elf_program_headers", count=phnum)
        covered = max(covered, phoff + phentsize * phnum)
        for number in range(phnum):
            at = phoff + number * phentsize
            if wide:
                p_type, p_flags, offset, vaddr, _paddr, filesz, _memsz, _align = struct.unpack_from(order + "IIQQQQQQ", data, at)
            else:
                p_type, offset, vaddr, _paddr, filesz, _memsz, p_flags, _align = struct.unpack_from(order + "IIIIIIII", data, at)
            if filesz:
                index = regions.add(offset, offset + filesz, "elf_segment", type=_SEGMENT_TYPES.get(p_type, hex(p_type)),
                                    vaddr=vaddr, executable=bool(p_flags & 1))
                if index is not None:
                    segments.append((index, p_type, offset, vaddr, filesz))
                covered = max(covered, offset + filesz)
    if shoff and shnum and shentsize:
        shnum = min(shnum, _MAX_ENTRIES)
        regions.add(shoff, shoff + shentsize * shnum, "elf_section_headers", count=shnum)
        covered = max(covered, shoff + shentsize * shnum)
        headers = []
        for number in range(shnum):
            at = shoff + number * shentsize
            if wide:
                name, s_type, s_flags, _addr, offset, size = struct.unpack_from(order + "IIQQQQ", data, at)
            else:
                name, s_type, s_flags, _addr, offset, size = struct.unpack_from(order + "IIIIII", data, at)
            headers.append((name, s_type, s_flags, offset, size))
        names = headers[shstrndx] if shstrndx < len(headers) else None
        for name, s_type, s_flags, offset, size in headers[1:]:
            if s_type == _NOBITS or size == 0:
                continue
            label = _string(data, names[3] + name) if names else ""
            regions.add(offset, offset + size, "elf_section", name=label, type=s_type, executable=bool(s_flags & 4))
            covered = max(covered, offset + size)
    for index, p_type, offset, vaddr, filesz in segments:
        if p_type == _PT_LOAD and vaddr <= entry < vaddr + filesz:
            regions.add(offset + entry - vaddr, offset + entry - vaddr + 1, "elf_entry_point", parent=index, vaddr=entry)
            break
    if covered < len(data):
        regions.add(covered, len(data), "elf_overlay")


def _string(data: bytes, offset: int) -> str:
    end = data.find(b"\x00", offset, offset + 256)
    return data[offset:end if end != -1 else offset + 256].decode("latin-1")
