"""PE header fields by offset, for code that must edit them byte-exactly.

The injector and the repair executor both change the same handful of
fields (section count, section table, SizeOfImage, entry point, checksum),
so both use this one reader and the one checksum routine. Reading only:
nothing here maps or loads the image.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

import numpy as np


@dataclass(frozen=True)
class Section:
    index: int
    header_offset: int
    name: bytes
    virtual_size: int
    virtual_address: int
    raw_size: int
    raw_pointer: int
    characteristics: int


@dataclass(frozen=True)
class Layout:
    lfanew: int
    optional: int
    pe32_plus: bool
    table: int
    sections: tuple[Section, ...]
    entry_point: int
    section_alignment: int
    file_alignment: int
    size_of_image: int
    size_of_headers: int
    checksum: int
    certificate: tuple[int, int]  # (file offset, size); (0, 0) when absent

    # field offsets
    @property
    def count_offset(self) -> int:
        return self.lfanew + 6

    @property
    def entry_offset(self) -> int:
        return self.optional + 16

    @property
    def size_of_image_offset(self) -> int:
        return self.optional + 56

    @property
    def checksum_offset(self) -> int:
        return self.optional + 64

    @property
    def image_end(self) -> int:
        """End of headers and section raw data: where an overlay would start."""
        ends = [s.raw_pointer + s.raw_size for s in self.sections if s.raw_size]
        return max([self.size_of_headers, *ends])

    def section_at_rva(self, rva: int) -> Section | None:
        for section in self.sections:
            if section.virtual_address <= rva < section.virtual_address + max(section.virtual_size, section.raw_size):
                return section
        return None


def align(value: int, alignment: int) -> int:
    return value if alignment <= 1 else (value + alignment - 1) // alignment * alignment


def read(data: bytes) -> Layout:
    if data[:2] != b"MZ":
        raise ValueError("not a PE (no MZ)")
    lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[lfanew:lfanew + 4] != b"PE\x00\x00":
        raise ValueError("not a PE (no PE signature)")
    count, = struct.unpack_from("<H", data, lfanew + 6)
    optional_size, = struct.unpack_from("<H", data, lfanew + 20)
    optional = lfanew + 24
    magic, = struct.unpack_from("<H", data, optional)
    plus = magic == 0x20B
    entry, = struct.unpack_from("<I", data, optional + 16)
    section_alignment, file_alignment = struct.unpack_from("<II", data, optional + 32)
    size_of_image, size_of_headers, checksum = struct.unpack_from("<III", data, optional + 56)
    directories = optional + (112 if plus else 96)
    certificate = struct.unpack_from("<II", data, directories + 4 * 8) if directories + 40 <= optional + optional_size else (0, 0)
    table = optional + optional_size
    sections = []
    for index in range(count):
        at = table + 40 * index
        name, vsize, va, raw_size, raw_pointer = struct.unpack_from("<8sIIII", data, at)
        characteristics, = struct.unpack_from("<I", data, at + 36)
        sections.append(Section(index, at, name, vsize, va, raw_size, raw_pointer, characteristics))
    return Layout(lfanew, optional, plus, table, tuple(sections), entry, section_alignment, file_alignment,
                  size_of_image, size_of_headers, checksum, tuple(certificate))


def checksum(data: bytes, checksum_offset: int) -> int:
    """The PE image checksum (as in IMAGEHLP's CheckSumMappedFile)."""
    padded = data + b"\x00" * (len(data) % 2)
    words = np.frombuffer(padded, dtype="<u2").astype(np.uint64)
    skip = checksum_offset // 2
    total = int(words.sum()) - int(words[skip]) - int(words[skip + 1])
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (total + len(data)) & 0xFFFFFFFF


def put_u16(buffer: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<H", buffer, offset, value)


def put_u32(buffer: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<I", buffer, offset, value)
