"""OLE compound files (.doc, .xls, .ppt, .msg): streams with exact extents.

A stream is stored as a chain of sectors that need not be contiguous, so
each stream becomes one region per contiguous run of bytes (``extent``),
all carrying the stream's full path. Streams under a ``VBA`` storage are
tagged as macros, ``ObjectPool`` / ``Ole10Native`` as embedded objects.
Small streams living in the mini stream are mapped through it to file
offsets the same way. Chains are followed with loop and length guards.
"""
from __future__ import annotations

import struct

from repair_engine.regions import RegionMap

_END = 0xFFFFFFFE
_FREE = 0xFFFFFFFF
_SPECIAL = {0xFFFFFFFC, 0xFFFFFFFD, 0xFFFFFFFE, 0xFFFFFFFF}
_MAX_CHAIN = 1 << 20
_MAX_ENTRIES = 50_000


class _Compound:
    def __init__(self, data: bytes):
        self.data = data
        major, _order, shift, mini_shift = struct.unpack_from("<HHHH", data, 0x1A)
        if shift not in (9, 12) or mini_shift != 6:
            raise ValueError(f"unexpected sector sizes (shift {shift}, mini {mini_shift})")
        self.major = major
        self.sector = 1 << shift
        (self.fat_count, self.dir_first, _transaction, self.cutoff, self.minifat_first, self.minifat_count,
         self.difat_first, self.difat_count) = struct.unpack_from("<IIIIIIII", data, 0x2C)
        self.fat_sectors = self._fat_sectors()
        self.fat = self._table(self.fat_sectors)

    def offset(self, sector: int) -> int:
        return (sector + 1) * self.sector

    def _fat_sectors(self) -> list[int]:
        sectors = [s for s in struct.unpack_from("<109I", self.data, 0x4C) if s not in _SPECIAL]
        current, seen = self.difat_first, set()
        per = self.sector // 4 - 1
        while current not in _SPECIAL and current not in seen and len(seen) < _MAX_CHAIN:
            seen.add(current)
            values = struct.unpack_from(f"<{per + 1}I", self.data, self.offset(current))
            sectors.extend(s for s in values[:per] if s not in _SPECIAL)
            current = values[per]
        return sectors[: max(self.fat_count, 0) or len(sectors)]

    def _table(self, sectors: list[int]) -> list[int]:
        table: list[int] = []
        for sector in sectors:
            start = self.offset(sector)
            chunk = self.data[start:start + self.sector]
            table.extend(struct.unpack(f"<{len(chunk) // 4}I", chunk[: len(chunk) // 4 * 4]))
        return table

    def chain(self, first: int, table: list[int]) -> list[int]:
        out, seen, current = [], set(), first
        while current not in _SPECIAL and current < len(table) and current not in seen and len(out) < _MAX_CHAIN:
            seen.add(current)
            out.append(current)
            current = table[current]
        return out


def _merge(spans: list[tuple[int, int]]) -> list[tuple[int, int]]:
    merged: list[list[int]] = []
    for start, end in spans:
        if merged and merged[-1][1] == start:
            merged[-1][1] = end
        else:
            merged.append([start, end])
    return [(a, b) for a, b in merged]


def _role(path: list[str]) -> str | None:
    names = [part.lower() for part in path]
    if any(part in {"vba", "_vba_project_cur", "macros"} for part in names[:-1]) or names[-1] == "_vba_project":
        return "vba"
    if "objectpool" in names[:-1] or names[-1] in {"\x01ole10native", "\x01ole"}:
        return "embedded_object"
    if names[-1] in {"worddocument", "workbook", "book", "powerpoint document"}:
        return "document"
    return None


def parse_ole(data: bytes, regions: RegionMap) -> None:
    regions.format = "ole"
    try:
        _parse(data, regions)
    except (struct.error, IndexError, ValueError) as exc:
        regions.errors.append(f"ole: {type(exc).__name__}: {exc}")


def _parse(data: bytes, regions: RegionMap) -> None:
    compound = _Compound(data)
    size = compound.sector
    regions.add(0, 512 if compound.major == 3 else size, "ole_header", version=compound.major)
    for start, end in _merge([(compound.offset(s), compound.offset(s) + size) for s in sorted(compound.fat_sectors)]):
        regions.add(start, end, "ole_fat")
    directory = compound.chain(compound.dir_first, compound.fat)
    for start, end in _merge([(compound.offset(s), compound.offset(s) + size) for s in directory]):
        regions.add(start, end, "ole_directory")
    raw = b"".join(data[compound.offset(s):compound.offset(s) + size] for s in directory)
    entries = []
    for at in range(0, min(len(raw) // 128, _MAX_ENTRIES) * 128, 128):
        name_length = struct.unpack_from("<H", raw, at + 64)[0]
        name = raw[at:at + max(0, min(64, name_length) - 2)].decode("utf-16-le", "replace")
        kind = raw[at + 66]
        left, right, child = struct.unpack_from("<III", raw, at + 68)
        first, length = struct.unpack_from("<IQ", raw, at + 116)
        if compound.major == 3:
            length &= 0xFFFFFFFF
        entries.append((name, kind, left, right, child, first, length))
    if not entries:
        raise ValueError("empty directory")
    root = entries[0]
    mini_sectors = compound.chain(root[5], compound.fat)
    minifat = compound._table(compound.chain(compound.minifat_first, compound.fat))

    def extents(first: int, length: int) -> list[tuple[int, int]]:
        spans = []
        if length < compound.cutoff:
            for mini in compound.chain(first, minifat):
                position = mini * 64
                host = position // size
                if host >= len(mini_sectors):
                    break
                start = compound.offset(mini_sectors[host]) + position % size
                spans.append((start, start + 64))
        else:
            for sector in compound.chain(first, compound.fat):
                spans.append((compound.offset(sector), compound.offset(sector) + size))
        trimmed, remaining = [], length
        for start, end in _merge(spans):
            if remaining <= 0:
                break
            take = min(end - start, remaining)
            trimmed.append((start, start + take))
            remaining -= take
        return trimmed

    stack, visited = [(root[4], [])], set()
    while stack:
        index, path = stack.pop()
        if index in _SPECIAL or index >= len(entries) or index in visited:
            continue
        visited.add(index)
        name, kind, left, right, child, first, length = entries[index]
        stack.append((left, path))
        stack.append((right, path))
        here = path + [name]
        if kind == 1:  # storage
            stack.append((child, here))
        elif kind == 2 and length:
            role = _role(here)
            parts = extents(first, length)
            for number, (start, end) in enumerate(parts):
                regions.add(start, end, "ole_stream", path="/".join(here), role=role, extent=number,
                            extents=len(parts), stream_size=length)
    for start, end in _merge([(compound.offset(s), compound.offset(s) + size) for s in sorted(mini_sectors)]):
        regions.add(start, end, "ole_mini_stream")
    allocated = [s for s, value in enumerate(compound.fat) if value != _FREE]
    logical_end = compound.offset(max(allocated) + 1) if allocated else size
    if logical_end < len(data):
        regions.add(logical_end, len(data), "after_eof", logical_end=logical_end)
