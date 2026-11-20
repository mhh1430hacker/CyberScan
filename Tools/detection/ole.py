"""Minimal, bounded reader for OLE Compound File Binary (CFB) containers and VBA projects.

Used for legacy Office files (.doc/.xls/.ppt), Outlook .msg, and the ``vbaProject.bin`` part
inside macro-enabled OOXML files. Implements [MS-CFB] read paths and [MS-OVBA] decompression.

Every structure read from the file is bounds-checked; sector chains are capped and loop-checked;
total bytes materialised are capped. Malformed input raises ``OleError``, never anything else.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

CFB_SIGNATURE = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"
_FREESECT, _ENDOFCHAIN = 0xFFFFFFFF, 0xFFFFFFFE
_SPECIAL = {0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFD, 0xFFFFFFFC}
MAX_STREAM_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 48 * 1024 * 1024
MAX_DIRECTORY_ENTRIES = 4096
MAX_VBA_SOURCE_BYTES = 4 * 1024 * 1024


class OleError(Exception):
    """Raised for any malformed or over-limit compound file."""


@dataclass
class OleEntry:
    sid: int
    name: str
    kind: int  # 1 storage, 2 stream, 5 root
    start: int
    size: int
    left: int
    right: int
    child: int
    path: str = ""
    children: list[int] = field(default_factory=list)


class OleFile:
    def __init__(self, data: bytes):
        if len(data) < 512 or not data.startswith(CFB_SIGNATURE):
            raise OleError("Not an OLE compound file.")
        self.data = data
        self._budget = MAX_TOTAL_BYTES
        try:
            self._parse()
        except OleError:
            raise
        except (struct.error, IndexError, ValueError, OverflowError, RecursionError) as exc:
            raise OleError(f"Malformed compound file: {type(exc).__name__}") from exc

    # -- header / allocation tables -------------------------------------------------------
    def _parse(self) -> None:
        header = self.data[:512]
        sector_shift = struct.unpack_from("<H", header, 0x1E)[0]
        mini_shift = struct.unpack_from("<H", header, 0x20)[0]
        if sector_shift not in (9, 12) or mini_shift != 6:
            raise OleError("Unsupported sector size.")
        self.sector_size = 1 << sector_shift
        self.mini_sector_size = 1 << mini_shift
        num_fat = struct.unpack_from("<I", header, 0x2C)[0]
        first_dir = struct.unpack_from("<I", header, 0x30)[0]
        self.mini_cutoff = struct.unpack_from("<I", header, 0x38)[0]
        first_minifat = struct.unpack_from("<I", header, 0x3C)[0]
        num_minifat = struct.unpack_from("<I", header, 0x40)[0]
        first_difat = struct.unpack_from("<I", header, 0x44)[0]
        num_difat = struct.unpack_from("<I", header, 0x48)[0]
        self.max_sector = (len(self.data) - 512) // self.sector_size
        if num_fat > self.max_sector + 1 or num_difat > self.max_sector + 1:
            raise OleError("Allocation table count exceeds file size.")

        fat_sectors = [s for s in struct.unpack_from("<109I", header, 0x4C) if s not in _SPECIAL]
        difat_sector, seen = first_difat, set()
        per_difat = self.sector_size // 4 - 1
        while difat_sector not in _SPECIAL and len(seen) < num_difat + 1:
            if difat_sector in seen:
                raise OleError("DIFAT chain loop.")
            seen.add(difat_sector)
            values = struct.unpack_from(f"<{per_difat + 1}I", self._sector(difat_sector))
            fat_sectors.extend(v for v in values[:per_difat] if v not in _SPECIAL)
            difat_sector = values[per_difat]
        fat_sectors = fat_sectors[:num_fat]
        per_sector = self.sector_size // 4
        fat = bytearray()
        for sector in fat_sectors:
            fat += self._sector(sector)
        self.fat = struct.unpack(f"<{len(fat) // 4}I", bytes(fat[: len(fat) // 4 * 4])) if fat else ()
        if len(self.fat) > per_sector * (self.max_sector + 2):
            raise OleError("FAT larger than file.")

        dir_bytes = self._chain_bytes(first_dir, self.fat, self.sector_size, self._sector, MAX_DIRECTORY_ENTRIES * 128)
        self.entries: list[OleEntry] = []
        for sid in range(min(len(dir_bytes) // 128, MAX_DIRECTORY_ENTRIES)):
            raw = dir_bytes[sid * 128:(sid + 1) * 128]
            name_len = struct.unpack_from("<H", raw, 0x40)[0]
            name = raw[: max(0, min(64, name_len) - 2)].decode("utf-16-le", errors="replace")
            kind = raw[0x42]
            left, right, child = struct.unpack_from("<III", raw, 0x44)
            start = struct.unpack_from("<I", raw, 0x74)[0]
            size = struct.unpack_from("<Q", raw, 0x78)[0]
            if self.sector_size == 512:
                size &= 0xFFFFFFFF
            self.entries.append(OleEntry(sid, name, kind, start, size, left, right, child))
        if not self.entries or self.entries[0].kind != 5:
            raise OleError("Missing root directory entry.")

        root = self.entries[0]
        self.mini_stream = self._chain_bytes(root.start, self.fat, self.sector_size, self._sector, min(root.size, MAX_STREAM_BYTES)) \
            if root.size else b""
        minifat_bytes = self._chain_bytes(first_minifat, self.fat, self.sector_size, self._sector,
                                          num_minifat * self.sector_size) if num_minifat else b""
        self.minifat = struct.unpack(f"<{len(minifat_bytes) // 4}I", minifat_bytes[: len(minifat_bytes) // 4 * 4]) if minifat_bytes else ()
        self._build_paths()

    def _sector(self, index: int) -> bytes:
        if index > self.max_sector:
            raise OleError(f"Sector {index} beyond end of file.")
        offset = 512 + index * self.sector_size
        return self.data[offset: offset + self.sector_size]

    def _mini_sector(self, index: int) -> bytes:
        offset = index * self.mini_sector_size
        if offset >= len(self.mini_stream):
            raise OleError("Mini sector beyond mini stream.")
        return self.mini_stream[offset: offset + self.mini_sector_size]

    def _chain_bytes(self, start: int, table, unit: int, reader, limit: int) -> bytes:
        out = bytearray()
        sector, visited = start, set()
        max_steps = limit // unit + 2
        while sector not in _SPECIAL and len(out) < limit:
            if sector in visited or len(visited) > max_steps or sector >= len(table):
                raise OleError("Corrupt or looping sector chain.")
            visited.add(sector)
            out += reader(sector)
            sector = table[sector]
        self._budget -= len(out)
        if self._budget < 0:
            raise OleError("Compound file exceeds the materialisation budget.")
        return bytes(out[:limit])

    def _build_paths(self) -> None:
        count = len(self.entries)

        def siblings(sid: int, depth: int = 0) -> list[int]:
            # In-order walk of the red-black sibling tree, iterative to survive hostile depth.
            result, stack, current, guard = [], [], sid, 0
            while (stack or 0 <= current < count) and guard < count * 2:
                guard += 1
                while 0 <= current < count and guard < count * 2:
                    stack.append(current)
                    current = self.entries[current].left
                    guard += 1
                if not stack:
                    break
                node = stack.pop()
                if node not in result:
                    result.append(node)
                current = self.entries[node].right
            return result

        queue, visited = [(0, "")], {0}
        while queue:
            sid, prefix = queue.pop()
            entry = self.entries[sid]
            for child in siblings(entry.child):
                if child in visited or child >= count:
                    continue
                visited.add(child)
                child_entry = self.entries[child]
                child_entry.path = f"{prefix}{child_entry.name}" if not prefix else f"{prefix}/{child_entry.name}"
                entry.children.append(child)
                if child_entry.kind == 1:
                    queue.append((child, child_entry.path))

    # -- public API ----------------------------------------------------------------------------
    def streams(self) -> list[OleEntry]:
        return [entry for entry in self.entries if entry.kind == 2 and entry.path]

    def storages(self) -> list[OleEntry]:
        return [entry for entry in self.entries if entry.kind == 1 and entry.path]

    def read(self, entry: OleEntry, limit: int = MAX_STREAM_BYTES) -> bytes:
        size = min(entry.size, limit)
        if entry.size < self.mini_cutoff:
            return self._chain_bytes(entry.start, self.minifat, self.mini_sector_size, self._mini_sector, size)[:size]
        return self._chain_bytes(entry.start, self.fat, self.sector_size, self._sector, size)[:size]

    def find(self, path: str) -> OleEntry | None:
        wanted = path.lower()
        return next((entry for entry in self.entries if entry.path.lower() == wanted), None)


# ---------------------------------------------------------------------------
# [MS-OVBA] 2.4.1 compression
# ---------------------------------------------------------------------------

def decompress_vba(data: bytes, limit: int = MAX_VBA_SOURCE_BYTES) -> bytes:
    if not data or data[0] != 0x01:
        raise OleError("Not a VBA compressed container.")
    out = bytearray()
    pos = 1
    while pos + 2 <= len(data) and len(out) < limit:
        header = data[pos] | (data[pos + 1] << 8)
        chunk_size = (header & 0x0FFF) + 3
        if (header >> 12) & 0x7 != 0b011:
            raise OleError("Bad VBA chunk signature.")
        chunk_end = min(len(data), pos + chunk_size)
        pos += 2
        chunk_start = len(out)
        if not header & 0x8000:  # uncompressed chunk: 4096 raw bytes
            out += data[pos: pos + 4096]
            pos += 4096
            continue
        while pos < chunk_end and len(out) < limit:
            flags = data[pos]
            pos += 1
            for bit in range(8):
                if pos >= chunk_end:
                    break
                if not flags & (1 << bit):
                    out.append(data[pos])
                    pos += 1
                    continue
                if pos + 2 > chunk_end:
                    raise OleError("Truncated copy token.")
                token = data[pos] | (data[pos + 1] << 8)
                pos += 2
                difference = len(out) - chunk_start
                bit_count = 4
                while (1 << bit_count) < difference and bit_count < 12:
                    bit_count += 1
                length_mask = 0xFFFF >> bit_count
                length = (token & length_mask) + 3
                offset = (token >> (16 - bit_count)) + 1
                source = len(out) - offset
                if source < chunk_start:
                    raise OleError("Copy token points before chunk start.")
                for index in range(length):  # byte-by-byte: overlapping copies are legal
                    out.append(out[source + index])
        pos = chunk_end
    return bytes(out[:limit])


def _parse_dir_stream(decompressed: bytes) -> list[tuple[str, int]]:
    """Return (stream name, source offset) for every module listed in the VBA ``dir`` stream."""
    modules: list[tuple[str, int]] = []
    pos, current_name = 0, None
    while pos + 6 <= len(decompressed):
        record_id, size = struct.unpack_from("<HI", decompressed, pos)
        pos += 6
        if record_id == 0x0009:  # PROJECTVERSION: size field says 4 but 6 bytes follow
            size = 6
        if size > len(decompressed) - pos:
            break
        payload = decompressed[pos: pos + size]
        if record_id == 0x001A:  # MODULESTREAMNAME
            current_name = payload.decode("latin-1", errors="replace")
        elif record_id == 0x0031 and current_name is not None and size == 4:  # MODULEOFFSET
            modules.append((current_name, struct.unpack("<I", payload)[0]))
            current_name = None
        pos += size
    return modules


def extract_vba_sources(ole: OleFile, max_modules: int = 64) -> list[dict[str, str]]:
    """Decompress VBA module source from every ``VBA`` storage in the container."""
    sources: list[dict[str, str]] = []
    for storage in ole.storages():
        if storage.name.upper() != "VBA":
            continue
        children = {ole.entries[sid].name.lower(): ole.entries[sid] for sid in storage.children}
        dir_entry = children.get("dir")
        modules: list[tuple[str, int]] = []
        if dir_entry is not None:
            try:
                modules = _parse_dir_stream(decompress_vba(ole.read(dir_entry)))
            except OleError:
                modules = []
        for name, offset in modules[:max_modules]:
            entry = children.get(name.lower())
            if entry is None:
                continue
            try:
                code = decompress_vba(ole.read(entry)[offset:])
            except OleError:
                continue
            sources.append({"module": name, "storage": storage.path, "code": code.decode("latin-1", errors="replace")})
        if not modules:  # dir stream unreadable: scan module streams for a compressed container
            for name, entry in list(children.items())[:max_modules]:
                if name in {"dir", "_vba_project"} or name.startswith("__srp_"):
                    continue
                raw = ole.read(entry)
                for start in range(min(len(raw) - 3, 65536)):  # source sits after the p-code; bound the search
                    if raw[start] != 1 or (raw[start + 2] >> 4) & 0x7 != 0b011:
                        continue
                    try:
                        code = decompress_vba(raw[start:])
                    except OleError:
                        continue
                    if b"Attribute VB_" in code:
                        sources.append({"module": entry.name, "storage": storage.path,
                                        "code": code.decode("latin-1", errors="replace")})
                        break
    return sources
