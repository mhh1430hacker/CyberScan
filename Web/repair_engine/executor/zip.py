"""ZIP/OOXML repair: cut one member out and fix every offset that pointed past it."""
from __future__ import annotations

import struct

from repair_engine.executor.common import Refused, Removed


def central_directory(data: bytes):
    """[(cd_offset, cd_length, local_offset, compressed_size, flags, name)], eocd offset; None if unsupported."""
    end = data.rfind(b"PK\x05\x06")
    if end < 0 or end + 22 > len(data):
        return None
    _sig, disk, cd_disk, count_disk, count, cd_size, cd_offset, _comment = struct.unpack_from("<IHHHHIIH", data, end)
    if disk or cd_disk or count_disk != count or count == 0xFFFF or 0xFFFFFFFF in (cd_size, cd_offset):
        return None  # multi-disk or zip64
    if cd_offset + cd_size != end:
        return None  # data in front of the archive, or gaps
    entries, at = [], cd_offset
    for _ in range(count):
        if data[at:at + 4] != b"PK\x01\x02":
            return None
        flags, = struct.unpack_from("<H", data, at + 8)
        compressed, = struct.unpack_from("<I", data, at + 20)
        name_len, extra_len, comment_len = struct.unpack_from("<HHH", data, at + 28)
        local, = struct.unpack_from("<I", data, at + 42)
        length = 46 + name_len + extra_len + comment_len
        entries.append((at, length, local, compressed, flags, data[at + 46:at + 46 + name_len].decode("utf-8", "replace")))
        at += length
    return entries, end


def remove_member(data: bytes, name: str | None, start: int | None) -> tuple[bytes, list[Removed]]:
    listed = central_directory(data)
    if listed is None:
        raise Refused("unsupported zip layout (zip64, multi-disk, or data before the archive)")
    entries, end = listed
    target = next((e for e in entries if (name is not None and e[5] == name) or (name is None and e[2] == start)), None)
    if target is None:
        raise Refused(f"no member {name or start!r}")
    cd_at, cd_length, local, compressed, flags, _name = target
    name_len, extra_len = struct.unpack_from("<HH", data, local + 26)
    local_end = local + 30 + name_len + extra_len + compressed
    if flags & 0x08:
        local_end += 16 if data[local_end:local_end + 4] == b"PK\x07\x08" else 12
    shift = local_end - local
    cd_offset = entries[0][0]
    new_cd = bytearray()
    for entry in entries:
        if entry is target:
            continue
        block = bytearray(data[entry[0]:entry[0] + entry[1]])
        if entry[2] > local:
            struct.pack_into("<I", block, 42, entry[2] - shift)
        new_cd += block
    out = bytearray(data[:local]) + data[local_end:cd_offset] + new_cd + data[end:]
    eocd = cd_offset - shift + len(new_cd)
    count = len(entries) - 1
    struct.pack_into("<HHII", out, eocd + 8, count, count, len(new_cd), cd_offset - shift)
    return bytes(out), [Removed(local, local_end, "zip_member", data[local:local_end]),
                        Removed(cd_at, cd_at + cd_length, "zip_central_entry", data[cd_at:cd_at + cd_length])]
