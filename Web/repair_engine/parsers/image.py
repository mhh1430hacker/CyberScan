"""PNG, JPEG and GIF: their blocks, and anything stored past the image's
logical end (``IEND``, ``EOI``, the GIF trailer)."""
from __future__ import annotations

import struct

from repair_engine.regions import RegionMap

_MAX_BLOCKS = 100_000


def _after(data: bytes, regions: RegionMap, logical_end: int) -> None:
    if logical_end < len(data):
        regions.add(logical_end, len(data), "after_eof", logical_end=logical_end)
    regions.add(0, logical_end, "image_data")


def parse_png(data: bytes, regions: RegionMap) -> None:
    regions.format = "png"
    position, count = 8, 0
    regions.add(0, 8, "png_signature")
    while position + 12 <= len(data) and count < _MAX_BLOCKS:
        length = struct.unpack_from(">I", data, position)[0]
        kind = data[position + 4:position + 8].decode("latin-1")
        end = position + 12 + length
        regions.add(position, end, "png_chunk", type=kind)
        count += 1
        position = end
        if kind == "IEND":
            _after(data, regions, min(end, len(data)))
            return
    regions.errors.append("png: no IEND chunk")


def parse_jpeg(data: bytes, regions: RegionMap) -> None:
    regions.format = "jpeg"
    position, count = 2, 0
    while position + 2 <= len(data) and count < _MAX_BLOCKS:
        if data[position] != 0xFF:
            regions.errors.append(f"jpeg: expected a marker at {position}")
            return
        marker = data[position + 1]
        if marker == 0xD9:
            _after(data, regions, position + 2)
            return
        if marker == 0xFF:  # fill byte
            position += 1
            continue
        if marker == 0x01 or 0xD0 <= marker <= 0xD7:  # markers without a length
            position += 2
            continue
        if position + 4 > len(data):
            break
        length = struct.unpack_from(">H", data, position + 2)[0]
        end = position + 2 + length
        regions.add(position, end, "jpeg_segment", marker=f"FF{marker:02X}")
        count += 1
        position = end
        if marker == 0xDA:  # entropy-coded data runs to the next real marker
            while True:
                position = data.find(b"\xff", position)
                if position < 0 or position + 1 >= len(data):
                    position = len(data)
                    break
                if data[position + 1] == 0x00 or 0xD0 <= data[position + 1] <= 0xD7:  # stuffing, restarts
                    position += 2
                    continue
                break
            regions.add(end, position, "jpeg_scan_data")
    regions.errors.append("jpeg: no end-of-image marker")


def parse_gif(data: bytes, regions: RegionMap) -> None:
    regions.format = "gif"
    if len(data) < 13:
        regions.errors.append("gif: truncated header")
        return
    flags = data[10]
    position = 13 + (3 << ((flags & 7) + 1) if flags & 0x80 else 0)
    regions.add(0, position, "gif_header")
    count = 0
    while position < len(data) and count < _MAX_BLOCKS:
        introducer = data[position]
        start = position
        if introducer == 0x3B:
            _after(data, regions, position + 1)
            return
        if introducer == 0x21:
            position += 2
        elif introducer == 0x2C:
            local = data[position + 9] if position + 9 < len(data) else 0
            position += 10 + (3 << ((local & 7) + 1) if local & 0x80 else 0) + 1  # + LZW code size
        else:
            regions.errors.append(f"gif: unknown block 0x{introducer:02X} at {position}")
            return
        while position < len(data) and data[position] != 0:  # data sub-blocks
            position += data[position] + 1
        position += 1
        regions.add(start, position, "gif_block", type="extension" if introducer == 0x21 else "image")
        count += 1
    regions.errors.append("gif: no trailer")
