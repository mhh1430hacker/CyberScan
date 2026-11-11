"""PE repairs: strip an overlay, remove a trailing section, restore an entry point."""
from __future__ import annotations

from repair_engine import pe_layout
from repair_engine.executor.common import Refused, Removed, truncate_at


def _layout(data: bytes) -> pe_layout.Layout:
    try:
        return pe_layout.read(data)
    except Exception as exc:  # noqa: BLE001
        raise Refused(f"not a readable PE: {exc}") from exc


def _fix_checksum(buffer: bytearray, layout: pe_layout.Layout, original: int) -> None:
    """Recompute only if the file carried one; a zero checksum stays zero."""
    if original:
        pe_layout.put_u32(buffer, layout.checksum_offset, pe_layout.checksum(bytes(buffer), layout.checksum_offset))


def strip_overlay(data: bytes, start: int | None) -> tuple[bytes, list[Removed]]:
    layout = _layout(data)
    if start is None or start < layout.image_end:
        raise Refused("start is inside the image, not in the overlay")
    offset, size = layout.certificate
    if size and start < offset + size:
        raise Refused("the span overlaps the Authenticode certificate")
    return truncate_at(data, start, "pe_overlay")


def remove_section(data: bytes, start: int | None) -> tuple[bytes, list[Removed]]:
    layout = _layout(data)
    if start is None:
        raise Refused("no region given")
    target = next((s for s in layout.sections if s.raw_size and s.raw_pointer <= start < s.raw_pointer + s.raw_size), None)
    if target is None:
        raise Refused("the region is not inside a section's raw data")
    others = [s for s in layout.sections if s is not target]
    if layout.certificate[1]:
        raise Refused("the file is signed; removing a section breaks the signature's coverage")
    if target.index != len(layout.sections) - 1 or any(s.virtual_address > target.virtual_address for s in others):
        raise Refused("only the last section (in the table and in memory) can be removed without relocating others")
    if any(s.raw_pointer + s.raw_size > target.raw_pointer for s in others if s.raw_size) or target.raw_pointer + target.raw_size < len(data):
        raise Refused("the section's data is not the end of the file")
    if layout.section_at_rva(layout.entry_point) is target:
        raise Refused("the entry point lies in this section; restore it from a trusted reference first")
    remaining_end = max([layout.size_of_headers, *(s.raw_pointer + s.raw_size for s in others if s.raw_size)])
    cut = remaining_end if not any(data[remaining_end:target.raw_pointer]) else target.raw_pointer  # drop only zero padding
    out = bytearray(data[:cut])
    header = bytes(out[target.header_offset:target.header_offset + 40])
    out[target.header_offset:target.header_offset + 40] = bytes(40)
    pe_layout.put_u16(out, layout.count_offset, len(others))
    image = max(s.virtual_address + max(s.virtual_size, s.raw_size) for s in others) if others else layout.size_of_headers
    pe_layout.put_u32(out, layout.size_of_image_offset, pe_layout.align(image, layout.section_alignment))
    _fix_checksum(out, layout, layout.checksum)
    return bytes(out), [Removed(target.header_offset, target.header_offset + 40, "section_header", header),
                        Removed(cut, len(data), "section_data", data[cut:])]


def restore_entry_point(data: bytes, reference: int | None) -> tuple[bytes, list[Removed]]:
    """Only with a value from a trusted reference: the file alone cannot say where it was."""
    layout = _layout(data)
    if not isinstance(reference, int) or isinstance(reference, bool):
        raise Refused("no trusted reference entry point")
    if layout.section_at_rva(reference) is None:
        raise Refused("the reference entry point is in no section of this file")
    out = bytearray(data)
    old = bytes(out[layout.entry_offset:layout.entry_offset + 4])
    pe_layout.put_u32(out, layout.entry_offset, reference)
    _fix_checksum(out, layout, layout.checksum)
    return bytes(out), [Removed(layout.entry_offset, layout.entry_offset + 4, "entry_point_value", old)]
