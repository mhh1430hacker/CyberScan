"""Candidate originals: each infection pattern, run backwards.

An infector has only a few ways to put itself into a file and still let the
host run: append (an overlay or bytes after the format's end), add a
section and move the entry point into it, or prepend itself and carry the
host behind it. Each function here undoes one of those and returns every
original it could have been, with the parameters the file cannot state
(the old entry point, where the old file ended, where the host starts)
left as explicit alternatives. ``reconstruct`` then lets the witnesses
choose between them.

Nothing here decides; it only enumerates.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any

from repair_engine import pe_layout
from repair_engine.blind import pe_entry
from repair_engine.blind.witnesses import CODE, Witness, section_sums
from repair_engine.executor.common import Removed
from repair_engine.parsers import parse

_DAMAGED = (ValueError, struct.error, IndexError, KeyError, OverflowError)
TOP_ENTRIES = 8  # entry-point candidates built into full files; the rest only count as competition
SELF_CONTAINED_BITS = 8.0  # a carved piece that parses cleanly and ends exactly at the end of the file


@dataclass
class Candidate:
    family: str
    data: bytes
    removed: list[Removed]
    detail: dict[str, Any] = field(default_factory=dict)
    testimony: dict[str, float] = field(default_factory=dict)  # evidence that is not a witness (exits, stubs ...)
    alternatives: int = 1  # how many values the inferred parameter competed with
    free: bool = False  # it rests on an inferred value, so it needs evidence; a pure undo does not
    # witnesses whose outcome depends on the inferred value; when set, the value needs two independent sources
    discriminating: tuple[str, ...] | None = None
    fresh_file: bool = False  # a different file than the input (carved): its witnesses are not compared to the input's
    # filled in by the scoring
    restored: dict[str, float] = field(default_factory=dict)
    broken: dict[str, float] = field(default_factory=dict)
    net_bits: float = 0.0


def _checksum_held(infected: dict[str, Witness]) -> bool:
    witness = infected.get("pe.checksum")
    return witness is not None and witness.holds


def _refresh_checksum(buffer: bytearray, held: bool) -> None:
    """Keep the invariant the infector kept: if it recomputed the checksum, so do we; else leave the stored value."""
    if not held:
        return
    layout = pe_layout.read(bytes(buffer))
    if layout.checksum:
        pe_layout.put_u32(buffer, layout.checksum_offset, pe_layout.checksum(bytes(buffer), layout.checksum_offset))


# -- appended data ----------------------------------------------------------------------------------


def truncations(data: bytes, infected: dict[str, Witness]) -> list[Candidate]:
    regions = parse(data)
    if regions.format == "pe":
        if regions.of_kind("pe_certificate"):
            return []  # the overlay sits before a signature: cutting it is not a pure undo
        spans = regions.of_kind("pe_overlay")
    else:
        spans = regions.of_kind("after_eof", "elf_overlay")
    if not spans:
        return []
    start = min(span.start for span in spans)
    if not 0 < start < len(data):
        return []
    out = bytearray(data[:start])
    if regions.format == "pe":
        try:
            _refresh_checksum(out, _checksum_held(infected))
        except _DAMAGED:
            return []
    return [Candidate("truncate_to_logical_end", bytes(out), [Removed(start, len(data), "after_logical_end", data[start:])],
                      {"logical_end": start, "format": regions.format})]


# -- a host carried behind the infector (prepender) -------------------------------------------------

_CARVE_MAGIC = (
    (b"MZ", {"pe"}), (b"\x7fELF", {"elf"}), (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", {"ole"}),
    (b"PK\x03\x04", {"zip", "ooxml"}), (b"\x89PNG\r\n\x1a\n", {"png"}), (b"GIF8", {"gif"}), (b"%PDF-", {"pdf"}),
    (b"\xff\xd8\xff", {"jpeg"}),
)
_TRAILING = ("after_eof", "elf_overlay", "pe_overlay")
MAX_HITS = 32


def carves(data: bytes) -> list[Candidate]:
    found = []
    for magic, formats in _CARVE_MAGIC:
        at, hits = data.find(magic, 1), 0
        while at > 0 and hits < MAX_HITS:
            hits += 1
            piece = data[at:]
            regions = parse(piece)
            if len(piece) >= 64 and regions.format in formats and not regions.errors and not regions.of_kind(*_TRAILING):
                found.append(Candidate("carve_embedded", piece, [Removed(0, at, "prepended", data[:at])],
                                       {"offset": at, "format": regions.format}, {"self_contained_file": SELF_CONTAINED_BITS},
                                       free=True, fresh_file=True))
            at = data.find(magic, at + 1)
    for candidate in found:
        candidate.alternatives = len(found)
    return found


# -- an added PE section, with or without a moved entry point ---------------------------------------


def _directory_in(data: bytes, layout: pe_layout.Layout, section: pe_layout.Section) -> int | None:
    directories = layout.optional + (112 if layout.pe32_plus else 96)
    count = max(0, min(16, (layout.table - directories) // 8))
    end = section.virtual_address + max(section.virtual_size, section.raw_size)
    for index in range(count):
        if index == 4:  # the certificate entry holds a file offset, not an RVA
            continue
        rva, size = struct.unpack_from("<II", data, directories + 8 * index)
        if size and section.virtual_address <= rva < end:
            return index
    return None


def added_section(data: bytes, infected: dict[str, Witness], notes: list[str]) -> list[Candidate]:
    try:
        layout = pe_layout.read(data)
    except _DAMAGED:
        return []
    if len(layout.sections) < 2:
        return []
    target, others = layout.sections[-1], layout.sections[:-1]
    if any(s.virtual_address > target.virtual_address for s in others) or not target.raw_size:
        return []
    if target.raw_pointer + target.raw_size != len(data):
        return []
    if any(s.raw_size and s.raw_pointer + s.raw_size > target.raw_pointer for s in others):
        return []
    certificate_at, certificate_size = layout.certificate
    if certificate_size and certificate_at + certificate_size > target.raw_pointer:
        return []
    directory = _directory_in(data, layout, target)
    if directory is not None:
        notes.append(f"data directory {directory} points into the last section: undoing it would need more than removal")
        return []

    remaining_end = max([layout.size_of_headers, certificate_at + certificate_size,
                         *(s.raw_pointer + s.raw_size for s in others if s.raw_size)])
    cuts = [target.raw_pointer]
    if remaining_end < target.raw_pointer and not any(data[remaining_end:target.raw_pointer]):
        cuts.append(remaining_end)  # the infector may have padded the file up to its alignment
    size_of_code, size_of_init = struct.unpack_from("<II", data, layout.optional + 4)
    kept_code, kept_init = (value == total for value, total in zip((size_of_code, size_of_init), section_sums(layout)))
    held = _checksum_held(infected)
    moved = layout.section_at_rva(layout.entry_point) is target

    built: list[Candidate] = []
    for cut in cuts:
        out = bytearray(data[:cut])
        out[target.header_offset:target.header_offset + 40] = bytes(40)
        pe_layout.put_u16(out, layout.count_offset, len(others))
        image = max(s.virtual_address + max(s.virtual_size, s.raw_size) for s in others)
        pe_layout.put_u32(out, layout.size_of_image_offset, pe_layout.align(image, layout.section_alignment))
        code, init = section_sums(pe_layout.read(bytes(out)))
        if kept_code:  # the infector kept SizeOfCode in step with the sections: keep doing so
            pe_layout.put_u32(out, layout.optional + 4, code)
        if kept_init:
            pe_layout.put_u32(out, layout.optional + 8, init)
        removed = [Removed(target.header_offset, target.header_offset + 40, "section_header",
                           data[target.header_offset:target.header_offset + 40]),
                   Removed(cut, len(data), "section_data", data[cut:])]
        detail = {"section": target.name.rstrip(b"\x00").decode("latin-1"), "cut": cut}
        if not moved:
            _refresh_checksum(out, held)
            # Every PE ends with some section, so removing one is never a pure undo: it needs witnesses.
            built.append(Candidate("remove_added_section", bytes(out), removed, detail, alternatives=len(cuts), free=True))
            continue
        built += _entry_candidates(data, layout, target, out, removed, detail, held, len(cuts))
    if moved and not built:
        notes.append("the entry point was moved into the added section and nothing in the file says where it was")
    return built


def _entry_candidates(data: bytes, layout: pe_layout.Layout, target: pe_layout.Section, base: bytearray,
                      removed: list[Removed], detail: dict, held: bool, cuts: int) -> list[Candidate]:
    usable = bool(layout.checksum) and not held  # the stored checksum is still the original's
    votes = pe_entry.evidence(data, layout, target, usable)
    if not votes:
        return []
    solver = None
    if usable:
        try:
            solver = pe_entry.ChecksumSolver(bytes(base), layout.checksum_offset, layout.entry_offset)
        except ValueError:
            solver = None

    def quick(rva: int) -> float:  # pre-ranking only; the full witnesses are recomputed on the built file
        bits = sum(votes[rva].values())
        return bits + (16.0 if solver is not None and solver.checksum(rva) == layout.checksum else 0.0)

    ranked = sorted(votes, key=lambda rva: (-quick(rva), rva))[:TOP_ENTRIES]
    old = data[layout.entry_offset:layout.entry_offset + 4]
    made = []
    for rva in ranked:
        out = bytearray(base)
        pe_layout.put_u32(out, layout.entry_offset, rva)
        _refresh_checksum(out, held)
        made.append(Candidate("remove_added_section+restore_entry", bytes(out),
                              removed + [Removed(layout.entry_offset, layout.entry_offset + 4, "entry_point_value", old)],
                              {**detail, "entry_point": rva, "moved_entry_point": layout.entry_point},
                              dict(votes[rva]), alternatives=len(votes) * cuts, free=True,
                              discriminating=("pe.checksum", "pe.authenticode")))
    return made
