"""Inert anomaly injection into verified-clean files, with exact ground truth.

Each family takes a clean file and returns an ``Injection``: the modified
bytes, the untouched original (the repair target), the exact byte spans that
were added or changed in the modified file, and the repair action a correct
planner should choose. Content comes only from ``synth.content`` (random
bytes, zeros, placeholder text). A family returns None when a file is not
eligible (for example a signed PE for a family that would break the
signature's coverage), instead of producing a half-valid file.

Sizes, positions, names and content kinds are drawn widely so a model
cannot key on injector habits. What this does *not* do is imitate how real
malware modifies files; see the README's Limitations.
"""
from __future__ import annotations

import random
import re
import struct
import zlib
from dataclasses import dataclass, field
from typing import Any, Callable

from repair_engine import pe_layout
from repair_engine.executor.zip import central_directory
from repair_engine.parsers import parse
from repair_engine.parsers.pdf import _ENDOBJ, _OBJECT  # the same tokenisation the parser uses
from repair_engine.synth.content import KINDS, inert, size_between


@dataclass
class Injection:
    family: str
    original: bytes
    modified: bytes
    regions: list[tuple[int, int, str]]  # exact [start, end) spans in ``modified``, with what they are
    action: str  # the planner label (M3)
    content_kind: str
    name: str = ""  # file name to report (changes only for the magic-mismatch family)
    details: dict[str, Any] = field(default_factory=dict)


def _kind(rng: random.Random) -> str:
    return rng.choice(KINDS)


def _logical_end(data: bytes) -> int | None:
    """Where the format's own data ends, if the parser knows it."""
    regions = parse(data)
    if regions.format == "pe":
        return pe_layout.read(data).image_end if not regions.of_kind("pe_certificate") else None
    for kind in ("after_eof", "elf_overlay"):
        found = regions.of_kind(kind)
        if found:
            return found[0].start
    ends = {"zip": "zip_end_record", "ooxml": "zip_end_record", "pdf": "pdf_eof_marker"}
    marker = ends.get(regions.format)
    if marker:
        found = regions.of_kind(marker)
        return found[-1].end if found else None
    if regions.format in {"png", "jpeg", "gif", "elf", "ole"}:
        return len(data)
    return None


# -- generic ------------------------------------------------------------------------------


def append_after_end(data: bytes, name: str, rng: random.Random) -> Injection | None:
    """Trailing data after the format's logical end (overlay for PE/ELF)."""
    end = _logical_end(data)
    if end is None or end != len(data):  # unknown end, or the file already carries trailing data
        return None
    fmt = parse(data).format
    kind = _kind(rng)
    payload = inert(kind, size_between(rng, 16, max(64, min(4 << 20, len(data) * 2))), rng)
    action = "strip_overlay" if fmt in {"pe", "elf"} else "truncate_after_eof"
    return Injection("append_after_end", data, data + payload, [(len(data), len(data) + len(payload), "appended")],
                     action, kind, name, {"format": fmt})


def high_entropy_block(data: bytes, name: str, rng: random.Random) -> Injection | None:
    """A random block inside a plain-text file (no structure to remove it by)."""
    if parse(data).format != "unknown" or len(data) < 256:
        return None
    sample = data[:65536]
    if sum(32 <= b < 127 or b in (9, 10, 13) for b in sample) < 0.95 * len(sample):
        return None
    lines = [i + 1 for i, b in enumerate(data) if b == 10] or [len(data) // 2]
    at = rng.choice(lines)
    block = inert("random", size_between(rng, 64, max(128, min(1 << 20, len(data)))), rng)
    return Injection("high_entropy_block", data, data[:at] + block + data[at:], [(at, at + len(block), "inserted")],
                     "report_only", "random", name, {"note": "no structural boundary: localise and report, never cut"})


_MISMATCH = {"pe": ".pdf", "pdf": ".docx", "zip": ".jpg", "ooxml": ".pdf", "ole": ".png", "png": ".exe", "jpeg": ".doc",
             "gif": ".txt", "elf": ".pdf"}


def magic_mismatch(data: bytes, name: str, rng: random.Random) -> Injection | None:
    """Same bytes under a name that promises another format. Nothing to cut."""
    fmt = parse(data).format
    if fmt not in _MISMATCH:
        return None
    stem = name.rsplit(".", 1)[0] if "." in name else (name or "file")
    return Injection("magic_mismatch", data, data, [(0, min(16, len(data)), "signature")], "report_only", "none",
                     f"{stem}{_MISMATCH[fmt]}", {"format": fmt})


# -- PE --------------------------------------------------------------------------------------

_SECTION_NAMES = [b".text", b".data", b".rdata", b".idata", b".tls", b".reloc", b".bss", b".pdata", b".code", b".rsrc"]
_SECTION_FLAGS = [0x60000020, 0xC0000040, 0x40000040, 0xE0000020, 0xE0000060]


def _new_section_name(rng: random.Random, existing: set[bytes]) -> bytes:
    for _ in range(20):
        base = rng.choice(_SECTION_NAMES) if rng.random() < 0.6 else b"." + bytes(rng.choice(b"abcdefghijklmnopqrstuvwxyz") for _ in range(rng.randint(2, 6)))
        name = base if base not in existing else base[:6] + str(rng.randint(0, 9)).encode()
        if name not in existing:
            return name.ljust(8, b"\x00")[:8]
    return b".s%05d" % rng.randint(0, 99999)


def _pe_add_section(data: bytes, rng: random.Random, redirect_entry: bool) -> tuple[bytes, list, dict] | None:
    try:
        layout = pe_layout.read(data)
    except (ValueError, struct.error):
        return None
    if layout.certificate[1] or layout.image_end != len(data) or not layout.sections:
        return None  # signed, or already has an overlay: the new section would not be the file's end
    header_at = layout.table + 40 * len(layout.sections)
    first_raw = min([s.raw_pointer for s in layout.sections if s.raw_size] or [layout.size_of_headers])
    if header_at + 40 > min(layout.size_of_headers, first_raw) or any(data[header_at:header_at + 40]):
        return None  # no free slot in the section table
    kind = _kind(rng)
    size = size_between(rng, 64, 1 << 20)
    raw_pointer = pe_layout.align(len(data), layout.file_alignment)
    raw_size = pe_layout.align(size, layout.file_alignment)
    last = max(layout.sections, key=lambda s: s.virtual_address)
    va = pe_layout.align(last.virtual_address + max(last.virtual_size, last.raw_size), layout.section_alignment)
    name = _new_section_name(rng, {s.name for s in layout.sections})
    flags = rng.choice(_SECTION_FLAGS) if not redirect_entry else rng.choice([0x60000020, 0xE0000020])
    out = bytearray(data) + bytes(raw_pointer - len(data)) + inert(kind, size, rng) + bytes(raw_size - size)
    struct.pack_into("<8sIIIIIIHHI", out, header_at, name, size, va, raw_size, raw_pointer, 0, 0, 0, 0, flags)
    pe_layout.put_u16(out, layout.count_offset, len(layout.sections) + 1)
    pe_layout.put_u32(out, layout.size_of_image_offset, pe_layout.align(va + size, layout.section_alignment))
    regions = [(header_at, header_at + 40, "section_header"), (layout.count_offset, layout.count_offset + 2, "header_field"),
               (layout.size_of_image_offset, layout.size_of_image_offset + 4, "header_field"),
               (len(data), len(out), "section_data")]
    details = {"section": name.rstrip(b"\x00").decode("latin-1"), "va": va, "content_kind": kind, "original_entry": layout.entry_point}
    if redirect_entry:
        entry = va + rng.randrange(0, size)
        pe_layout.put_u32(out, layout.entry_offset, entry)
        regions.append((layout.entry_offset, layout.entry_offset + 4, "entry_point"))
        details["entry"] = entry
    if layout.checksum:
        pe_layout.put_u32(out, layout.checksum_offset, pe_layout.checksum(bytes(out), layout.checksum_offset))
        regions.append((layout.checksum_offset, layout.checksum_offset + 4, "header_field"))
    return bytes(out), sorted(regions), details


def pe_add_section(data: bytes, name: str, rng: random.Random) -> Injection | None:
    made = _pe_add_section(data, rng, redirect_entry=False)
    if made is None:
        return None
    modified, regions, details = made
    return Injection("pe_add_section", data, modified, regions, "remove_section_and_fix_headers", details["content_kind"], name, details)


def pe_entry_redirect(data: bytes, name: str, rng: random.Random) -> Injection | None:
    """A new section with the entry point moved into it. The original entry
    point is not recoverable from the modified file alone, so the honest
    label is report_only unless a trusted reference supplies it."""
    made = _pe_add_section(data, rng, redirect_entry=True)
    if made is None:
        return None
    modified, regions, details = made
    return Injection("pe_entry_redirect", data, modified, regions, "report_only", details["content_kind"], name,
                     {**details, "with_reference_action": "restore_entry_point"})


# -- OOXML / ZIP ----------------------------------------------------------------------------------


def _zip_entries(data: bytes):
    """Central directory entries as (cd_offset, cd_length, local_offset, name); None if unsupported."""
    listed = central_directory(data)
    if listed is None:
        return None
    entries, end = listed
    return [(at, length, local, name) for at, length, local, _size, _flags, name in entries], end


def _ooxml_add_member(data: bytes, name: str, rng: random.Random, family: str) -> Injection | None:
    if parse(data).format != "ooxml":
        return None
    listed = _zip_entries(data)
    if listed is None:
        return None
    entries, end = listed
    names = {entry[3] for entry in entries}
    root = next((part.split("/")[0] for part in names if part.split("/")[0] in {"word", "xl", "ppt"}), "word")
    if family == "ooxml_vba_part":
        member = f"{root}/vbaProject.bin"
    else:
        member = f"{root}/embeddings/oleObject{rng.randint(1, 40)}.bin"
    if member in names:
        return None
    kind = _kind(rng)
    content = inert(kind, size_between(rng, 64, 1 << 20), rng)
    deflate = rng.random() < 0.7
    if deflate:
        compressor = zlib.compressobj(rng.randint(1, 9), zlib.DEFLATED, -15)
        stored = compressor.compress(content) + compressor.flush()
    else:
        stored = content
    crc = zlib.crc32(content) & 0xFFFFFFFF
    dos_time = (rng.randint(0, 23) << 11) | (rng.randint(0, 59) << 5) | rng.randint(0, 29)
    dos_date = ((rng.randint(2015, 2025) - 1980) << 9) | (rng.randint(1, 12) << 5) | rng.randint(1, 28)
    raw_name, method = member.encode(), (8 if deflate else 0)
    cd_offset = entries[0][0] if entries else end
    # Where the member's bytes go: before some existing member, or just before the central directory.
    boundaries = sorted({local for _at, _length, local, _name in entries}) + [cd_offset]
    insert_at = rng.choice(boundaries)
    local = struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, 0, method, dos_time, dos_date, crc, len(stored), len(content),
                        len(raw_name), 0) + raw_name + stored
    central = struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, 20, 20, 0, method, dos_time, dos_date, crc, len(stored),
                          len(content), len(raw_name), 0, 0, 0, 0, 0, insert_at) + raw_name
    shift = len(local)
    position = rng.randint(0, len(entries))  # where its entry goes in the central directory
    new_cd = bytearray()
    for index, (at, length, local_offset, _name) in enumerate(entries):
        if index == position:
            new_cd += central
        entry = bytearray(data[at:at + length])
        if local_offset >= insert_at:  # members after the insertion point move
            struct.pack_into("<I", entry, 42, local_offset + shift)
        new_cd += entry
    if position == len(entries):
        new_cd += central
    out = bytearray(data[:insert_at]) + local + data[insert_at:cd_offset] + new_cd + data[end:]
    cd_start = cd_offset + shift
    eocd = cd_start + len(new_cd)
    struct.pack_into("<HHII", out, eocd + 8, len(entries) + 1, len(entries) + 1, len(new_cd), cd_start)
    central_at = cd_start + sum(length for _at, length, *_rest in entries[:position])
    regions = [(insert_at, insert_at + len(local), "zip_member"), (central_at, central_at + len(central), "zip_central_entry"),
               (eocd + 8, eocd + 20, "zip_end_record_fields")]
    return Injection(family, data, bytes(out), sorted(regions), "remove_zip_member", kind, name,
                     {"member": member, "insert_at": insert_at, "cd_position": position, "deflate": deflate})


def ooxml_vba_part(data: bytes, name: str, rng: random.Random) -> Injection | None:
    return _ooxml_add_member(data, name, rng, "ooxml_vba_part")


def ooxml_embedded_object(data: bytes, name: str, rng: random.Random) -> Injection | None:
    return _ooxml_add_member(data, name, rng, "ooxml_embedded_object")


# -- PDF -------------------------------------------------------------------------------------------------

_ROOT = re.compile(rb"/Root\s+(\d+)\s+(\d+)\s+R")
_SIZE = re.compile(rb"/Size\s+(\d+)")
_STARTXREF = re.compile(rb"startxref\s+(\d+)")


def _pdf_catalog(data: bytes) -> tuple[int, int, bytes] | None:
    roots, sizes, xrefs = _ROOT.findall(data), _SIZE.findall(data), _STARTXREF.findall(data)
    if not roots or not sizes or not xrefs:
        return None
    number, generation = int(roots[-1][0]), int(roots[-1][1])
    body = None
    for match in _OBJECT.finditer(data):  # the last definition of the root object wins
        if int(match.group(1)) == number and int(match.group(2)) == generation:
            end = _ENDOBJ.search(data, match.end())
            if end:
                body = data[match.end():end.start()].strip()
    if body is None or not body.startswith(b"<<") or b"stream" in body:
        return None  # catalog inside an object stream, or unreadable
    return number, generation, body


def _pdf_incremental(data: bytes, name: str, rng: random.Random, family: str) -> Injection | None:
    if parse(data).format != "pdf" or parse(data).of_kind("after_eof"):
        return None
    found = _pdf_catalog(data)
    if found is None:
        return None
    root, generation, catalog = found
    size = max(int(value) for value in _SIZE.findall(data))
    previous = int(_STARTXREF.findall(data)[-1])
    kind = rng.choice(("placeholder", "zeros")) if family == "pdf_javascript" else _kind(rng)
    objects: list[tuple[int, bytes]] = []
    if family == "pdf_javascript":
        if b"/OpenAction" in catalog or b"/AA" in catalog:
            return None
        text = inert("placeholder", size_between(rng, 24, 400), rng).replace(b"(", b"").replace(b")", b"")
        objects.append((size, b"<< /Type /Action /S /JavaScript /JS (// " + text + b") >>"))
        addition = b" /OpenAction %d 0 R" % size
    else:
        if b"/Names" in catalog:
            return None
        payload = inert(kind, size_between(rng, 32, 1 << 19), rng)
        filename = b"attachment%d.%s" % (rng.randint(1, 999), rng.choice([b"txt", b"bin", b"dat", b"pdf"]))
        objects.append((size, b"<< /Type /EmbeddedFile /Length %d >>\nstream\n" % len(payload) + payload + b"\nendstream"))
        objects.append((size + 1, b"<< /Type /Filespec /F (" + filename + b") /EF << /F %d 0 R >> >>" % size))
        addition = b" /Names << /EmbeddedFiles << /Names [(" + filename + b") %d 0 R] >> >>" % (size + 1)
    new_catalog = b"<<" + addition + catalog[2:]
    eol = b"\r\n" if data.endswith(b"\r\n") else b"\n"
    tail = b"" if data.endswith((b"\n", b"\r")) else eol
    offsets: dict[int, int] = {}
    chunk = bytearray(tail)
    base = len(data)
    for number, body in objects + [(root, new_catalog)]:
        offsets[number] = base + len(chunk)
        chunk += b"%d %d obj%s" % (number, generation if number == root else 0, eol) + body + eol + b"endobj" + eol
    xref_at = base + len(chunk)
    # Cross-reference entries are exactly 20 bytes: a two-byte line end even in LF files.
    chunk += b"xref" + eol + b"0 1" + eol + b"0000000000 65535 f\r\n"
    for number in sorted(offsets):
        gen = generation if number == root else 0
        chunk += b"%d 1" % number + eol + b"%010d %05d n\r\n" % (offsets[number], gen)
    top = max(offsets) + 1
    chunk += b"trailer" + eol + b"<< /Size %d /Root %d %d R /Prev %d >>" % (max(top, size), root, generation, previous) + eol
    chunk += b"startxref" + eol + b"%d" % xref_at + eol + b"%%EOF" + eol
    return Injection(family, data, data + bytes(chunk), [(base, base + len(chunk), "incremental_update")],
                     "remove_pdf_object_and_refs", kind, name,
                     {"objects": sorted(offsets), "catalog": root})


def pdf_javascript(data: bytes, name: str, rng: random.Random) -> Injection | None:
    return _pdf_incremental(data, name, rng, "pdf_javascript")


def pdf_embedded_file(data: bytes, name: str, rng: random.Random) -> Injection | None:
    return _pdf_incremental(data, name, rng, "pdf_embedded_file")


FAMILIES: dict[str, Callable[[bytes, str, random.Random], Injection | None]] = {
    "append_after_end": append_after_end,
    "high_entropy_block": high_entropy_block,
    "magic_mismatch": magic_mismatch,
    "pe_add_section": pe_add_section,
    "pe_entry_redirect": pe_entry_redirect,
    "ooxml_vba_part": ooxml_vba_part,
    "ooxml_embedded_object": ooxml_embedded_object,
    "pdf_javascript": pdf_javascript,
    "pdf_embedded_file": pdf_embedded_file,
}
# Listed in the spec, not built yet (they need a resource-tree / CFB writer):
NOT_YET = ("pe_resource_blob", "ole_vba_stream", "ole_embedded_object", "elf_add_section")


def inject(data: bytes, name: str, family: str, seed: int) -> Injection | None:
    return FAMILIES[family](data, name, random.Random(seed))
