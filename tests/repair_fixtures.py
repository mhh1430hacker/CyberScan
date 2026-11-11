"""Small, inert, well-formed files built byte by byte for the repair engine tests.

Every builder returns ``(data, facts)``: the bytes, plus the exact offsets
the parser is expected to find. Section and stream contents are zeros or
placeholder text; nothing here is runnable code.
"""
from __future__ import annotations

import io
import struct
import zipfile
import zlib

PLACEHOLDER = b"PLACEHOLDER-CONTENT "


def build_pe(overlay: bytes = b"", certificate: bytes = b"") -> tuple[bytes, dict]:
    lfanew, file_align = 0x80, 0x200
    sections = [(b".text", 0x60000020), (b".data", 0xC0000040)]
    dos = bytearray(lfanew)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, lfanew)
    file_header = struct.pack("<HHIIIHH", 0x14C, len(sections), 0, 0, 0, 0xE0, 0x102)
    size_of_image = 0x1000 * (len(sections) + 1)
    optional = struct.pack(
        "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
        0x10B, 14, 0, file_align, file_align, 0, 0x1000, 0x1000, 0x2000, 0x400000, 0x1000, file_align,
        6, 0, 0, 0, 6, 0, 0, size_of_image, 0x200, 0, 2, 0, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16,
    )
    body_end = 0x200 + file_align * len(sections)
    certificate_at = body_end + len(overlay)
    directories = bytearray(16 * 8)
    if certificate:
        struct.pack_into("<II", directories, 4 * 8, certificate_at, len(certificate))
    table = b""
    for number, (name, characteristics) in enumerate(sections):
        table += struct.pack("<8sIIIIIIHHI", name, file_align, 0x1000 * (number + 1), file_align,
                             0x200 + file_align * number, 0, 0, 0, 0, characteristics)
    headers = bytes(dos) + b"PE\x00\x00" + file_header + optional + bytes(directories) + table
    headers = headers.ljust(0x200, b"\x00")
    data = headers + bytes(file_align) + (PLACEHOLDER * 30)[:file_align] + overlay + certificate
    facts = {
        "sections": [(0x200, 0x400), (0x400, 0x600)],
        "entry_point": 0x200,
        "overlay": (body_end, body_end + len(overlay)) if overlay else None,
        "certificate": (certificate_at, certificate_at + len(certificate)) if certificate else None,
    }
    return data, facts


def build_elf(overlay: bytes = b"") -> tuple[bytes, dict]:
    text_at, text = 120, bytes(32)
    names = b"\x00.text\x00.shstrtab\x00"
    names_at = text_at + len(text)
    shoff = (names_at + len(names) + 7) // 8 * 8
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    header = ident + struct.pack("<HHIQQQIHHHHHH", 2, 0x3E, 1, 0x400000 + text_at, 64, shoff, 0, 64, 56, 1, 64, 3, 2)
    program = struct.pack("<IIQQQQQQ", 1, 5, 0, 0x400000, 0x400000, names_at, names_at, 0x1000)
    body = (header + program + text + names).ljust(shoff, b"\x00")
    sections = bytes(64)
    sections += struct.pack("<IIQQQQIIQQ", 1, 1, 6, 0x400000 + text_at, text_at, len(text), 0, 0, 16, 0)
    sections += struct.pack("<IIQQQQIIQQ", 7, 3, 0, 0, names_at, len(names), 0, 0, 1, 0)
    data = body + sections + overlay
    end = shoff + len(sections)
    return data, {"text": (text_at, text_at + len(text)), "entry_point": text_at, "overlay": (end, len(data)) if overlay else None}


def build_zip(prefix: bytes = b"", trailing: bytes = b"", members=None) -> tuple[bytes, dict]:
    members = members or {"readme.txt": b"hello " * 50, "data/notes.txt": PLACEHOLDER * 20}
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in members.items():
            archive.writestr(name, content)
    core = buffer.getvalue()
    data = prefix + core + trailing
    return data, {"logical_end": len(prefix) + len(core), "prefix": len(prefix)}


def build_ooxml() -> tuple[bytes, dict]:
    rels = (b'<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            b'<Relationship Id="rId1" Type="http://x/oleObject" Target="https://example.invalid/template.dotm" TargetMode="External"/>'
            b'</Relationships>')
    return build_zip(members={
        "[Content_Types].xml": b"<Types/>",
        "word/document.xml": b"<w:document/>",
        "word/vbaProject.bin": PLACEHOLDER * 10,
        "word/embeddings/oleObject1.bin": PLACEHOLDER * 5,
        "word/_rels/document.xml.rels": rels,
    })


def _ole_entry(name: str, kind: int, left=0xFFFFFFFF, right=0xFFFFFFFF, child=0xFFFFFFFF, start=0, size=0) -> bytes:
    encoded = (name + "\x00").encode("utf-16-le")
    entry = bytearray(128)
    entry[: len(encoded)] = encoded
    struct.pack_into("<HBBIII", entry, 64, len(encoded), kind, 1, left, right, child)
    struct.pack_into("<IQ", entry, 116, start, size)
    return bytes(entry)


def build_ole(trailing: bytes = b"") -> tuple[bytes, dict]:
    """v3 compound file; Module1 is fragmented (sectors 11-14 and 23-27), CompObj lives in the mini stream."""
    sector = 512
    word, data_stream = (b"W" * 4096), (b"D" * 4096)
    module = (PLACEHOLDER * 300)[:4608]
    compobj = (PLACEHOLDER * 10)[:100]
    END, FREE, FATSECT = 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFD
    fat = [FREE] * 128
    fat[0] = FATSECT
    fat[1], fat[2] = 2, END

    def link(chain):
        for a, b in zip(chain, chain[1:]):
            fat[a] = b
        fat[chain[-1]] = END

    link(list(range(3, 11)))
    link([11, 12, 13, 14, 23, 24, 25, 26, 27])
    link(list(range(15, 23)))
    fat[28] = END
    fat[29] = END
    entries = [
        _ole_entry("Root Entry", 5, child=1, start=28, size=512),
        _ole_entry("Macros", 1, right=4, child=2),
        _ole_entry("VBA", 1, child=3),
        _ole_entry("Module1", 2, start=11, size=len(module)),
        _ole_entry("WordDocument", 2, right=5, start=3, size=len(word)),
        _ole_entry("Data", 2, right=6, start=15, size=len(data_stream)),
        _ole_entry("\x01CompObj", 2, start=0, size=len(compobj)),
        bytes(128),
    ]
    minifat = [1, END] + [FREE] * 126
    header = bytearray(512)
    header[0:8] = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
    struct.pack_into("<HHHHH", header, 0x18, 0x3E, 3, 0xFFFE, 9, 6)
    struct.pack_into("<IIIIIIIII", header, 0x28, 0, 1, 1, 0, 4096, 29, 1, END, 0)
    struct.pack_into("<109I", header, 0x4C, 0, *([FREE] * 108))
    sectors = [b""] * 30
    sectors[0] = struct.pack("<128I", *fat)
    directory = b"".join(entries)
    sectors[1], sectors[2] = directory[:512], directory[512:]
    for index, chunk in zip(range(3, 11), [word[i:i + sector] for i in range(0, 4096, sector)]):
        sectors[index] = chunk
    pieces = [module[i:i + sector] for i in range(0, len(module), sector)]
    for index, chunk in zip([11, 12, 13, 14, 23, 24, 25, 26, 27], pieces):
        sectors[index] = chunk
    for index, chunk in zip(range(15, 23), [data_stream[i:i + sector] for i in range(0, 4096, sector)]):
        sectors[index] = chunk
    sectors[28] = compobj
    sectors[29] = struct.pack("<128I", *minifat)
    data = bytes(header) + b"".join(chunk.ljust(sector, b"\x00") for chunk in sectors)
    return data + trailing, {
        "module": module,
        "module_extents": [(12 * sector, 16 * sector), (24 * sector, 24 * sector + 4608 - 2048)],
        "compobj": compobj,
        "compobj_extent": (29 * sector, 29 * sector + 100),
        "logical_end": len(data),
    }


def build_pdf(trailing: bytes = b"") -> tuple[bytes, dict]:
    tricky = b"raw bytes that say endobj\n7 0 obj and endstream-ish"
    hidden = zlib.compress(b"6 0 << /S /JavaScript /JS (placeholder) >>")
    parts = [b"%PDF-1.7\n"]
    offsets = {}

    def obj(number: int, body: bytes) -> None:
        offsets[number] = sum(map(len, parts))
        parts.append(b"%d 0 obj\n" % number + body + b"\nendobj\n")

    obj(1, b"<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>")
    obj(2, b"<< /Type /Pages /Kids [] /Count 0 >>")
    obj(3, b"<< /Length %d >>\nstream\n" % len(tricky) + tricky + b"\nendstream")
    obj(4, b"<< /S /J#61vaScript /JS (placeholder) >>")
    # Object 6 hidden, compressed, inside an object stream.
    obj(5, b"<< /Type /ObjStm /N 1 /First 4 /Length %d /Filter /FlateDecode >>\nstream\n" % len(hidden) + hidden + b"\nendstream")
    xref_at = sum(map(len, parts))
    parts.append(b"xref\n0 6\n0000000000 65535 f \ntrailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n%d\n" % xref_at)
    parts.append(b"%%EOF\n")
    core = b"".join(parts)
    return core + trailing, {"objects": offsets, "tricky": tricky, "logical_end": len(core)}


def build_png(trailing: bytes = b"") -> tuple[bytes, dict]:
    def chunk(kind: bytes, body: bytes) -> bytes:
        return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body))

    core = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 0, 0, 0, 0)) \
        + chunk(b"IDAT", zlib.compress(b"\x00\x00")) + chunk(b"IEND", b"")
    return core + trailing, {"logical_end": len(core)}


def build_jpeg(trailing: bytes = b"") -> tuple[bytes, dict]:
    core = (b"\xff\xd8" + b"\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
            + b"\xff\xda\x00\x08\x01\x01\x00\x00\x3f\x00" + b"\x12\x34\xff\x00\x56\xff\xd0\x78" + b"\xff\xd9")
    return core + trailing, {"logical_end": len(core)}


def build_gif(trailing: bytes = b"") -> tuple[bytes, dict]:
    core = (b"GIF89a" + struct.pack("<HHBBB", 1, 1, 0x80, 0, 0) + bytes(6)
            + b"\x2c" + struct.pack("<HHHHB", 0, 0, 1, 1, 0) + b"\x02\x02\x4c\x01\x00" + b"\x3b")
    return core + trailing, {"logical_end": len(core)}
