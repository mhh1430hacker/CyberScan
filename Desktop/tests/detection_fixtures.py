"""Builders for harmless, synthetic test fixtures.

Every file built here is inert: macros are never runnable (they are text in a container that
nothing executes), "executables" are names or truncated headers, and URLs use reserved or
non-routable example domains. They exist to exercise parsers and detection logic offline.
"""
from __future__ import annotations

import io
import struct
import zipfile
import zlib

# ---------------------------------------------------------------------------
# MS-OVBA compression (literal-only: valid, simple, and enough for tests)
# ---------------------------------------------------------------------------


def vba_compress(data: bytes) -> bytes:
    out = bytearray(b"\x01")
    for start in range(0, len(data), 3600):
        block = data[start:start + 3600]
        body = bytearray()
        for i in range(0, len(block), 8):
            body.append(0)  # flag byte: next 8 tokens are literals
            body += block[i:i + 8]
        size = len(body) + 2
        out += struct.pack("<H", 0x8000 | 0x3000 | (size - 3)) + body
    return bytes(out)


def vba_dir_stream(module: str) -> bytes:
    name = module.encode("latin-1")
    records = struct.pack("<HI", 0x0009, 4) + struct.pack("<IIH", 4, 1, 1)  # PROJECTVERSION (6-byte quirk)
    records += struct.pack("<HI", 0x0019, len(name)) + name  # MODULENAME
    records += struct.pack("<HI", 0x001A, len(name)) + name  # MODULESTREAMNAME
    records += struct.pack("<HI", 0x0032, len(name) * 2) + module.encode("utf-16-le")
    records += struct.pack("<HI", 0x0031, 4) + struct.pack("<I", 0)  # MODULEOFFSET = 0
    records += struct.pack("<HI", 0x002B, 0)  # MODULE terminator
    records += struct.pack("<HI", 0x0010, 0)  # dir terminator
    return vba_compress(records)


# ---------------------------------------------------------------------------
# Minimal CFB (OLE) writer: 512-byte sectors, small streams in the mini stream
# ---------------------------------------------------------------------------

_END, _FREE, _FATSECT = 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFD


def make_cfb(tree: dict) -> bytes:
    """``tree`` maps names to bytes (streams) or nested dicts (storages)."""
    entries = [{"name": "Root Entry", "type": 5, "data": b"", "children": []}]

    def add(node: dict, parent: int) -> None:
        for name, value in node.items():
            index = len(entries)
            entries.append({"name": name, "type": 1 if isinstance(value, dict) else 2,
                            "data": b"" if isinstance(value, dict) else value, "children": []})
            entries[parent]["children"].append(index)
            if isinstance(value, dict):
                add(value, index)

    add(tree, 0)
    mini_stream, mini_fat = bytearray(), []
    big_streams = []
    for entry in entries:
        if entry["type"] != 2:
            continue
        data = entry["data"]
        if len(data) < 4096:
            start = len(mini_stream) // 64
            count = max(1, -(-len(data) // 64))
            entry["start"] = start if data else _END
            if data:
                mini_fat += [start + i + 1 for i in range(count - 1)] + [_END]
                mini_stream += data + b"\x00" * (count * 64 - len(data))
        else:
            big_streams.append(entry)

    sectors: list[bytes] = []
    fat: list[int] = []

    def place(data: bytes) -> int:
        if not data:
            return _END
        count = -(-len(data) // 512)
        first = len(sectors)
        for i in range(count):
            sectors.append(data[i * 512:(i + 1) * 512].ljust(512, b"\x00"))
            fat.append(first + i + 1 if i < count - 1 else _END)
        return first

    fat_placeholder = len(sectors)
    sectors.append(b"")
    fat.append(_FATSECT)
    root_start = place(bytes(mini_stream))
    entries[0]["start"], entries[0]["size"] = root_start, len(mini_stream)
    minifat_bytes = b"".join(struct.pack("<I", value) for value in mini_fat)
    minifat_bytes += struct.pack("<I", _FREE) * ((-len(minifat_bytes) // 4) % 128)
    minifat_start = place(minifat_bytes) if mini_fat else _END
    for entry in big_streams:
        entry["start"] = place(entry["data"])

    def dir_entry(index: int) -> bytes:
        entry = entries[index]
        name = entry["name"].encode("utf-16-le") + b"\x00\x00"
        parent = next((e for e in entries if index in e["children"]), None)
        siblings = parent["children"] if parent else []
        right = siblings[siblings.index(index) + 1] if parent and siblings.index(index) + 1 < len(siblings) else _FREE
        child = entry["children"][0] if entry["children"] else _FREE
        size = entry.get("size", len(entry["data"]))
        raw = name.ljust(64, b"\x00") + struct.pack("<HBB", len(name), entry["type"], 1)
        raw += struct.pack("<III", _FREE, right, child) + b"\x00" * 16 + struct.pack("<I", 0) + b"\x00" * 16
        raw += struct.pack("<IQ", entry.get("start", _END) if entry["type"] != 1 else 0, size)
        return raw

    directory = b"".join(dir_entry(i) for i in range(len(entries)))
    directory += b"\x00" * ((-len(directory)) % 512)
    dir_start = place(directory)

    fat_bytes = b"".join(struct.pack("<I", value) for value in fat)
    assert len(fat_bytes) <= 512, "fixture too large for a single FAT sector"
    sectors[fat_placeholder] = fat_bytes.ljust(512, b"\xff")  # 0xFFFFFFFF = FREESECT
    header = bytearray(512)
    header[0:8] = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"
    struct.pack_into("<HHHH", header, 0x18, 0x3E, 3, 0xFFFE, 9)
    struct.pack_into("<H", header, 0x20, 6)
    struct.pack_into("<IIIIIIII", header, 0x2C, 1, dir_start, 0, 4096, minifat_start, 1 if mini_fat else 0, _END, 0)
    struct.pack_into("<109I", header, 0x4C, fat_placeholder, *([_FREE] * 108))
    return bytes(header) + b"".join(sectors)


def make_vba_project(code: str, module: str = "Module1") -> bytes:
    return make_cfb({"VBA": {"dir": vba_dir_stream(module), module: vba_compress(code.encode("latin-1")),
                             "_VBA_PROJECT": b"\xcc\x61\xff\xff\x00\x00\x00"},
                     "PROJECT": f'ID="{{00000000-0000-0000-0000-000000000000}}"\r\nModule={module}\r\n'.encode()})


# ---------------------------------------------------------------------------
# Office Open XML, PDF, RTF
# ---------------------------------------------------------------------------

CONTENT_TYPES = (b'<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                 b'<Default Extension="xml" ContentType="application/xml"/></Types>')


def make_docx(document_xml: str = "<w:document><w:body><w:p><w:r><w:t>Quarterly report</w:t></w:r></w:p></w:body></w:document>",
              extra: dict[str, bytes] | None = None) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", CONTENT_TYPES)
        archive.writestr("_rels/.rels", '<Relationships><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>')
        archive.writestr("word/document.xml", document_xml)
        archive.writestr("docProps/core.xml", "<cp:coreProperties><dc:creator>Test Author</dc:creator></cp:coreProperties>")
        for name, data in (extra or {}).items():
            archive.writestr(name, data)
    return buffer.getvalue()


def make_pdf(objects: list[bytes]) -> bytes:
    out = bytearray(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for number, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{number} 0 obj\n".encode() + body + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode()
    out += b"".join(f"{offset:010d} 00000 n \n".encode() for offset in offsets)
    out += f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    return bytes(out)


def pdf_stream(content: bytes, compress: bool = True) -> bytes:
    data = zlib.compress(content) if compress else content
    filt = b" /Filter /FlateDecode" if compress else b""
    return b"<< /Length " + str(len(data)).encode() + filt + b" >>\nstream\n" + data + b"\nendstream"


BENIGN_PDF_OBJECTS = [
    b"<< /Type /Catalog /Pages 2 0 R >>",
    b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
    b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>",
    pdf_stream(b"BT /F1 12 Tf 72 720 Td (Meeting notes) Tj ET"),
]


def make_zip(members: dict[str, bytes], encrypted: set[str] | None = None) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    raw = bytearray(buffer.getvalue())
    # zipfile refuses to write encrypted entries, so set the "encrypted" flag bit in the local and
    # central headers afterwards. The content stays plain; the inspector never tries to read it.
    for name in encrypted or ():
        encoded = name.encode()
        pos = 0
        while (pos := raw.find(b"PK\x01\x02", pos)) >= 0:
            name_len = struct.unpack_from("<H", raw, pos + 28)[0]
            if raw[pos + 46: pos + 46 + name_len] == encoded:
                raw[pos + 8] |= 0x1
                local = struct.unpack_from("<I", raw, pos + 42)[0]
                raw[local + 6] |= 0x1
            pos += 4
    return bytes(raw)


# ---------------------------------------------------------------------------
# Android binary XML
# ---------------------------------------------------------------------------


def make_axml(elements: list[tuple[str, dict[str, str | bool]]]) -> bytes:
    strings: list[str] = []

    def index(value: str) -> int:
        if value not in strings:
            strings.append(value)
        return strings.index(value)

    encoded_elements = []
    for tag, attributes in elements:
        attrs = b""
        for key, value in attributes.items():
            if isinstance(value, bool):
                attrs += struct.pack("<IIIHBBI", 0xFFFFFFFF, index(key), 0xFFFFFFFF, 8, 0, 0x12, 0xFFFFFFFF if value else 0)
            else:
                position = index(value)
                attrs += struct.pack("<IIIHBBI", 0xFFFFFFFF, index(key), position, 8, 0, 0x03, position)
        body = struct.pack("<II", 1, 0xFFFFFFFF) + struct.pack("<IIHHHHHH", 0xFFFFFFFF, index(tag), 20, 20, len(attributes), 0, 0, 0) + attrs
        encoded_elements.append(struct.pack("<HHI", 0x0102, 16, 8 + len(body)) + body)

    pool_strings = b""
    offsets = []
    for value in strings:
        offsets.append(len(pool_strings))
        pool_strings += struct.pack("<H", len(value)) + value.encode("utf-16-le") + b"\x00\x00"
    pool_strings += b"\x00" * ((-len(pool_strings)) % 4)
    header_size = 28
    strings_start = header_size + 4 * len(strings)
    pool = struct.pack("<IIIII", len(strings), 0, 0, strings_start, 0) + b"".join(struct.pack("<I", o) for o in offsets) + pool_strings
    pool_chunk = struct.pack("<HHI", 0x0001, header_size, 8 + len(pool)) + pool
    body = pool_chunk + b"".join(encoded_elements)
    return struct.pack("<HHI", 0x0003, 8, 8 + len(body)) + body


def make_apk(permissions: list[str], services: list[str] | None = None, extra: dict[str, bytes] | None = None,
             debuggable: bool = False) -> bytes:
    elements: list[tuple[str, dict]] = [("manifest", {"package": "org.example.fixture"})]
    elements += [("uses-permission", {"name": f"android.permission.{p}"}) for p in permissions]
    elements.append(("application", {"debuggable": debuggable}))
    elements += [("service", {"name": f"org.example.S{i}", "permission": f"android.permission.{s}"}) for i, s in enumerate(services or [])]
    members = {"AndroidManifest.xml": make_axml(elements), "classes.dex": b"dex\n035\x00" + b"\x00" * 64,
               "META-INF/CERT.RSA": b"\x30\x82"}
    members.update(extra or {})
    return make_zip(members)
