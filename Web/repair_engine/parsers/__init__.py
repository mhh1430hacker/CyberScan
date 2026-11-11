"""Turn any file's bytes into a region map with exact offsets.

The format comes from the bytes (magic), never from the name. The name is
only used to report a mismatch: a file called ``invoice.pdf`` that is a
Windows executable gets a ``magic_mismatch`` region over its signature.

Parsers take ``bytes`` and return data. Nothing here opens, runs, renders
or loads the file; malformed input yields errors in the map, not
exceptions.
"""
from __future__ import annotations

from pathlib import PurePath

from repair_engine.parsers.elf import parse_elf
from repair_engine.parsers.image import parse_gif, parse_jpeg, parse_png
from repair_engine.parsers.ole import parse_ole
from repair_engine.parsers.pdf import parse_pdf
from repair_engine.parsers.pe import parse_pe
from repair_engine.parsers.zip import parse_zip
from repair_engine.regions import RegionMap

_MAGIC = (
    (b"MZ", "pe"),
    (b"\x7fELF", "elf"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole"),
    (b"PK\x03\x04", "zip"),
    (b"PK\x05\x06", "zip"),
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"\xff\xd8\xff", "jpeg"),
    (b"GIF87a", "gif"),
    (b"GIF89a", "gif"),
)
_PARSERS = {
    "pe": parse_pe, "elf": parse_elf, "ole": parse_ole, "zip": parse_zip, "pdf": parse_pdf,
    "png": parse_png, "jpeg": parse_jpeg, "gif": parse_gif,
}
# What a name promises. "zip" also covers OOXML, which is a zip.
_EXPECTED = {
    ".exe": {"pe"}, ".dll": {"pe"}, ".sys": {"pe"}, ".scr": {"pe"}, ".cpl": {"pe"}, ".ocx": {"pe"},
    ".so": {"elf"}, ".elf": {"elf"},
    ".doc": {"ole"}, ".xls": {"ole"}, ".ppt": {"ole"}, ".msg": {"ole"},
    ".docx": {"ooxml"}, ".xlsx": {"ooxml"}, ".pptx": {"ooxml"}, ".docm": {"ooxml"}, ".xlsm": {"ooxml"}, ".pptm": {"ooxml"},
    ".zip": {"zip", "ooxml"}, ".jar": {"zip"}, ".apk": {"zip"},
    ".pdf": {"pdf"}, ".png": {"png"}, ".jpg": {"jpeg"}, ".jpeg": {"jpeg"}, ".gif": {"gif"},
    ".txt": {"unknown"}, ".csv": {"unknown"},
}


def detect(data: bytes) -> str:
    for magic, kind in _MAGIC:
        if data.startswith(magic):
            return kind
    if b"%PDF-" in data[:1024]:
        return "pdf"
    if b"PK\x05\x06" in data[-65_557:]:  # a zip with something in front of it
        return "zip"
    return "unknown"


def parse(data: bytes, name: str = "") -> RegionMap:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("parse() takes the file's bytes")
    data = bytes(data)
    regions = RegionMap(len(data))
    kind = detect(data)
    parser = _PARSERS.get(kind)
    if parser is not None:
        try:
            parser(data, regions)
        except Exception as exc:  # noqa: BLE001 - last line of defence: the map survives any input
            regions.errors.append(f"{kind}: {type(exc).__name__}: {exc}")
    expected = _EXPECTED.get(PurePath(name).suffix.lower()) if name else None
    if expected is not None and regions.format not in expected:
        regions.add(0, min(len(data), 16), "magic_mismatch", extension=PurePath(name).suffix.lower(),
                    detected=regions.format, expected=sorted(expected))
    return regions
