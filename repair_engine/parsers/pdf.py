"""PDF regions from a byte scan: objects, their streams, xref/trailer
sections, revisions (each ``%%EOF``), and data after the final ``%%EOF``.

Objects are tagged with the active entries they carry (JavaScript,
OpenAction/AA, Launch, EmbeddedFile, URI, SubmitForm, RichMedia), after
undoing ``#xx`` escapes in names, which hide ``/JavaScript`` as
``/J#61vaScript``. Flate streams are decoded (bounded) only to record
their decoded size and whether the decoded text names an active entry.
Nothing is rendered or interpreted.
"""
from __future__ import annotations

import re
import zlib

from repair_engine.regions import RegionMap

_OBJECT = re.compile(rb"(?<![0-9])(\d{1,10})\s+(\d{1,5})\s+obj\b")
_ENDOBJ = re.compile(rb"\bendobj\b")
_STREAM = re.compile(rb"\bstream(\r\n|\n|\r)")
_ENDSTREAM = re.compile(rb"(\r\n|\n|\r)?endstream\b")
_LENGTH = re.compile(rb"/Length\s+(\d{1,12}+)(?!\s+\d+\s+R)")  # a direct length, not "12 0 R"
_NAME_ESCAPE = re.compile(rb"#([0-9A-Fa-f]{2})")
_EOF = re.compile(rb"%%EOF[ \t]*(\r\n|\n|\r)?")
_XREF = re.compile(rb"(?:^|[\r\n])(xref)\s")
_STARTXREF = re.compile(rb"startxref\s+\d+\s*")
_ACTIVE = {
    b"JavaScript": "javascript", b"JS": "javascript",
    b"OpenAction": "auto_action", b"AA": "auto_action",
    b"Launch": "launch",
    b"EmbeddedFile": "embedded_file", b"EmbeddedFiles": "embedded_file",
    b"URI": "uri",
    b"SubmitForm": "submit_form",
    b"RichMedia": "rich_media",
}
_ACTIVE_NAME = re.compile(rb"/(" + b"|".join(sorted(_ACTIVE, key=len, reverse=True)) + rb")(?![A-Za-z0-9])")
_OBJECT_STREAM = re.compile(rb"/Type\s*/ObjStm\b")
_MAX_OBJECTS = 100_000
_MAX_DECODED = 16 * 1024 * 1024


def _unescape(text: bytes) -> bytes:
    if b"#" not in text:
        return text
    return _NAME_ESCAPE.sub(lambda match: bytes([int(match.group(1), 16)]), text)


def _flags(text: bytes) -> list[str]:
    found = {_ACTIVE[match.group(1)] for match in _ACTIVE_NAME.finditer(_unescape(text))}
    return sorted(found)


def parse_pdf(data: bytes, regions: RegionMap) -> None:
    regions.format = "pdf"
    header = data.find(b"%PDF-", 0, 1024)
    if header > 0:
        regions.add(0, header, "pdf_prefix")
    count = 0
    position = max(header, 0)
    while count < _MAX_OBJECTS:
        match = _OBJECT.search(data, position)
        if match is None:
            break
        count += 1
        position = _object(data, regions, match)
    for match in _XREF.finditer(data):
        start = match.start(1)
        startxref = _STARTXREF.search(data, start)
        regions.add(start, startxref.end() if startxref else start + 4, "pdf_xref_trailer")
    eofs = list(_EOF.finditer(data))
    for number, match in enumerate(eofs):
        regions.add(match.start(), match.end(), "pdf_eof_marker", revision=number)
    if eofs:
        logical_end = eofs[-1].end()
        if logical_end < len(data) and data[logical_end:].strip(b"\x00\t\r\n ") != b"":
            regions.add(logical_end, len(data), "after_eof", logical_end=logical_end)
    else:
        regions.errors.append("pdf: no %%EOF marker")


def _object(data: bytes, regions: RegionMap, match: re.Match) -> int:
    """Adds one object (and its stream); returns where the scan continues."""
    number, generation = int(match.group(1)), int(match.group(2))
    end_match = _ENDOBJ.search(data, match.end())
    limit = end_match.start() if end_match else len(data)
    # A stream's bytes may contain "endobj" or "N 0 obj"; skip past endstream first.
    stream = _STREAM.search(data, match.end(), limit)
    closing = _stream_end(data, data[match.end():stream.start()], stream.end()) if stream else None
    if closing is not None:
        end_match = _ENDOBJ.search(data, closing.end())
    next_object = _OBJECT.search(data, closing.end() if closing else match.end())
    if end_match is None or (next_object is not None and next_object.start() < end_match.start()):
        # No endobj before the next object: a broken object; keep it to the next one.
        end = next_object.start() if next_object is not None else len(data)
        regions.errors.append(f"pdf: object {number} at {match.start()} has no endobj")
    else:
        end = end_match.end()
    dictionary = data[match.end():stream.start() if stream else end]
    parent = regions.add(match.start(), end, "pdf_object", number=number, generation=generation, flags=_flags(dictionary))
    if stream is None or parent is None:
        return max(end, match.end())
    start = stream.end()
    stream_end = closing.start() if closing else end
    metadata = {"filter": _filter(dictionary), "object_stream": bool(_OBJECT_STREAM.search(dictionary))}
    if metadata["filter"] == "FlateDecode":
        try:
            decoded = zlib.decompressobj().decompress(data[start:stream_end], _MAX_DECODED)
            metadata["decoded_size"] = len(decoded)
            if metadata["object_stream"]:  # compressed objects can carry active entries; page content cannot
                metadata["decoded_flags"] = _flags(decoded)
        except zlib.error as exc:
            metadata["decode_error"] = str(exc)
    regions.add(start, stream_end, "pdf_stream", parent=parent, number=number, **metadata)
    return max(end, match.end())


def _stream_end(data: bytes, dictionary: bytes, start: int) -> re.Match | None:
    """Where the stream's data stops: at its declared /Length when that lands on
    "endstream" (stream bytes may contain the word), else the first "endstream"."""
    length = _LENGTH.search(dictionary)
    if length:
        declared = _ENDSTREAM.match(data, start + int(length.group(1)))
        if declared:
            return declared
    return _ENDSTREAM.search(data, start)


def _filter(dictionary: bytes) -> str | None:
    match = re.search(rb"/Filter\s*\[?\s*/([A-Za-z0-9#]+)", dictionary)
    return _unescape(match.group(1)).decode("latin-1") if match else None
