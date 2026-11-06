"""ZIP regions, and OOXML (docx/xlsx/pptx) parts on top of them.

Every member gets its local header + data range; the central directory,
the end record, data before the first member (an executable stub, for
instance) and data after the end record are regions of their own.

OOXML members are tagged by role: VBA projects, embedded objects, ActiveX
controls, and relationship parts that point outside the document.
"""
from __future__ import annotations

import io
import re
import struct
import zipfile

from repair_engine.regions import RegionMap

_EOCD = b"PK\x05\x06"
_MAX_MEMBERS = 20_000
_MAX_RELS_BYTES = 2 * 1024 * 1024
_EXTERNAL = re.compile(rb"<Relationship\b[^>]*?TargetMode=\"External\"[^>]*>", re.IGNORECASE)
_TARGET = re.compile(rb"Target=\"([^\"]*)\"")
_TYPE = re.compile(rb"Type=\"[^\"]*/([^\"/]+)\"")


def parse_zip(data: bytes, regions: RegionMap) -> None:
    regions.format = "zip"
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, OSError, ValueError, EOFError) as exc:
        # zipfile looks for the end record only in the last 64 KiB; with more
        # data appended it gives up. Find the record ourselves and read up to it.
        end = data.rfind(_EOCD)
        if end < 0 or end + 22 > len(data):
            regions.errors.append(f"zip: {exc}")
            return
        logical_end = end + 22 + struct.unpack_from("<H", data, end + 20)[0]
        try:
            archive = zipfile.ZipFile(io.BytesIO(data[:logical_end]))
        except (zipfile.BadZipFile, OSError, ValueError, EOFError):
            regions.errors.append(f"zip: {exc}")
            return
    with archive:
        try:
            _parse(data, archive, regions)
        except (struct.error, IndexError, ValueError, zipfile.BadZipFile, OSError, EOFError) as exc:
            regions.errors.append(f"zip: {type(exc).__name__}: {exc}")


def _role(name: str) -> str | None:
    lower = name.lower()
    if lower.endswith("vbaproject.bin"):
        return "vba_project"
    if "/embeddings/" in lower or "oleobject" in lower:
        return "embedded_object"
    if "/activex/" in lower:
        return "activex"
    if lower.endswith(".rels"):
        return "relationships"
    return None


def _parse(data: bytes, archive: zipfile.ZipFile, regions: RegionMap) -> None:
    members = archive.infolist()[:_MAX_MEMBERS]
    ooxml = any(info.filename == "[Content_Types].xml" for info in members)
    if ooxml:
        regions.format = "ooxml"
    first_member = len(data)
    for info in members:
        offset = int(info.header_offset)
        first_member = min(first_member, offset)
        name_length, extra_length = struct.unpack_from("<HH", data, offset + 26)
        start = offset + 30 + name_length + extra_length
        end = start + int(info.compress_size)
        if info.flag_bits & 0x08:  # a data descriptor follows the data
            end += 16 if data[end:end + 4] == b"PK\x07\x08" else 12
        role = _role(info.filename) if ooxml else None
        member = regions.add(offset, end, "zip_member", name=info.filename, compressed=info.compress_type != 0,
                             encrypted=bool(info.flag_bits & 0x01), role=role)
        if member is None:
            continue
        regions.add(start, start + int(info.compress_size), "zip_member_data", parent=member, name=info.filename)
        if role == "relationships":
            _external_links(archive, info, regions, member)
    central = int(getattr(archive, "start_dir", 0))
    eocd = data.rfind(_EOCD)
    if eocd < 0:
        regions.errors.append("zip: no end record")
        return
    regions.add(central, eocd, "zip_central_directory")
    comment_length = struct.unpack_from("<H", data, eocd + 20)[0]
    logical_end = eocd + 22 + comment_length
    regions.add(eocd, logical_end, "zip_end_record")
    if 0 < first_member <= len(data):
        regions.add(0, first_member, "zip_prefix")
    if logical_end < len(data):
        regions.add(logical_end, len(data), "after_eof", logical_end=logical_end)


def _external_links(archive: zipfile.ZipFile, info: zipfile.ZipInfo, regions: RegionMap, member: int) -> None:
    if info.file_size > _MAX_RELS_BYTES:
        return
    try:
        text = archive.read(info)
    except (zipfile.BadZipFile, RuntimeError, OSError, EOFError, ValueError):
        return
    targets, kinds = [], []
    for match in _EXTERNAL.finditer(text):
        target = _TARGET.search(match.group(0))
        kind = _TYPE.search(match.group(0))
        if target:
            targets.append(target.group(1).decode("utf-8", "replace"))
            kinds.append(kind.group(1).decode("utf-8", "replace") if kind else "")
    if targets:
        region = regions.regions[member]
        regions.add(region.start, region.end, "ooxml_external_link", parent=member, part=info.filename, targets=targets, types=kinds)
