"""Document and image metadata extraction shared by tools 071 (EXIF), 079 (leakage) and 080 (removal check).

Structure-level inventories use only the standard library (JPEG APPn segments, PNG/WebP chunks, OOXML
parts, PDF dictionaries). EXIF tag values are decoded with Pillow when it is installed. Archives are
read with size limits; nothing is rendered or executed.
"""
from __future__ import annotations

import io
import re
import struct
import zipfile
from typing import Any

MAX_PART = 4 * 1024 * 1024
OOXML_CORE = ("creator", "lastModifiedBy", "title", "subject", "keywords", "description", "category", "created", "modified",
              "lastPrinted", "revision")
OOXML_APP = ("Company", "Manager", "Application", "AppVersion", "Template", "TotalTime", "HyperlinkBase")
PDF_INFO_KEYS = ("Author", "Creator", "Producer", "Title", "Subject", "Keywords", "CreationDate", "ModDate")


def sniff(data: bytes) -> str:
    if data[:3] == b"\xff\xd8\xff":
        return "jpeg"
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "png"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    if data[:4] in (b"II*\x00", b"MM\x00*"):
        return "tiff"
    if data[:5] == b"%PDF-":
        return "pdf"
    if data[:4] == b"PK\x03\x04":
        return "ooxml" if b"[Content_Types].xml" in data[:65536] or b"docProps/" in data[:200000] else "zip"
    return "unknown"


# ---- images -----------------------------------------------------------------------------------

def jpeg_segments(data: bytes) -> list[dict[str, Any]]:
    segments, pos = [], 2
    while pos + 4 <= len(data) and data[pos] == 0xFF:
        marker = data[pos + 1]
        if marker in (0xD9, 0xDA):  # end of image / start of scan: metadata segments are over
            break
        if marker == 0x01 or 0xD0 <= marker <= 0xD7:
            pos += 2
            continue
        length = struct.unpack(">H", data[pos + 2:pos + 4])[0]
        payload = data[pos + 4:pos + 2 + length]
        kind = None
        if marker == 0xE1 and payload.startswith(b"Exif\x00\x00"):
            kind = "exif"
        elif marker == 0xE1 and payload.startswith(b"http://ns.adobe.com/xap/1.0/"):
            kind = "xmp"
        elif marker == 0xED and payload.startswith(b"Photoshop 3.0"):
            kind = "iptc"
        elif marker == 0xE2 and payload.startswith(b"ICC_PROFILE"):
            kind = "icc_profile"
        elif marker == 0xFE:
            kind = "comment"
        elif 0xE3 <= marker <= 0xEF:
            kind = f"app{marker - 0xE0}"
        if kind:
            segments.append({"kind": kind, "bytes": length, "payload": payload[:65536]})
        pos += 2 + length
    return segments


def png_chunks(data: bytes) -> list[dict[str, Any]]:
    chunks, pos = [], 8
    while pos + 8 <= len(data):
        length = struct.unpack(">I", data[pos:pos + 4])[0]
        kind = data[pos + 4:pos + 8].decode("latin-1")
        payload = data[pos + 8:pos + 8 + min(length, 65536)]
        if kind in ("tEXt", "iTXt", "zTXt", "eXIf", "tIME", "iCCP"):
            keyword = payload.split(b"\x00", 1)[0].decode("latin-1", errors="replace")[:80] if kind in ("tEXt", "iTXt", "zTXt") else ""
            chunks.append({"kind": {"eXIf": "exif", "iCCP": "icc_profile", "tIME": "timestamp"}.get(kind, "text"), "chunk": kind,
                           "keyword": keyword, "bytes": length, "payload": payload})
        if kind == "IEND":
            break
        pos += 12 + length
    return chunks


def webp_chunks(data: bytes) -> list[dict[str, Any]]:
    chunks, pos = [], 12
    while pos + 8 <= len(data):
        kind = data[pos:pos + 4].decode("latin-1")
        length = struct.unpack("<I", data[pos + 4:pos + 8])[0]
        if kind in ("EXIF", "XMP ", "ICCP"):
            chunks.append({"kind": {"EXIF": "exif", "XMP ": "xmp", "ICCP": "icc_profile"}[kind], "bytes": length,
                           "payload": data[pos + 8:pos + 8 + min(length, 65536)]})
        pos += 8 + length + (length & 1)
    return chunks


def image_inventory(data: bytes) -> list[dict[str, Any]]:
    kind = sniff(data)
    if kind == "jpeg":
        return jpeg_segments(data)
    if kind == "png":
        return png_chunks(data)
    if kind == "webp":
        return webp_chunks(data)
    if kind == "tiff":
        return [{"kind": "exif", "bytes": len(data), "payload": b""}]  # TIFF headers are the EXIF structure itself
    return []


GPS_TAGS = {1: "GPSLatitudeRef", 2: "GPSLatitude", 3: "GPSLongitudeRef", 4: "GPSLongitude", 6: "GPSAltitude", 29: "GPSDateStamp"}
EXIF_TAGS = {0x010F: "Make", 0x0110: "Model", 0x0131: "Software", 0x013B: "Artist", 0x8298: "Copyright", 0x0132: "DateTime",
             0x9003: "DateTimeOriginal", 0xA431: "BodySerialNumber", 0xA435: "LensSerialNumber", 0xA430: "CameraOwnerName",
             0x9C9D: "XPAuthor", 0x9286: "UserComment", 0x010E: "ImageDescription", 0xA420: "ImageUniqueID", 0x0103: "Compression"}


def _ratio(value) -> float:
    try:
        return float(value)
    except (TypeError, ValueError, ZeroDivisionError):
        try:
            return value[0] / value[1]
        except Exception:  # noqa: BLE001
            return 0.0


def exif_values(data: bytes) -> dict[str, Any] | None:
    """Decoded EXIF/GPS values with Pillow; None if Pillow is unavailable."""
    try:
        from PIL import Image
    except ImportError:
        return None
    try:
        with Image.open(io.BytesIO(data)) as image:
            exif = image.getexif()
            values: dict[str, Any] = {}
            for tag, name in EXIF_TAGS.items():
                if tag in exif:
                    values[name] = exif[tag]
            sub = exif.get_ifd(0x8769)  # Exif sub-IFD holds DateTimeOriginal, serial numbers, owner name
            for tag, name in EXIF_TAGS.items():
                if tag in sub and name not in values:
                    values[name] = sub[tag]
            gps = exif.get_ifd(0x8825)
            if gps:
                values["GPS"] = {GPS_TAGS.get(k, str(k)): v for k, v in gps.items() if k in GPS_TAGS}
            values["_has_thumbnail"] = bool(exif.get_ifd(0x0001)) if hasattr(exif, "get_ifd") else False
            values["_format"] = image.format
            values["_size"] = image.size
    except Exception:  # noqa: BLE001 - unreadable image: no decoded values
        return {}
    for key, value in list(values.items()):
        if isinstance(value, bytes):
            values[key] = value.decode("utf-16-le" if key.startswith("XP") else "utf-8", errors="replace").strip("\x00 ")
    return values


def gps_coordinates(gps: dict[str, Any]) -> tuple[float, float] | None:
    try:
        def degrees(dms):
            d, m, s = (_ratio(v) for v in dms)
            return d + m / 60 + s / 3600
        lat = degrees(gps["GPSLatitude"]) * (-1 if str(gps.get("GPSLatitudeRef", "N")).upper().startswith("S") else 1)
        lon = degrees(gps["GPSLongitude"]) * (-1 if str(gps.get("GPSLongitudeRef", "E")).upper().startswith("W") else 1)
    except (KeyError, TypeError, ValueError):
        return None
    if lat == 0 and lon == 0:
        return None
    return lat, lon


# ---- OOXML ------------------------------------------------------------------------------------

def _read(archive: zipfile.ZipFile, name: str) -> str:
    try:
        info = archive.getinfo(name)
    except KeyError:
        return ""
    if info.file_size > MAX_PART or info.flag_bits & 0x1:
        return ""
    with archive.open(info) as handle:
        return handle.read(MAX_PART).decode("utf-8", errors="replace")


def _xml_text(xml: str, tag: str) -> str | None:
    match = re.search(rf"<(?:\w+:)?{tag}\b[^>]*>(.*?)</(?:\w+:)?{tag}>", xml, re.S)
    return re.sub(r"<[^>]+>", "", match.group(1)).strip()[:500] if match else None


def ooxml_inventory(data: bytes) -> dict[str, Any]:
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except Exception as exc:  # noqa: BLE001
        raise ValueError("not a readable OOXML (ZIP) document") from exc
    with archive:
        names = [i.filename for i in archive.infolist()[:5000]]
        core, app, custom = _read(archive, "docProps/core.xml"), _read(archive, "docProps/app.xml"), _read(archive, "docProps/custom.xml")
        props = {k: v for k in OOXML_CORE if (v := _xml_text(core, k))}
        props.update({k: v for k in OOXML_APP if (v := _xml_text(app, k))})
        custom_names = re.findall(r'<property\b[^>]*\bname="([^"]{1,100})"', custom)
        comment_parts = [n for n in names if re.search(r"(?i)(?:comments\d*\.xml|commentsExtended|threadedComments|/comments/)", n)]
        comments = sum(len(re.findall(r"<(?:w:comment|comment|p188:cm|p:cm)\b", _read(archive, n))) for n in comment_parts[:20])
        authors = sorted(set(re.findall(r'w:author="([^"]{1,100})"', "".join(_read(archive, n) for n in comment_parts[:20]))))
        body = _read(archive, "word/document.xml")
        settings = _read(archive, "word/settings.xml")
        people = _read(archive, "word/people.xml")
        return {
            "properties": props,
            "custom_properties": custom_names[:50],
            "comments": comments,
            "comment_authors": authors[:20] + sorted(set(re.findall(r'w15:author="([^"]{1,100})"', people)))[:20],
            "tracked_insertions": len(re.findall(r"<w:ins\b", body)),
            "tracked_deletions": len(re.findall(r"<w:del\b", body)),
            "hidden_text_runs": len(re.findall(r"<w:vanish\s*/>", body)),
            "thumbnail": any(n.lower().startswith("docprops/thumbnail") for n in names),
            "remove_personal_information": "removePersonalInformation" in settings,
            "embedded_objects": [n for n in names if re.search(r"(?i)/embeddings/", n)][:20],
            "external_links": len(re.findall(r'TargetMode="External"', "".join(_read(archive, n) for n in names if n.endswith(".rels"))[:2_000_000])),
            "parts": len(names),
        }


# ---- PDF --------------------------------------------------------------------------------------

def _pdf_string(raw: bytes) -> str:
    raw = raw.strip()
    if raw.startswith(b"<") and raw.endswith(b">"):
        try:
            value = bytes.fromhex(re.sub(rb"\s", b"", raw[1:-1]).decode())
        except ValueError:
            return ""
    elif raw.startswith(b"(") and raw.endswith(b")"):
        value = re.sub(rb"\\([nrtbf()\\])", lambda m: {b"n": b"\n", b"r": b"\r", b"t": b"\t", b"b": b"", b"f": b""}.get(m.group(1), m.group(1)), raw[1:-1])
    else:
        return ""
    if value.startswith(b"\xfe\xff"):
        return value[2:].decode("utf-16-be", errors="replace")
    return value.decode("latin-1", errors="replace")


def pdf_inventory(data: bytes) -> dict[str, Any]:
    info: dict[str, str] = {}
    for key in PDF_INFO_KEYS:
        for match in re.finditer(rb"/" + key.encode() + rb"\s*(\((?:\\.|[^\\)])*\)|<[0-9A-Fa-f\s]*>)", data[:20_000_000]):
            value = _pdf_string(match.group(1))
            if value.strip():
                info[key] = value.strip()[:300]
    return {
        "info": info,
        "xmp_metadata": bool(re.search(rb"/Type\s*/Metadata\b", data)) or b"<x:xmpmeta" in data,
        "revisions": len(re.findall(rb"%%EOF", data)),
        "javascript": bool(re.search(rb"/JavaScript\b|/JS\s*[(<]", data)),
        "embedded_files": len(re.findall(rb"/EmbeddedFile\b", data)),
        "annotations": len(re.findall(rb"/Annot\b", data)),
    }
