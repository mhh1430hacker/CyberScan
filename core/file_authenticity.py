from __future__ import annotations

import os
from typing import Any


_SIGNATURES: tuple[tuple[str, bytes], ...] = (
    ("PNG image", b"\x89PNG\r\n\x1a\n"),
    ("JPEG image", b"\xff\xd8\xff"),
    ("GIF image", b"GIF8"),
    ("BMP image", b"BM"),
    ("PDF document", b"%PDF-"),
    ("OLE compound document", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"),
    ("7-Zip archive", b"7z\xbc\xaf\x27\x1c"),
    ("RAR archive", b"Rar!\x1a\x07"),
    ("GZIP archive", b"\x1f\x8b"),
    ("ELF executable", b"\x7fELF"),
)

_EXTENSION_FORMATS = {
    ".pdf": "PDF document",
    ".png": "PNG image",
    ".jpg": "JPEG image",
    ".jpeg": "JPEG image",
    ".gif": "GIF image",
    ".bmp": "BMP image",
    ".doc": "OLE compound document",
    ".xls": "OLE compound document",
    ".ppt": "OLE compound document",
    ".docx": "OOXML document",
    ".xlsx": "OOXML spreadsheet",
    ".pptx": "OOXML presentation",
    ".zip": "ZIP archive",
    ".rar": "RAR archive",
    ".7z": "7-Zip archive",
    ".gz": "GZIP archive",
    ".exe": "PE executable",
    ".dll": "PE executable",
    ".txt": "Text document",
    ".csv": "Text document",
}


def identify_file_format(data: bytes, file_name: str = "") -> dict[str, Any]:
    """Compare a filename's claimed type with a bounded set of file signatures."""
    if not isinstance(data, bytes):
        raise TypeError("file data must be bytes.")

    extension = os.path.splitext(os.path.basename(file_name))[1].lower()
    declared = _EXTENSION_FORMATS.get(extension)
    observed: str | None = None
    confidence = "low"
    evidence: list[str] = []

    if data.startswith(b"MZ"):
        observed = "PE executable" if _is_pe(data) else "MZ header (PE structure unverified)"
        confidence = "high" if observed == "PE executable" else "medium"
        evidence.append("DOS MZ signature" if confidence == "medium" else "MZ header and PE signature")
    elif data.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        observed = "ZIP archive"
        confidence = "medium"
        evidence.append("ZIP local-file, empty-archive, or spanning signature")
        if extension in {".docx", ".xlsx", ".pptx"}:
            observed = "ZIP-based OOXML container (internal parts not validated)"
            evidence.append("The container is ZIP-based; OOXML document parts were not validated")
    else:
        for label, signature in _SIGNATURES:
            if data.startswith(signature) or (label == "PDF document" and data[:1024].find(signature) >= 0):
                observed = label
                confidence = "high"
                evidence.append(f"{label} signature")
                break

    if observed is None and data:
        observed = "Unknown binary or text format"
        evidence.append("No supported signature identified")
    elif not data:
        observed = "Empty file"
        evidence.append("File contains no bytes")

    mismatch: bool | None = None
    ooxml_container = extension in {".docx", ".xlsx", ".pptx"} and bool(
        observed and observed.startswith("ZIP-based OOXML")
    )
    if declared:
        mismatch = bool(observed and declared != observed and not ooxml_container)
    elif observed == "PE executable":
        mismatch = extension not in {".exe", ".dll"}

    if mismatch and declared:
        evidence.append(f"Extension {extension} suggests {declared}, but the content resembles {observed}")
    elif mismatch:
        evidence.append(f"Executable signature detected under non-executable extension {extension}")
    elif declared and observed == declared:
        evidence.append(f"Extension {extension} agrees with the observed format")
    elif declared and observed == "ZIP archive" and declared.startswith("OOXML "):
        evidence.append("The extension suggests an OOXML package; required internal parts were not confirmed")

    return {
        "file_name": os.path.basename(file_name),
        "extension": extension or None,
        "declared_format": declared,
        "detected_format": observed,
        "confidence": confidence,
        "extension_mismatch": mismatch,
        "evidence": evidence,
        "limitations": [
            "A matching signature identifies a format, not a trusted publisher or a safe file."
        ],
    }


def _is_pe(data: bytes) -> bool:
    if len(data) < 64:
        return False
    offset = int.from_bytes(data[0x3C:0x40], "little")
    return 64 <= offset <= len(data) - 4 and data[offset:offset + 4] == b"PE\0\0"
