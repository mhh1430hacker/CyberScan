from __future__ import annotations

import os
import re

MAGIC_SIGNATURES = {
    ".exe": b"MZ",
    ".dll": b"MZ",
    ".pdf": b"%PDF",
    ".zip": b"PK",
    ".png": b"\x89PNG",
    ".gif": b"GIF8",
    ".jpg": b"\xFF\xD8\xFF",
    ".bmp": b"BM",
    ".class": b"\xCA\xFE\xBA\xBE",
}


def detect_magic_issue(header_bytes: bytes, extension: str) -> dict[str, object]:
    ext = (extension or "").lower()
    header = header_bytes[:8]
    mismatch = False
    severity = "info"
    explanation = "Header is consistent with the file extension."

    if not header:
        return {"mismatch": False, "severity": "info", "explanation": explanation}

    expected = MAGIC_SIGNATURES.get(ext)
    if expected:
        if not header.startswith(expected):
            mismatch = True
            severity = "high"
            explanation = f"File extension {ext} does not match the observed magic bytes."
    elif ext in {".exe", ".dll", ".sys", ".scr"}:
        if not header.startswith(b"MZ"):
            mismatch = True
            severity = "high"
            explanation = "Executable extension is present but the file does not begin with a valid PE header."

    if ext not in {".exe", ".dll", ".sys", ".scr"} and header.startswith(b"MZ"):
        mismatch = True
        severity = "high"
        explanation = f"Executable header signature detected but the file is named with a non-executable extension: {ext}."

    return {"mismatch": mismatch, "severity": severity, "explanation": explanation}


def detect_double_extension(path: str) -> bool:
    name = os.path.basename(path)
    return bool(re.search(r"\.(pdf|doc|docx|jpg|png|txt|xls|ppt)\.(exe|bat|cmd|vbs|ps1|scr)$", name, re.IGNORECASE))


def is_executable_extension(path: str) -> bool:
    ext = os.path.splitext(path)[1].lower()
    return ext in {".exe", ".dll", ".scr", ".bat", ".cmd", ".vbs", ".ps1", ".hta", ".js"}


def naturally_compressed(header: bytes) -> bool:
    """Formats whose content is compressed by design: high entropy in them is normal.

    Pictures, sound, video, PDF, ZIP (and every format built on it: docx,
    xlsx, jar, apk), gzip, 7z, rar, cab.
    """
    head = header[:16]
    return (
        head.startswith((b"\x89PNG", b"\xFF\xD8\xFF", b"GIF8", b"%PDF", b"PK\x03\x04", b"PK\x05\x06", b"\x1f\x8b",
                         b"7z\xBC\xAF", b"Rar!", b"MSCF", b"ID3", b"OggS", b"fLaC", b"\x1A\x45\xDF\xA3", b"wOFF", b"wOF2"))
        or (head[:2] in (b"\xFF\xFB", b"\xFF\xF3", b"\xFF\xF2"))  # MP3 frames
        or (head[:4] == b"RIFF" and head[8:12] in (b"WEBP", b"AVI "))
        or head[4:8] == b"ftyp"  # MP4, MOV, HEIC
    )
