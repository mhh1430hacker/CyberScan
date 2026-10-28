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
