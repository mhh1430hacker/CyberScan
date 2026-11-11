from __future__ import annotations

import os
from core.entropy import shannon_entropy
from core.magic_bytes import detect_double_extension, detect_magic_issue, is_executable_extension


SUSPICIOUS_STRING_PATTERNS = [
    "powershell",
    "cmd.exe",
    "invoke-expression",
    "wget",
    "curl",
    "downloadstring",
    "runas",
    "bypass",
    "http://",
    "https://",
]


def extract_features_from_bytes(data: bytes, file_name: str = "") -> dict[str, object]:
    name = os.path.basename(file_name or "")
    ext = os.path.splitext(name)[1].lower()
    entropy = shannon_entropy(data)
    header = data[:8]
    magic_info = detect_magic_issue(header, ext)
    # Decode and lowercase once (the previous loop re-decoded the whole buffer per pattern).
    lowered = data.decode("latin-1").lower()
    suspicious_strings = sum(1 for pattern in SUSPICIOUS_STRING_PATTERNS if pattern in lowered)

    features = {
        "file_size": len(data),
        "entropy": float(entropy),
        "extension_category": ext or "no_extension",
        "is_executable": is_executable_extension(name),
        "magic_mismatch": bool(magic_info["mismatch"]),
        "double_extension": detect_double_extension(name),
        "section_count": 1 if data else 0,
        "average_section_entropy": float(entropy),
        "max_section_entropy": float(entropy),
        # Bytes-only extractor: real PE imports are reported by core.pe_decompiler. These two
        # keys are kept for feature-schema compatibility, so training and scanning stay consistent.
        "import_count": 0,
        "suspicious_import_count": suspicious_strings,
        "string_count": max(1, len(data) // 32),
        "suspicious_string_count": suspicious_strings,
        "executable_section_count": 1 if is_executable_extension(name) and data else 0,
        "packing_indicator": float(entropy > 7.0),
    }
    return features
