from __future__ import annotations

import os
import re

from core.entropy import shannon_entropy
from core.entropy import entropy_topography
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
    suspicious_strings = 0
    for pattern in SUSPICIOUS_STRING_PATTERNS:
        if pattern.lower() in data.decode("latin-1", errors="ignore").lower():
            suspicious_strings += 1

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
        "import_count": 0,
        "suspicious_import_count": suspicious_strings,
        "string_count": max(1, len(data) // 32),
        "suspicious_string_count": suspicious_strings,
        "executable_section_count": 1 if is_executable_extension(name) and data else 0,
        "packing_indicator": float(entropy > 7.0),
    }
    return features


def extract_file_features(
    data: bytes,
    file_name: str = "",
    max_string_scan_size: int = 200_000,
    *,
    include_topography: bool = False,
) -> dict[str, object]:
    if isinstance(max_string_scan_size, bool) or not isinstance(max_string_scan_size, int) or max_string_scan_size < 0:
        raise ValueError("max_string_scan_size must be a non-negative integer.")
    scan_data = data[:max_string_scan_size]
    features = extract_features_from_bytes(scan_data, file_name)
    topology = entropy_topography(data)
    features.update({
        "file_size": len(data),
        "entropy": float(shannon_entropy(data)),
        "average_section_entropy": float(topology["mean_entropy"]),
        "max_section_entropy": float(topology["peak_entropy"]),
    })
    if include_topography:
        features["entropy_topography"] = topology
    return features
