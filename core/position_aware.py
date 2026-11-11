from __future__ import annotations

import hashlib
import math
from collections.abc import Mapping, Sequence
from typing import Any


POSITION_SCHEMA = "cyberscan-position-v1"
MAX_POSITION_ENTROPY_BOUNDARIES = 128
MAX_REGION_HASH_BYTES = 16 * 1024 * 1024


def build_position_aware_evidence(
    data: bytes,
    entropy_topography: Mapping[str, Any],
    pe_analysis: Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes.")
    if not isinstance(entropy_topography, Mapping):
        raise TypeError("entropy_topography must be a mapping.")
    if not isinstance(pe_analysis, Mapping):
        raise TypeError("pe_analysis must be a mapping.")

    entropy_boundaries: list[dict[str, Any]] = []
    rejected_observations = 0
    omitted_observations = 0
    hashed_region_bytes = 0
    anomalies = entropy_topography.get("anomalies", [])
    if isinstance(anomalies, Sequence) and not isinstance(anomalies, (str, bytes)):
        for anomaly in anomalies:
            if not isinstance(anomaly, Mapping):
                rejected_observations += 1
                continue
            start = anomaly.get("offset_start")
            end = anomaly.get("offset_end")
            delta = anomaly.get("delta")
            severity = anomaly.get("severity")
            try:
                numeric_delta = float(delta)
            except (OverflowError, TypeError, ValueError):
                numeric_delta = math.nan
            if (
                isinstance(start, bool)
                or not isinstance(start, int)
                or isinstance(end, bool)
                or not isinstance(end, int)
                or start < 0
                or end <= start
                or end > len(data)
                or isinstance(delta, bool)
                or not isinstance(delta, (int, float))
                or not math.isfinite(numeric_delta)
                or not isinstance(severity, str)
                or severity not in {"medium", "high", "critical"}
            ):
                rejected_observations += 1
                continue
            if len(entropy_boundaries) >= MAX_POSITION_ENTROPY_BOUNDARIES:
                omitted_observations += 1
                continue
            region_length = end - start
            region_sha256 = None
            hash_status = "omitted_size_limit"
            if region_length <= MAX_REGION_HASH_BYTES - hashed_region_bytes:
                region = memoryview(data)[start:end]
                region_sha256 = hashlib.sha256(region).hexdigest()
                hashed_region_bytes += region_length
                hash_status = "verified"
            entropy_boundaries.append({
                "kind": "measured_entropy_transition",
                "offset_start": start,
                "offset_end": end,
                "length": region_length,
                "region_sha256": region_sha256,
                "region_hash_status": hash_status,
                "entropy_delta_bits_per_byte": round(numeric_delta, 6),
                "severity": severity,
                "evidence_source": "core.entropy.entropy_topography",
                "interpretation": (
                    "Measured encoding/statistical transition; not evidence of "
                    "maliciousness by itself."
                ),
            })

    sections: list[dict[str, Any]] = []
    raw_sections = pe_analysis.get("sections", [])
    if isinstance(raw_sections, Sequence) and not isinstance(raw_sections, (str, bytes)):
        for section in raw_sections:
            if not isinstance(section, Mapping):
                continue
            raw_offset = section.get("raw_offset")
            raw_size = section.get("raw_size")
            virtual_address = section.get("virtual_address")
            virtual_size = section.get("virtual_size")
            offset_valid = (
                isinstance(raw_offset, int)
                and not isinstance(raw_offset, bool)
                and raw_offset >= 0
                and isinstance(raw_size, int)
                and not isinstance(raw_size, bool)
                and raw_size >= 0
            )
            raw_end = raw_offset + raw_size if offset_valid else None
            range_in_file = bool(
                offset_valid
                and raw_end is not None
                and raw_offset <= len(data)
                and raw_end <= len(data)
                and raw_size > 0
                and section.get("raw_data_length") == raw_size
                and section.get("raw_range_verified") is True
            )
            sections.append({
                "name": str(section.get("name", "")),
                "file_offset_start": raw_offset if range_in_file else None,
                "file_offset_end": raw_end if range_in_file else None,
                "rva_start": (
                    virtual_address
                    if isinstance(virtual_address, int)
                    and not isinstance(virtual_address, bool)
                    and virtual_address >= 0
                    else None
                ),
                "virtual_size": (
                    virtual_size
                    if isinstance(virtual_size, int)
                    and not isinstance(virtual_size, bool)
                    and virtual_size >= 0
                    else None
                ),
                "raw_size": raw_size if offset_valid else None,
                "executable": section.get("executable") is True,
                "range_status": "within_file" if range_in_file else "unverified_or_out_of_bounds",
                "evidence_source": "pefile section table",
            })

    return {
        "schema": POSITION_SCHEMA,
        "coordinate_system": "zero-based half-open file byte offsets [start, end)",
        "file_size": len(data),
        "file_sha256": hashlib.sha256(data).hexdigest(),
        "entropy_boundaries": entropy_boundaries,
        "pe_sections": sections,
        "rejected_entropy_observations": rejected_observations,
        "omitted_entropy_observations": omitted_observations,
        "hashed_region_bytes": hashed_region_bytes,
        "limits": {
            "max_entropy_boundaries": MAX_POSITION_ENTROPY_BOUNDARIES,
            "max_total_region_hash_bytes": MAX_REGION_HASH_BYTES,
        },
        "limitations": [
            "Positions are static measurements, not model-predicted malicious regions.",
            "Entropy transitions do not prove malicious content.",
            "PE virtual addresses and raw file offsets are distinct coordinate systems.",
            "This data cannot establish a safe byte patch or repair scope.",
        ],
    }
