from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace

import pytest

from core.entropy import entropy_topography
from core.file_analyzer import analyze_file
from core.pe_decompiler import analyze_pe_file
from core.position_aware import POSITION_SCHEMA, build_position_aware_evidence
from reports.exporter import export_report
from reports.report_generator import generate_report


def test_entropy_transition_has_verified_byte_range_and_region_hash():
    data = b"\x00" * 4096 + bytes(range(256)) * 16
    topology = entropy_topography(data, window_size=4096, step_size=4096)

    result = build_position_aware_evidence(data, topology, {})

    assert result["schema"] == POSITION_SCHEMA
    assert result["coordinate_system"] == "zero-based half-open file byte offsets [start, end)"
    assert result["file_size"] == len(data)
    assert result["file_sha256"] == hashlib.sha256(data).hexdigest()
    assert result["entropy_boundaries"]
    boundary = result["entropy_boundaries"][0]
    assert boundary["offset_start"] == 0
    assert boundary["offset_end"] == len(data)
    assert boundary["region_sha256"] == hashlib.sha256(data).hexdigest()
    assert boundary["region_hash_status"] == "verified"
    assert "not evidence of maliciousness" in boundary["interpretation"]


def test_rejects_invalid_or_out_of_file_entropy_ranges():
    data = b"sample"
    anomalies = [
        {"offset_start": -1, "offset_end": 2, "delta": 2.0, "severity": "high"},
        {"offset_start": 0, "offset_end": 99, "delta": 2.0, "severity": "high"},
        {"offset_start": True, "offset_end": 2, "delta": 2.0, "severity": "high"},
        {"offset_start": 0, "offset_end": 1, "delta": float("nan"), "severity": "high"},
        {"offset_start": 0, "offset_end": 1, "delta": 10**10000, "severity": "high"},
        {"offset_start": 0, "offset_end": 1, "delta": 2.0, "severity": "unknown"},
        {"offset_start": 0, "offset_end": 1, "delta": 2.0, "severity": []},
    ]

    result = build_position_aware_evidence(data, {"anomalies": anomalies}, {})

    assert result["entropy_boundaries"] == []
    assert result["rejected_entropy_observations"] == len(anomalies)


def test_caps_emitted_boundaries_and_region_hash_work():
    data = b"sample"
    anomalies = [
        {"offset_start": 0, "offset_end": 1, "delta": 2.0, "severity": "high"}
        for _ in range(130)
    ]

    result = build_position_aware_evidence(data, {"anomalies": anomalies}, {})

    assert len(result["entropy_boundaries"]) == 128
    assert result["omitted_entropy_observations"] == 2
    assert result["hashed_region_bytes"] == 128


def test_omits_hash_for_regions_over_work_budget():
    data = b"x" * (16 * 1024 * 1024 + 1)
    anomaly = {
        "offset_start": 0,
        "offset_end": len(data),
        "delta": 2.0,
        "severity": "high",
    }

    result = build_position_aware_evidence(data, {"anomalies": [anomaly]}, {})

    assert result["entropy_boundaries"][0]["region_sha256"] is None
    assert result["entropy_boundaries"][0]["region_hash_status"] == "omitted_size_limit"
    assert result["hashed_region_bytes"] == 0


def test_maps_pe_section_only_when_its_raw_span_is_verified_in_file():
    data = b"0123456789"
    section = {
        "name": ".text",
        "raw_offset": 2,
        "raw_size": 4,
        "raw_data_length": 4,
        "raw_range_verified": True,
        "virtual_address": 4096,
        "virtual_size": 8,
        "executable": True,
    }

    result = build_position_aware_evidence(data, {}, {"sections": [section]})

    assert result["pe_sections"] == [{
        "name": ".text",
        "file_offset_start": 2,
        "file_offset_end": 6,
        "rva_start": 4096,
        "virtual_size": 8,
        "raw_size": 4,
        "executable": True,
        "range_status": "within_file",
        "evidence_source": "pefile section table",
    }]


@pytest.mark.parametrize(
    "changes",
    [
        {"raw_offset": 8},
        {"raw_range_verified": False},
        {"raw_data_length": 3},
    ],
)
def test_does_not_claim_unverified_pe_raw_span(changes):
    section = {
        "name": ".data",
        "raw_offset": 2,
        "raw_size": 4,
        "raw_data_length": 4,
        "raw_range_verified": True,
        **changes,
    }

    result = build_position_aware_evidence(b"012345", {}, {"sections": [section]})

    assert result["pe_sections"][0]["file_offset_start"] is None
    assert result["pe_sections"][0]["file_offset_end"] is None
    assert result["pe_sections"][0]["range_status"] == "unverified_or_out_of_bounds"


def test_pe_parser_reports_raw_offset_virtual_address_and_range_verification(monkeypatch):
    section_data = b"code"
    section = SimpleNamespace(
        Name=b".text\0\0\0",
        Misc_VirtualSize=8,
        SizeOfRawData=len(section_data),
        PointerToRawData=4,
        VirtualAddress=0x1000,
        Characteristics=0x20000000,
        get_data=lambda: section_data,
    )
    fake_pe = SimpleNamespace(
        sections=[section],
        DIRECTORY_ENTRY_IMPORT=[],
        OPTIONAL_HEADER=SimpleNamespace(AddressOfEntryPoint=0x1000, Subsystem=2),
        FILE_HEADER=SimpleNamespace(Machine=0x14C, NumberOfSections=1, TimeDateStamp=0),
    )
    monkeypatch.setattr(
        "core.pe_decompiler.pefile",
        SimpleNamespace(PE=lambda **_kwargs: fake_pe),
    )

    result = analyze_pe_file("sample.exe", data=b"headcode")

    assert result["status"] == "ok"
    assert result["sections"][0]["raw_offset"] == 4
    assert result["sections"][0]["virtual_address"] == 0x1000
    assert result["sections"][0]["raw_range_verified"] is True


def test_analyzer_and_json_report_expose_position_evidence(tmp_path):
    sample = tmp_path / "positioned.txt"
    sample.write_bytes(b"ordinary text content")

    result = analyze_file(str(sample))

    position = result.feature_summary["position_aware_evidence"]
    assert position["schema"] == POSITION_SCHEMA
    assert position["file_sha256"] == result.feature_summary["sha256"]
    report = tmp_path / "report.json"
    export_report(result, report, "json")
    exported = json.loads(report.read_text(encoding="utf-8"))
    assert exported["feature_summary"]["position_aware_evidence"] == position
    text_report = generate_report(result)
    assert "Position-aware ranges (measured indicators, not malicious-region predictions):" in text_report
