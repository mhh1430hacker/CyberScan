from __future__ import annotations

import io
import stat
import struct
import zipfile

from core.archive_inspector import inspect_zip
from core.file_analyzer import analyze_file


def _zip_bytes(members: list[tuple[str, str | zipfile.ZipInfo, bytes | None]]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, info_or_name, data in members:
            info = info_or_name if isinstance(info_or_name, zipfile.ZipInfo) else None
            archive.writestr(info or name, data or b"")
    return output.getvalue()


def test_inspects_nested_zip_without_extracting_members():
    inner = _zip_bytes([("note.txt", "note.txt", b"plain text")])
    outer = _zip_bytes([("nested.zip", "nested.zip", inner)])

    result = inspect_zip(outer)

    assert result.status == "ok"
    assert [entry.path for entry in result.entries] == ["nested.zip", "nested.zip!/note.txt"]
    assert result.entries[0].file_type == "zip"
    assert result.entries[1].file_type == "text_candidate"
    assert result.as_dict()["member_contents_analyzed_for_malware"] is False


def test_skips_traversal_and_symlink_members():
    symlink = zipfile.ZipInfo("link")
    symlink.create_system = 3
    symlink.external_attr = (stat.S_IFLNK | 0o777) << 16
    archive = _zip_bytes([
        ("../outside.txt", "../outside.txt", b"not extracted"),
        (r"C:\outside.txt", r"C:\outside.txt", b"not extracted"),
        ("link", symlink, b"target"),
    ])

    result = inspect_zip(archive)

    assert result.status == "partial"
    assert result.unsafe_member_paths == 2
    assert result.symlink_members == 1
    assert all(entry.status != "inspected" for entry in result.entries)


def test_enforces_total_decompressed_size_before_reading_unbounded_content():
    archive = _zip_bytes([("large.txt", "large.txt", b"x" * 1000)])

    result = inspect_zip(archive, max_total_size=8)

    assert result.status == "limit_exceeded"
    assert result.decompressed_bytes <= 9
    assert result.entries[0].status == "limit_exceeded"


def test_enforces_entry_count_before_parsing_all_members():
    archive = _zip_bytes([
        ("one.txt", "one.txt", b"1"),
        ("two.txt", "two.txt", b"2"),
    ])

    result = inspect_zip(archive, max_entries=1)

    assert result.status == "limit_exceeded"
    assert result.entries == []


def test_rejects_central_directory_count_mismatch():
    archive = bytearray(_zip_bytes([
        ("one.txt", "one.txt", b"1"),
        ("two.txt", "two.txt", b"2"),
    ]))
    end_record = archive.rfind(b"PK\x05\x06")
    struct.pack_into("<H", archive, end_record + 8, 1)
    struct.pack_into("<H", archive, end_record + 10, 1)

    result = inspect_zip(bytes(archive))

    assert result.status == "partial"
    assert any("entry count is inconsistent" in error for error in result.errors)


def test_skips_encrypted_members_without_requesting_a_password():
    archive = bytearray(_zip_bytes([("secret.txt", "secret.txt", b"not decrypted")]))
    local_header = archive.find(b"PK\x03\x04")
    central_header = archive.find(b"PK\x01\x02")
    struct.pack_into("<H", archive, local_header + 6, 1)
    struct.pack_into("<H", archive, central_header + 8, 1)

    result = inspect_zip(bytes(archive))

    assert result.status == "partial"
    assert result.encrypted_members == 1
    assert result.entries[0].status == "encrypted"


def test_enforces_per_member_size_limit():
    archive = _zip_bytes([("large.txt", "large.txt", b"x" * 10)])

    result = inspect_zip(archive, max_entry_size=4, max_total_size=20)

    assert result.status == "limit_exceeded"
    assert result.decompressed_bytes == 0
    assert result.entries[0].status == "limit_exceeded"


def test_enforces_nested_archive_depth_limit():
    inner = _zip_bytes([("note.txt", "note.txt", b"plain text")])
    outer = _zip_bytes([("nested.zip", "nested.zip", inner)])

    result = inspect_zip(outer, max_depth=0)

    assert result.status == "limit_exceeded"
    assert result.entries[0].file_type == "zip"
    assert len(result.entries) == 1


def test_detects_duplicate_content_and_reports_actual_limits():
    archive = _zip_bytes([
        ("first.txt", "first.txt", b"same"),
        ("second.txt", "second.txt", b"same"),
    ])

    result = inspect_zip(archive, max_entries=3)

    assert result.status == "ok"
    assert result.duplicate_contents == [{
        "sha256": result.entries[0].sha256,
        "first_path": "first.txt",
        "duplicate_path": "second.txt",
    }]
    assert result.as_dict()["limits"]["max_entries"] == 3


def test_malformed_zip_signature_is_reported_as_partial():
    result = inspect_zip(b"PK\x03\x04not a complete archive")

    assert result.status == "partial"
    assert result.errors


def test_file_analysis_exposes_bounded_archive_summary(tmp_path):
    archive_path = tmp_path / "misleading.bin"
    archive_path.write_bytes(_zip_bytes([("note.txt", "note.txt", b"ordinary text")]))

    result = analyze_file(str(archive_path))

    summary = result.feature_summary["archive_inspection"]
    assert summary["status"] == "ok"
    assert summary["entry_count"] == 1
    assert summary["member_contents_analyzed_for_malware"] is False
    assert result.engine_status["Archive"].startswith("bounded structure inspection")
