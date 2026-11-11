from __future__ import annotations

import hashlib
import struct
import zlib
import zipfile

from core.file_integrity import verify_file_integrity


def _png_chunk(kind: bytes, data: bytes) -> bytes:
    checksum = zlib.crc32(kind + data) & 0xFFFFFFFF
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", checksum)


def _minimal_png(width: int = 1) -> bytes:
    return (
        b"\x89PNG\r\n\x1a\n"
        + _png_chunk(b"IHDR", struct.pack(">IIBBBBB", width, 1, 8, 2, 0, 0, 0))
        + _png_chunk(b"IDAT", zlib.compress(b"\x00\xff\x00\x00"))
        + _png_chunk(b"IEND", b"")
    )


def test_valid_png_is_independently_hashed_and_structurally_valid(tmp_path):
    sample = tmp_path / "pixel.png"
    sample.write_bytes(_minimal_png())

    report = verify_file_integrity(sample)

    assert report["status"] == "structurally_valid"
    assert report["format"] == "PNG"
    assert report["sha256"] == hashlib.sha256(sample.read_bytes()).hexdigest()
    assert report["checks"][1]["status"] == "passed"


def test_png_chunk_crc_corruption_is_reported_as_damage(tmp_path):
    content = bytearray(_minimal_png())
    content[-1] ^= 0x01
    sample = tmp_path / "corrupt.png"
    sample.write_bytes(content)

    report = verify_file_integrity(sample)

    assert report["status"] == "damage_detected"
    assert "checksum mismatch" in report["checks"][1]["detail"]


def test_truncated_png_is_detected(tmp_path):
    sample = tmp_path / "truncated.png"
    sample.write_bytes(_minimal_png()[:-8])

    report = verify_file_integrity(sample)

    assert report["status"] == "damage_detected"
    assert "Truncated PNG chunk header" in report["checks"][1]["detail"]


def test_invalid_png_dimensions_are_detected(tmp_path):
    sample = tmp_path / "zero-width.png"
    sample.write_bytes(_minimal_png(width=0))

    report = verify_file_integrity(sample)

    assert report["status"] == "damage_detected"
    assert "IHDR" in report["checks"][1]["detail"]


def test_valid_zip_checks_crc_without_extracting_and_identifies_nested_archives(tmp_path):
    nested = tmp_path / "nested.zip"
    with zipfile.ZipFile(nested, "w") as archive:
        archive.writestr("note.txt", "safe fixture")
    sample = tmp_path / "outer.zip"
    with zipfile.ZipFile(sample, "w") as archive:
        archive.writestr("inner.zip", nested.read_bytes())
        archive.writestr("../outside.txt", "never extracted")

    report = verify_file_integrity(sample)

    assert report["status"] == "structurally_valid"
    assert report["nested_archives_detected"] == 1
    assert any("no extraction" in warning for warning in report["limitations"])
    assert any("nested archive" in warning for warning in report["limitations"])
    assert {path.name for path in tmp_path.iterdir()} == {"nested.zip", "outer.zip"}


def test_zip_decompressor_errors_are_reported_not_raised(tmp_path, monkeypatch):
    sample = tmp_path / "archive.zip"
    with zipfile.ZipFile(sample, "w") as archive:
        archive.writestr("note.txt", b"fixture")
    original_open = zipfile.ZipFile.open

    def broken_open(archive, name, mode="r", pwd=None, *, force_zip64=False):
        if getattr(name, "filename", name) == "note.txt":
            raise OSError("invalid member offset")
        return original_open(archive, name, mode, pwd, force_zip64=force_zip64)

    monkeypatch.setattr(zipfile.ZipFile, "open", broken_open)

    report = verify_file_integrity(sample)

    assert report["status"] == "damage_detected"
    assert "OSError" in report["checks"][1]["detail"]


def test_appended_png_data_is_incomplete_not_reported_as_corruption(tmp_path):
    sample = tmp_path / "appended.png"
    sample.write_bytes(_minimal_png() + b"extra")

    report = verify_file_integrity(sample)

    assert report["status"] == "verification_incomplete"
    assert report["trailing_bytes"] == 5
    assert "follow IEND" in report["checks"][1]["detail"]


def test_corrupt_zip_member_is_detected(tmp_path):
    sample = tmp_path / "archive.zip"
    with zipfile.ZipFile(sample, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("note.txt", b"original content")
    data = bytearray(sample.read_bytes())
    data[data.index(b"original content")] ^= 0x01
    sample.write_bytes(data)
    original = sample.read_bytes()

    report = verify_file_integrity(sample)

    assert report["status"] == "damage_detected"
    assert "ZIP structure or entry integrity check failed" in report["checks"][1]["detail"]
    assert sample.read_bytes() == original


def test_zip_expansion_limit_prevents_large_decompression(tmp_path):
    sample = tmp_path / "large-expansion.zip"
    with zipfile.ZipFile(sample, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("large.bin", b"x" * (100 * 1024 * 1024 + 1))

    report = verify_file_integrity(sample, max_file_size=1024 * 1024)

    assert report["status"] == "verification_incomplete"
    assert "expansion" in report["checks"][1]["detail"]


def test_pdf_boundary_only_validation_is_never_claimed_as_complete(tmp_path):
    sample = tmp_path / "sample.pdf"
    sample.write_bytes(b"%PDF-1.7\nnot parsed\n%%EOF\n")

    report = verify_file_integrity(sample)

    assert report["status"] == "verification_incomplete"
    assert report["format"] == "PDF"
    assert "not parsed" in report["checks"][1]["detail"]


def test_pdf_trailing_bytes_after_eof_are_not_called_corruption(tmp_path):
    sample = tmp_path / "padded.pdf"
    sample.write_bytes(b"%PDF-1.7\nnot parsed\n%%EOF\n\x00payload")

    report = verify_file_integrity(sample)

    assert report["status"] == "verification_incomplete"
    assert report["trailing_bytes"] == len(b"\n\x00payload")
    assert "follow the last %%EOF" in report["checks"][1]["detail"]


def test_jpeg_appended_bytes_are_reported_separately(tmp_path):
    sample = tmp_path / "appended.jpg"
    sample.write_bytes(b"\xff\xd8\xffdata\xff\xd9" + b"payload")

    report = verify_file_integrity(sample)

    assert report["status"] == "verification_incomplete"
    assert report["trailing_bytes"] == len(b"payload")
    assert "follow the last EOI marker" in report["checks"][1]["detail"]


def test_unsupported_format_and_changed_analysis_snapshot_are_incomplete(tmp_path):
    sample = tmp_path / "unknown.bin"
    sample.write_bytes(b"not a recognized format")

    report = verify_file_integrity(sample, expected_sha256="0" * 64)

    assert report["status"] == "verification_incomplete"
    assert report["format"] == "unknown"
    assert report["hash_matches_analysis"] is False
    assert report["checks"][1]["status"] == "failed"


def test_file_above_validation_limit_is_not_parsed(tmp_path):
    sample = tmp_path / "large.bin"
    sample.write_bytes(b"x" * 10)

    report = verify_file_integrity(sample, max_file_size=4)

    assert report["status"] == "verification_incomplete"
    assert report["sha256"] is None
    assert report["checks"][0]["status"] == "incomplete"
