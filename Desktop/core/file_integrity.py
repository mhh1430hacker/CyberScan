from __future__ import annotations

import hashlib
import os
import struct
import zipfile
import zlib
from pathlib import Path
from typing import Any, BinaryIO


_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
_ZIP_SIGNATURES = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
_MAX_ZIP_MEMBERS = 256
_MAX_ZIP_EXPANDED_BYTES = 100 * 1024 * 1024
_MAX_ZIP_EXPANSION_RATIO = 200
_READ_CHUNK_SIZE = 64 * 1024


def _check(name: str, status: str, detail: str) -> dict[str, str]:
    return {"name": name, "status": status, "detail": detail}


def _identify_format(header: bytes) -> str:
    if header.startswith(_PNG_SIGNATURE):
        return "PNG"
    if header.startswith(_ZIP_SIGNATURES):
        return "ZIP"
    if header.startswith(b"%PDF-"):
        return "PDF"
    if header.startswith(b"\xff\xd8\xff"):
        return "JPEG"
    if header.startswith((b"GIF87a", b"GIF89a")):
        return "GIF"
    return "unknown"


def _validate_png(stream: BinaryIO, size: int) -> dict[str, Any]:
    stream.seek(len(_PNG_SIGNATURE))
    offset = len(_PNG_SIGNATURE)
    saw_ihdr = False
    saw_idat = False
    idat_ended = False
    saw_plte = False
    color_type: int | None = None
    chunk_count = 0
    while offset < size:
        chunk_header = stream.read(8)
        if len(chunk_header) != 8:
            return {"status": "failed", "detail": "Truncated PNG chunk header."}
        length = int.from_bytes(chunk_header[:4], "big")
        kind = chunk_header[4:]
        offset += 8
        if offset + length + 4 > size:
            return {"status": "failed", "detail": f"PNG {kind.decode('ascii', 'replace')} chunk extends past end of file."}
        if not kind.isalpha() or not kind.isascii():
            return {"status": "failed", "detail": "PNG contains an invalid chunk type."}
        if kind[2:3].islower():
            return {"status": "failed", "detail": "PNG chunk type uses the reserved lowercase bit."}
        if chunk_count == 0 and kind != b"IHDR":
            return {"status": "failed", "detail": "PNG does not begin with IHDR."}
        if kind == b"IHDR":
            if saw_ihdr or length != 13:
                return {"status": "failed", "detail": "PNG has a duplicate or incorrectly sized IHDR chunk."}
            saw_ihdr = True
        elif not saw_ihdr:
            return {"status": "failed", "detail": "PNG data appears before IHDR."}
        elif kind[:1].isupper() and kind not in {b"PLTE", b"IDAT", b"IEND"}:
            return {"status": "failed", "detail": "PNG contains an unknown critical chunk."}
        if kind == b"PLTE":
            if saw_plte or saw_idat or not 0 < length <= 768 or length % 3:
                return {"status": "failed", "detail": "PNG palette is duplicate, misplaced, or incorrectly sized."}
            if color_type in {0, 4}:
                return {"status": "failed", "detail": "PNG color type does not permit a palette chunk."}
            saw_plte = True
        if kind == b"IDAT":
            if idat_ended:
                return {"status": "failed", "detail": "PNG IDAT chunks are not consecutive."}
            if color_type == 3 and not saw_plte:
                return {"status": "failed", "detail": "Indexed-color PNG is missing its PLTE chunk before IDAT."}
            saw_idat = True
        elif saw_idat and kind != b"IEND":
            idat_ended = True

        crc = zlib.crc32(kind)
        ihdr_data = bytearray() if kind == b"IHDR" else None
        remaining = length
        while remaining:
            data = stream.read(min(_READ_CHUNK_SIZE, remaining))
            if not data:
                return {"status": "failed", "detail": "Truncated PNG chunk data."}
            crc = zlib.crc32(data, crc)
            if ihdr_data is not None:
                ihdr_data.extend(data)
            remaining -= len(data)
        stored_crc = stream.read(4)
        if len(stored_crc) != 4:
            return {"status": "failed", "detail": "Truncated PNG chunk checksum."}
        offset += length + 4
        if crc & 0xFFFFFFFF != int.from_bytes(stored_crc, "big"):
            return {"status": "failed", "detail": f"PNG {kind.decode('ascii', 'replace')} chunk checksum mismatch."}
        if kind == b"IHDR":
            if ihdr_data is None:
                return {"status": "failed", "detail": "PNG IHDR data is missing."}
            width, height, bit_depth, parsed_color_type, compression, filtering, interlace = struct.unpack(">IIBBBBB", ihdr_data)
            color_type = parsed_color_type
            allowed_depths = {
                0: {1, 2, 4, 8, 16},
                2: {8, 16},
                3: {1, 2, 4, 8},
                4: {8, 16},
                6: {8, 16},
            }
            if (
                width == 0
                or height == 0
                or bit_depth not in allowed_depths.get(parsed_color_type, set())
                or compression != 0
                or filtering != 0
                or interlace not in {0, 1}
            ):
                return {"status": "failed", "detail": "PNG IHDR contains invalid dimensions or encoding parameters."}
        chunk_count += 1
        if kind == b"IEND":
            if length != 0:
                return {"status": "failed", "detail": "PNG IEND chunk must be empty."}
            if not saw_idat:
                return {"status": "failed", "detail": "PNG contains no image data (IDAT chunk)."}
            trailing_bytes = size - offset
            return {
                "status": "incomplete" if trailing_bytes else "passed",
                "detail": f"Validated {chunk_count} PNG chunks and their CRCs; pixel decoding was not performed."
                + (f" {trailing_bytes} trailing byte(s) follow IEND." if trailing_bytes else ""),
                "trailing_bytes": trailing_bytes,
            }
    return {"status": "failed", "detail": "PNG is missing its terminal IEND chunk."}


def _nested_archive_prefix(prefix: bytes) -> bool:
    return prefix.startswith(_ZIP_SIGNATURES + (b"Rar!\x1a\x07", b"\x1f\x8b", b"7z\xbc\xaf\x27\x1c"))


def _validate_zip(stream: BinaryIO) -> dict[str, Any]:
    try:
        with zipfile.ZipFile(stream) as archive:
            members = archive.infolist()
            if len(members) > _MAX_ZIP_MEMBERS:
                return {
                    "status": "incomplete",
                    "detail": f"ZIP contains {len(members)} entries; limit is {_MAX_ZIP_MEMBERS}.",
                    "nested_archives": 0,
                    "warnings": [],
                }
            expanded_size = sum(info.file_size for info in members)
            compressed_size = sum(info.compress_size for info in members)
            if expanded_size > _MAX_ZIP_EXPANDED_BYTES:
                return {
                    "status": "incomplete",
                    "detail": f"ZIP declared expansion exceeds the {_MAX_ZIP_EXPANDED_BYTES}-byte validation limit.",
                    "nested_archives": 0,
                    "warnings": [],
                }
            if expanded_size and (not compressed_size or expanded_size / compressed_size > _MAX_ZIP_EXPANSION_RATIO):
                return {
                    "status": "incomplete",
                    "detail": f"ZIP expansion ratio exceeds the {_MAX_ZIP_EXPANSION_RATIO}:1 validation limit.",
                    "nested_archives": 0,
                    "warnings": [],
                }
            if any(
                info.file_size
                and (
                    not info.compress_size
                    or info.file_size / info.compress_size > _MAX_ZIP_EXPANSION_RATIO
                )
                for info in members
            ):
                return {
                    "status": "incomplete",
                    "detail": f"A ZIP entry exceeds the {_MAX_ZIP_EXPANSION_RATIO}:1 validation ratio limit.",
                    "nested_archives": 0,
                    "warnings": [],
                }

            unsafe_paths = sum(
                1
                for info in members
                if Path(info.filename.replace("\\", "/")).is_absolute()
                or ".." in info.filename.replace("\\", "/").split("/")
                or (len(info.filename) >= 2 and info.filename[1] == ":")
            )
            nested_archives = 0
            checked_bytes = 0
            for info in members:
                if info.flag_bits & 0x1:
                    return {
                        "status": "incomplete",
                        "detail": "Encrypted ZIP entries cannot be integrity-checked without a password.",
                        "nested_archives": nested_archives,
                        "warnings": [],
                    }
                prefix = bytearray()
                with archive.open(info, "r") as member:
                    while True:
                        chunk = member.read(_READ_CHUNK_SIZE)
                        if not chunk:
                            break
                        checked_bytes += len(chunk)
                        if checked_bytes > _MAX_ZIP_EXPANDED_BYTES:
                            return {
                                "status": "incomplete",
                                "detail": "ZIP actual expansion exceeded the validation limit.",
                                "nested_archives": nested_archives,
                                "warnings": [],
                            }
                        if len(prefix) < 8:
                            prefix.extend(chunk[:8 - len(prefix)])
                if _nested_archive_prefix(bytes(prefix)):
                    nested_archives += 1
            detail = f"Validated {len(members)} ZIP entries and CRCs without extracting files."
            warnings = []
            if unsafe_paths:
                warnings.append(f"{unsafe_paths} member path(s) contain traversal or absolute-path components; no extraction was performed.")
            if nested_archives:
                warnings.append(f"Detected {nested_archives} nested archive(s); nested contents were not recursively validated.")
            return {
                "status": "passed",
                "detail": detail,
                "nested_archives": nested_archives,
                "warnings": warnings,
            }
    except Exception as exc:
        return {
            "status": "failed",
            "detail": f"ZIP structure or entry integrity check failed: {type(exc).__name__}.",
            "nested_archives": 0,
            "warnings": [],
        }


def _validate_boundary_format(stream: BinaryIO, size: int, file_format: str) -> dict[str, Any]:
    if file_format == "PDF":
        stream.seek(0)
        header = stream.read(min(size, 1024))
        stream.seek(max(0, size - 1024))
        tail = stream.read(min(size, 1024))
        if b"%PDF-" not in header:
            return {"status": "failed", "detail": "PDF header marker is missing from the first 1024 bytes."}
        eof_offset = tail.rfind(b"%%EOF")
        if eof_offset < 0:
            return {"status": "failed", "detail": "PDF end-of-file marker is missing; the file may be truncated."}
        trailing_bytes = len(tail) - eof_offset - len(b"%%EOF")
        return {
            "status": "incomplete",
            "detail": "PDF boundary markers are present; cross-reference tables and object structure were not parsed."
            + (f" {trailing_bytes} byte(s) follow the last %%EOF marker." if trailing_bytes else ""),
            "trailing_bytes": trailing_bytes,
        }
    if file_format == "JPEG":
        stream.seek(0)
        header = stream.read(3)
        stream.seek(max(0, size - 1024))
        tail = stream.read(min(size, 1024))
        eoi_offset = tail.rfind(b"\xff\xd9")
        if header != b"\xff\xd8\xff" or eoi_offset < 0:
            return {"status": "failed", "detail": "JPEG SOI/EOI boundary markers are missing or truncated."}
        trailing_bytes = len(tail) - eoi_offset - 2
        return {
            "status": "incomplete",
            "detail": "JPEG boundary markers are present; frame and scan data were not decoded."
            + (f" {trailing_bytes} byte(s) follow the last EOI marker." if trailing_bytes else ""),
            "trailing_bytes": trailing_bytes,
        }
    stream.seek(0)
    header = stream.read(6)
    stream.seek(max(0, size - 1))
    trailer = stream.read(1)
    if header not in (b"GIF87a", b"GIF89a") or trailer != b";":
        return {"status": "failed", "detail": "GIF header or terminal trailer is missing or truncated."}
    return {"status": "incomplete", "detail": "GIF boundary markers are present; image blocks and LZW data were not decoded."}


def verify_file_integrity(
    path: str | os.PathLike[str],
    expected_sha256: str | None = None,
    max_file_size: int = 50 * 1024 * 1024,
) -> dict[str, Any]:
    """Check a file without modifying it; structural validity is not a safety verdict."""
    file_path = Path(path)
    checks: list[dict[str, str]] = []
    limitations: list[str] = []
    with file_path.open("rb") as stream:
        initial_stat = os.fstat(stream.fileno())
        size = initial_stat.st_size
        if size > max_file_size:
            return {
                "status": "verification_incomplete",
                "format": "unknown",
                "size_bytes": size,
                "sha256": None,
                "hash_matches_analysis": None,
                "checks": [_check("size limit", "incomplete", f"File exceeds the {max_file_size}-byte validation limit.")],
                "limitations": ["Format validation was skipped because the file exceeds the configured size limit."],
                "nested_archives_detected": 0,
            }

        digest = hashlib.sha256()
        stream.seek(0)
        while True:
            chunk = stream.read(_READ_CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)
        sha256 = digest.hexdigest()
        stream.seek(0)
        header = stream.read(16)
        file_format = _identify_format(header)
        checks.append(_check("SHA-256", "passed", f"Calculated SHA-256 over {size} bytes."))

        if expected_sha256 is not None:
            hash_matches_analysis = sha256 == expected_sha256
            checks.append(_check(
                "analysis snapshot",
                "passed" if hash_matches_analysis else "failed",
                "Verification hash matches the primary analysis." if hash_matches_analysis else "File bytes differ from the primary analysis snapshot.",
            ))
        else:
            hash_matches_analysis = None

        nested_archives = 0
        structural_status = "incomplete"
        trailing_bytes = 0
        if file_format == "PNG":
            result = _validate_png(stream, size)
            checks.append(_check("PNG structure", result["status"], result["detail"]))
            structural_status = result["status"]
            trailing_bytes = result.get("trailing_bytes", 0)
        elif file_format == "ZIP":
            result = _validate_zip(stream)
            checks.append(_check("ZIP archive", result["status"], result["detail"]))
            nested_archives = result["nested_archives"]
            limitations.extend(result["warnings"])
            structural_status = result["status"]
        elif file_format in {"PDF", "JPEG", "GIF"}:
            result = _validate_boundary_format(stream, size, file_format)
            checks.append(_check(f"{file_format} boundary markers", result["status"], result["detail"]))
            structural_status = result["status"]
            trailing_bytes = result.get("trailing_bytes", 0)
        else:
            checks.append(_check("format structure", "incomplete", "Format is not supported by the structural validators."))
            limitations.append("No format-specific structural validation was available.")

        final_stat = os.fstat(stream.fileno())
        try:
            path_stat = file_path.stat()
            path_replaced = (path_stat.st_dev, path_stat.st_ino) != (initial_stat.st_dev, initial_stat.st_ino)
        except FileNotFoundError:
            path_replaced = True
        changed_while_reading = (
            initial_stat.st_size != final_stat.st_size
            or initial_stat.st_mtime_ns != final_stat.st_mtime_ns
            or path_replaced
        )
        if changed_while_reading:
            checks.append(_check("source stability", "failed", "File changed or was replaced during verification."))
        else:
            checks.append(_check("source stability", "passed", "File identity, size, and modification time remained stable."))

    if nested_archives:
        limitations.append("Nested archives were identified but were not opened recursively.")
    if file_format in {"PDF", "JPEG", "GIF"} and structural_status == "incomplete":
        limitations.append("Boundary checks cannot establish complete internal validity or safety.")
    status = (
        "verification_incomplete"
        if changed_while_reading or hash_matches_analysis is False or structural_status == "incomplete"
        else "damage_detected"
        if structural_status == "failed"
        else "structurally_valid"
    )
    return {
        "status": status,
        "format": file_format,
        "size_bytes": size,
        "sha256": sha256,
        "hash_matches_analysis": hash_matches_analysis,
        "checks": checks,
        "limitations": limitations,
        "nested_archives_detected": nested_archives,
        "trailing_bytes": trailing_bytes,
    }
