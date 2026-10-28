from __future__ import annotations

import hashlib
import io
import re
import stat
import struct
import zipfile
import zlib
from dataclasses import asdict, dataclass, field


MAX_ARCHIVE_DEPTH = 2
MAX_ARCHIVE_ENTRIES = 1000
MAX_ARCHIVE_ENTRY_SIZE = 16 * 1024 * 1024
MAX_ARCHIVE_TOTAL_SIZE = 64 * 1024 * 1024
MAX_ARCHIVE_INPUT_SIZE = 50 * 1024 * 1024
_ZIP_SIGNATURES = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")


@dataclass
class ArchiveEntry:
    path: str
    depth: int
    declared_size: int
    status: str
    file_type: str | None = None
    sha256: str | None = None


@dataclass
class ArchiveInspection:
    status: str
    limits: dict[str, int] = field(default_factory=dict)
    entries: list[ArchiveEntry] = field(default_factory=list)
    duplicate_contents: list[dict[str, str]] = field(default_factory=list)
    decompressed_bytes: int = 0
    unsafe_member_paths: int = 0
    encrypted_members: int = 0
    symlink_members: int = 0
    errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, object]:
        return {
            **asdict(self),
            "entries": [asdict(entry) for entry in self.entries],
            "entry_count": len(self.entries),
            "member_contents_analyzed_for_malware": False,
        }


def _looks_like_zip(data: bytes) -> bool:
    return data.startswith(_ZIP_SIGNATURES)


def _member_path_is_unsafe(name: str) -> bool:
    normalized = name.replace("\\", "/")
    return (
        "\\" in name
        or normalized.startswith("/")
        or bool(re.match(r"^[A-Za-z]:", normalized))
        or any(part == ".." for part in normalized.split("/"))
    )


def _identify_content(data: bytes) -> str:
    if _looks_like_zip(data):
        return "zip"
    if data.startswith(b"%PDF-"):
        return "pdf"
    if data.startswith(b"\x7fELF"):
        return "elf"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if data.startswith(b"MZ"):
        if len(data) >= 64:
            pe_offset = int.from_bytes(data[0x3C:0x40], "little")
            if 64 <= pe_offset <= len(data) - 4 and data[pe_offset:pe_offset + 4] == b"PE\0\0":
                return "pe"
        return "mz_header_unverified"
    if not data:
        return "empty"
    sample = data[:4096]
    if b"\x00" not in sample:
        try:
            sample.decode("utf-8")
            return "text_candidate"
        except UnicodeDecodeError:
            pass
    return "unknown"


def _central_directory_entry_count(
    data: bytes,
    maximum_entries: int,
) -> tuple[int | None, str | None]:
    search_start = max(0, len(data) - 65_557)
    marker = b"PK\x05\x06"
    search_end = len(data)
    while True:
        offset = data.rfind(marker, search_start, search_end)
        if offset < 0:
            return None, "ZIP end-of-central-directory record is missing."
        if offset + 22 <= len(data):
            (
                _signature,
                disk_number,
                central_directory_disk,
                entries_on_disk,
                total_entries,
                central_directory_size,
                central_directory_offset,
                comment_size,
            ) = struct.unpack_from("<4s4H2LH", data, offset)
            if offset + 22 + comment_size == len(data):
                if disk_number != 0 or central_directory_disk != 0 or entries_on_disk != total_entries:
                    return None, "Multi-disk ZIP archives are unsupported."
                if (
                    entries_on_disk == 0xFFFF
                    or total_entries == 0xFFFF
                    or central_directory_size == 0xFFFFFFFF
                    or central_directory_offset == 0xFFFFFFFF
                ):
                    return None, "ZIP64 archives are unsupported by bounded inspection."
                central_end = central_directory_offset + central_directory_size
                if central_end > offset or central_end > len(data):
                    return None, "ZIP central-directory bounds are invalid."
                cursor = central_directory_offset
                counted_entries = 0
                while cursor < central_end:
                    if cursor + 46 > central_end or data[cursor:cursor + 4] != b"PK\x01\x02":
                        return None, "ZIP central-directory entry is malformed."
                    compressed_size = struct.unpack_from("<I", data, cursor + 20)[0]
                    uncompressed_size = struct.unpack_from("<I", data, cursor + 24)[0]
                    filename_size = struct.unpack_from("<H", data, cursor + 28)[0]
                    extra_size = struct.unpack_from("<H", data, cursor + 30)[0]
                    member_comment_size = struct.unpack_from("<H", data, cursor + 32)[0]
                    member_disk = struct.unpack_from("<H", data, cursor + 34)[0]
                    local_header_offset = struct.unpack_from("<I", data, cursor + 42)[0]
                    if (
                        compressed_size == 0xFFFFFFFF
                        or uncompressed_size == 0xFFFFFFFF
                        or local_header_offset == 0xFFFFFFFF
                    ):
                        return None, "ZIP64 members are unsupported by bounded inspection."
                    if member_disk != 0:
                        return None, "Multi-disk ZIP members are unsupported."
                    record_size = 46 + filename_size + extra_size + member_comment_size
                    if cursor + record_size > central_end:
                        return None, "ZIP central-directory record exceeds its declared bounds."
                    cursor += record_size
                    counted_entries += 1
                    if counted_entries > maximum_entries:
                        return None, "ZIP central-directory entry-count limit exceeded."
                if counted_entries != total_entries:
                    return None, "ZIP central-directory entry count is inconsistent."
                return counted_entries, None
        search_end = offset


def inspect_zip(
    data: bytes,
    *,
    max_depth: int = MAX_ARCHIVE_DEPTH,
    max_entries: int = MAX_ARCHIVE_ENTRIES,
    max_entry_size: int = MAX_ARCHIVE_ENTRY_SIZE,
    max_total_size: int = MAX_ARCHIVE_TOTAL_SIZE,
) -> ArchiveInspection:
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes.")
    limits = (max_depth, max_entries, max_entry_size, max_total_size)
    if any(isinstance(value, bool) or not isinstance(value, int) for value in limits):
        raise TypeError("Archive limits must be integers.")
    if max_depth < 0 or max_entries < 1 or max_entry_size < 1 or max_total_size < 1:
        raise ValueError("Archive limits must be positive, except max_depth may be zero.")
    active_limits = {
        "max_depth": max_depth,
        "max_entries": max_entries,
        "max_entry_size": max_entry_size,
        "max_total_size": max_total_size,
        "max_input_size": MAX_ARCHIVE_INPUT_SIZE,
    }
    if not _looks_like_zip(data):
        return ArchiveInspection(status="not_zip", limits=active_limits)
    if len(data) > MAX_ARCHIVE_INPUT_SIZE:
        return ArchiveInspection(
            status="limit_exceeded",
            limits=active_limits,
            errors=["Archive input-size limit exceeded."],
        )

    result = ArchiveInspection(status="ok", limits=active_limits)
    content_paths: dict[str, str] = {}
    decompressed_bytes = 0

    def mark_partial(message: str) -> None:
        if result.status == "ok":
            result.status = "partial"
        result.errors.append(message)

    def visit(archive_data: bytes, depth: int, prefix: str) -> None:
        nonlocal decompressed_bytes
        remaining_entries = max_entries - len(result.entries)
        entry_count, directory_error = _central_directory_entry_count(
            archive_data,
            remaining_entries,
        )
        if directory_error:
            if "limit exceeded" in directory_error:
                result.status = "limit_exceeded"
                result.errors.append(directory_error)
            else:
                mark_partial(
                    f"Unsupported or malformed ZIP container at {prefix or '<root>'}: "
                    f"{directory_error}"
                )
            return
        if entry_count is None or entry_count > remaining_entries:
            result.status = "limit_exceeded"
            result.errors.append("Archive entry-count limit exceeded.")
            return
        try:
            archive = zipfile.ZipFile(io.BytesIO(archive_data))
        except (zipfile.BadZipFile, OSError, EOFError, ValueError) as exc:
            mark_partial(f"Malformed ZIP container at {prefix or '<root>'}: {type(exc).__name__}.")
            return

        with archive:
            infos = archive.infolist()
            if len(infos) != entry_count:
                mark_partial("ZIP central-directory entry count is inconsistent.")
                return
            for info in infos:

                path = f"{prefix}!/{info.filename}" if prefix else info.filename
                if info.is_dir():
                    result.entries.append(
                        ArchiveEntry(path, depth, info.file_size, "directory")
                    )
                    continue
                if _member_path_is_unsafe(info.filename):
                    result.unsafe_member_paths += 1
                    result.entries.append(
                        ArchiveEntry(path, depth, info.file_size, "unsafe_path")
                    )
                    mark_partial("Unsafe member path skipped; no archive path was extracted.")
                    continue
                mode = info.external_attr >> 16
                if stat.S_ISLNK(mode):
                    result.symlink_members += 1
                    result.entries.append(
                        ArchiveEntry(path, depth, info.file_size, "symlink")
                    )
                    mark_partial("Symbolic-link member skipped.")
                    continue
                if info.flag_bits & 0x1:
                    result.encrypted_members += 1
                    result.entries.append(
                        ArchiveEntry(path, depth, info.file_size, "encrypted")
                    )
                    mark_partial("Encrypted member skipped; no password was attempted.")
                    continue
                if info.file_size > max_entry_size:
                    result.entries.append(
                        ArchiveEntry(path, depth, info.file_size, "limit_exceeded")
                    )
                    result.status = "limit_exceeded"
                    result.errors.append("Archive member-size limit exceeded.")
                    return
                if info.file_size > max_total_size - decompressed_bytes:
                    result.entries.append(
                        ArchiveEntry(path, depth, info.file_size, "limit_exceeded")
                    )
                    result.status = "limit_exceeded"
                    result.errors.append("Total decompressed-size limit exceeded.")
                    return

                content = bytearray()
                member_error: str | None = None
                try:
                    with archive.open(info, "r") as member:
                        while True:
                            entry_remaining = max_entry_size - len(content)
                            total_remaining = max_total_size - decompressed_bytes
                            read_size = min(64 * 1024, entry_remaining + 1, total_remaining + 1)
                            chunk = member.read(read_size)
                            if not chunk:
                                break
                            decompressed_bytes += len(chunk)
                            if len(chunk) > entry_remaining or len(chunk) > total_remaining:
                                member_error = "Archive decompression limit exceeded."
                                break
                            content.extend(chunk)
                except (
                    zipfile.BadZipFile,
                    OSError,
                    EOFError,
                    RuntimeError,
                    NotImplementedError,
                    zlib.error,
                ) as exc:
                    member_error = f"Unable to read archive member: {type(exc).__name__}."

                result.decompressed_bytes = decompressed_bytes
                if member_error:
                    result.entries.append(
                        ArchiveEntry(
                            path,
                            depth,
                            info.file_size,
                            "limit_exceeded" if "limit" in member_error else "read_error",
                        )
                    )
                    if "limit" in member_error:
                        result.status = "limit_exceeded"
                    else:
                        mark_partial(member_error)
                    return
                if len(content) != info.file_size:
                    result.entries.append(
                        ArchiveEntry(path, depth, info.file_size, "read_error")
                    )
                    mark_partial("Archive member size did not match its declared size.")
                    continue

                digest = hashlib.sha256(content).hexdigest()
                previous_path = content_paths.get(digest)
                if previous_path is not None:
                    result.duplicate_contents.append(
                        {"sha256": digest, "first_path": previous_path, "duplicate_path": path}
                    )
                else:
                    content_paths[digest] = path
                file_type = _identify_content(content)
                result.entries.append(
                    ArchiveEntry(path, depth, info.file_size, "inspected", file_type, digest)
                )

                if file_type == "zip":
                    if depth >= max_depth:
                        result.status = "limit_exceeded"
                        result.errors.append("Archive nesting-depth limit exceeded.")
                        return
                    visit(bytes(content), depth + 1, path)

    visit(data, 0, "")
    result.decompressed_bytes = decompressed_bytes
    return result
