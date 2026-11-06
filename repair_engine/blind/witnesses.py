"""Witnesses: integrity facts that a file's own producer wrote into it.

A linker writes a PE checksum and SizeOfCode, a signer writes an
Authenticode digest, a zip tool writes a CRC per member and the offset of
its central directory, a PNG encoder writes a CRC per chunk, a PDF writer
writes the byte offset of every object. Each of these is a small hash of
the *original* file, made before any infection. An infector changes bytes
but rarely keeps every one of these facts in step, so they still testify to
what the clean file was. That makes them usable as a verification oracle
for a clean copy nobody has.

Every witness carries ``bits``: how unlikely it is to hold by chance for a
wrong reconstruction (a CRC32 that matches is about 32 bits, the folded PE
checksum about 16, a SHA-256 digest 256). The numbers are conservative
estimates, not measurements, and many weak witnesses of one kind are capped
so they cannot add up to false certainty.
"""
from __future__ import annotations

import hashlib
import io
import re
import struct
import zipfile
import zlib
from dataclasses import dataclass

from repair_engine import pe_layout
from repair_engine.parsers import detect

_DAMAGED = (ValueError, struct.error, IndexError, KeyError, zlib.error, zipfile.BadZipFile, OSError, EOFError, OverflowError)
MAX_MEMBER = 64 << 20  # zip members larger than this are not decompressed to check their CRC


@dataclass(frozen=True)
class Witness:
    key: str
    bits: float
    holds: bool
    restorable: bool = False  # the repair can re-establish it itself (a checksum), so failing it costs nothing


def collect(data: bytes, skip: tuple[str, ...] = ()) -> dict[str, Witness]:
    """Every witness the bytes carry, by key. Unreadable structure gives none, never an exception."""
    fmt = detect(data)
    reader = {"pe": pe_witnesses, "zip": zip_witnesses, "png": png_witnesses, "pdf": pdf_witnesses}.get(fmt)
    if reader is None:
        return {}
    try:
        found = reader(data)
    except _DAMAGED:
        return {}
    return {w.key: w for w in found if not w.key.startswith(skip)}


def _capped(witnesses: list[Witness], cap: float) -> list[Witness]:
    """Scale a group of many small witnesses so the group as a whole is worth at most ``cap`` bits."""
    total = sum(w.bits for w in witnesses)
    if total <= cap or not witnesses:
        return witnesses
    scale = cap / total
    return [Witness(w.key, w.bits * scale, w.holds, w.restorable) for w in witnesses]


# -- PE ---------------------------------------------------------------------------------------------

SPC_INDIRECT_DATA = bytes.fromhex("060a2b060104018237020104")  # 1.3.6.1.4.1.311.2.1.4
_DIGEST_INFO = (
    (bytes.fromhex("0609608648016503040201") + b"\x05\x00\x04\x20", "sha256", 32),
    (bytes.fromhex("06052b0e03021a") + b"\x05\x00\x04\x14", "sha1", 20),
)
CODE, INITIALIZED = 0x20, 0x40


def section_sums(layout: pe_layout.Layout) -> tuple[int, int]:
    """What a linker writes into SizeOfCode and SizeOfInitializedData."""
    code = sum(s.raw_size for s in layout.sections if s.characteristics & CODE)
    init = sum(s.raw_size for s in layout.sections if s.characteristics & INITIALIZED)
    return code, init


def signed_digest(data: bytes, layout: pe_layout.Layout) -> tuple[str, bytes] | None:
    """The image digest inside the Authenticode signature (SpcIndirectDataContent's DigestInfo)."""
    offset, size = layout.certificate
    if not size or offset + size > len(data):
        return None
    blob = data[offset + 8:offset + size]
    content = blob.find(SPC_INDIRECT_DATA)
    if content < 0:
        return None
    for prefix, algorithm, length in _DIGEST_INFO:
        at = blob.find(prefix, content)
        if at >= 0 and at + len(prefix) + length <= len(blob):
            return algorithm, blob[at + len(prefix):at + len(prefix) + length]
    return None


def authenticode_hash(data: bytes, layout: pe_layout.Layout, algorithm: str) -> bytes:
    """The PE image hash: everything but the checksum, the certificate directory entry and the certificate."""
    checksum = layout.checksum_offset
    entry = layout.optional + (112 if layout.pe32_plus else 96) + 4 * 8
    offset, size = layout.certificate
    digest = hashlib.new(algorithm)
    for piece in (data[:checksum], data[checksum + 4:entry], data[entry + 8:offset], data[offset + size:]):
        digest.update(piece)
    return digest.digest()


def pe_witnesses(data: bytes) -> list[Witness]:
    layout = pe_layout.read(data)
    found: list[Witness] = []
    if layout.checksum:
        found.append(Witness("pe.checksum", 16, layout.checksum == pe_layout.checksum(data, layout.checksum_offset), True))
    code, init = section_sums(layout)
    size_of_code, size_of_init = struct.unpack_from("<II", data, layout.optional + 4)
    if size_of_code:
        found.append(Witness("pe.size_of_code", 8, size_of_code == code))
    if size_of_init:
        found.append(Witness("pe.size_of_initialized_data", 6, size_of_init == init))
    signed = signed_digest(data, layout)
    if signed is not None:
        algorithm, digest = signed
        found.append(Witness("pe.authenticode", 8.0 * len(digest), authenticode_hash(data, layout, algorithm) == digest))
    return found


# -- ZIP --------------------------------------------------------------------------------------------


def zip_witnesses(data: bytes) -> list[Witness]:
    found: list[Witness] = []
    end = data.rfind(b"PK\x05\x06")
    if end >= 0 and end + 22 <= len(data):
        cd_size, cd_offset = struct.unpack_from("<II", data, end + 12)
        found.append(Witness("zip.central_directory_offset", 16, cd_offset + cd_size == end))
    crcs = []
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        for info in archive.infolist()[:256]:
            if info.file_size > MAX_MEMBER or info.flag_bits & 0x1:
                continue
            try:
                archive.read(info)
                ok = True
            except _DAMAGED + (NotImplementedError, RuntimeError):
                ok = False
            crcs.append(Witness(f"zip.crc:{info.filename}", 32, ok))
    return found + _capped(crcs, 256)


# -- PNG --------------------------------------------------------------------------------------------


def png_witnesses(data: bytes) -> list[Witness]:
    crcs, at, index = [], 8, 0
    while at + 12 <= len(data) and index < 4096:
        length, = struct.unpack_from(">I", data, at)
        kind = data[at + 4:at + 8]
        if at + 12 + length > len(data):
            break
        stored, = struct.unpack_from(">I", data, at + 8 + length)
        crcs.append(Witness(f"png.crc:{index}:{kind.decode('latin-1')}", 32, zlib.crc32(data[at + 4:at + 8 + length]) & 0xFFFFFFFF == stored))
        at += 12 + length
        index += 1
        if kind == b"IEND":
            break
    return _capped(crcs, 256)


# -- PDF --------------------------------------------------------------------------------------------

_XREF_ENTRY = re.compile(rb"(\d{10}) (\d{5}) ([nf])")
_STARTXREF = re.compile(rb"startxref\s+(\d+)")


def pdf_witnesses(data: bytes) -> list[Witness]:
    """Each classic xref entry names the byte offset of ``N G obj``: a prefix or an insertion shifts them all."""
    found: list[Witness] = []
    tail = data[-4096:]
    pointers = list(_STARTXREF.finditer(tail))
    if not pointers:
        return found
    xref = int(pointers[-1].group(1))
    found.append(Witness("pdf.startxref", 8, data[xref:xref + 4] == b"xref"))
    if data[xref:xref + 4] != b"xref":
        return found
    section = data[xref:xref + 20 * 4096]
    first = re.match(rb"xref\s+(\d+)\s+\d+\s+", section)
    if first is None:
        return found
    number = int(first.group(1))
    entries = []
    for offset, match in enumerate(_XREF_ENTRY.finditer(section[first.end():first.end() + 20 * 1024])):
        if match.group(3) != b"n":
            continue
        position, generation = int(match.group(1)), int(match.group(2))
        head = re.match(rb"\s*(\d+)\s+(\d+)\s+obj", data[position:position + 32])
        ok = head is not None and int(head.group(1)) == number + offset and int(head.group(2)) == generation
        entries.append(Witness(f"pdf.xref:{number + offset}", 6, ok))
    return found + _capped(entries, 96)
