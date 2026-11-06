"""Where was a PE's entry point before an infector moved it?

The file no longer says so directly, but three independent sources still do:

* the added code itself: an infector that keeps its host working has to
  hand control back to it, so its body holds a transfer into the host's
  code (``jmp rel32``, ``push va; ret``, ``mov reg, va; jmp reg``);
* the host's code: compilers emit a recognisable entry stub, and on x64 the
  exception directory lists every function start, which the entry must be;
* the PE checksum: a ones'-complement sum of the whole file. If the
  infector left the original value, it fixes the sum of the entry point's
  two 16-bit halves, so each candidate is checked in O(1) (see
  ``ChecksumSolver``) and a wrong one passes with odds of about 1 in 65 535.

Byte patterns are matched, nothing is disassembled or run.
"""
from __future__ import annotations

import math
import re
import struct
from collections import defaultdict
from dataclasses import dataclass

import numpy as np

from repair_engine import pe_layout

EXECUTE, CODE = 0x20000000, 0x20
EXIT_BITS = 12.0  # an exit from the added code that lands in host code
STUB_BITS = {"msvc_x64": 12.0, "msvc_x86": 10.0}
ALIGNED_BITS = 2.0
MAX_CANDIDATES = 4096

_STUBS = {
    "msvc_x64": re.compile(rb"\x48\x83\xEC\x28\xE8(.{4})\x48\x83\xC4\x28\xE9(.{4})", re.DOTALL),
    "msvc_x86": re.compile(rb"\xE8(.{4})\xE9(.{4})", re.DOTALL),
}
_FILLER = {0xCC, 0x90, 0x00}


@dataclass(frozen=True)
class HostCode:
    section: pe_layout.Section
    data: bytes  # the section's raw bytes

    def contains(self, rva: int) -> bool:
        """Only code that is present in the file: an entry point in zero-filled memory runs nothing."""
        size = min(self.section.raw_size, self.section.virtual_size) if self.section.virtual_size else self.section.raw_size
        return self.section.virtual_address <= rva < self.section.virtual_address + size

    def byte_at(self, rva: int) -> int | None:
        at = rva - self.section.virtual_address
        return self.data[at] if 0 <= at < len(self.data) else None


def image_base(data: bytes, layout: pe_layout.Layout) -> int:
    return struct.unpack_from("<Q", data, layout.optional + 24)[0] if layout.pe32_plus else struct.unpack_from("<I", data, layout.optional + 28)[0]


def host_code(data: bytes, layout: pe_layout.Layout, exclude: pe_layout.Section) -> list[HostCode]:
    return [HostCode(s, data[s.raw_pointer:s.raw_pointer + s.raw_size]) for s in layout.sections
            if s is not exclude and s.raw_size and s.characteristics & (EXECUTE | CODE)]


def _in_host(hosts: list[HostCode], rva: int) -> HostCode | None:
    return next((h for h in hosts if h.contains(rva)), None)


def _looks_like_start(host: HostCode, rva: int) -> bool:
    """A function start the way compilers lay them out: not filler, after filler or a ret, or at the section start."""
    here = host.byte_at(rva)
    if here is None or here in _FILLER:
        return False
    before = host.byte_at(rva - 1)
    return before is None or before in _FILLER or before == 0xC3 or rva % 16 == 0


def exits(body: bytes, body_rva: int, base: int, hosts: list[HostCode]) -> set[int]:
    """Transfers from the added code into host code: the infector handing control back."""
    found: set[int] = set()
    view = memoryview(body)
    for at in range(len(body) - 4):
        op = view[at]
        if op == 0xE9 and at + 5 <= len(body):  # jmp rel32
            target = (body_rva + at + 5 + struct.unpack_from("<i", body, at + 1)[0]) & 0xFFFFFFFF
        elif op == 0x68 and at + 6 <= len(body) and view[at + 5] == 0xC3:  # push va; ret
            target = (struct.unpack_from("<I", body, at + 1)[0] - base) & 0xFFFFFFFF
        elif 0xB8 <= op <= 0xBF and at + 7 <= len(body) and view[at + 5] == 0xFF and view[at + 6] == 0xE0 + op - 0xB8:  # mov r32, va; jmp r32
            target = (struct.unpack_from("<I", body, at + 1)[0] - base) & 0xFFFFFFFF
        elif op == 0x48 and at + 13 <= len(body) and 0xB8 <= view[at + 1] <= 0xBF and view[at + 10] == 0xFF \
                and view[at + 11] == 0xE0 + view[at + 1] - 0xB8:  # movabs r64, va; jmp r64
            target = (struct.unpack_from("<Q", body, at + 2)[0] - base) & 0xFFFFFFFFFFFFFFFF
        else:
            continue
        if _in_host(hosts, target) is not None:
            found.add(target)
        if len(found) > 64:  # random data, not a jump back: testimony this noisy is worth nothing
            return set()
    return found


def stubs(hosts: list[HostCode], x64: bool) -> dict[int, str]:
    """Compiler entry stubs (a call and a jump, both into the same code), at plausible function starts."""
    found: dict[int, str] = {}
    for name, pattern in _STUBS.items():
        if (name == "msvc_x64") != x64:
            continue
        for host in hosts:
            for match in pattern.finditer(host.data):
                rva = host.section.virtual_address + match.start()
                if not _looks_like_start(host, rva):
                    continue
                call_end = rva + (9 if x64 else 5)
                jump_end = rva + match.end() - match.start()
                call = (call_end + struct.unpack("<i", match.group(1))[0]) & 0xFFFFFFFF
                jump = (jump_end + struct.unpack("<i", match.group(2))[0]) & 0xFFFFFFFF
                if host.contains(call) and host.contains(jump):
                    found[rva] = name
                if len(found) > 256:
                    return found
    return found


def function_starts(data: bytes, layout: pe_layout.Layout) -> set[int]:
    """x64 only: every RUNTIME_FUNCTION's BeginAddress from the exception directory."""
    if not layout.pe32_plus:
        return set()
    directories = layout.optional + 112
    if directories + 4 * 8 > layout.table:
        return set()
    rva, size = struct.unpack_from("<II", data, directories + 3 * 8)
    section = layout.section_at_rva(rva)
    if not rva or not size or section is None:
        return set()
    at = section.raw_pointer + rva - section.virtual_address
    table = data[at:at + min(size, len(data) - at)]
    return {struct.unpack_from("<I", table, i)[0] for i in range(0, len(table) - 11, 12)}


def aligned_starts(hosts: list[HostCode]) -> set[int]:
    """Every plausible function start in host code (used only when the checksum can sift them)."""
    found = set()
    for host in hosts:
        for at in range(0, len(host.data), 16):
            rva = host.section.virtual_address + at
            if _looks_like_start(host, rva):
                found.add(rva)
            if len(found) >= MAX_CANDIDATES:
                return found
    return found


class ChecksumSolver:
    """PE checksum of a buffer for any value of one 32-bit field, in O(1) per value.

    The checksum is a ones'-complement sum of 16-bit words plus the length.
    Summing every word except the checksum and the field once leaves the
    field's two halves as the only unknown term.
    """

    def __init__(self, buffer: bytes, checksum_offset: int, field_offset: int):
        if checksum_offset % 2 or field_offset % 2:
            raise ValueError("odd header offsets: no word-aligned shortcut")
        padded = buffer + b"\x00" * (len(buffer) % 2)
        words = np.frombuffer(padded, dtype="<u2").astype(np.uint64)
        skip = [checksum_offset // 2, checksum_offset // 2 + 1, field_offset // 2, field_offset // 2 + 1]
        self.rest = int(words.sum()) - sum(int(words[i]) for i in skip)
        self.length = len(buffer)

    def checksum(self, value: int) -> int:
        total = self.rest + (value & 0xFFFF) + (value >> 16)
        while total >> 16:
            total = (total & 0xFFFF) + (total >> 16)
        return (total + self.length) & 0xFFFFFFFF


def evidence(data: bytes, layout: pe_layout.Layout, added: pe_layout.Section, checksum_usable: bool) -> dict[int, dict[str, float]]:
    """Candidate original entry points, each with the testimony for it (in bits)."""
    hosts = host_code(data, layout, added)
    if not hosts:
        return {}
    body = data[added.raw_pointer:added.raw_pointer + added.raw_size]
    votes: dict[int, dict[str, float]] = defaultdict(dict)
    for rva in exits(body, added.virtual_address, image_base(data, layout), hosts):
        votes[rva]["exit_from_added_code"] = EXIT_BITS
    for rva, name in stubs(hosts, layout.pe32_plus).items():
        votes[rva][f"entry_stub:{name}"] = STUB_BITS[name]
    starts = function_starts(data, layout)
    if checksum_usable:  # only a checksum can sift a pool this large
        for rva in starts or aligned_starts(hosts):
            votes.setdefault(rva, {})
    code_bytes = sum(len(h.data) for h in hosts)
    start_bits = min(10.0, max(0.0, math.log2(code_bytes / len(starts)))) if starts else 0.0
    for rva in list(votes):
        host = _in_host(hosts, rva)
        if host is None:
            del votes[rva]
            continue
        if rva in starts:
            votes[rva]["function_start"] = start_bits
        elif _looks_like_start(host, rva):
            votes[rva]["aligned_start"] = ALIGNED_BITS
        if len(votes) > MAX_CANDIDATES:
            break
    return dict(votes)
