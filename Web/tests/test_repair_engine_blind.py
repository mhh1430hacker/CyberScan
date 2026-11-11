"""Blind repair: the clean original is rebuilt from the infected file alone.

Each test builds a small host in memory, infects it the way real file
infectors do (an added section with the entry point moved into it, an
overlay, a prepended wrapper), hands *only the infected bytes* to the
engine, and checks the result is byte-identical to the host the engine
never saw. The infections carry random filler plus at most one jump back
into the host; nothing here can run or spread, and nothing is written to
disk except by the one test that goes through ``repair_file`` (a PNG).
"""
from __future__ import annotations

import io
import random
import struct
import zipfile

import pytest

from repair_engine import pe_layout
from repair_engine.blind import ACCEPT_BITS, reconstruct
from repair_engine.blind.pe_entry import ChecksumSolver
from repair_engine.blind.witnesses import collect
from repair_engine.executor import Plan, apply
from repair_engine.executor.run import repair_file
from tests.repair_fixtures import build_png

TEXT_RVA, FILE_ALIGN, SECTION_ALIGN = 0x1000, 0x200, 0x1000
FUNCTIONS = (0x10, 0x30, 0x80, 0xA0)  # offsets of the host's (placeholder) functions inside .text
OEP_OFFSET = 0x60


def _function(seed: int) -> bytes:
    rng = random.Random(seed)  # push ebp; mov ebp, esp; <placeholder bytes>; pop ebp; ret
    return b"\x55\x8B\xEC" + bytes(rng.choice(range(0x40, 0x7F)) for _ in range(rng.randint(4, 10))) + b"\x5D\xC3"


def build_host(*, checksum: bool = True, stub: bool = True) -> bytes:
    """A two-section PE32 laid out like linker output, with room for one more section header."""
    text = bytearray(b"\xCC" * 0x400)
    for number, at in enumerate(FUNCTIONS):
        body = _function(number)
        text[at:at + len(body)] = body
    if stub:  # call <f0>; jmp <f1>: the shape of an MSVC x86 entry stub
        call_end, jump_end = TEXT_RVA + OEP_OFFSET + 5, TEXT_RVA + OEP_OFFSET + 10
        text[OEP_OFFSET:OEP_OFFSET + 10] = b"\xE8" + struct.pack("<i", TEXT_RVA + FUNCTIONS[0] - call_end) + \
            b"\xE9" + struct.pack("<i", TEXT_RVA + FUNCTIONS[1] - jump_end)
    else:
        body = b"\x55\x8B\xEC\x6A\x00\x5D\xC3"
        text[OEP_OFFSET:OEP_OFFSET + len(body)] = body
    data_section = (b"PLACEHOLDER-CONTENT " * 30)[:0x200]
    lfanew = 0x80
    dos = bytearray(lfanew)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, lfanew)
    file_header = struct.pack("<HHIIIHH", 0x14C, 2, 0x5F000000, 0, 0, 0xE0, 0x102)
    optional = struct.pack(
        "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
        0x10B, 14, 0, len(text), len(data_section), 0, TEXT_RVA + OEP_OFFSET, TEXT_RVA, 0x2000, 0x400000,
        SECTION_ALIGN, FILE_ALIGN, 6, 0, 0, 0, 6, 0, 0, 0x3000, 0x200, 0, 2, 0, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16,
    )
    table = struct.pack("<8sIIIIIIHHI", b".text", 0x3F0, TEXT_RVA, 0x400, 0x200, 0, 0, 0, 0, 0x60000020)
    table += struct.pack("<8sIIIIIIHHI", b".data", 0x200, 0x2000, 0x200, 0x600, 0, 0, 0, 0, 0xC0000040)
    headers = (bytes(dos) + b"PE\x00\x00" + file_header + optional + bytes(16 * 8) + table).ljust(0x200, b"\x00")
    out = bytearray(headers + bytes(text) + data_section)
    if checksum:
        layout = pe_layout.read(bytes(out))
        pe_layout.put_u32(out, layout.checksum_offset, pe_layout.checksum(bytes(out), layout.checksum_offset))
    return bytes(out)


def infect(host: bytes, rng: random.Random, *, jump_back: bool = True, fix_checksum: bool = False,
           fix_size_of_code: bool = False, body_size: int = 0x300) -> bytes:
    """Append a code section, move the entry point into it, optionally end it with a jmp to the old entry."""
    layout = pe_layout.read(host)
    raw_pointer, raw_size = pe_layout.align(len(host), FILE_ALIGN), pe_layout.align(body_size, FILE_ALIGN)
    va = 0x3000
    body = bytearray(rng.randbytes(body_size))
    body = bytearray(bytes(b if b not in (0xE9, 0x68) else 0x90 for b in body))  # filler only: no accidental jumps
    if jump_back:
        at = body_size - 5
        body[at:at + 5] = b"\xE9" + struct.pack("<i", layout.entry_point - (va + at + 5))
    out = bytearray(host) + bytes(raw_pointer - len(host)) + bytes(body) + bytes(raw_size - body_size)
    header_at = layout.table + 40 * len(layout.sections)
    struct.pack_into("<8sIIIIIIHHI", out, header_at, b".vx", body_size, va, raw_size, raw_pointer, 0, 0, 0, 0, 0x60000020)
    pe_layout.put_u16(out, layout.count_offset, 3)
    pe_layout.put_u32(out, layout.size_of_image_offset, pe_layout.align(va + body_size, SECTION_ALIGN))
    pe_layout.put_u32(out, layout.entry_offset, va + rng.randrange(0, body_size - 16))
    if fix_size_of_code:
        pe_layout.put_u32(out, layout.optional + 4, 0x400 + raw_size)
    if fix_checksum:
        pe_layout.put_u32(out, layout.checksum_offset, pe_layout.checksum(bytes(out), layout.checksum_offset))
    return bytes(out)


# -- entry point recovery ---------------------------------------------------------------------------


@pytest.mark.parametrize("seed", range(6))
def test_entry_point_recovered_from_the_untouched_checksum_alone(seed):
    """No jump back, no compiler stub: only the original checksum knows the entry point, and it is enough."""
    host = build_host(checksum=True, stub=False)
    infected = infect(host, random.Random(seed), jump_back=False)
    result = reconstruct(infected)
    assert result.decision == "repair", result.reason
    assert result.data == host
    assert "pe.checksum" in result.best.restored
    assert result.best.net_bits >= ACCEPT_BITS


@pytest.mark.parametrize("seed", range(6))
def test_entry_point_recovered_from_the_jump_back_and_the_entry_stub(seed):
    """The infector recomputed the checksum and SizeOfCode, so only the code itself testifies."""
    host = build_host(checksum=True, stub=True)
    infected = infect(host, random.Random(seed), jump_back=True, fix_checksum=True, fix_size_of_code=True)
    result = reconstruct(infected)
    assert result.decision == "repair", result.reason
    assert result.data == host
    assert {"exit_from_added_code", "entry_stub:msvc_x86"} <= set(result.best.testimony)


def test_refuses_when_nothing_in_the_file_says_where_the_entry_was():
    host = build_host(checksum=True, stub=False)
    infected = infect(host, random.Random(1), jump_back=False, fix_checksum=True, fix_size_of_code=True)
    result = reconstruct(infected)
    assert result.decision == "refuse"
    assert result.data is None


def test_refuses_on_a_jump_back_alone():
    """One jump into the host is testimony, not proof: 12 bits is below the bar."""
    host = build_host(checksum=False, stub=False)
    infected = infect(host, random.Random(2), jump_back=True, fix_size_of_code=True)
    result = reconstruct(infected)
    assert result.decision == "refuse"
    assert "bits" in result.reason


def test_section_added_without_moving_the_entry_is_undone_exactly():
    host = build_host()
    layout = pe_layout.read(host)
    infected = bytearray(infect(host, random.Random(3), jump_back=False))
    pe_layout.put_u32(infected, layout.entry_offset, layout.entry_point)  # entry left where it was
    result = reconstruct(bytes(infected))
    assert result.decision == "repair", result.reason
    assert result.data == host
    assert result.best.family == "remove_added_section"


def test_checksum_solver_matches_the_full_checksum():
    host = build_host()
    layout = pe_layout.read(host)
    solver = ChecksumSolver(host, layout.checksum_offset, layout.entry_offset)
    for value in (0, 1, 0x1060, 0xFFFF, 0x10000, 0xDEADBEEF):
        buffer = bytearray(host)
        pe_layout.put_u32(buffer, layout.entry_offset, value)
        assert solver.checksum(value) == pe_layout.checksum(bytes(buffer), layout.checksum_offset)


# -- other infection patterns -----------------------------------------------------------------------


def test_prepended_wrapper_is_carved_off_once_the_detector_names_the_front():
    host = build_host()
    wrapper = build_host(checksum=False, stub=False)  # another program in front, carrying the host
    unsure = reconstruct(wrapper + host)  # could as well be an installer and its payload
    assert unsure.decision == "refuse" and "back to back" in unsure.reason
    result = reconstruct(wrapper + host, front_is_infector=True)
    assert result.decision == "repair", result.reason
    assert result.data == host
    assert result.best.family == "carve_embedded"
    assert apply(wrapper + host, [Plan("blind_reconstruct", params={"front_is_infector": True})]).repaired == host


def test_clean_pe_is_left_alone():
    """Every PE ends with a section; without witnesses, removing it would be a guess."""
    for host in (build_host(), build_host(checksum=False, stub=False)):
        assert reconstruct(host).decision == "refuse"


def test_prepended_zip_is_carved_using_its_central_directory_offset():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("a.txt", "PLACEHOLDER-CONTENT " * 50)
        archive.writestr("b.txt", "PLACEHOLDER-CONTENT " * 20)
    host = buffer.getvalue()
    result = reconstruct(random.Random(4).randbytes(3000).replace(b"PK", b"pk") + host)
    assert result.decision == "repair", result.reason
    assert result.data == host
    assert "zip.central_directory_offset" in result.best.restored


def test_appended_data_is_cut_at_the_logical_end():
    png, facts = build_png(trailing=b"\x00" * 7 + bytes(range(200)))
    result = reconstruct(png)
    assert result.decision == "repair", result.reason
    assert result.data == png[:facts["logical_end"]]


def test_clean_file_with_nothing_to_undo_is_refused():
    png, _ = build_png()
    assert reconstruct(png).decision == "refuse"
    assert reconstruct(b"plain text, no structure at all\n" * 10).decision == "refuse"


@pytest.mark.parametrize("seed", range(40))
def test_damaged_input_never_raises(seed):
    rng = random.Random(seed)
    infected = bytearray(infect(build_host(), rng))
    for _ in range(rng.randint(1, 30)):
        infected[rng.randrange(len(infected))] = rng.randrange(256)
    cut = infected[:rng.randrange(1, len(infected))] if seed % 3 == 0 else infected
    result = reconstruct(bytes(cut))
    assert result.decision in {"repair", "refuse"}


def test_witnesses_report_a_broken_checksum():
    host = build_host()
    assert collect(host)["pe.checksum"].holds
    assert not collect(infect(host, random.Random(5)))["pe.checksum"].holds


# -- through the executor and the on-disk runner ----------------------------------------------------


def test_executor_action_and_refusal():
    host = build_host(stub=False)
    outcome = apply(infect(host, random.Random(6), jump_back=False), [Plan("blind_reconstruct")])
    assert outcome.repaired == host
    assert {r.label for r in outcome.removed} == {"section_header", "section_data", "entry_point_value"}
    refused = apply(infect(host, random.Random(6), jump_back=False, fix_checksum=True, fix_size_of_code=True),
                    [Plan("blind_reconstruct")])
    assert refused.repaired is None and refused.refused.startswith("blind reconstruction")


def test_repair_file_validates_and_seals(tmp_path):
    png, facts = build_png(trailing=b"TRAILING" * 40)
    source = tmp_path / "in.png"
    source.write_bytes(png)
    result = repair_file(source, [Plan("blind_reconstruct")], output=tmp_path / "out.png", key=bytes(32), vault=tmp_path / "vault")
    assert result.status == "repaired", result.details
    assert (tmp_path / "out.png").read_bytes() == png[:facts["logical_end"]]
    assert source.read_bytes() == png and result.sealed
