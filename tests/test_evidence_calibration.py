# Claude (AI assistant, Anthropic) worked on this file, 2026-11-06: new regression tests for the changes above.
"""Regression tests for evasion-resistant text heuristics and benign-calibrated PE evidence.

Every sample is inert: placeholder text carrying indicator fragments, or a
hand-built PE whose few code bytes are a textbook XOR loop over junk. Nothing
is executed.
"""
from __future__ import annotations

import base64
import random
import struct

from core.heuristic_engine import evaluate_heuristics, strings_beyond
from core.nextgen_engine import NextGenCyberEngine
from core.pe_decompiler import analyze_pe_file

FILLER = "Placeholder text of an inert test sample.\r\n" * 8


def _flags(text: str) -> bool:
    return evaluate_heuristics(text, file_name="sample.txt")["score"] > 0


# -- text: tricks that hide an indicator --------------------------------------------------------

def test_utf16_api_chain_survives_decoding():
    hidden = "VirtualAlloc\x00WriteProcessMemory\x00CreateRemoteThread".encode("utf-16-le").decode("latin-1")
    assert _flags(FILLER + hidden + FILLER)


def test_short_base64_command_is_decoded():
    hidden = base64.b64encode(b"wmic shadowcopy delete").decode()  # 32 characters
    assert _flags(FILLER + hidden + FILLER)


def test_spaced_letters_with_two_letter_words_are_collapsed():
    assert _flags(FILLER + " ".join("certutil -urlcache -split -f http://") + FILLER)


def test_tab_separated_letters_are_collapsed():
    assert _flags(FILLER + "\t".join("WMIC.exe SHADOWCOPY DELETE") + FILLER)


def test_big_endian_utf16_keeps_its_last_character():
    hidden = "bcdedit /set {default} recoveryenabled NO".encode("utf-16-be").decode("latin-1")
    assert _flags(FILLER + hidden + FILLER)


def test_stacked_tricks_are_undone_in_layers():
    stacked = " ".join("^".join("vssadmin delete shadows /all"))
    assert _flags(FILLER + stacked + FILLER)


def test_ordinary_prose_raises_nothing():
    prose = "The quick brown fox jumps over the lazy dog. I am a b c d e reader.\n" * 50
    assert evaluate_heuristics(prose, file_name="notes.txt")["score"] == 0


# -- text: the whole file, not just its head ----------------------------------------------------

def test_indicator_after_zero_padding_is_found_in_tail_strings():
    data = bytes(3 * 1024 * 1024) + b"cmd.exe /c vssadmin delete shadows /all /quiet" + bytes(1024)
    tail, info = strings_beyond(data, 200_000)
    assert "vssadmin delete shadows" in tail
    assert info["truncated"] is False


def test_repeated_filler_text_cannot_push_the_indicator_out():
    data = b"lorem ipsum dolor sit amet " * 200_000 + b"schtasks /create /sc minute /tn upd"
    tail, info = strings_beyond(data, 0, budget=200_000)
    assert "schtasks /create" in tail
    assert info["characters"] < 200_000


def test_distinct_junk_beyond_the_budget_is_reported_truncated():
    rng = random.Random(3)
    junk = b"\x00".join(bytes(rng.choice(b"abcdefghij") for _ in range(40)) for _ in range(5000))
    _tail, info = strings_beyond(junk, 0, budget=10_000)
    assert info["truncated"] is True


# -- text: credential-in-URL marker -------------------------------------------------------------

def test_credentials_in_url_still_flagged():
    assert _flags("visit http://admin:secret@login.example.com/path now")


def test_binary_between_url_and_at_sign_is_not_a_credential():
    blob = "WXXX\x00\x00\x00http://example.com" + "\x01\x9f\xff" * 20 + "@\x00\x07"
    findings = evaluate_heuristics(blob, file_name="song.mp3")["findings"]
    assert not any("credential" in f["label"].lower() for f in findings)


# -- PE: evidence patterns ----------------------------------------------------------------------

# mov ecx,0x100 / mov esi,0x401000 / loop: xor byte [esi],0x5a / inc esi / dec ecx / jnz loop / ret
XOR_DECODER = bytes.fromhex("b900010000" "be00104000" "80365a" "46" "49" "75f9" "c3")
# The same loop shape, XOR between registers only (as in hashing): not an in-place decoder.
REGISTER_XOR = bytes.fromhex("b900010000" "be00104000" "31d0" "46" "49" "75fa" "c3")


def _pe(code: bytes, text_characteristics: int, data_section: bytes = b"", clr: bool = False) -> bytes:
    lfanew, align = 0x80, 0x200
    sections = [(b".text", text_characteristics), (b".data", 0xC0000040)]
    dos = bytearray(lfanew)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, lfanew)
    file_header = struct.pack("<HHIIIHH", 0x14C, len(sections), 0, 0, 0, 0xE0, 0x102)
    optional = struct.pack(
        "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
        0x10B, 14, 0, align, align, 0, 0x1000, 0x1000, 0x2000, 0x400000, 0x1000, align,
        6, 0, 0, 0, 6, 0, 0, 0x3000, 0x200, 0, 2, 0, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16,
    )
    directories = bytearray(16 * 8)
    if clr:
        struct.pack_into("<II", directories, 14 * 8, 0x2000, 0x48)
    table = b""
    for number, (name, characteristics) in enumerate(sections):
        table += struct.pack("<8sIIIIIIHHI", name, align, 0x1000 * (number + 1), align,
                             0x200 + align * number, 0, 0, 0, 0, characteristics)
    headers = (bytes(dos) + b"PE\x00\x00" + file_header + optional + bytes(directories) + table).ljust(0x200, b"\x00")
    text = code.ljust(align, b"\xcc")
    data = data_section.ljust(align, b"\x00")[:align]
    return headers + text + data


def _evidence(data: bytes) -> list[str]:
    result = analyze_pe_file("sample.exe", data=data)
    assert result["status"] == "ok"
    return result["cfg_topology"]["evidence_patterns"]


def test_decoder_loop_in_self_modifying_section_is_evidence():
    assert _evidence(_pe(XOR_DECODER, 0xE0000020)) == ["INPLACE_XOR_DECODER_LOOP"]


def test_decoder_loop_with_encrypted_body_is_evidence():
    body = random.Random(1).randbytes(0x200)
    assert _evidence(_pe(XOR_DECODER, 0x60000020, data_section=body)) == ["INPLACE_XOR_DECODER_LOOP"]


def test_decoder_loop_without_anywhere_to_decrypt_into_is_not_evidence():
    assert _evidence(_pe(XOR_DECODER, 0x60000020)) == []


def test_register_only_xor_loop_is_not_evidence():
    assert _evidence(_pe(REGISTER_XOR, 0xE0000020)) == []


def test_zeroing_xor_and_int3_padding_are_not_evidence():
    code = bytes.fromhex("31c0" "31db") + b"\xcc" * 64 + bytes(64)  # xor eax,eax; xor ebx,ebx; padding
    topology = NextGenCyberEngine.extract_cfg_topology(code, "x86-32")
    assert topology["evidence_patterns"] == []


def test_dotnet_assembly_is_not_disassembled_as_x86():
    result = analyze_pe_file("managed.dll", data=_pe(XOR_DECODER, 0xE0000020, clr=True))
    assert result["is_managed"] is True
    assert result["cfg_topology"]["status"] == "managed_code"
    assert result["cfg_topology"]["evidence_patterns"] == []


def test_architecture_comes_from_the_header():
    result = analyze_pe_file("sample.exe", data=_pe(XOR_DECODER, 0xE0000020))
    assert result["cfg_topology"]["architecture"] == "x86-32"
