"""Phase 3b + executor + validator: inert injection with exact ground truth,
byte-identical repair, refusals instead of guesses, rollback, sealed regions."""
from __future__ import annotations

import io
import random
import struct
import zipfile
import zlib

import pytest

from repair_engine import pe_layout
from repair_engine.executor import Plan, apply
from repair_engine.executor.run import repair_file
from repair_engine.parsers import parse
from repair_engine.synth.content import PLACEHOLDER, inert, is_inert
from repair_engine.synth.injector import FAMILIES, inject
from repair_engine.synth.roundtrip import evaluate, oracle_plans
from repair_engine.validator import validate
from repair_fixtures import build_elf, build_gif, build_jpeg, build_pe, build_png, build_zip


def simple_pdf() -> bytes:
    parts, offsets = [b"%PDF-1.4\n"], {}
    for number, body in ((1, b"<< /Type /Catalog /Pages 2 0 R >>"), (2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>"),
                         (3, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>")):
        offsets[number] = sum(map(len, parts))
        parts.append(b"%d 0 obj\n" % number + body + b"\nendobj\n")
    xref = sum(map(len, parts))
    parts.append(b"xref\n0 4\n0000000000 65535 f\r\n" + b"".join(b"%010d 00000 n\r\n" % offsets[n] for n in (1, 2, 3)))
    parts.append(b"trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % xref)
    return b"".join(parts)


def plain_docx() -> bytes:
    data, _ = build_zip(members={"[Content_Types].xml": b"<Types/>", "word/document.xml": b"<w:document>" + PLACEHOLDER * 40 + b"</w:document>",
                                 "word/styles.xml": b"<w:styles/>", "docProps/core.xml": b"<cp/>"})
    return data


def checksummed_pe() -> bytes:
    data = bytearray(build_pe()[0])
    layout = pe_layout.read(bytes(data))
    pe_layout.put_u32(data, layout.checksum_offset, pe_layout.checksum(bytes(data), layout.checksum_offset))
    return bytes(data)


CORPUS = [
    ("tool.exe", build_pe()[0]), ("signed-checksum.exe", checksummed_pe()), ("lib.so", build_elf()[0]),
    ("report.docx", plain_docx()), ("archive.zip", build_zip()[0]), ("paper.pdf", simple_pdf()),
    ("photo.png", build_png()[0]), ("photo.jpg", build_jpeg()[0]), ("anim.gif", build_gif()[0]),
    ("notes.txt", b"Meeting notes, line after line.\n" * 200),
]


# --- content stays inert ---------------------------------------------------------------------


def test_content_generator_only_makes_the_three_inert_kinds():
    rng = random.Random(1)
    for kind in ("random", "zeros", "placeholder"):
        assert is_inert(inert(kind, 1000, rng), kind)
    with pytest.raises(ValueError):
        inert("shellcode", 10, rng)
    assert not is_inert(b"MZ\x90\x00", "placeholder") and not is_inert(b"\x01", "zeros")


@pytest.mark.parametrize("seed", range(6))
def test_injected_bytes_are_inert(seed):
    for name, data in CORPUS:
        for family in ("append_after_end", "pe_add_section", "ooxml_vba_part", "pdf_javascript"):
            injection = inject(data, name, family, seed)
            if injection is None:
                continue
            if family == "append_after_end":
                start, end, _ = injection.regions[0]
                assert is_inert(injection.modified[start:end], injection.content_kind)
            elif family == "pe_add_section":
                (start, end, _), = [r for r in injection.regions if r[2] == "section_data"]
                assert is_inert(injection.modified[start:end].strip(b"\x00"), injection.content_kind) or injection.content_kind == "random"
            elif family == "ooxml_vba_part":
                with zipfile.ZipFile(io.BytesIO(injection.modified)) as archive:
                    assert is_inert(archive.read(injection.details["member"]), injection.content_kind)
            else:
                script = injection.modified[len(data):].split(b"/JS (// ", 1)[1].split(b")", 1)[0]
                assert is_inert(script, "placeholder")


# --- exact ground truth ----------------------------------------------------------------------------


@pytest.mark.parametrize("family", list(FAMILIES))
def test_regions_are_exact_and_everything_else_is_untouched(family):
    seen = 0
    for name, data in CORPUS:
        for seed in range(4):
            injection = inject(data, name, family, seed)
            if injection is None:
                continue
            seen += 1
            modified = injection.modified
            for start, end, _label in injection.regions:
                assert 0 <= start < end <= len(modified)
            if family in {"append_after_end", "pdf_javascript", "pdf_embedded_file"}:
                (start, end, _), = injection.regions
                assert modified[:start] == data and end == len(modified)
            if family == "high_entropy_block":
                (start, end, _), = injection.regions
                assert modified[:start] + modified[end:] == data
            if family in {"pe_add_section", "pe_entry_redirect"}:
                mask = bytearray(len(modified))
                for start, end, _ in injection.regions:
                    mask[start:end] = b"\x01" * (end - start)
                assert all(modified[i] == data[i] for i in range(len(data)) if not mask[i])
            assert parse(modified, injection.name).format == parse(data).format
    assert seen, f"{family} found no eligible file in the corpus"


# --- byte-identical repair ------------------------------------------------------------------------------


def test_oracle_repair_restores_every_repairable_family_byte_for_byte():
    summary = evaluate(CORPUS, seeds=4)
    for family, row in summary.items():
        assert row["eligible"] > 0, family
        assert row["byte_identical"] == row["repairable"], (family, row)
        assert row["validated"] == row["repairable"], (family, row)
        assert not row["refused"], (family, row)


def test_entry_point_redirect_without_reference_is_report_only():
    injection = inject(build_pe()[0], "tool.exe", "pe_entry_redirect", 3)
    assert injection.action == "report_only"
    assert [p.action for p in oracle_plans(injection)] == ["report_only"]
    # Removing the section alone is refused: the entry point still points into it.
    layout = pe_layout.read(injection.modified)
    added = max(layout.sections, key=lambda s: s.raw_pointer)
    assert apply(injection.modified, [Plan("remove_section_and_fix_headers", added.raw_pointer)]).refused


# --- refusals instead of guesses ---------------------------------------------------------------------------


def test_executor_refuses_what_it_cannot_do_exactly():
    pe = build_pe(overlay=b"\x00" * 64, certificate=b"\x01" * 64)[0]
    layout = pe_layout.read(pe)
    assert "certificate" in apply(pe, [Plan("strip_overlay", layout.certificate[0])]).refused
    assert apply(pe, [Plan("strip_overlay", 0x300)]).refused  # inside the image
    assert apply(plain_docx(), [Plan("remove_zip_member", params={"member": "nope.bin"})]).refused
    assert apply(simple_pdf(), [Plan("remove_pdf_object_and_refs", params={"objects": [3]})]).refused  # no earlier revision
    assert apply(build_png(trailing=b"x" * 10)[0], [Plan("truncate_after_eof", 5)]).refused  # not the logical end
    assert apply(b"x", [Plan("remove_ole_stream")]).refused


def test_pdf_update_with_other_edits_is_not_rolled_back():
    injection = inject(simple_pdf(), "paper.pdf", "pdf_javascript", 2)
    flagged = [n for n in injection.details["objects"] if n != injection.details["catalog"]]
    # Add an unrelated object to the same update: the rollback would lose a real edit.
    cut = injection.modified.rindex(b"xref")
    extra = injection.modified[:cut] + b"9 0 obj\n<< /Producer (editor) >>\nendobj\n" + injection.modified[cut:]
    assert apply(extra, [Plan("remove_pdf_object_and_refs", params={"objects": flagged})]).refused
    # A catalog that also changed in another way is refused too.
    relabelled = injection.modified[:len(simple_pdf())] + injection.modified[len(simple_pdf()):].replace(
        b"/Type /Catalog", b"/Type /Catalog /Lang (en)", 1)
    assert apply(relabelled, [Plan("remove_pdf_object_and_refs", params={"objects": flagged})]).refused


# --- validator --------------------------------------------------------------------------------------------------


def test_validator_catches_broken_structure():
    pe = checksummed_pe()
    broken = bytearray(pe)
    broken[0x210] ^= 0xFF  # change a byte: the stored checksum no longer matches
    assert validate(pe, bytes(broken)).checks["structure"] == "checksum does not match"
    docx = plain_docx()
    damaged = bytearray(docx)
    at = docx.index(b"PLACEHOLDER") if b"PLACEHOLDER" in docx else 40
    damaged[at] ^= 0x55
    assert not validate(docx, bytes(damaged)).passed
    result = validate(pe, pe)
    assert result.passed and not result.clean_confirmed  # no trained scorer yet
    assert validate(pe, pe, scorers=(lambda b: ("m1", 0.1, 0.5),)).clean_confirmed
    assert not validate(pe, pe, scorers=(lambda b: ("m1", 0.9, 0.5),)).clean_confirmed


# --- on disk: original untouched, rollback, sealed regions ---------------------------------------------------------


def test_repair_file_keeps_the_original_and_seals_what_it_removed(tmp_path):
    # PNG, not PE: a local antivirus blocks reading back even the clean minimal PE fixture once it is on disk.
    from core.scanner import restore_quarantined_file

    injection = inject(build_png()[0], "photo.png", "append_after_end", 5)
    source = tmp_path / "tool.sample"
    source.write_bytes(injection.modified)
    key = bytes(range(32))
    result = repair_file(source, oracle_plans(injection), output=tmp_path / "tool.repaired.sample", key=key, vault=tmp_path / "vault")
    assert result.status == "repaired"
    assert source.read_bytes() == injection.modified  # untouched
    assert result.output.read_bytes() == injection.original
    (sealed,) = result.sealed
    assert injection.modified[len(injection.original):] not in sealed.read_bytes()  # encrypted
    restored = restore_quarantined_file(sealed, tmp_path / "region.bin", key)
    assert restored.read_bytes() == injection.modified[len(injection.original):]


def test_failed_validation_rolls_back_and_writes_nothing(tmp_path, monkeypatch):
    import repair_engine.executor.run as run
    from repair_engine.validator import Validation

    injection = inject(build_png()[0], "photo.png", "append_after_end", 5)
    source = tmp_path / "tool.sample"
    source.write_bytes(injection.modified)
    monkeypatch.setattr(run, "validate", lambda *a, **k: Validation(False, False, {"structure": "broken"}))
    result = repair_file(source, oracle_plans(injection), output=tmp_path / "out.sample", key=bytes(32), vault=tmp_path / "vault")
    assert result.status == "rolled_back"
    assert not (tmp_path / "out.sample").exists() and not (tmp_path / "vault").exists()
    assert source.read_bytes() == injection.modified


def test_quarantine_whole_file_is_returned_not_edited():
    outcome = apply(b"MZ" + bytes(100), [Plan("quarantine_whole_file")])
    assert outcome.quarantine_whole_file and outcome.repaired is None
