"""Phase 2: every format yields exact, in-bounds regions, and nothing breaks the parser."""
from __future__ import annotations

import random
import re
from pathlib import Path

import pytest

from repair_engine import parse
from repair_engine.regions import RegionMap
from repair_fixtures import (
    build_elf, build_gif, build_jpeg, build_ole, build_ooxml, build_pdf, build_pe, build_png, build_zip,
)

TRAIL = b"APPENDED-PLACEHOLDER" * 4


def spans(regions: RegionMap, kind: str) -> list[tuple[int, int]]:
    return [(r.start, r.end) for r in regions.of_kind(kind)]


# --- PE ---------------------------------------------------------------------------


def test_pe_sections_entry_point_overlay_and_certificate():
    data, facts = build_pe(overlay=TRAIL, certificate=b"\x00" * 64)
    regions = parse(data, "tool.exe")
    assert regions.format == "pe" and not regions.errors
    assert spans(regions, "pe_section") == facts["sections"]
    assert [r.metadata["executable"] for r in regions.of_kind("pe_section")] == [True, False]
    (entry,) = regions.of_kind("pe_entry_point")
    assert entry.start == facts["entry_point"] and regions.regions[entry.parent].metadata["name"] == ".text"
    assert spans(regions, "pe_overlay") == [facts["overlay"]]  # the certificate is not overlay
    assert spans(regions, "pe_certificate") == [facts["certificate"]]
    assert spans(regions, "pe_dos_header") == [(0, 64)] and spans(regions, "pe_dos_stub") == [(64, 0x80)]
    assert not regions.of_kind("magic_mismatch")


def test_pe_without_overlay_has_none():
    data, _facts = build_pe()
    assert parse(data).of_kind("pe_overlay") == []


def test_unparseable_pe_is_reported_not_patched():
    data = b"MZ" + bytes(10)
    regions = parse(data)
    assert regions.format == "pe" and regions.errors
    assert [r.kind for r in regions.regions] == ["file"]


# --- ELF ------------------------------------------------------------------------------


def test_elf_sections_entry_point_and_overlay():
    data, facts = build_elf(overlay=TRAIL)
    regions = parse(data)
    assert regions.format == "elf" and not regions.errors
    (text,) = [r for r in regions.of_kind("elf_section") if r.metadata["name"] == ".text"]
    assert (text.start, text.end) == facts["text"] and text.metadata["executable"]
    assert regions.of_kind("elf_entry_point")[0].start == facts["entry_point"]
    assert spans(regions, "elf_overlay") == [facts["overlay"]]


# --- ZIP / OOXML ----------------------------------------------------------------------------


def test_zip_members_prefix_and_data_after_end():
    data, facts = build_zip(prefix=b"STUB" * 32, trailing=TRAIL)
    regions = parse(data, "archive.zip")
    assert regions.format == "zip" and not regions.errors
    assert spans(regions, "zip_prefix") == [(0, facts["prefix"])]
    assert spans(regions, "after_eof") == [(facts["logical_end"], len(data))]
    members = regions.of_kind("zip_member")
    assert {m.metadata["name"] for m in members} == {"readme.txt", "data/notes.txt"}
    assert all(data[m.start:m.start + 4] == b"PK\x03\x04" for m in members)


def test_zip_with_more_than_64k_appended_is_still_mapped():
    data, facts = build_zip(trailing=bytes(200_000))
    regions = parse(data, "archive.zip")
    assert regions.format == "zip" and not regions.errors
    assert spans(regions, "after_eof") == [(facts["logical_end"], len(data))]


def test_ooxml_roles_and_external_links():
    data, _facts = build_ooxml()
    regions = parse(data, "report.docx")
    assert regions.format == "ooxml" and not regions.of_kind("magic_mismatch")
    roles = {m.metadata["name"]: m.metadata["role"] for m in regions.of_kind("zip_member")}
    assert roles["word/vbaProject.bin"] == "vba_project"
    assert roles["word/embeddings/oleObject1.bin"] == "embedded_object"
    (link,) = regions.of_kind("ooxml_external_link")
    assert link.metadata["targets"] == ["https://example.invalid/template.dotm"]


# --- OLE ----------------------------------------------------------------------------------------


def test_ole_fragmented_macro_stream_maps_to_exact_extents():
    data, facts = build_ole(trailing=TRAIL)
    regions = parse(data, "letter.doc")
    assert regions.format == "ole" and not regions.errors, regions.errors
    module = [r for r in regions.of_kind("ole_stream") if r.metadata["path"] == "Macros/VBA/Module1"]
    assert [(r.start, r.end) for r in module] == facts["module_extents"]
    assert all(r.metadata["role"] == "vba" for r in module)
    assert b"".join(data[r.start:r.end] for r in module) == facts["module"]
    (compobj,) = [r for r in regions.of_kind("ole_stream") if r.metadata["path"] == "\x01CompObj"]
    assert (compobj.start, compobj.end) == facts["compobj_extent"]
    assert data[compobj.start:compobj.end] == facts["compobj"]
    assert spans(regions, "after_eof") == [(facts["logical_end"], len(data))]


# --- PDF ------------------------------------------------------------------------------------------


def test_pdf_objects_active_entries_streams_and_after_eof():
    data, facts = build_pdf(trailing=TRAIL)
    regions = parse(data, "invoice.pdf")
    objects = {r.metadata["number"]: r for r in regions.of_kind("pdf_object")}
    assert sorted(objects) == [1, 2, 3, 4, 5]  # "7 0 obj" inside stream 3 is not an object
    assert {n: r.start for n, r in objects.items()} == facts["objects"]
    assert "auto_action" in objects[1].metadata["flags"]
    assert "javascript" in objects[4].metadata["flags"]  # /J#61vaScript
    (raw,) = [s for s in regions.of_kind("pdf_stream") if s.metadata["number"] == 3]
    assert data[raw.start:raw.end] == facts["tricky"]
    (flate,) = [s for s in regions.of_kind("pdf_stream") if s.metadata["number"] == 5]
    assert "javascript" in flate.metadata["decoded_flags"]
    assert spans(regions, "after_eof") == [(facts["logical_end"], len(data))]
    assert regions.of_kind("pdf_xref_trailer")


def test_pdf_indirect_length_falls_back_to_endstream():
    data = (b"%PDF-1.7\n1 0 obj\n<< /Length 12 0 R >>\nstream\nPLACEHOLDER\nendstream\nendobj\n"
            b"12 0 obj\n11\nendobj\n%%EOF\n")
    (stream,) = parse(data).of_kind("pdf_stream")
    assert data[stream.start:stream.end] == b"PLACEHOLDER"


def test_pdf_trailing_newlines_are_not_after_eof():
    data, _facts = build_pdf(trailing=b"\r\n\n")
    assert parse(data).of_kind("after_eof") == []


# --- images --------------------------------------------------------------------------------------------


@pytest.mark.parametrize("builder, fmt", [(build_png, "png"), (build_jpeg, "jpeg"), (build_gif, "gif")])
def test_images_find_their_logical_end(builder, fmt):
    data, facts = builder(trailing=TRAIL)
    regions = parse(data)
    assert regions.format == fmt and not regions.errors, regions.errors
    assert spans(regions, "after_eof") == [(facts["logical_end"], len(data))]
    clean, _ = builder()
    assert parse(clean).of_kind("after_eof") == []


# --- dispatch and snapping ------------------------------------------------------------------------------


def test_extension_magic_mismatch_is_a_region():
    data, _facts = build_pe()
    (mismatch,) = parse(data, "invoice.pdf").of_kind("magic_mismatch")
    assert (mismatch.start, mismatch.end) == (0, 16)
    assert mismatch.metadata == {"extension": ".pdf", "detected": "pe", "expected": ["pdf"]}


def test_snap_moves_a_fuzzy_span_onto_structure():
    data, facts = build_pe(overlay=TRAIL)
    regions = parse(data)
    start, end = facts["overlay"]
    assert regions.snap(start + 7, end - 5) == (start, end)
    assert regions.snap(start - 3, start + 2)[0] == start


# --- robustness ------------------------------------------------------------------------------------------

BUILDERS = [build_pe, build_elf, build_zip, build_ooxml, build_ole, build_pdf, build_png, build_jpeg, build_gif]


@pytest.mark.parametrize("builder", BUILDERS, ids=lambda b: b.__name__)
def test_truncated_and_corrupted_input_never_raises_or_escapes_bounds(builder):
    data, _facts = builder()
    rng = random.Random(1234)
    variants = [data[:cut] for cut in sorted({rng.randrange(len(data)) for _ in range(25)} | {0, 1, 7})]
    for _ in range(25):
        broken = bytearray(data)
        for _ in range(8):
            broken[rng.randrange(len(broken))] = rng.randrange(256)
        variants.append(bytes(broken))
    for variant in variants:
        regions = parse(variant)
        for region in regions.regions:
            assert 0 <= region.start < region.end <= len(variant) or (region.kind == "file" and len(variant) == 0)


def test_engine_code_cannot_run_or_load_anything():
    forbidden = re.compile(r"\b(subprocess|os\.system|os\.popen|ctypes|pickle|joblib|marshal|importlib|runpy)\b|\b(exec|eval)\(")
    root = Path(__file__).resolve().parents[1] / "repair_engine"
    hits = [f"{path.name}:{n}" for path in root.rglob("*.py")
            for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1) if forbidden.search(line)]
    assert hits == []


def test_damaged_office_packages_are_refused_never_raised():
    """Found by fuzzing: a damaged member made the analyzer raise instead of refusing."""
    import io
    import random
    import zipfile

    from repair_engine.analyze import analyze

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as package:
        package.writestr("[Content_Types].xml", "<Types/>")
        package.writestr("word/document.xml", "<w:document>" + "text " * 2000 + "</w:document>")
        package.writestr("word/vbaProject.bin", bytes(range(256)) * 40)
    base = buffer.getvalue()
    rng = random.Random(5)
    for round_ in range(200):
        data = bytearray(base)
        if round_ % 2:
            data[:64] = bytes(64)
        else:
            cut = rng.randrange(len(data))
            data = data[:cut] + base[rng.randrange(len(base)):]
        analyze(bytes(data), "report.docx")  # must not raise
