"""Is a repaired file still a sound file of its kind?

Three groups of checks:
  parse      the repaired bytes parse as the same format, with no parse
             error the input did not already have;
  structure  format-specific integrity (PE header arithmetic and checksum,
             every ZIP member's CRC, the PDF's final cross-reference, ...);
  scores     optional scorers (M1/M2 once trained) must call it clean.

``passed`` covers parse + structure. ``clean_confirmed`` additionally needs
every scorer to pass; with no scorer available it is False, and callers
must not auto-repair on structure alone.
"""
from __future__ import annotations

import io
import re
import zipfile
from dataclasses import dataclass, field
from typing import Callable

import pefile

from repair_engine import pe_layout
from repair_engine.parsers import parse

Scorer = Callable[[bytes], tuple[str, float, float]]  # -> (name, score, threshold); clean when score < threshold
_STARTXREF = re.compile(rb"startxref\s+(\d+)\s+%%EOF\s*$")


@dataclass
class Validation:
    passed: bool
    clean_confirmed: bool
    checks: dict[str, str] = field(default_factory=dict)

    @property
    def failures(self) -> dict[str, str]:
        return {name: result for name, result in self.checks.items() if not result.startswith("ok")}


def _pe(data: bytes) -> str:
    try:
        layout = pe_layout.read(data)
        pefile.PE(data=data, fast_load=True).close()
    except Exception as exc:  # noqa: BLE001
        return f"unreadable PE: {exc}"
    for section in layout.sections:
        if section.raw_size and section.raw_pointer + section.raw_size > len(data):
            return f"section {section.name!r} runs past the end of the file"
    if layout.entry_point and layout.section_at_rva(layout.entry_point) is None:
        return "entry point in no section"
    image = max((s.virtual_address + max(s.virtual_size, s.raw_size) for s in layout.sections), default=layout.size_of_headers)
    if layout.size_of_image != pe_layout.align(image, layout.section_alignment):
        return "SizeOfImage does not match the sections"
    if layout.checksum and layout.checksum != pe_layout.checksum(data, layout.checksum_offset):
        return "checksum does not match"
    return "ok"


def _zip(data: bytes) -> str:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            broken = archive.testzip()
    except Exception as exc:  # noqa: BLE001
        return f"unreadable zip: {exc}"
    return "ok" if broken is None else f"member {broken!r} fails its CRC"


def _pdf(data: bytes) -> str:
    match = _STARTXREF.search(data[-2048:])
    if match is None:
        return "no final startxref/%%EOF"
    offset = int(match.group(1))
    head = data[offset:offset + 64].lstrip()
    if not (head.startswith(b"xref") or re.match(rb"\d+\s+\d+\s+obj", head)):
        return "startxref does not point at cross-reference data"
    return "ok"


_STRUCTURE = {"pe": _pe, "zip": _zip, "ooxml": _zip, "pdf": _pdf}


def validate(infected: bytes, repaired: bytes, scorers: tuple[Scorer, ...] = (), *,
             allow_format_change: bool = False) -> Validation:
    """``allow_format_change``: a host carved from behind a prepender may be another format than its wrapper."""
    before, after = parse(infected), parse(repaired)
    checks: dict[str, str] = {}
    changed = after.format != before.format
    new_errors = after.errors if changed else [e for e in after.errors if e not in before.errors]
    same_format = not changed or (allow_format_change and after.format != "unknown")
    checks["parse"] = "ok" if same_format and not new_errors else \
        f"format {before.format}->{after.format}, new errors {new_errors[:3]}"
    structure = _STRUCTURE.get(after.format)
    checks["structure"] = structure(repaired) if structure else "ok (no format-specific checks)"
    leftovers = after.of_kind("after_eof")
    if leftovers:  # reported, not failed: some clean files legitimately carry trailing data
        checks["trailing_data"] = f"ok (note: {leftovers[0].size} bytes after the logical end remain)"
    passed = all(result.startswith("ok") for result in checks.values())
    clean = passed and bool(scorers)
    for scorer in scorers:
        name, score, threshold = scorer(repaired)
        checks[f"score:{name}"] = f"ok ({score:.3f} < {threshold:.3f})" if score < threshold else f"{score:.3f} >= {threshold:.3f}"
        clean = clean and score < threshold
    if not scorers:
        checks["scores"] = "ok (no trained scorer yet: structure only, auto-repair not allowed)"
    return Validation(passed, clean, checks)
