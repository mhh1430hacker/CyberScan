"""Deterministic repair: each action edits bytes in exactly one documented way.

``apply(data, plans)`` runs a list of ``Plan``s in order and returns the
repaired bytes plus every byte range it removed. Each action checks its own
preconditions first and *refuses* (``Refused``) instead of guessing:
nothing here infers a value it cannot read from the file or from a trusted
reference passed in by the caller.

Actions (the planner's fixed set, plus ``remove_zip_member`` for OOXML):
  strip_overlay, truncate_after_eof, remove_section_and_fix_headers,
  restore_entry_point, remove_zip_member, remove_pdf_object_and_refs,
  quarantine_whole_file, report_only.
``remove_ole_stream`` is part of the set but not implemented yet; it
refuses, so the outcome falls back to a report.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from repair_engine.executor import pdf, pe, zip as zip_actions
from repair_engine.executor.common import Refused, Removed, truncate_at
from repair_engine.parsers import parse

ACTIONS = (
    "strip_overlay", "truncate_after_eof", "remove_section_and_fix_headers", "restore_entry_point",
    "remove_zip_member", "remove_ole_stream", "remove_pdf_object_and_refs", "quarantine_whole_file", "report_only",
)


@dataclass
class Plan:
    action: str
    start: int | None = None  # the located region, already snapped to structure
    end: int | None = None
    params: dict[str, Any] = field(default_factory=dict)


@dataclass
class Outcome:
    repaired: bytes | None  # None: nothing changed (report only) or the whole file goes to quarantine
    removed: list[Removed]
    steps: list[dict[str, Any]]
    quarantine_whole_file: bool = False
    refused: str | None = None


def _truncate_after_eof(data: bytes, plan: Plan) -> tuple[bytes, list[Removed]]:
    regions = parse(data)
    candidates = [r.start for r in regions.of_kind("after_eof")]
    if regions.format == "pdf":
        candidates += [r.end for r in regions.of_kind("pdf_eof_marker")]
    if plan.start is None or plan.start not in candidates:
        raise Refused(f"{plan.start} is not a logical end of this {regions.format} file")
    return truncate_at(data, plan.start, "after_eof")


def _single(data: bytes, plan: Plan) -> tuple[bytes, list[Removed]]:
    if plan.action == "strip_overlay":
        return pe.strip_overlay(data, plan.start) if data[:2] == b"MZ" else _strip_elf_overlay(data, plan.start)
    if plan.action == "truncate_after_eof":
        return _truncate_after_eof(data, plan)
    if plan.action == "remove_section_and_fix_headers":
        return pe.remove_section(data, plan.start)
    if plan.action == "restore_entry_point":
        return pe.restore_entry_point(data, plan.params.get("reference_entry"))
    if plan.action == "remove_zip_member":
        return zip_actions.remove_member(data, plan.params.get("member"), plan.start)
    if plan.action == "remove_pdf_object_and_refs":
        return pdf.remove_last_update(data, plan.params.get("objects") or [])
    if plan.action == "remove_ole_stream":
        raise Refused("remove_ole_stream is not implemented yet")
    raise Refused(f"unknown action {plan.action!r}")


def _strip_elf_overlay(data: bytes, start: int | None) -> tuple[bytes, list[Removed]]:
    overlay = parse(data).of_kind("elf_overlay")
    if not overlay or start is None or start < overlay[0].start:
        raise Refused("start is not inside the ELF overlay")
    return truncate_at(data, start, "elf_overlay")


def apply(data: bytes, plans: list[Plan]) -> Outcome:
    if any(plan.action not in ACTIONS for plan in plans):
        raise ValueError("unknown action in plan")
    if any(plan.action == "quarantine_whole_file" for plan in plans):
        return Outcome(None, [Removed(0, len(data), "whole_file", data)], [{"action": "quarantine_whole_file"}], True)
    current, removed, steps = data, [], []
    for plan in plans:
        if plan.action == "report_only":
            steps.append({"action": "report_only"})
            continue
        try:
            current, cut = _single(current, plan)
        except Refused as reason:
            return Outcome(None, [], steps + [{"action": plan.action, "refused": str(reason)}], refused=str(reason))
        removed += cut
        steps.append({"action": plan.action, "removed": [(r.start, r.end, r.label) for r in cut]})
    changed = current != data
    return Outcome(current if changed else None, removed, steps)
