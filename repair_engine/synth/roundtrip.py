"""Inject, repair with the ground-truth plan, and check the original comes back.

This measures the *executor and validator* only: plans come from the
injection's own ground truth (an oracle), not from a model. A model-driven
measurement replaces ``oracle_plans`` once M2/M3 exist (Phase 5).
"""
from __future__ import annotations

import random
from collections import Counter
from dataclasses import dataclass

from repair_engine import pe_layout
from repair_engine.executor import Plan, apply
from repair_engine.synth.injector import FAMILIES, Injection, inject
from repair_engine.validator import validate


def oracle_plans(injection: Injection, *, with_reference: bool = False) -> list[Plan]:
    family, details = injection.family, injection.details
    if family == "append_after_end":
        return [Plan(injection.action, injection.regions[0][0])]
    if family in {"pe_add_section", "pe_entry_redirect"}:
        layout = pe_layout.read(injection.modified)
        added = max(layout.sections, key=lambda s: s.raw_pointer)
        remove = Plan("remove_section_and_fix_headers", added.raw_pointer)
        if family == "pe_add_section":
            return [remove]
        if not with_reference:
            return [Plan("report_only")]
        return [Plan("restore_entry_point", params={"reference_entry": details["original_entry"]}), remove]
    if family.startswith("ooxml_"):
        return [Plan("remove_zip_member", params={"member": details["member"]})]
    if family.startswith("pdf_"):
        flagged = [n for n in details["objects"] if n != details["catalog"]]
        return [Plan("remove_pdf_object_and_refs", params={"objects": flagged})]
    return [Plan("report_only")]


@dataclass
class Trial:
    family: str
    eligible: bool
    restored: bool = False  # repaired bytes == original
    validated: bool = False
    refused: str | None = None
    report_only: bool = False


def trial(data: bytes, name: str, family: str, seed: int, *, with_reference: bool = True) -> Trial:
    injection = inject(data, name, family, seed)
    if injection is None:
        return Trial(family, False)
    plans = oracle_plans(injection, with_reference=with_reference)
    if all(plan.action == "report_only" for plan in plans):
        return Trial(family, True, report_only=True)
    outcome = apply(injection.modified, plans)
    if outcome.refused or outcome.repaired is None:
        return Trial(family, True, refused=outcome.refused or "no change")
    return Trial(family, True, outcome.repaired == injection.original,
                 validate(injection.modified, outcome.repaired).passed)


def evaluate(corpus: list[tuple[str, bytes]], seeds: int = 3, families: list[str] | None = None) -> dict:
    rng = random.Random(7)
    results: list[Trial] = []
    for name, data in corpus:
        for family in families or list(FAMILIES):
            for _ in range(seeds):
                results.append(trial(data, name, family, rng.randrange(1 << 30)))
    summary: dict[str, dict] = {}
    for family in families or list(FAMILIES):
        mine = [t for t in results if t.family == family and t.eligible]
        repairable = [t for t in mine if not t.report_only]
        summary[family] = {
            "eligible": len(mine),
            "report_only": sum(t.report_only for t in mine),
            "repairable": len(repairable),
            "byte_identical": sum(t.restored for t in repairable),
            "validated": sum(t.validated for t in repairable),
            "refused": dict(Counter(t.refused for t in repairable if t.refused)),
        }
    return summary
