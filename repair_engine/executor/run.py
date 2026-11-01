"""Repair a file on disk with rollback.

The original is never modified. The repaired bytes are validated in memory
first; only if validation passes is the output written (via a temporary file
and an atomic rename) and are the removed regions sealed into the vault.
Any failure leaves the disk exactly as it was and returns the reason.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from repair_engine.executor import Outcome, Plan, apply
from repair_engine.executor.vault import seal
from repair_engine.validator import Scorer, Validation, validate


@dataclass
class RepairResult:
    status: str  # repaired | report_only | quarantine_whole_file | refused | rolled_back
    output: Path | None
    sealed: list[Path]
    outcome: Outcome
    validation: Validation | None
    details: dict[str, Any] = field(default_factory=dict)


def repair_file(source: Path, plans: list[Plan], *, output: Path, key: bytes, vault: Path,
                scorers: tuple[Scorer, ...] = ()) -> RepairResult:
    data = source.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    outcome = apply(data, plans)
    if outcome.quarantine_whole_file:
        return RepairResult("quarantine_whole_file", None, [], outcome, None, {"sha256": digest})
    if outcome.refused:
        return RepairResult("refused", None, [], outcome, None, {"reason": outcome.refused})
    if outcome.repaired is None:
        return RepairResult("report_only", None, [], outcome, None)
    validation = validate(data, outcome.repaired, scorers)
    if not validation.passed:
        return RepairResult("rolled_back", None, [], outcome, validation, {"failures": validation.failures})
    if output.resolve() == source.resolve():
        raise ValueError("the repaired file must not overwrite the original")
    temporary = output.with_name(output.name + ".tmp")
    temporary.write_bytes(outcome.repaired)
    temporary.replace(output)
    sealed = seal(outcome.removed, key, vault, digest)
    return RepairResult("repaired", output, sealed, outcome, validation,
                        {"sha256_before": digest, "sha256_after": hashlib.sha256(outcome.repaired).hexdigest()})
