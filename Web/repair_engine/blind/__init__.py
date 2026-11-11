"""Blind repair: rebuild an infected file's original without a clean copy.

The idea (witness-constrained reconstruction):

1. *Hypotheses.* Run every known way of infecting a file backwards
   (``hypotheses``). Each gives one or more candidate originals; whatever
   the file cannot state (the old entry point, where the host starts) stays
   an explicit set of alternatives.
2. *Witnesses.* A file's producer wrote integrity facts into it: checksums,
   CRCs, signed digests, size fields, offset tables (``witnesses``). They
   were computed over the clean file, so they act as a hash of an original
   nobody has. A candidate earns the bits of every witness the infection
   broke and the candidate restores, plus any other testimony (the added
   code's jump back into the host, a compiler entry stub). It loses the
   bits of every witness that held before and that it breaks.
3. *Decision.* ``net = earned - broken - log2(alternatives)``. A candidate
   that rests on an inferred value must reach ``ACCEPT_BITS`` (a wrong
   reconstruction passing is then about 1 in 65 536 or rarer), and the
   best must beat every different candidate by ``MARGIN_BITS``. A pure undo
   with nothing inferred (cutting appended data) only has to break nothing.
   Anything else is a refusal with the reason, never a guess.

``reconstruct`` only reads bytes and returns bytes; the executor's
``blind_reconstruct`` action and ``run.repair_file`` handle validation, the
vault and the disk.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any

from repair_engine.blind import hypotheses
from repair_engine.blind.hypotheses import Candidate
from repair_engine.blind.witnesses import Witness, collect

ACCEPT_BITS = 16.0
MARGIN_BITS = 8.0

__all__ = ["ACCEPT_BITS", "MARGIN_BITS", "BlindResult", "Candidate", "reconstruct"]


@dataclass
class BlindResult:
    decision: str  # repair | refuse
    best: Candidate | None
    reason: str
    ranking: list[dict[str, Any]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def data(self) -> bytes | None:
        return self.best.data if self.best is not None and self.decision == "repair" else None


SHAPE_CAP_BITS = 12.0  # stub, function start, alignment: one source (the host's code layout), however many hints
CRYPTOGRAPHIC_BITS = 128.0  # a restored witness this strong (a signed digest) is enough on its own


def sources(candidate: Candidate) -> set[str]:
    """The independent sources backing a candidate's inferred value.

    Code shape alone was seen to pick the wrong function on real binaries
    (another function shaped like an entry stub), so one source is never
    enough for an inferred value.
    """
    found = set()
    if candidate.discriminating is not None and any(k.startswith(candidate.discriminating) for k in candidate.restored):
        found.add("integrity")
    if "exit_from_added_code" in candidate.testimony:
        found.add("infector_code")
    if any(k.startswith(("entry_stub", "function_start", "aligned_start")) for k in candidate.testimony):
        found.add("host_shape")
    return found


def _independent_enough(candidate: Candidate) -> bool:
    if candidate.discriminating is None:
        return True
    if any(bits >= CRYPTOGRAPHIC_BITS for k, bits in candidate.restored.items() if k.startswith(candidate.discriminating)):
        return True
    return len(sources(candidate)) >= 2


def _score(candidate: Candidate, infected: dict[str, Witness]) -> None:
    after = collect(candidate.data)
    if candidate.fresh_file:
        candidate.restored = {k: w.bits for k, w in after.items() if w.holds}
        candidate.broken = {}
    else:
        candidate.restored = {k: w.bits for k, w in after.items() if w.holds and not (k in infected and infected[k].holds)}
        candidate.broken = {k: w.bits for k, w in infected.items()
                            if w.holds and not w.restorable and k in after and not after[k].holds}
    shape = sum(b for k, b in candidate.testimony.items() if k.startswith(("entry_stub", "function_start", "aligned_start")))
    other = sum(b for k, b in candidate.testimony.items() if not k.startswith(("entry_stub", "function_start", "aligned_start")))
    earned = sum(candidate.restored.values()) + other + min(shape, SHAPE_CAP_BITS)
    candidate.net_bits = earned - sum(candidate.broken.values()) - math.log2(max(1, candidate.alternatives))


def _summary(candidate: Candidate) -> dict[str, Any]:
    return {"family": candidate.family, "net_bits": round(candidate.net_bits, 2), "restored": candidate.restored,
            "testimony": candidate.testimony, "broken": candidate.broken, "alternatives": candidate.alternatives,
            "size": len(candidate.data), "detail": candidate.detail}


def _split_files(candidates: list[Candidate], front_is_infector: bool, notes: list[str]) -> list[Candidate]:
    """Two complete files back to back: a prepender and its host, or an installer and its payload.

    The bytes cannot say which half is the infection, so neither half wins
    on witnesses alone; the caller (the detector that localised the front
    part) has to say so with ``front_is_infector``.
    """
    ends = {c.detail.get("logical_end") for c in candidates if c.family == "truncate_to_logical_end"}
    split = [c for c in candidates if c.family == "carve_embedded" and c.detail["offset"] in ends]
    if not split:
        return candidates
    offsets = {s.detail["offset"] for s in split}
    keeps_front = [c for c in candidates if c.family == "truncate_to_logical_end" and c.detail["logical_end"] in offsets]
    if front_is_infector:
        return [c for c in candidates if c not in keeps_front]
    notes.append(f"two complete files back to back at offset {split[0].detail['offset']}: "
                 "which one is the infection is for the detector to say (front_is_infector)")
    return [c for c in candidates if c not in split and c not in keeps_front]  # keeping either half would be a guess


def reconstruct(data: bytes, *, front_is_infector: bool = False) -> BlindResult:
    data = bytes(data)
    infected = collect(data)
    notes: list[str] = []
    candidates = hypotheses.truncations(data, infected) + hypotheses.carves(data) + hypotheses.added_section(data, infected, notes)
    candidates = [c for c in candidates if c.data != data and c.data]
    candidates = _split_files(candidates, front_is_infector, notes)
    for candidate in candidates:
        _score(candidate, infected)
    candidates.sort(key=lambda c: -c.net_bits)
    ranking = [_summary(c) for c in candidates[:8]]
    if not candidates:
        return BlindResult("refuse", None, notes[0] if notes else "no infection pattern can be undone on this file", ranking, notes)

    def eligible(c: Candidate) -> bool:
        return not c.broken and c.net_bits >= (ACCEPT_BITS if c.free else 0.0) and _independent_enough(c)

    best = next((c for c in candidates if eligible(c)), None)
    if best is None:
        top = candidates[0]
        if top.broken:
            why = f"breaks {sorted(top.broken)}"
        elif not _independent_enough(top):
            why = f"rests on one source of evidence only ({', '.join(sorted(sources(top))) or 'none'}); needs two"
        else:
            why = f"only {top.net_bits:.1f} bits of evidence (needs {ACCEPT_BITS:.0f})"
        return BlindResult("refuse", None, f"best reconstruction ({top.family}) {why}", ranking, notes)
    rival = next((c for c in candidates if c is not best and c.data != best.data), None)
    if rival is not None and best.net_bits - rival.net_bits < MARGIN_BITS:
        return BlindResult("refuse", None, f"ambiguous: {best.family} ({best.net_bits:.1f} bits) vs {rival.family} "
                           f"({rival.net_bits:.1f} bits), needs a {MARGIN_BITS:.0f}-bit margin", ranking, notes)
    return BlindResult("repair", best, f"{best.family}: {best.net_bits:.1f} bits of evidence", ranking, notes)
