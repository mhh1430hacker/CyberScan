"""Counterfactual self-audit: what is the verdict actually resting on?

For a file the model calls ``suspicious`` or ``malware``, blank out one region
at a time (in memory only; nothing is written or run), re-embed and re-ask the
model. The smallest region whose removal turns the verdict into ``clean`` is
what the verdict rests on:

* ``incidental``: a part the Windows loader ignores (overlay, Rich header,
  timestamp). The verdict is reading clothing; an attacker can flip it for
  free. A training run up-weights such samples (``ml.training.train``).
* ``substantive``: code, data or resources: something the program uses.
* ``distributed``: no single region flips it; the evidence is spread across
  the file, the most robust case.

Each tried region also reports how far it moved the score of the original
label, which doubles as a coarse attribution map.
"""
from __future__ import annotations

import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass

import numpy as np

from ml.pe_layout import parse_layout

INCIDENTAL_KINDS = frozenset({"overlay", "rich_header", "timestamp"})
CLEAN = "clean"


@dataclass(frozen=True)
class Ablation:
    name: str
    kind: str
    start: int
    end: int

    @property
    def size(self) -> int:
        return self.end - self.start


def ablations(data: bytes) -> list[Ablation]:
    """Regions to blank out, smallest first."""
    layout = parse_layout(data)
    regions: list[Ablation] = []
    if layout is not None:
        if layout.overlay_start is not None:
            regions.append(Ablation("overlay", "overlay", layout.overlay_start, len(data)))
        if layout.rich_header is not None:
            regions.append(Ablation("Rich header", "rich_header", *layout.rich_header))
        regions.append(Ablation("link timestamp", "timestamp", layout.timestamp_offset, layout.timestamp_offset + 4))
        for section in layout.sections:
            regions.append(Ablation(section.name or "?", section.kind, section.raw_start, section.raw_end))
    elif len(data) >= 4:
        quarter = len(data) // 4
        for index in range(4):
            end = len(data) if index == 3 else (index + 1) * quarter
            regions.append(Ablation(f"quarter {index + 1}", "content", index * quarter, end))
    return sorted(regions, key=lambda region: (region.size, region.start))


def _blank(data: bytes, region: Ablation) -> bytes:
    if region.kind == "overlay":
        return data[:region.start]
    return data[:region.start] + bytes(region.size) + data[region.end:]


def audit(
    data: bytes,
    predict: Callable[[np.ndarray], tuple[list[str], np.ndarray]],
    embed: Callable[[bytes], Sequence[float]],
    classes: Sequence[str],
    *,
    max_regions: int = 8,
    deadline: float | None = None,
) -> dict[str, object]:
    """Find the smallest region whose removal clears the verdict.

    ``predict`` maps a batch of embeddings to (labels, class scores in
    ``classes`` order). ``deadline`` is a ``time.monotonic()`` value after which
    no further regions are tried.
    """
    labels, scores = predict(np.asarray([embed(data)], dtype=np.float32))
    label = labels[0]
    if label == CLEAN:
        return {"status": "not_needed", "label": label}
    column = list(classes).index(label)
    baseline = float(scores[0][column])
    tried: list[dict[str, object]] = []
    flip: dict[str, object] | None = None
    for region in ablations(data)[:max_regions]:
        if deadline is not None and time.monotonic() > deadline:
            break
        new_labels, new_scores = predict(np.asarray([embed(_blank(data, region))], dtype=np.float32))
        record = {
            "region": region.name,
            "kind": region.kind,
            "offset_start": region.start,
            "offset_end": region.end,
            "bytes": region.size,
            "label_after": new_labels[0],
            "score_drop": round(baseline - float(new_scores[0][column]), 4),
        }
        tried.append(record)
        if flip is None and new_labels[0] == CLEAN:
            flip = record
            break  # regions are tried smallest first: this is the minimal one
    if flip is None:
        basis = "distributed" if tried else "unknown"
    else:
        basis = "incidental" if flip["kind"] in INCIDENTAL_KINDS else "substantive"
    return {
        "status": "audited",
        "label": label,
        "baseline_score": round(baseline, 4),
        "verdict_basis": basis,
        "flip": flip,
        "regions_tried": tried,
    }


def incidental_indices(
    samples: Sequence[bytes],
    labels: Sequence[str],
    predict: Callable[[np.ndarray], tuple[list[str], np.ndarray]],
    embed: Callable[[bytes], Sequence[float]],
    classes: Sequence[str],
) -> list[int]:
    """Indices of non-clean samples whose verdict rests on an incidental region."""
    found = []
    for index, (data, label) in enumerate(zip(samples, labels)):
        if label == CLEAN:
            continue
        result = audit(data, predict, embed, classes)
        if result.get("verdict_basis") == "incidental":
            found.append(index)
    return found
