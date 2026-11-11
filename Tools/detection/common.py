"""Shared evidence type, score fusion and resource limits for the detection package."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Iterable

# Resource limits. Every analyzer treats its input as hostile and stays inside these bounds.
MAX_DEEP_SCAN_BYTES = 32 * 1024 * 1024      # bytes of a document/container read for inspection
MAX_ZIP_ENTRIES = 5_000                     # central-directory entries inspected
MAX_ZIP_MEMBER_READ = 2 * 1024 * 1024       # bytes read from any single archive member
MAX_TOTAL_MEMBER_READ = 24 * 1024 * 1024    # bytes read from all archive members together
MAX_PDF_STREAMS = 400                       # PDF streams decompressed
MAX_PDF_INFLATED_PER_STREAM = 2 * 1024 * 1024
MAX_PDF_INFLATED_TOTAL = 16 * 1024 * 1024
MAX_URLS_PER_INPUT = 25                     # links extracted and analyzed per input
MAX_URL_LENGTH = 8192

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Indicator:
    """One piece of evidence. ``contribution`` is 0-100 and is fused, never simply summed."""

    category: str
    severity: str
    label: str
    explanation: str
    contribution: int
    data: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def noisy_or(contributions: Iterable[float]) -> int:
    """Combine independent pieces of evidence: ``1 - prod(1 - c/100)``.

    Several weak indicators corroborate each other, but cannot saturate the score
    the way a plain sum does. A single strong indicator keeps its own weight.
    """
    remaining = 1.0
    for value in contributions:
        bounded = max(0.0, min(100.0, float(value)))
        remaining *= 1.0 - bounded / 100.0
    return int(round(100.0 * (1.0 - remaining)))


# Findings that observe the *same* underlying fact through different engines. They corroborate
# nothing, so only the strongest finding of each group is fused.
CORRELATED_EVIDENCE = {
    "Capability: process injection": "injection-apis",
    "Capability: process hollowing": "injection-apis",
    "SuspiciousProcessInjection": "injection-apis",
    "Encoded PowerShell execution": "encoded-powershell",
    "EncodedPowerShell": "encoded-powershell",
    "Shadow copy deletion": "shadow-copy-deletion",
    "ShadowCopyDeletion": "shadow-copy-deletion",
    "Double extension": "double-extension",
    "Double extension spoofing": "double-extension",
    "Executable extension": "executable-extension",
    "Executable file extension": "executable-extension",
    "High entropy": "packing",
    "Known packer or protector": "packing",
}


def fuse_correlated(items: Iterable[tuple[str, float]]) -> int:
    """noisy-OR over (label, contribution) pairs, keeping only the strongest member of each correlated group."""
    strongest: dict[str, float] = {}
    for label, contribution in items:
        key = CORRELATED_EVIDENCE.get(label, "label:" + label)
        strongest[key] = max(strongest.get(key, 0.0), float(contribution))
    return noisy_or(strongest.values())


def classify(score: int) -> str:
    """Same vocabulary and thresholds as the rest of CyberScan."""
    return "SUSPICIOUS" if score >= 50 else "UNKNOWN" if score > 0 else "SAFE"


def fuse(indicators: Iterable[Indicator], *, exclude_categories: Iterable[str] = ("privacy", "info")) -> dict[str, Any]:
    """Fuse indicators and describe how much independent evidence agrees.

    ``corroboration`` counts distinct categories that contributed at least medium
    severity. It is a statement about evidence agreement, not a probability.
    """
    excluded = set(exclude_categories)
    scoring = [item for item in indicators if item.category not in excluded and item.contribution > 0]
    score = noisy_or(item.contribution for item in scoring)
    strong_categories = sorted({
        item.category for item in scoring if SEVERITY_ORDER.get(item.severity, 0) >= SEVERITY_ORDER["medium"]
    })
    if not scoring:
        agreement = "none"
    elif len(strong_categories) >= 3:
        agreement = "strong"
    elif len(strong_categories) == 2:
        agreement = "moderate"
    else:
        agreement = "single-source"
    return {
        "score": score,
        "classification": classify(score),
        "evidence_agreement": agreement,
        "corroborating_categories": strong_categories,
    }


def heuristic_dicts(indicators: Iterable[Indicator]) -> list[dict[str, Any]]:
    """Render indicators in the dict shape the existing ``core`` code already consumes."""
    return [
        {
            "category": item.category,
            "severity": item.severity,
            "label": item.label,
            "explanation": item.explanation,
            "contribution": item.contribution,
        }
        for item in indicators
    ]


def redact(value: str, keep_start: int = 4, keep_end: int = 2) -> str:
    """Show only enough of a secret to recognise it; never the whole value."""
    if len(value) <= keep_start + keep_end + 2:
        return value[:2] + "…" + f" ({len(value)} chars)"
    return f"{value[:keep_start]}…{value[-keep_end:]} ({len(value)} chars)"
