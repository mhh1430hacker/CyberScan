"""Presentation model for a completed scan.

Turns an engine ``ScanResult`` into the plain values the results screen draws.
This module never changes detection logic or risk scoring: every value here is
read from the result, and every interpretation is one of the named rules below.

Interpretation rules
--------------------
* Verdict comes from ``ScanResult.classification`` as produced by the engine:
  ``SUSPICIOUS`` -> high risk, ``REVIEW`` -> needs review,
  ``NO_INDICATORS_OBSERVED`` -> low risk (never "safe").
* Inconclusive: no indicators were observed but an engine that can contribute
  evidence failed or only partly ran, or the classification is not one the
  interface knows. The structural model is excluded because its score does
  not feed the risk index by default.
* Risk index: ``combined_score`` is shown only when it is a finite number in
  0..100. It is a heuristic index, not a probability.
* Engine coverage is classified from the ``engine_status`` text with the
  keyword rules in ``classify_engine_status``.
* MITRE entries with the id ``N/A`` are the mapper's "nothing mapped"
  placeholder and are not counted as techniques.
"""
from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

KNOWN_CLASSIFICATIONS = {"SUSPICIOUS", "REVIEW", "NO_INDICATORS_OBSERVED"}


@dataclass(frozen=True)
class Verdict:
    key: str
    title: str
    detail: str
    tone: str
    symbol: str


VERDICTS = {
    "high": Verdict(
        "high",
        "High risk",
        "Strong static indicators were observed. Review the evidence before opening or sharing this target.",
        "danger",
        "▲",
    ),
    "review": Verdict(
        "review",
        "Needs review",
        "Weak or isolated indicators were observed. Review the evidence before trusting this target.",
        "warn",
        "◆",
    ),
    "low": Verdict(
        "low",
        "Low risk",
        "No indicators were observed by the engines that ran. This does not prove the target is safe.",
        "ok",
        "●",
    ),
    "inconclusive": Verdict(
        "inconclusive",
        "Inconclusive",
        "No indicators were observed, but part of the analysis did not complete, so this result cannot be relied on.",
        "neutral",
        "?",
    ),
    "unrecognized": Verdict(
        "inconclusive",
        "Inconclusive",
        "The engine returned a result this interface does not recognise. Review the technical details.",
        "neutral",
        "?",
    ),
}

SEVERITY_RANK = {"high": 3, "medium": 2, "low": 1, "info": 0, "unknown": -1}
SEVERITY_ALIASES = {
    "critical": "high",
    "high": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "info": "info",
    "informational": "info",
}
SEVERITY_LABELS = {
    "high": ("▲", "High"),
    "medium": ("◆", "Medium"),
    "low": ("●", "Low"),
    "info": ("○", "Info"),
    "unknown": ("?", "Unknown"),
}
SEVERITY_TONES = {"high": "danger", "medium": "warn", "low": "info", "info": "neutral", "unknown": "neutral"}

CATEGORY_LABELS = {
    "structural": "File structure",
    "statistical": "Entropy and statistics",
    "heuristic": "Heuristic rules",
    "text": "Text indicators",
    "url": "URL indicators",
    "pe": "Executable (PE)",
    "yara": "Signature rules (YARA)",
    "archive": "Archive",
    "test_marker": "Test marker",
    "osint": "Threat intelligence",
    "dissonance": "Claim-capability dissonance",
    "model": "Learning model",
}

ENGINE_LABELS = {
    "YARA": "Signature rules (YARA)",
    "PE": "Executable structure (PE)",
    "ML": "Structural model",
    "Archive": "Archive inspection",
    "OSINT": "Threat intelligence",
    "Heuristics": "Heuristic rules",
    "Dissonance": "Claim-capability dissonance",
    "Surprise map": "Compression surprise map",
}

COVERAGE_LABELS = {
    "ran": ("✓", "Ran"),
    "not_applicable": ("–", "Not applicable"),
    "disabled": ("○", "Off"),
    "unavailable": ("!", "Unavailable"),
    "partial": ("◐", "Partial"),
    "failed": ("✕", "Failed"),
    "unknown": ("?", "Unknown"),
}
COVERAGE_TONES = {
    "ran": "ok",
    "not_applicable": "neutral",
    "disabled": "neutral",
    "unavailable": "warn",
    "partial": "warn",
    "failed": "danger",
    "unknown": "neutral",
}

# Engines whose failure leaves a "no indicators" result unreliable.
_EVIDENCE_ENGINES_EXCLUDED = {"ML"}


@dataclass(frozen=True)
class FindingView:
    severity: str
    category: str
    title: str
    explanation: str
    contribution: int


@dataclass(frozen=True)
class CategoryCount:
    category: str
    count: int
    top_severity: str


@dataclass(frozen=True)
class EngineCoverage:
    name: str
    state: str
    status: str


@dataclass(frozen=True)
class ResultView:
    verdict: Verdict
    classification: str
    score: int | None
    target: str
    display_name: str
    findings: tuple[FindingView, ...]
    categories: tuple[CategoryCount, ...]
    coverage: tuple[EngineCoverage, ...]
    highest_severity: str | None
    mitre_count: int
    yara_count: int
    file_size: int | None
    sha256: str | None
    input_profile: str | None
    mean_entropy: float | None
    pe_status: str | None
    limitations: str
    model_status: str
    extra: Mapping[str, Any] = field(default_factory=dict)

    @property
    def engines_ran(self) -> int:
        return sum(1 for engine in self.coverage if engine.state == "ran")


def normalize_severity(value: Any) -> str:
    return SEVERITY_ALIASES.get(str(value or "").strip().lower(), "unknown")


def classify_engine_status(status: Any) -> str:
    """Map an engine_status string to a coverage state (see module rules)."""
    text = str(status or "").strip().lower()
    if not text:
        return "unknown"
    if any(word in text for word in ("error", "failed", "timed out")):
        return "failed"
    if "partial" in text or "timeout" in text:
        return "partial"
    if text.startswith(("disabled", "not requested")) or "disabled by settings" in text:
        return "disabled"
    if text in {"not_pe", "not applicable", "not_applicable", "invalid_indicator"} or text.startswith("not a "):
        return "not_applicable"
    if any(
        word in text
        for word in ("unavailable", "missing", "no rules configured", "rejected", "not available", "not loaded", "unsupported", "not_run")
    ):
        return "unavailable"
    if text.startswith(
        ("available", "ok", "enabled", "matched", "no_match", "success", "complete", "bounded structure inspection", "4096-d supervised")
    ):
        return "ran"
    return "unknown"


def _finite_number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    return number if math.isfinite(number) else None


def _score(value: Any) -> int | None:
    number = _finite_number(value)
    if number is None or not 0 <= number <= 100:
        return None
    return int(round(number))


def _findings(evidence: Any) -> tuple[FindingView, ...]:
    views = []
    for item in evidence or ():
        contribution = _finite_number(getattr(item, "contribution", None))
        views.append(
            FindingView(
                severity=normalize_severity(getattr(item, "severity", "")),
                category=str(getattr(item, "category", "") or "other"),
                title=str(getattr(item, "evidence", "") or ""),
                explanation=str(getattr(item, "explanation", "") or ""),
                contribution=int(contribution) if contribution is not None else 0,
            )
        )
    views.sort(key=lambda view: (-view.contribution, -SEVERITY_RANK[view.severity], view.title))
    return tuple(views)


def _categories(findings: tuple[FindingView, ...]) -> tuple[CategoryCount, ...]:
    counts = Counter(view.category for view in findings)
    top: dict[str, str] = {}
    for view in findings:
        current = top.get(view.category)
        if current is None or SEVERITY_RANK[view.severity] > SEVERITY_RANK[current]:
            top[view.category] = view.severity
    ordered = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    return tuple(CategoryCount(category, count, top[category]) for category, count in ordered)


def _coverage(engine_status: Any) -> tuple[EngineCoverage, ...]:
    if not isinstance(engine_status, Mapping):
        return ()
    return tuple(
        EngineCoverage(str(name), classify_engine_status(status), str(status))
        for name, status in engine_status.items()
    )


def _verdict(classification: str, coverage: tuple[EngineCoverage, ...]) -> Verdict:
    if classification == "SUSPICIOUS":
        return VERDICTS["high"]
    if classification == "REVIEW":
        return VERDICTS["review"]
    if classification == "NO_INDICATORS_OBSERVED":
        incomplete = any(
            engine.state in {"failed", "partial"}
            for engine in coverage
            if engine.name not in _EVIDENCE_ENGINES_EXCLUDED
        )
        return VERDICTS["inconclusive"] if incomplete else VERDICTS["low"]
    return VERDICTS["unrecognized"]


def build_result_view(result: Any, nextgen: Mapping[str, Any] | None = None) -> ResultView:
    """Build the presentation model from a ScanResult and optional nextgen data."""
    classification = str(getattr(result, "classification", "") or "")
    coverage = _coverage(getattr(result, "engine_status", None))
    findings = _findings(getattr(result, "evidence", None))
    features = getattr(result, "feature_summary", None)
    features = features if isinstance(features, Mapping) else {}
    nextgen = nextgen if isinstance(nextgen, Mapping) else {}
    entropy = nextgen.get("entropy_topography")
    entropy = entropy if isinstance(entropy, Mapping) else {}
    pe = getattr(result, "pe_analysis", None)
    pe = pe if isinstance(pe, Mapping) else {}

    mitre = getattr(result, "mitre_techniques", None) or []
    mitre_count = sum(
        1
        for item in mitre
        if isinstance(item, Mapping) and str(item.get("id", "")).strip() not in {"", "N/A"}
    )
    target = str(getattr(result, "target", "") or "")
    size = _finite_number(features.get("file_size"))
    sha256 = features.get("sha256")
    highest = max((view.severity for view in findings), key=lambda s: SEVERITY_RANK[s], default=None)

    return ResultView(
        verdict=_verdict(classification, coverage),
        classification=classification,
        score=_score(getattr(result, "combined_score", None)),
        target=target,
        display_name=(Path(target).name or target) if features else target,
        findings=findings,
        categories=_categories(findings),
        coverage=coverage,
        highest_severity=highest,
        mitre_count=mitre_count,
        yara_count=len(getattr(result, "yara_matches", None) or []),
        file_size=int(size) if size is not None and size >= 0 else None,
        sha256=sha256 if isinstance(sha256, str) and sha256 else None,
        input_profile=str(nextgen["input_profile"]) if nextgen.get("input_profile") else None,
        mean_entropy=_finite_number(entropy.get("mean_entropy")),
        pe_status=str(pe["status"]) if pe.get("status") else None,
        limitations=str(getattr(result, "limitations", "") or ""),
        model_status=str(getattr(result, "model_status", "") or ""),
    )
