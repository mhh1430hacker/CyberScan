from __future__ import annotations

import math


def clamp(value: float, lower: float = 0.0, upper: float = 100.0) -> float:
    return max(lower, min(upper, value))


def combine_scores(heuristic_score: float, ml_score: float | None, heuristic_weight: float = 1.0, ml_weight: float = 0.0) -> float:
    values = (heuristic_score, heuristic_weight, ml_weight)
    if any(not math.isfinite(value) for value in values):
        raise ValueError("Risk scores and weights must be finite numbers.")
    if heuristic_weight < 0 or ml_weight < 0:
        raise ValueError("Risk weights must be non-negative.")
    if ml_score is None:
        return clamp(heuristic_score)
    if not math.isfinite(ml_score):
        raise ValueError("ML risk score must be finite.")
    total_weight = heuristic_weight + ml_weight
    if total_weight <= 0:
        return clamp(heuristic_score)
    normalized_heuristic = heuristic_weight / total_weight
    normalized_ml = ml_weight / total_weight
    combined = (heuristic_score * normalized_heuristic) + (ml_score * normalized_ml)
    return clamp(round(combined, 2))


def classify_risk(score: float) -> str:
    if score >= 50:
        return "SUSPICIOUS"
    if score > 0:
        return "REVIEW"
    return "NO_INDICATORS_OBSERVED"


def finalize_result(result, heuristic_weight: float = 1.0, ml_weight: float = 0.0):
    """Recompute the canonical score and classification after collecting evidence."""
    base_score = clamp(float(result.heuristic_score))
    evidence_floor = max(
        (clamp(float(item.contribution)) for item in result.evidence),
        default=0.0,
    )
    weighted_score = combine_scores(
        base_score,
        result.ml_risk_score,
        heuristic_weight=heuristic_weight,
        ml_weight=ml_weight,
    )
    result.combined_score = int(round(max(evidence_floor, weighted_score)))
    result.classification = classify_risk(result.combined_score)
    # Only an exact listing (same SHA-256) by a threat-intelligence source makes a file "known malware";
    # rules and heuristics, however strong, stay "suspicious".
    if any(item.category == "intel" and str(item.evidence).startswith("Known malware") for item in result.evidence):
        result.classification = "KNOWN_MALWARE"
    result.summary = (
        f"Static score: {int(base_score)}/100; combined score: "
        f"{result.combined_score}/100; classification: {result.classification}."
    )
    return result
