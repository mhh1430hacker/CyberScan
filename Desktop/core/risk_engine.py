from __future__ import annotations


def clamp(value: float, lower: float = 0.0, upper: float = 100.0) -> float:
    return max(lower, min(upper, value))


def combine_scores(heuristic_score: float, ml_score: float | None, heuristic_weight: float = 0.7, ml_weight: float = 0.3) -> float:
    if ml_score is None:
        return clamp(heuristic_score)
    total_weight = heuristic_weight + ml_weight
    if total_weight <= 0:
        return clamp(heuristic_score)
    normalized_heuristic = heuristic_weight / total_weight
    normalized_ml = ml_weight / total_weight
    combined = (heuristic_score * normalized_heuristic) + (ml_score * normalized_ml)
    return clamp(round(combined, 2))
