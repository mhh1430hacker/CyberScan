from __future__ import annotations

from urllib.parse import urlparse

from core.heuristic_engine import evaluate_heuristics
from core.risk_engine import classify_risk


def analyze_url(url: str, *, enable_heuristics: bool = True) -> dict[str, object]:
    text = (url or "").strip()
    if not text:
        return {"score": 0, "findings": [], "classification": "NO_INDICATORS_OBSERVED"}

    parsed = urlparse(text)
    heuristic = (
        evaluate_heuristics(text)
        if enable_heuristics and parsed.scheme in {"http", "https"} and parsed.hostname
        else {"score": 0, "findings": []}
    )
    score = heuristic["score"]
    score = max(0, min(100, score))
    classification = classify_risk(score)
    return {"score": score, "findings": heuristic["findings"], "classification": classification}
