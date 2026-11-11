from __future__ import annotations

from urllib.parse import urlparse

from core import protection
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
    findings = list(heuristic["findings"])
    score = heuristic["score"]
    if enable_heuristics:
        # threat lists (URLhaus, Phishing.Database) and lookalike checks
        extra = protection.check_url(text)
        findings += extra
        score += sum(int(item["contribution"]) for item in extra)
    score = max(0, min(100, score))
    classification = classify_risk(score)
    return {"score": score, "findings": findings, "classification": classification}
