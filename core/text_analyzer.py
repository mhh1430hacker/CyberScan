from __future__ import annotations

from core.heuristic_engine import evaluate_heuristics
from core.hashing import is_valid_md5, is_valid_sha1, is_valid_sha256
from core.risk_engine import classify_risk


def analyze_text_target(value: str, *, enable_heuristics: bool = True) -> dict[str, object]:
    text = (value or "").strip()
    if not text:
        return {"score": 0, "classification": "NO_INDICATORS_OBSERVED", "findings": [], "summary": "No input provided."}

    if is_valid_md5(text) or is_valid_sha1(text) or is_valid_sha256(text):
        return {"score": 0, "classification": "NO_INDICATORS_OBSERVED", "findings": [], "summary": "A valid hash format was detected and no heuristic indicators were triggered."}

    heuristic = evaluate_heuristics(text) if enable_heuristics else {"score": 0, "findings": []}
    score = heuristic["score"]
    classification = classify_risk(score)
    return {"score": score, "classification": classification, "findings": heuristic["findings"], "summary": heuristic["findings"] and heuristic["findings"][0]["label"] or "No suspicious text patterns matched."}
