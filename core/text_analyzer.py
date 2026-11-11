from __future__ import annotations

import re

from core import protection
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
    findings = list(heuristic["findings"])
    score = heuristic["score"]
    if enable_heuristics:
        extra = protection.find_secrets(text)   # API keys, tokens, private keys (gitleaks rules)
        labels = {item["label"] for item in extra}
        for link in dict.fromkeys(_LINK.findall(text[:500_000])).keys():
            for item in protection.check_url(link.rstrip(".,;:)]}'\"")):
                if item["label"] not in labels:
                    labels.add(item["label"])
                    extra.append(item)
            if len(labels) >= 12:
                break
        findings += extra
        score += sum(int(item["contribution"]) for item in extra)
    score = max(0, min(100, score))
    classification = classify_risk(score)
    return {"score": score, "classification": classification, "findings": findings, "summary": findings and findings[0]["label"] or "No suspicious text patterns matched."}


_LINK = re.compile(r"https?://[^\s<>\"']{4,2000}", re.IGNORECASE)
