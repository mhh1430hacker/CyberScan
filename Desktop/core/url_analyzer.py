from __future__ import annotations

from typing import Any

from core.heuristic_engine import URL_PATTERNS, evaluate_heuristics
from detection.common import classify, noisy_or
from detection.url_intel import analyze_url_intel

# URL-structure rules in the heuristic engine are superseded by detection.url_intel, which
# implements the same checks (with the same labels) plus typosquatting, homographs, brand
# impersonation, obfuscated IPs and redirect chains. Counting both would double-count.
_SUPERSEDED_LABELS = {label for _, _, label, _ in URL_PATTERNS}


def analyze_url(url: str) -> dict[str, Any]:
    """Static, offline URL assessment."""
    text = (url or "").strip()
    if not text:
        return {"score": 0, "findings": [], "classification": "SAFE"}

    intel = analyze_url_intel(text)
    heuristic = evaluate_heuristics(text)
    extra = [item for item in heuristic["findings"] if item["label"] not in _SUPERSEDED_LABELS]
    findings = intel["findings"] + extra
    score = noisy_or(item["contribution"] for item in findings)
    return {
        "score": score,
        "findings": findings,
        "classification": classify(score),
        "url_intel": {key: value for key, value in intel.items() if key not in {"indicators", "findings"}},
    }
