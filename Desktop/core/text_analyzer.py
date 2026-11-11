from __future__ import annotations

from core.hashing import is_valid_md5, is_valid_sha1, is_valid_sha256
from core.heuristic_engine import URL_PATTERNS, evaluate_heuristics
from detection.common import classify, noisy_or
from detection.messages import analyze_message
from detection.script_rules import scan_command_text
from detection.secrets import scan_secrets

_SUPERSEDED_LABELS = {label for _, _, label, _ in URL_PATTERNS}


def analyze_text_target(value: str) -> dict[str, object]:
    text = (value or "").strip()
    if not text:
        return {"score": 0, "classification": "SAFE", "findings": [], "summary": "No input provided."}

    if is_valid_md5(text) or is_valid_sha1(text) or is_valid_sha256(text):
        return {
            "score": 0,
            "classification": "SAFE",
            "findings": [],
            "summary": "A valid hash format was detected and no heuristic indicators were triggered.",
        }

    heuristic = evaluate_heuristics(text)
    message = analyze_message(text)
    has_links = bool(message["links"])
    # When the text contains links, URL-structure rules are covered (once) by the message link analysis.
    findings = [item for item in heuristic["findings"] if not (has_links and item["label"] in _SUPERSEDED_LABELS)]
    findings += message["findings"]
    findings += [{**item, "category": "tradecraft"} for item in scan_command_text(text)]

    score = noisy_or(item["contribution"] for item in findings)
    classification = classify(score)
    privacy = scan_secrets(text)
    strongest = max(findings, key=lambda item: item["contribution"], default=None)
    summary = strongest["label"] if strongest else "No suspicious text patterns matched."
    if privacy["count"]:
        summary += f" Privacy exposure: {privacy['exposure_level']} ({privacy['count']} secret(s), redacted)."
    return {
        "score": score,
        "classification": classification,
        "findings": findings,
        "summary": summary,
        "evidence_agreement": message["evidence_agreement"] if message["findings"] else ("single-source" if findings else "none"),
        "links": message["links"],
        "email_headers": message["email_headers"],
        "privacy": {key: value for key, value in privacy.items() if key != "indicators"},
    }
