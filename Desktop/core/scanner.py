from __future__ import annotations

import re
from typing import Any

from core.file_analyzer import analyze_file
from core.mitre_mapper import map_findings_to_mitre
from core.models import Finding, ScanResult
from core.text_analyzer import analyze_text_target
from core.url_analyzer import analyze_url


def _findings_from_heuristics(items: list[dict[str, Any]]) -> list[Finding]:
    return [
        Finding(
            str(item.get("category", "heuristic")),
            str(item.get("severity", "low")),
            str(item.get("label", "")),
            str(item.get("explanation") or item.get("label", "")),
            int(item.get("contribution", 0)),
        )
        for item in items
    ]


def _static_result(target: str, data: dict[str, Any], summary: str) -> ScanResult:
    findings = _findings_from_heuristics(data.get("findings", []))
    return ScanResult(
        target=target,
        heuristic_score=int(data["score"]),
        ml_anomaly_score=None,
        combined_score=int(data["score"]),
        classification=str(data["classification"]),
        evidence=findings,
        feature_summary={},
        model_status="ML model not applicable to text/URL targets.",
        limitations="Static analysis active; ML applies to files only.",
        summary=summary,
        mitre_techniques=map_findings_to_mitre(findings=[item.evidence for item in findings]),
        content_analysis={
            key: data[key] for key in ("url_intel", "links", "email_headers", "privacy", "evidence_agreement") if data.get(key)
        },
    )


# A single token that is clearly a URL even without http(s):// (www., script/data schemes, domain + path).
_URL_TOKEN = re.compile(
    r"^(?:(?:https?|hxxps?|ftp|javascript|vbscript|data|file):|www\.|(?:[a-z0-9-]+\.)+[a-z]{2,24}/)", re.IGNORECASE
)


def _is_url_target(target: str) -> bool:
    stripped = target.strip()
    return bool(stripped) and not re.search(r"\s", stripped) and bool(_URL_TOKEN.match(stripped))


def scan_target(target: str, is_file: bool = False, settings: dict | None = None) -> ScanResult:
    if is_file:
        return analyze_file(target, settings=settings)
    if _is_url_target(target):
        data = analyze_url(target)
        return _static_result(target, data, f"URL checked with static heuristics; classification: {data['classification']}.")
    data = analyze_text_target(target)
    return _static_result(target, data, str(data["summary"]))
