from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Finding:
    category: str
    severity: str
    evidence: str
    explanation: str
    contribution: int


@dataclass
class ScanResult:
    target: str
    heuristic_score: int
    ml_risk_score: float | None
    combined_score: int
    classification: str
    evidence: list[Finding] = field(default_factory=list)
    feature_summary: dict[str, Any] = field(default_factory=dict)
    model_status: str = "Trained structural classifier not available."
    limitations: str = "Static analysis active; trained structural classifier unavailable."
    summary: str = ""
    yara_matches: list[dict[str, Any]] = field(default_factory=list)
    engine_status: dict[str, str] = field(default_factory=dict)
    nextgen_analysis: dict[str, Any] = field(default_factory=dict)
    pe_analysis: dict[str, Any] = field(default_factory=dict)
    mitre_techniques: list[dict[str, Any]] = field(default_factory=list)
    osint_summary: dict[str, Any] = field(default_factory=dict)
    structural_embedding: tuple[float, ...] | None = field(default=None, repr=False)
    structural_prediction: dict[str, Any] = field(default_factory=dict)

    def as_text(self) -> str:
        lines = [
            "CYBERSCAN REPORT",
            f"Target: {self.target}",
            f"Heuristic Risk: {self.heuristic_score}/100",
            f"ML Structural Risk Score (uncalibrated): {self.ml_risk_score if self.ml_risk_score is not None else 'not available'}",
            f"Structural model class: {'not sure (abstained)' if self.structural_prediction.get('abstained') else self.structural_prediction.get('label', 'not available')}",
            f"Structural class scores (uncalibrated): {self.structural_prediction.get('class_scores', 'not available')}",
            f"Combined Risk: {self.combined_score}/100",
            f"Classification: {self.classification}",
            f"Summary: {self.summary}",
            "",
            "Evidence:",
        ]
        for item in self.evidence:
            lines.append(f"- [{item.severity.upper()}] {item.evidence}: {item.explanation}")
        if self.mitre_techniques:
            lines.append("")
            lines.append("MITRE ATT&CK:")
            for technique in self.mitre_techniques:
                lines.append(f"- {technique.get('id', 'N/A')}: {technique.get('name', 'Unnamed Technique')}")
        lines.extend(["", f"Model status: {self.model_status}", f"Limitations: {self.limitations}"])
        if self.engine_status:
            lines.extend(["", "Analysis engines:"])
            lines.extend(f"- {name}: {status}" for name, status in sorted(self.engine_status.items()))
        return "\n".join(lines)
