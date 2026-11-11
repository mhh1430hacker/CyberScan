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
    ml_anomaly_score: float | None
    combined_score: int
    classification: str
    evidence: list[Finding] = field(default_factory=list)
    feature_summary: dict[str, Any] = field(default_factory=dict)
    model_status: str = "ML model not available."
    limitations: str = "Static analysis active; ML unavailable."
    summary: str = ""
    yara_matches: list[dict[str, Any]] = field(default_factory=list)
    pe_analysis: dict[str, Any] = field(default_factory=dict)
    mitre_techniques: list[dict[str, Any]] = field(default_factory=list)
    sha256: str | None = None
    integrity_report: dict[str, Any] | None = None
    # Content inspection (detection.engine): detected type, per-format details, evidence agreement,
    # and a separate privacy section whose secret values are already redacted.
    content_analysis: dict[str, Any] = field(default_factory=dict)

    def as_text(self) -> str:
        lines = [
            "CYBERSCAN REPORT",
            f"Target: {self.target}",
            *([f"SHA-256: {self.sha256}"] if self.sha256 else []),
            f"Heuristic Risk: {self.heuristic_score}/100",
            f"ML Anomaly: {self.ml_anomaly_score if self.ml_anomaly_score is not None else 'not available'}",
            f"Combined Risk: {self.combined_score}/100",
            f"Classification: {self.classification}",
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
        content = self.content_analysis or {}
        if content.get("file_type"):
            lines.extend(["", f"Detected content type: {content['file_type']}",
                          f"Evidence agreement: {content.get('evidence_agreement', 'none')}"
                          + (f" ({', '.join(content['corroborating_categories'])})" if content.get("corroborating_categories") else "")])
        privacy = content.get("privacy") or {}
        if privacy.get("count"):
            lines.extend(["", f"Privacy exposure: {privacy['exposure_level']} ({privacy['count']} item(s); values redacted)"])
            for item in privacy.get("findings", [])[:20]:
                lines.append(f"- [{item['severity'].upper()}] {item['label']} at line {item['line']}: {item['redacted']}")
        lines.extend(["", f"Model status: {self.model_status}", f"Limitations: {self.limitations}"])
        if self.integrity_report is not None:
            integrity = self.integrity_report
            lines.extend([
                "",
                "File integrity verification:",
                f"- Status: {integrity['status']}",
                f"- Format: {integrity['format']}",
                f"- Verification SHA-256: {integrity['sha256'] or 'not calculated'}",
            ])
            for check in integrity["checks"]:
                lines.append(f"- [{check['status'].upper()}] {check['name']}: {check['detail']}")
            for limitation in integrity["limitations"]:
                lines.append(f"- Limitation: {limitation}")
        return "\n".join(lines)
