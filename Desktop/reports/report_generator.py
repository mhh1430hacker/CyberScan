from __future__ import annotations

from datetime import datetime
from pathlib import Path

from config import REPORT_DIR
from core.models import ScanResult


def generate_report(result: ScanResult, target_name: str | None = None) -> str:
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    target = target_name or result.target
    lines = [
        "CYBERSCAN REPORT",
        f"Timestamp: {timestamp}",
        f"Target: {target}",
        # The old report printed the *target path* on the SHA-256 line.
        f"SHA-256: {result.sha256 or 'not applicable (non-file target)'}",
        f"Heuristic score: {result.heuristic_score}/100",
        f"ML anomaly score: {result.ml_anomaly_score if result.ml_anomaly_score is not None else 'not available'}",
        f"Combined score: {result.combined_score}/100",
        f"Classification: {result.classification}",
        "",
        "Evidence:",
    ]
    if result.evidence:
        for item in result.evidence:
            lines.append(f"- [{item.severity.upper()}] {item.evidence}: {item.explanation}")
    else:
        lines.append("- No direct evidence recorded.")
    if result.mitre_techniques and result.mitre_techniques[0].get("id") != "N/A":
        lines.extend(["", "MITRE ATT&CK:"])
        for technique in result.mitre_techniques:
            lines.append(f"- {technique.get('id')}: {technique.get('name')}")
    lines.extend(["", f"Model status: {result.model_status}", f"Limitations: {result.limitations}"])
    if result.integrity_report is not None:
        integrity = result.integrity_report
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


def save_report(result: ScanResult, target_name: str | None = None, file_name: str | None = None) -> Path:
    report_dir = Path(REPORT_DIR)
    report_dir.mkdir(parents=True, exist_ok=True)
    # Use only the base name so a caller-supplied name cannot escape the reports directory.
    file_name = Path(file_name).name if file_name else f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    path = report_dir / file_name
    path.write_text(generate_report(result, target_name), encoding="utf-8")
    return path
