from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from core.models import ScanResult


def export_report(result: ScanResult, output_path: str | Path, format_name: str = "txt") -> Path:
    path = Path(output_path)
    if format_name.lower() == "json":
        payload = {
            "target": result.target,
            "sha256": result.sha256,
            "integrity_report": result.integrity_report,
            "summary": result.summary,
            "heuristic_score": result.heuristic_score,
            "ml_anomaly_score": result.ml_anomaly_score,
            "combined_score": result.combined_score,
            "classification": result.classification,
            "evidence": [asdict(item) for item in result.evidence],
            "yara_matches": result.yara_matches,
            "pe_analysis": result.pe_analysis,
            "mitre_techniques": result.mitre_techniques,
            "feature_summary": result.feature_summary,
            "model_status": result.model_status,
            "limitations": result.limitations,
            "content_analysis": result.content_analysis,
        }
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    else:
        path.write_text(result.as_text(), encoding="utf-8")
    return path
