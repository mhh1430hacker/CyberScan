from __future__ import annotations

import json
from pathlib import Path

from core.models import ScanResult
from reports.report_generator import generate_report


def export_report(result: ScanResult, output_path: str | Path, format_name: str = "txt") -> Path:
    path = Path(output_path)
    if format_name.lower() == "json":
        payload = {
            "target": result.target,
            "heuristic_score": result.heuristic_score,
            "ml_risk_score": result.ml_risk_score,
            "structural_prediction": result.structural_prediction,
            "combined_score": result.combined_score,
            "classification": result.classification,
            "evidence": [item.__dict__ for item in result.evidence],
            "engine_status": result.engine_status,
            "nextgen_analysis": result.nextgen_analysis,
            "feature_summary": result.feature_summary,
            "pe_analysis": result.pe_analysis,
            "mitre_techniques": result.mitre_techniques,
            "osint_summary": result.osint_summary,
            "summary": result.summary,
            "model_status": result.model_status,
            "limitations": result.limitations,
        }
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    else:
        path.write_text(generate_report(result), encoding="utf-8")
    return path
