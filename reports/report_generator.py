from __future__ import annotations

from datetime import datetime
from pathlib import Path

from config import REPORT_DIR
from core.models import ScanResult


def _risk_flags(result: ScanResult) -> list[str]:
    return [
        f"[{item.severity.upper()}] {item.evidence}: {item.explanation}"
        for item in result.evidence
        if item.severity.casefold() in {"critical", "high"}
    ]


def _structural_summary(result: ScanResult) -> list[str]:
    features = result.feature_summary
    topology = features.get("entropy_topography", {})
    pe = result.pe_analysis
    cfg = pe.get("cfg_topology", {}) if isinstance(pe, dict) else {}
    lines = [
        f"File size: {features.get('file_size', 'not available')} bytes",
        f"Shannon entropy: {features.get('entropy', 'not available')} bits/byte",
        f"Entropy topography peak: {topology.get('peak_entropy', 'not available')} bits/byte",
        f"Entropy discontinuities: {len(topology.get('anomalies', []))}",
        f"PE status: {pe.get('status', 'not available')}",
        f"PE sections: {pe.get('section_count', 'not available')}",
        f"Imported APIs: {pe.get('import_count', 'not available')}",
        f"CFG basic blocks: {cfg.get('basic_block_count', 'not available')}",
        f"CFG cyclomatic complexity: {cfg.get('cyclomatic_complexity', 'not available')}",
        f"CFG graph density: {cfg.get('graph_density', 'not available')}",
    ]
    position = features.get("position_aware_evidence", {})
    if position:
        lines.extend([
            "Position-aware ranges (measured indicators, not malicious-region predictions):",
            f"- Entropy boundaries: {len(position.get('entropy_boundaries', []))}; omitted: {position.get('omitted_entropy_observations', 0)}",
        ])
        for boundary in position.get("entropy_boundaries", [])[:6]:
            lines.append(
                f"- Entropy transition: 0x{boundary['offset_start']:X}-"
                f"0x{boundary['offset_end']:X}; ΔH "
                f"{boundary['entropy_delta_bits_per_byte']:+.3f}; "
                f"{boundary['severity']}; hash "
                f"{boundary.get('region_hash_status', 'unavailable')}"
            )
        verified_sections = [
            section
            for section in position.get("pe_sections", [])
            if section.get("range_status") == "within_file"
        ]
        for section in verified_sections[:8]:
            rva = section.get("rva_start")
            rva_suffix = f"; RVA 0x{rva:X}" if isinstance(rva, int) else ""
            lines.append(
                f"- PE section {section['name']}: file bytes "
                f"0x{section['file_offset_start']:X}-"
                f"0x{section['file_offset_end']:X}{rva_suffix}"
            )
        if not position.get("entropy_boundaries") and not verified_sections:
            lines.append("- No valid position-mapped ranges.")
    return lines


def generate_report(result: ScanResult, target_name: str | None = None) -> str:
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    target = target_name or result.target
    sha256 = result.feature_summary.get("sha256", "not available")
    flags = _risk_flags(result)
    structural_prediction = result.structural_prediction
    class_scores = structural_prediction.get("class_scores", {})
    class_score_text = ", ".join(
        f"{label}: {score:.2f}%" for label, score in class_scores.items()
    ) or "not available"
    lines = [
        "CYBERSCAN FORENSIC VERDICT SUMMARY",
        f"Timestamp: {timestamp}",
        f"Target: {target}",
        f"SHA-256: {sha256}",
        f"Heuristic score: {result.heuristic_score}/100",
        f"ML structural risk score: {result.ml_risk_score if result.ml_risk_score is not None else 'not available'} (uncalibrated)",
        f"ML structural class: {structural_prediction.get('label', 'not available')}",
        f"ML class scores (uncalibrated): {class_score_text}",
        f"Combined score: {result.combined_score}/100",
        f"Classification: {result.classification}",
        "Confidence: not calibrated; this score is not a malware probability.",
        "Repair: no automatic repair, deletion, or blocking is performed; restoration requires explicit approval and a trusted clean source.",
        "",
        "Critical risk flags:",
    ]
    lines.extend(f"- {flag}" for flag in flags)
    if not flags:
        lines.append("- No critical or high-severity findings were recorded.")
    lines.extend(["", "Structural breakdown:"])
    lines.extend(f"- {line}" for line in _structural_summary(result))
    lines.extend(["", "MITRE ATT&CK mapping:"])
    if result.mitre_techniques:
        for technique in result.mitre_techniques:
            evidence = ", ".join(technique.get("evidence", []))
            item = f"- {technique.get('id', 'N/A')}: {technique.get('name', 'Unknown')}"
            lines.append(f"{item}; evidence: {evidence}" if evidence else item)
    else:
        lines.append("- No mapped technique.")
    lines.extend(["", "Evidence:"])
    if result.evidence:
        for item in result.evidence:
            lines.append(f"- [{item.severity.upper()}] {item.evidence}: {item.explanation}")
    else:
        lines.append("- No direct evidence recorded.")

    intelligence = result.osint_summary
    lines.extend(["", "OSINT correlation:"])
    if intelligence:
        lines.append(f"- Status: {intelligence.get('status', 'unknown')}")
        lines.append(f"- Indicator type: {intelligence.get('indicator_type', 'unknown')}")
        lines.append(f"- Matches: {len(intelligence.get('matches', []))}")
        lines.append(f"- Attributions: {', '.join(intelligence.get('attributions', [])) or 'none reported'}")
        lines.append(f"- Interpretation: {intelligence.get('interpretation', 'External feed results are not proof of maliciousness; a miss is not proof of safety.')}")
    else:
        lines.append("- Not queried.")
    lines.extend([
        "",
        f"Model status: {result.model_status}",
        f"Limitations: {result.limitations}",
    ])
    if result.engine_status:
        lines.extend(["", "Analysis engine status:"])
        lines.extend(f"- {name}: {status}" for name, status in sorted(result.engine_status.items()))
    if result.nextgen_analysis:
        nextgen = result.nextgen_analysis
        entropy = nextgen.get("entropy_topography", {})
        cfg = nextgen.get("cfg_topology", {})
        lines.extend([
            "",
            "Additional structural analysis:",
            f"- Input profile: {nextgen.get('input_profile', 'not available')}",
            f"- Structural indicator score: {nextgen.get('composite_innovation_score', 'not available')}/100 (not a probability)",
            f"- Mean / peak entropy: {entropy.get('mean_entropy', 'not available')} / {entropy.get('peak_entropy', 'not available')}",
            f"- CFG architecture: {cfg.get('architecture', 'not available')}",
            f"- CFG complexity: {cfg.get('cyclomatic_complexity', 'not available')}",
        ])
    return "\n".join(lines)


def save_report(result: ScanResult, target_name: str | None = None, file_name: str | None = None) -> Path:
    report_dir = Path(REPORT_DIR)
    report_dir.mkdir(parents=True, exist_ok=True)
    file_name = file_name or f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    if Path(file_name).name != file_name or file_name in {".", ".."}:
        raise ValueError("file_name must be a plain file name without path components.")
    path = report_dir / file_name
    path.write_text(generate_report(result, target_name), encoding="utf-8")
    return path
