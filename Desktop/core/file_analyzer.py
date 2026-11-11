from __future__ import annotations

import os

from config import resolve_settings
from core.feature_extractor import extract_features_from_bytes
from core.file_integrity import verify_file_integrity
from core.hashing import compute_file_sha256
from core.heuristic_engine import evaluate_heuristics
from core.mitre_mapper import map_findings_to_mitre
from core.models import Finding, ScanResult
from core.pe_decompiler import analyze_pe_file
from core.risk_engine import combine_scores
from core.yara_engine import scan_file_for_yara, yara_evidence_from_matches
from detection.common import fuse_correlated
from detection.engine import inspect_content, read_for_inspection
from ml.model_manager import get_detector

EICAR_TEST_SIGNATURE = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

# Formats whose payload is compressed or encoded by design: high entropy is expected, not suspicious.
COMPRESSED_MAGIC = (
    b"\x1f\x8b", b"7z\xbc\xaf", b"Rar!", b"\xfd7zXZ", b"BZh", b"(\xb5/\xfd", b"MSCF", b"\x89PNG", b"\xff\xd8\xff",
    b"GIF8", b"RIFF", b"OggS", b"fLaC", b"ID3", b"\x00\x00\x00\x18ftyp", b"\x00\x00\x00\x1cftyp", b"\x00\x00\x00\x20ftyp",
)


def analyze_file(path: str, settings: dict | None = None) -> ScanResult:
    settings = resolve_settings(settings)
    file_size = os.path.getsize(path)
    if file_size > int(settings["maximum_file_size"]):
        raise ValueError("File exceeds configured maximum file size.")

    read_limit = min(file_size, int(settings["max_analysis_bytes"]))
    with open(path, "rb") as handle:
        data = handle.read(read_limit)

    file_name = os.path.basename(path)
    sha256 = compute_file_sha256(path)
    try:
        integrity_report = verify_file_integrity(
            path,
            expected_sha256=sha256,
            max_file_size=int(settings["maximum_file_size"]),
        )
    except Exception as exc:
        integrity_report = {
            "status": "verification_incomplete",
            "format": "unknown",
            "size_bytes": file_size,
            "sha256": None,
            "hash_matches_analysis": None,
            "checks": [{
                "name": "integrity verifier",
                "status": "incomplete",
                "detail": f"Integrity verification failed unexpectedly: {type(exc).__name__}.",
            }],
            "limitations": ["The primary file analysis completed, but integrity verification did not."],
            "nested_archives_detected": 0,
            "trailing_bytes": 0,
        }
    features = extract_features_from_bytes(data, file_name)
    entropy = float(features.get("entropy") or 0.0)

    # Heuristic rules run on the file *content* (decoded bytes) plus its name.
    # Previously they received the SHA-256 string, so content rules could never fire.
    if settings["heuristic_rules"]:
        content = data[: int(settings["max_string_scan_size"])].decode("latin-1")
        heuristic = evaluate_heuristics(content, file_name=file_name, scan_content=True)
    else:
        heuristic = {"score": 0, "findings": []}
    score = heuristic["score"]

    yara_result = scan_file_for_yara(path, max_bytes=read_limit)
    pe_result = analyze_pe_file(path)
    yara_evidence = yara_evidence_from_matches(yara_result)

    # Content inspection (documents, archives, APKs, extensions, PE/ELF structure, scripts, secrets).
    # PE import evidence now comes from capability combinations in detection.executables; the former
    # "any suspicious import" rule fired on IsDebuggerPresent/CreateProcessW, which the C runtime imports.
    try:
        content_analysis = inspect_content(read_for_inspection(path, data, file_size), file_name,
                                           total_size=file_size, path=path)
    except OSError as exc:
        content_analysis = {"findings": [], "indicators": [], "analyzer_errors": [f"content read failed: {exc}"]}

    findings: list[Finding] = []
    if features.get("magic_mismatch"):
        findings.append(Finding("structural", "high", "Header mismatch", "The file extension does not match the observed magic bytes.", 25))
    if settings["entropy_analysis"] and entropy > 7.0:
        if content_analysis.get("sniffed_type") in {"zip", "pdf"} or data.startswith(COMPRESSED_MAGIC):
            findings.append(Finding("statistical", "info", "High entropy (expected)", "The format is compressed by design, so high entropy is not evidence of packing.", 0))
        else:
            findings.append(Finding("statistical", "medium", "High entropy", "The content deviates from typical low-entropy file data and may indicate packing or obfuscation.", 18))
    if features.get("double_extension"):
        findings.append(Finding("structural", "high", "Double extension", "A misleading file name attempts to hide an executable payload behind a benign extension.", 35))
    if features.get("is_executable"):
        findings.append(Finding("structural", "medium", "Executable extension", "The file extension is associated with executable content.", 12))
    for item in content_analysis.get("indicators", []):
        if item.category != "privacy":
            findings.append(Finding(item.category, item.severity, item.label, item.explanation, item.contribution))
    for match in yara_result.get("matches", []):
        findings.append(Finding("yara", "high", match.get("rule_name", "YARA match"), match.get("description", "A YARA rule matched suspicious indicators."), 20))
    for item in heuristic["findings"]:
        findings.append(Finding("heuristic", item["severity"], item["label"], item.get("explanation", item["label"]), item["contribution"]))

    if EICAR_TEST_SIGNATURE in data:
        findings.append(Finding(
            "test_marker",
            "info",
            "EICAR test marker",
            "The standard EICAR anti-malware test string is present. It is a benign test marker, not a virus.",
            0,
        ))

    # Evidence is fused with noisy-OR (collaboration/DECISIONS.md D-002): independent engines that agree
    # reinforce each other, but many weak indicators cannot add up to a verdict on their own. Findings that
    # observe the same fact through two engines (e.g. YARA and import analysis on the same API names) are
    # correlated and count once (detection.common.CORRELATED_EVIDENCE).
    score = fuse_correlated(
        (item.evidence, item.contribution) for item in findings if item.category != "test_marker" and item.contribution > 0
    )

    model_available = False
    ml_score = None
    detector = None
    if settings["ml_analysis"]:
        detector = get_detector()
        model_available = detector.model_available
        if model_available:
            ml_score = detector.anomaly_percentage(features)
    combined_score = max(
        score,
        int(combine_scores(score, ml_score, float(settings["heuristic_weight"]), float(settings["ml_weight"]))),
    )

    mitre_techniques = map_findings_to_mitre(
        findings=[item.evidence for item in findings],
        yara_matches=yara_result.get("matches", []),
        pe_summary=pe_result,
    )

    classification = "SUSPICIOUS" if combined_score >= 50 else "UNKNOWN" if combined_score > 0 else "SAFE"
    if not settings["ml_analysis"]:
        model_status = "ML analysis disabled in settings; static evidence only."
        limitations = "Static analysis is heuristic; ML analysis is switched off."
    elif model_available:
        model_status = "Curated-benign IsolationForest loaded; anomaly score is not a malware probability."
        limitations = "Static analysis and a curated-benign anomaly model are active; validate against an independent labeled dataset."
    else:
        model_status = "ML model not available; static evidence only."
        limitations = "Static analysis is heuristic; no provenance-validated ML model is available."
        if detector is not None and detector.metadata.get("load_error"):
            model_status = f"ML model rejected: {detector.metadata['load_error']} Static evidence remains active."
    if file_size > read_limit:
        limitations += f" Only the first {read_limit:,} of {file_size:,} bytes were analyzed (the SHA-256 covers the whole file)."
    if content_analysis.get("truncated_input"):
        limitations += " Container inspection was limited to the first 32 MB."
    if content_analysis.get("analyzer_errors"):
        limitations += " Content analyzer errors: " + "; ".join(content_analysis["analyzer_errors"]) + "."

    return ScanResult(
        target=path,
        heuristic_score=score,
        ml_anomaly_score=ml_score,
        combined_score=combined_score,
        classification=classification,
        evidence=findings,
        feature_summary=features,
        model_status=model_status,
        limitations=limitations,
        summary=f"Static score: {score}/100; combined score: {combined_score}/100; classification: {classification}.",
        yara_matches=yara_result.get("matches", []),
        pe_analysis=pe_result,
        mitre_techniques=mitre_techniques,
        sha256=sha256,
        integrity_report=integrity_report,
        content_analysis={
            "file_type": content_analysis.get("file_type"),
            "score": content_analysis.get("score", 0),
            "evidence_agreement": content_analysis.get("evidence_agreement", "none"),
            "corroborating_categories": content_analysis.get("corroborating_categories", []),
            "details": content_analysis.get("details", {}),
            "findings": [item.as_dict() for item in content_analysis.get("indicators", []) if item.category != "privacy"],
            "privacy": content_analysis.get("privacy", {}),
            "analyzer_errors": content_analysis.get("analyzer_errors", []),
        },
    )
