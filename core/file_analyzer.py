from __future__ import annotations

import hashlib
import math
import os
import time

from config import DEFAULT_SETTINGS
from core.archive_inspector import inspect_zip
from core.feature_extractor import extract_file_features
from core.mitre_mapper import map_findings_to_mitre
from core.pe_decompiler import analyze_pe_file
from core.yara_engine import scan_file_for_yara
from core.heuristic_engine import evaluate_heuristics
from core.models import Finding, ScanResult
from core.position_aware import build_position_aware_evidence
from core.risk_engine import finalize_result
from core.deep_embedding import HighDimensionalEmbedding
from ml.structural_classifier import StructuralClassifier

EICAR_TEST_SIGNATURE = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def analyze_file(
    path: str,
    settings: dict | None = None,
    *,
    file_data: bytes | None = None,
) -> ScanResult:
    settings = DEFAULT_SETTINGS if settings is None else settings
    started_at = time.monotonic()
    timeout = float(settings.get("analysis_timeout", DEFAULT_SETTINGS["analysis_timeout"]))
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("analysis_timeout must be a finite positive number.")

    def check_deadline() -> None:
        if time.monotonic() - started_at > timeout:
            raise TimeoutError(f"File analysis exceeded the configured {timeout:g}-second deadline.")

    maximum_file_size = int(settings.get("maximum_file_size", DEFAULT_SETTINGS["maximum_file_size"]))
    if maximum_file_size < 0:
        raise ValueError("maximum_file_size must be non-negative.")
    if file_data is None:
        initial_size = os.path.getsize(path)
        if initial_size > maximum_file_size:
            raise ValueError("File exceeds configured maximum file size.")
        with open(path, "rb") as handle:
            file_data = handle.read(maximum_file_size + 1)
        if len(file_data) > maximum_file_size:
            raise ValueError("File exceeds configured maximum file size.")
    elif not isinstance(file_data, bytes):
        raise TypeError("file_data must be bytes.")
    check_deadline()
    file_size = len(file_data)
    if file_size > maximum_file_size:
        raise ValueError("File exceeds configured maximum file size.")

    scan_limit = min(file_size, int(settings.get("max_string_scan_size", 200_000)))
    scanned_data = file_data[:scan_limit]
    entropy_enabled = bool(settings.get("entropy_analysis", True))
    contains_eicar = EICAR_TEST_SIGNATURE in file_data
    features = extract_file_features(
        file_data,
        os.path.basename(path),
        max_string_scan_size=int(settings.get("max_string_scan_size", 200_000)),
        include_topography=True,
    )
    archive_inspection = inspect_zip(file_data)
    archive_summary = archive_inspection.as_dict()
    if archive_inspection.status != "not_zip":
        features["archive_inspection"] = archive_summary
    model_topography = features.pop("entropy_topography")
    topography = model_topography if entropy_enabled else {}
    entropy = float(features["entropy"]) if entropy_enabled else 0.0
    if topography:
        features["average_section_entropy"] = float(topography["mean_entropy"])
        features["max_section_entropy"] = float(topography["peak_entropy"])
    features["entropy"] = float(features["entropy"])
    sha256 = hashlib.sha256(file_data).hexdigest()
    features["sha256"] = sha256
    if topography:
        features["entropy_topography"] = topography
    check_deadline()
    heuristic = (
        evaluate_heuristics(scanned_data.decode("latin-1"), file_name=os.path.basename(path))
        if settings.get("heuristic_rules", True)
        else {"score": 0, "findings": []}
    )
    score = heuristic["score"]

    remaining = max(0.0, timeout - (time.monotonic() - started_at))
    yara_timeout = max(1, math.ceil(remaining))
    yara_result = scan_file_for_yara(path, data=file_data, timeout_seconds=yara_timeout)
    check_deadline()
    pe_result = analyze_pe_file(path, data=file_data)
    position_aware_evidence = build_position_aware_evidence(
        file_data,
        topography,
        pe_result,
    )
    features["position_aware_evidence"] = position_aware_evidence
    check_deadline()

    findings: list[Finding] = []
    if archive_inspection.status != "not_zip":
        findings.append(Finding(
            "archive",
            "info",
            f"ZIP structure: {archive_inspection.status}",
            (
                f"Bounded inspection recorded {len(archive_inspection.entries)} member(s) "
                f"and {archive_inspection.decompressed_bytes} decompressed byte(s). "
                "Archive members were not independently scanned for malware."
            ),
            0,
        ))
        if archive_inspection.unsafe_member_paths:
            findings.append(Finding(
                "archive",
                "info",
                "Unsafe archive member paths skipped",
                f"{archive_inspection.unsafe_member_paths} member path(s) could escape an extraction directory; no members were extracted.",
                0,
            ))
        if archive_inspection.encrypted_members:
            findings.append(Finding(
                "archive",
                "info",
                "Encrypted archive members skipped",
                f"{archive_inspection.encrypted_members} encrypted member(s) could not be inspected without a password.",
                0,
            ))
    if features.get("magic_mismatch"):
        findings.append(Finding("structural", "high", "Header mismatch", "The file extension does not match the observed magic bytes.", 25))
    peak_entropy = float(topography.get("peak_entropy", entropy))
    if peak_entropy > 7.0:
        findings.append(Finding("statistical", "medium", "High entropy", "The content deviates from typical low-entropy file data and may indicate packing or obfuscation.", 18))
    for anomaly in topography.get("anomalies", []):
        if anomaly.get("high_entropy_boundary"):
            findings.append(Finding(
                "statistical",
                str(anomaly["severity"]),
                "Entropy discontinuity",
                (
                    f"Entropy changed by {float(anomaly['delta']):+.3f} bits/byte across "
                    f"offsets 0x{int(anomaly['offset_start']):X}-0x{int(anomaly['offset_end']):X}; "
                    "this boundary can indicate a change in content encoding."
                ),
                12,
            ))
    if features.get("double_extension"):
        findings.append(Finding("structural", "high", "Double extension", "A misleading file name attempts to hide an executable payload behind a benign extension.", 35))
    if features.get("is_executable"):
        findings.append(Finding("structural", "medium", "Executable extension", "The file extension is associated with executable content.", 12))
    if pe_result.get("status") == "ok" and pe_result.get("suspicious_imports"):
        findings.append(Finding("pe", "high", "Suspicious PE imports", "The binary imports APIs commonly associated with memory manipulation and process injection.", 35))
    cfg_topology = pe_result.get("cfg_topology", {})
    if pe_result.get("status") == "ok" and cfg_topology.get("detected_patterns"):
        patterns = ", ".join(cfg_topology["detected_patterns"])
        findings.append(Finding(
            "pe",
            "medium",
            "PE structural obfuscation indicator",
            f"Static executable-section decoding identified {patterns}; this is a review indicator, not proof of obfuscation.",
            15,
        ))
    if yara_result.get("matches"):
        for match in yara_result["matches"]:
            findings.append(Finding("yara", "high", match.get("rule_name", "YARA match"), match.get("description", "A YARA rule matched suspicious indicators."), 50))
    for item in heuristic["findings"]:
        findings.append(Finding("heuristic", item["severity"], item["label"], item["label"], item["contribution"]))

    if contains_eicar:
        findings.append(Finding(
            "test_marker",
            "info",
            "EICAR test marker",
            "The standard EICAR anti-malware test string is present. It is a benign test marker, not a virus.",
            0,
        ))

    score = max(
        int(score),
        max((item.contribution for item in findings), default=0),
    )
    classifier = StructuralClassifier()
    model_enabled = bool(settings.get("ml_analysis", True))
    model_available = model_enabled and classifier.load()
    structural_embedding = None
    structural_prediction = {
        "status": "untrained",
        "label": None,
        "class_scores": {},
        "infection_score": None,
        "scores_are_calibrated": False,
    }
    ml_score = None
    if model_available:
        structural_embedding = HighDimensionalEmbedding().embed_bytes(file_data)
        structural_prediction = classifier.predict(structural_embedding)
        ml_score = structural_prediction["infection_score"]
        features["structural_classifier"] = structural_prediction
    check_deadline()

    mitre_techniques = map_findings_to_mitre(
        findings=[item.evidence for item in findings],
        yara_matches=yara_result.get("matches", []),
        pe_summary=pe_result,
    )

    model_status = "No trained three-class structural model is available; static evidence only."
    limitations = (
        "The supervised model requires reviewed examples for all three classes; "
        "no infection probability or automatic repair is claimed."
    )
    if model_available:
        model_status = (
            "4096-D supervised structural classifier loaded; class scores are uncalibrated."
        )
        limitations = (
            "Static features are projected into 4096 coordinates; this projection is not "
            "lossless. Class scores are uncalibrated, and compressed/encrypted content "
            "cannot be semantically inspected without its key or decompression."
        )
    elif classifier.metadata.get("load_error"):
        model_status = (
            f"Structural model rejected: {classifier.metadata['load_error']} "
            "Static evidence remains active."
        )
    elif not model_enabled:
        model_status = "ML analysis disabled by settings."
    yara_status = (
        f"available; {yara_result['rules_loaded']} rule(s) loaded"
        if yara_result.get("available") and yara_result.get("rules_loaded")
        else "unavailable" if not yara_result.get("available")
        else "no rules configured"
    )
    if yara_result.get("error"):
        yara_status += f" ({yara_result['error']})"
    result = ScanResult(
        target=path,
        heuristic_score=score,
        ml_risk_score=ml_score,
        combined_score=score,
        classification="NO_INDICATORS_OBSERVED",
        evidence=findings,
        feature_summary=features,
        model_status=model_status,
        limitations=limitations,
        summary="",
        yara_matches=yara_result.get("matches", []),
        engine_status={
            "YARA": yara_status,
            "PE": str(pe_result.get("status", "unknown")),
            "ML": model_status,
            "Archive": (
                f"bounded structure inspection; {archive_inspection.status}; "
                f"{len(archive_inspection.entries)} member(s); member contents not malware-scanned"
                if archive_inspection.status != "not_zip"
                else "not a ZIP container"
            ),
        },
        pe_analysis=pe_result,
        mitre_techniques=mitre_techniques,
        structural_embedding=structural_embedding,
        structural_prediction=structural_prediction,
    )
    return finalize_result(
        result,
        heuristic_weight=float(settings.get("heuristic_weight", 1.0)),
        ml_weight=float(settings.get("ml_weight", 0.0)),
    )
