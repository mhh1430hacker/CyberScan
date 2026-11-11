# Claude (AI assistant, Anthropic) worked on this file, 2026-11-06: heuristics read the strings of the whole file; warnings use evidence_patterns only.
from __future__ import annotations

import hashlib
import math
import os
import time
from pathlib import Path

from config import DEFAULT_SETTINGS
from core.archive_inspector import inspect_zip
from core.feature_extractor import extract_file_features
from core.mitre_mapper import map_findings_to_mitre
from core.pe_decompiler import analyze_pe_file
from core.yara_engine import scan_file_for_yara
from core.heuristic_engine import PIECE_SEPARATOR, evaluate_heuristics, strings_beyond
from core.magic_bytes import naturally_compressed
from core.authenticode import verify as verify_signature
from core.models import Finding, ScanResult
from core.position_aware import build_position_aware_evidence
from core.risk_engine import finalize_result
from core.deep_embedding import HighDimensionalEmbedding
from core import dissonance
from core import surprise_map
from ml import counterfactual
# Only a model a person approved by SHA-256 can load (see ml.model_runtime).
from ml.model_runtime import UNAPPROVED_STATUS, ApprovedStructuralClassifier as StructuralClassifier

# Compiler padding (0xCC between functions) reads as "anti-disassembly" to a naive check.
PADDING_PATTERNS = {"ANTI_DISASSEMBLY_TRAP_PADDING", "ANTI_DISASSEMBLY_GAP"}


def meaningful_patterns(patterns) -> list[str]:
    return [p for p in (patterns or []) if p not in PADDING_PATTERNS]


def injection_chain(imports) -> bool:
    """Imports that only mean something together: write into another process, then run code there."""
    names = {str(name).casefold() for name in imports}
    writes = "writeprocessmemory" in names
    starts = bool(names & {"createremotethread", "queueuserapc", "ntcreatethreadex", "setthreadcontext"})
    return writes and starts


HIDDEN_TAIL_SIGNATURES = (b"MZ", b"PK\x03\x04", b"%PDF", b"\x7fELF", b"Rar!", b"7z\xbc\xaf", b"<script", b"<html", b"#!", b"powershell")


def hidden_tail_findings(data: bytes, name: str) -> list[Finding]:
    """Data stored after a format's logical end (a picture or PDF with an archive glued on).

    Uses the repair engine's parsers, which know where each format ends. A phone's
    "motion photo" keeps a video after the picture; that is reported, not scored.
    """
    try:
        from repair_engine.parsers import parse

        regions = parse(data, name)
    except Exception:  # noqa: BLE001 - a parser problem must never stop a scan
        return []
    if regions.format in {"pe", "elf"}:
        return []  # a program's overlay is judged by the program checks
    findings = []
    for region in regions.of_kind("after_eof"):
        tail = data[region.start:region.end]
        if not tail.strip(b"\x00\t\r\n "):
            continue
        size = len(tail)
        where = f"0x{region.start:X}"
        if regions.format == "jpeg" and b"ftyp" in tail[:64]:
            findings.append(Finding("structural", "info", "Video after the picture",
                                    f"{size} bytes after the picture ends (from {where}) look like a phone's motion photo.", 0))
        elif any(sig.lower() in tail[:4096].lower() for sig in HIDDEN_TAIL_SIGNATURES):
            findings.append(Finding("structural", "high", "Hidden data after the end of the file",
                                    f"{size} bytes stored after the {regions.format.upper()} ends (from {where}), starting like a program, an archive or a script.", 45))
        else:
            findings.append(Finding("structural", "medium", "Data after the end of the file",
                                    f"{size} bytes stored after the {regions.format.upper()} ends (from {where}). Readers ignore them; other programs can use them.", 15))
    return findings


DISSONANCE_TEXT_BYTES = 2_000_000
_profiles: dict[tuple[str, str, str], object] = {}


def _profile(kind: str, settings: dict):
    """The approved dissonance/surprise profile (cached), or None when absent or rejected."""
    if kind == "surprise":
        path = settings.get("surprise_profile") or str(surprise_map.DEFAULT_PROFILE)
        digest = settings.get("surprise_profile_sha256") or surprise_map.DEFAULT_PROFILE_SHA256
        loader = surprise_map.load_profile
    else:
        path, digest = settings.get("dissonance_profile"), settings.get("dissonance_profile_sha256")
        if not path:
            return None  # the expert prior
        loader = dissonance.load_profile
    key = (kind, str(path), str(digest))
    if key not in _profiles:
        try:
            _profiles[key] = loader(Path(path), str(digest))
        except (OSError, ValueError, KeyError, TypeError):
            _profiles[key] = None
    return _profiles[key]


def dissonance_findings(assessment: dict, signed: bool) -> list[Finding]:
    """A program whose claimed role and capabilities disagree (see core.dissonance)."""
    if assessment.get("status") != "ok" or assessment["level"] == "low":
        return []
    text = dissonance.describe(assessment)
    if signed:
        # A valid signature names who answers for the program; keep the observation, not the score.
        return [Finding("dissonance", "info", "Claim and capabilities differ (signed program)", text, 0)]
    if assessment["level"] == "high":
        return [Finding("dissonance", "high", "Claim and capabilities disagree", text, 35)]
    return [Finding("dissonance", "medium", "Claim and capabilities disagree", text, 20)]


def surprise_findings(result: dict, signed: bool) -> list[Finding]:
    """Code-section bytes that honest code never looks like (see core.surprise_map)."""
    if result.get("status") != "ok" or signed:
        return []
    code = [region for region in result["regions"] if region["role"] == "code"]
    if not code:
        return []
    region = code[0]
    return [Finding(
        "statistical",
        "medium",
        "Foreign content in program code",
        (
            f"{len(code)} stretch(es) of the code section {region['part']!r} do not look like program code "
            f"(from 0x{region['offset_start']:X}: {region['surprise_bits_per_byte']:.2f} bits/byte away from "
            f"honest code, where 99.9% of honest code stays within {region['benign_p999']:.2f}). "
            "Packed, encrypted or injected content looks like this."
        ),
        15,
    )]


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
    if settings.get("heuristic_rules", True):
        # The head as it is, then the strings of everything after it: an indicator placed
        # behind megabytes of padding is still read.
        heuristic_text = scanned_data.decode("latin-1")
        if file_size > scan_limit:
            tail_strings, features["string_scan"] = strings_beyond(file_data, scan_limit)
            heuristic_text += PIECE_SEPARATOR + tail_strings
        heuristic = evaluate_heuristics(heuristic_text, file_name=os.path.basename(path))
    else:
        heuristic = {"score": 0, "findings": []}
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
    # A program whose signature checks out (static WinVerifyTrust, no network) is judged on
    # strong evidence only: packing, entropy and code shape are normal in signed software.
    signature = verify_signature(str(path)) if file_data[:2] == b"MZ" and os.path.isfile(str(path)) else "not a program"
    features["authenticode"] = signature
    signed = signature.startswith("valid")
    if signed:
        findings.append(Finding("signature", "info", "Signed program", "The program's digital signature is intact and trusted on this computer.", 0))
    elif signature == "unsigned or invalid":
        findings.append(Finding("signature", "info", "Unsigned program", "The program has no valid digital signature, so its publisher can't be confirmed.", 0))
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
    # Pictures, sound, video, PDF and ZIP-based documents are compressed by design:
    # their high entropy and the jump from header to compressed body are normal.
    compressed = naturally_compressed(file_data[:16])
    if peak_entropy > 7.0 and not compressed and not signed:
        findings.append(Finding("statistical", "medium", "High entropy", "The content deviates from typical low-entropy file data and may indicate packing or obfuscation.", 18))
    for anomaly in topography.get("anomalies", []):
        if anomaly.get("high_entropy_boundary") and not compressed and not signed:
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
        # A fact, not a warning: a program is judged by what is in it, not by being one.
        findings.append(Finding("structural", "info", "Executable extension", "The file extension is associated with executable content.", 0))
    findings += hidden_tail_findings(file_data, os.path.basename(path))
    if settings.get("dissonance_analysis", True):
        claim_check = dissonance.assess(
            os.path.basename(path),
            pe_result,
            file_data[:DISSONANCE_TEXT_BYTES].decode("latin-1").lower(),
            signed=signed,
            profile=_profile("dissonance", settings),
        )
        if claim_check.get("status") == "ok":
            features["dissonance"] = claim_check
            findings += dissonance_findings(claim_check, signed)
    surprise_profile = _profile("surprise", settings) if settings.get("surprise_analysis", True) else None
    if surprise_profile is not None:
        surprise = surprise_map.surprise_map(file_data, pe_result, surprise_profile)
        if surprise.get("status") == "ok":
            features["surprise_map"] = surprise
            # Located, so the structure view and galaxy can show where they are.
            position_aware_evidence["surprise_regions"] = surprise["regions"]
            findings += surprise_findings(surprise, signed)
    check_deadline()
    if pe_result.get("status") == "ok" and injection_chain(pe_result.get("suspicious_imports") or []):
        findings.append(Finding("pe", "high", "Suspicious PE imports", "The binary imports APIs commonly associated with memory manipulation and process injection.", 35))
    cfg_topology = pe_result.get("cfg_topology", {})
    # Only the strict evidence patterns warn: the descriptive ones fire on most honest programs.
    if pe_result.get("status") == "ok" and cfg_topology.get("evidence_patterns") and not signed:
        patterns = ", ".join(cfg_topology["evidence_patterns"])
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
        # Every antivirus reports the EICAR file as a detection: that is what it is for
        # (checking that protection works). It is harmless, and the explanation says so.
        findings.append(Finding(
            "test_marker",
            "high",
            "EICAR anti-malware test file",
            "The standard EICAR test file. It is harmless by design: it exists so people can check that antivirus protection reacts. CyberScan reports it the way antivirus products do.",
            60,
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
        if structural_prediction.get("label") not in (None, "clean") and not structural_prediction.get("abstained"):
            # What does the verdict rest on? Regions are blanked in memory only.
            audit = counterfactual.audit(
                file_data,
                classifier.labels_and_scores,
                HighDimensionalEmbedding().embed_bytes,
                ("clean", "suspicious", "malware"),
                max_regions=int(settings.get("counterfactual_regions", 6)),
                deadline=started_at + timeout * 0.9,
            )
            structural_prediction["counterfactual"] = audit
            if audit.get("verdict_basis") == "incidental":
                flip = audit["flip"]
                findings.append(Finding(
                    "model", "info", "Model verdict rests on an ignored part",
                    f"The model's {structural_prediction['label']!r} verdict disappears when the {flip['region']} "
                    f"({flip['bytes']} bytes, a part Windows ignores when running the program) is removed, "
                    "so the verdict is weak evidence on its own.",
                    0,
                ))
    check_deadline()

    mitre_techniques = map_findings_to_mitre(
        findings=[item.evidence for item in findings],
        yara_matches=yara_result.get("matches", []),
        pe_summary=pe_result,
    )

    # The runtime explains itself: not approved, missing, rejected or loaded.
    runtime_state = getattr(classifier, "state", None)
    model_status = runtime_state.detail if runtime_state is not None else UNAPPROVED_STATUS
    limitations = (
        "The supervised model requires reviewed examples for all three classes; "
        "no infection probability or automatic repair is claimed."
    )
    if model_available and structural_prediction.get("abstained"):
        model_status = (
            "4096-D structural classifier loaded, but not sure about this file: "
            f"{len(structural_prediction.get('prediction_set', []))} classes remain possible at "
            f"{structural_prediction.get('conformal_coverage_target', 0.9):.0%} coverage, so the verdict rests on static evidence."
        )
    elif model_available:
        model_status = (
            "4096-D supervised structural classifier loaded; class scores are uncalibrated."
        )
        limitations = (
            "Static features are projected into 4096 coordinates; this projection is not "
            "lossless. Class scores are uncalibrated, and compressed/encrypted content "
            "cannot be semantically inspected without its key or decompression."
        )
    elif runtime_state is None and classifier.metadata.get("load_error"):
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
            "Dissonance": (
                f"{features['dissonance']['level']} ({features['dissonance']['dissonance_bits']:.1f} bits; profile: "
                f"{features['dissonance']['profile']})" if "dissonance" in features else "not a program"
            ),
            "Surprise map": (
                f"{len(features['surprise_map']['regions'])} foreign region(s); profile: {features['surprise_map']['profile']}"
                if "surprise_map" in features
                else "profile unavailable" if surprise_profile is None and settings.get("surprise_analysis", True)
                else "not a program"
            ),
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
