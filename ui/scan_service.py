from __future__ import annotations

import asyncio
import hashlib
import math
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from core.file_analyzer import meaningful_patterns
from core.magic_bytes import naturally_compressed
from config import DEFAULT_SETTINGS
from core.deep_embedding import HighDimensionalEmbedding
from core.global_intelligence import GlobalIntelligenceEngine
from core.models import Finding, ScanResult
from core.nextgen_engine import NextGenCyberEngine
from core.risk_engine import finalize_result
from core.scanner import scan_target

ProgressCallback = Callable[[int, str, str], None]


def looks_like_text(data: bytes) -> bool:
    sample = data[:8192]
    if not sample:
        return True
    if b"\x00" in sample:
        return False
    printable = sum(
        byte in (9, 10, 13) or 32 <= byte <= 126 or byte >= 160
        for byte in sample
    )
    return printable / len(sample) >= 0.90


def text_cfg_summary() -> dict[str, Any]:
    return {
        "basic_block_count": 0,
        "cyclomatic_complexity": 0,
        "graph_density": 0.0,
        "detected_patterns": [],
        "opcode_frequency": {
            name: 0.0 for name in ("XOR", "MOV", "PUSH", "CALL", "JMP", "NOP")
        },
        "edge_count": 0,
        "adjacency": {},
        "architecture": "text-content-skipped",
        "disassembly_available": False,
        "instruction_count": 0,
        "back_edge_count": 0,
        "back_edge_density": 0.0,
        "raw_byte_frequency": {},
    }


def score_artifacts(entropy: dict[str, Any], cfg: dict[str, Any]) -> float:
    entropy_score = (
        (entropy["mean_entropy"] / 8.0) * 20.0
        + (entropy["peak_entropy"] / 8.0) * 15.0
    )
    anomaly_score = min(len(entropy["anomalies"]) / 3.0, 1.0) * 20.0
    gradient_score = min(math.sqrt(entropy["gradient_variance"]) / 4.0, 1.0) * 10.0
    complexity_score = min(cfg["cyclomatic_complexity"] / 20.0, 1.0) * 15.0
    pattern_score = min(len(cfg["detected_patterns"]) / 3.0, 1.0) * 20.0
    return round(
        max(
            0.0,
            min(
                100.0,
                entropy_score
                + anomaly_score
                + gradient_score
                + complexity_score
                + pattern_score,
            ),
        ),
        2,
    )


def _disabled_intelligence() -> dict[str, Any]:
    return {
        "status": "disabled",
        "indicator": None,
        "indicator_type": None,
        "elapsed_ms": 0.0,
        "latency_budget_ms": 0.0,
        "feeds": {
            name: {
                "status": "disabled",
                "error": None,
                "records": [],
                "match_count": 0,
            }
            for name in ("ThreatFox", "URLhaus", "AlienVault OTX")
        },
        "matches": [],
        "attributions": [],
        "classifications": [],
    }


class ScanService:
    """Runs the existing static-analysis pipeline without coupling it to a UI."""

    def __init__(self) -> None:
        self.embedding = HighDimensionalEmbedding()

    def analyze(
        self,
        candidate: str,
        input_mode: str,
        settings: dict[str, Any],
        progress: ProgressCallback | None = None,
    ) -> tuple[ScanResult, dict[str, Any], tuple[float, ...], dict[str, Any], dict[str, Any], bytes]:
        report = progress or (lambda _index, _state, _detail: None)
        started_at = time.monotonic()
        timeout = float(settings.get("analysis_timeout", DEFAULT_SETTINGS["analysis_timeout"]))
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("analysis_timeout must be a finite positive number.")

        def check_deadline() -> None:
            if time.monotonic() - started_at > timeout:
                raise TimeoutError(
                    f"Analysis exceeded the configured {timeout:g}-second deadline."
                )

        is_url = input_mode == "URL"
        path = Path(candidate) if not is_url else None
        is_file = input_mode == "File" and bool(path and path.is_file())
        report(0, "running", "Reading the target and collecting static evidence")
        if is_file:
            assert path is not None
            file_size = path.stat().st_size
            maximum = int(settings.get("maximum_file_size", 50 * 1024 * 1024))
            if file_size > maximum:
                raise ValueError(
                    f"File size {file_size} exceeds the configured limit of {maximum} bytes"
                )
            with path.open("rb") as handle:
                raw_data = handle.read(maximum + 1)
            if len(raw_data) > maximum:
                raise ValueError(
                    f"File grew beyond the configured limit of {maximum} bytes during reading"
                )
            scan_result = scan_target(
                str(path), is_file=True, settings=settings, file_data=raw_data
            )
            filename = path.name
        elif is_url:
            raw_data = candidate.encode("utf-8")
            scan_result = scan_target(candidate, is_file=False, settings=settings)
            filename = "url-indicator.txt"
        else:
            raw_data = candidate.encode("utf-8", errors="replace")
            scan_result = scan_target(candidate, is_file=False, settings=settings)
            filename = "text-indicator.txt"
        check_deadline()
        report(0, "complete", f"Static findings collected · {len(raw_data):,} bytes")

        report(1, "running", "Measuring byte entropy and structural transitions")
        if is_file and settings.get("entropy_analysis", True):
            entropy = scan_result.feature_summary.get("entropy_topography")
        else:
            entropy = None
        if entropy is None:
            entropy = (
                NextGenCyberEngine.analyze_entropy_topography(raw_data)
                if settings.get("entropy_analysis", True)
                else {
                    "trajectory": [],
                    "window_offsets": [],
                    "gradients": [],
                    "mean_entropy": 0.0,
                    "peak_entropy": 0.0,
                    "gradient_variance": 0.0,
                    "anomalies": [],
                    "window_size": 0,
                    "step_size": 0,
                }
            )
        check_deadline()
        text_input = looks_like_text(raw_data)
        # Instruction patterns mean something only in a program; read as x86, a picture or a
        # PDF yields nonsense "patterns" (false warnings) and can take tens of seconds.
        program = raw_data[:2] == b"MZ" or raw_data[:4] == b"\x7fELF"
        cfg = (
            NextGenCyberEngine.extract_cfg_topology(raw_data)
            if program and not text_input
            else text_cfg_summary()
        )
        score = score_artifacts(entropy, cfg)
        nextgen = {
            "status": "SUCCESS",
            "filename": filename,
            "file_size": len(raw_data),
            "entropy_topography": entropy,
            "cfg_topology": cfg,
            "forensic_storyboard": NextGenCyberEngine.generate_forensic_storyline(
                filename, len(raw_data), entropy, cfg, score
            ),
            "composite_innovation_score": score,
            "input_profile": "text-content" if text_input else "binary-content",
            "heuristic_weight": float(settings.get("heuristic_weight", 1.0)),
            "ml_weight": float(settings.get("ml_weight", 0.0)),
        }
        report(1, "complete", f"Entropy and structure measured · {len(entropy['trajectory']):,} windows")

        report(2, "running", "Projecting observed structure into the 4096-D feature space")
        vector = scan_result.structural_embedding or self.embedding.embed_bytes(
            raw_data,
            entropy_topography=entropy,
            cfg_topology=cfg,
            pe_features=scan_result.pe_analysis,
        )
        prediction = scan_result.structural_prediction or {
            "status": "untrained",
            "label": None,
            "class_scores": {},
            "infection_score": None,
            "scores_are_calibrated": False,
            "repair_review_candidate": None,
        }
        check_deadline()
        report(
            2,
            "complete",
            f"4096 coordinates ready · classifier {prediction.get('status', 'untrained')}",
        )

        report(3, "running", "Cross-checking optional public intelligence feeds")
        if settings.get("osint_enabled", False):
            indicator = (
                candidate
                if is_url or not is_file
                else hashlib.sha256(raw_data).hexdigest()
            )
            intelligence = asyncio.run(
                GlobalIntelligenceEngine().query_indicator(indicator)
            )
        else:
            intelligence = _disabled_intelligence()
        check_deadline()
        report(
            3,
            "complete",
            f"Public lookups {intelligence['status']} · no file contents are submitted",
        )

        scan_result.osint_summary = intelligence
        quiet = naturally_compressed(raw_data[:16]) or str(scan_result.feature_summary.get("authenticode", "")).startswith("valid")
        for anomaly in ([] if quiet else entropy.get("anomalies", [])):
            scan_result.evidence.append(
                Finding(
                    "statistical",
                    str(anomaly.get("severity", "medium")),
                    "Entropy discontinuity",
                    (
                        f"Entropy changed by {float(anomaly.get('delta', 0)):+.3f} "
                        f"bits/byte across offsets "
                        f"0x{int(anomaly.get('offset_start', 0)):X}-"
                        f"0x{int(anomaly.get('offset_end', 0)):X}."
                    ),
                    12,
                )
            )
        signed = str(scan_result.feature_summary.get("authenticode", "")).startswith("valid")
        if meaningful_patterns(cfg.get("detected_patterns")) and not signed:
            scan_result.evidence.append(
                Finding(
                    "structural",
                    "medium",
                    "Static decoding indicator",
                    ", ".join(str(pattern) for pattern in meaningful_patterns(cfg.get("detected_patterns"))),
                    15,
                )
            )
        if intelligence.get("status") == "matched":
            scan_result.evidence.append(
                Finding(
                    "osint",
                    "high",
                    "External threat-intelligence match",
                    "A public feed reported this indicator; correlation is not proof that the file is malicious.",
                    70,
                )
            )
        finalize_result(
            scan_result,
            heuristic_weight=nextgen["heuristic_weight"],
            ml_weight=nextgen["ml_weight"],
        )
        scan_result.engine_status["OSINT"] = str(intelligence.get("status", "unknown"))
        scan_result.nextgen_analysis = nextgen
        return scan_result, nextgen, vector, prediction, intelligence, raw_data
