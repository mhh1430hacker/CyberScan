# Claude (AI assistant, Anthropic) worked on this file, 2026-11-06: desktop warnings use evidence_patterns only.
from __future__ import annotations

import asyncio
import hashlib
import math
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from core.magic_bytes import naturally_compressed
from config import DEFAULT_SETTINGS
from core import status_text
from core.deep_embedding import HighDimensionalEmbedding
from core.global_intelligence import GlobalIntelligenceEngine
from core.models import Finding, ScanResult
from core.nextgen_engine import NextGenCyberEngine
from core.risk_engine import finalize_result
from core.scanner import scan_target

ProgressCallback = Callable[[int, str, str], None]
# The longest the optional online lookups may hold up a scan (each source has its own shorter timeout).
OSINT_BUDGET_SECONDS = 5.0


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


def text_cfg_summary(reason: str = "text") -> dict[str, Any]:
    """No code graph: the input is text ("text") or binary data that is not a program ("non-program")."""
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
        "architecture": "text-content-skipped" if reason == "text" else "non-program-skipped",
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


class StageText(str):
    """One progress line: the English words (what string-only callers such as the desktop app show)
    plus ``i18n`` = ``{"code", "en", "ar", ...}`` from ``core.status_text`` for interfaces that
    show it in the reader's language. Behaves exactly like ``str`` everywhere else."""

    i18n: dict[str, Any]

    def __new__(cls, words: dict[str, Any]) -> "StageText":
        text = super().__new__(cls, str(words.get("en", "")))
        text.i18n = dict(words)
        return text

    def __reduce__(self):  # pickles (the desktop app sends progress between processes)
        return (StageText, (self.i18n,))


def _empty_entropy() -> dict[str, Any]:
    return {
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


def _osint_indicator(candidate: str, is_url: bool, is_file: bool, raw_data: bytes) -> str | None:
    """What the public feeds can look up: a file's SHA-256, a link, or a single hash / address /
    domain typed as text. Free text names nothing to look up (no "invalid_indicator" query)."""
    if is_file:
        return hashlib.sha256(raw_data).hexdigest()
    value = candidate.strip()
    if is_url:
        return value
    return value if GlobalIntelligenceEngine._infer_indicator_type(value) else None  # noqa: SLF001


def _not_applicable_intelligence() -> dict[str, Any]:
    return {**_disabled_intelligence(), "status": "not_applicable",
            "feeds": {name: {**feed, "status": "not_applicable"} for name, feed in _disabled_intelligence()["feeds"].items()}}


class ScanService:
    """Runs the existing static-analysis pipeline without coupling it to a UI.

    Time limit: ``analysis_timeout`` bounds the whole pipeline, but running out of time is not an
    error. Whatever finished is returned; stages that didn't start are reported ``skipped``; and
    ``feature_summary["analysis_incomplete"]`` lists what is missing (stable codes plus English and
    Arabic words). Only a static stage that didn't finish leaves the verdict UNKNOWN; evidence
    that was found (50+) stands either way."""

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
        incomplete: list[dict[str, Any]] = []

        def expired() -> bool:
            return time.monotonic() - started_at > timeout

        def skip(index: int, code: str) -> None:
            words = status_text.stage_skipped(index)
            report(index, "skipped", StageText(words))
            incomplete.append({**words, "code": code, "stage": index})

        # Say so instead of guessing: a missing file is not text, and empty input is nothing to check.
        if input_mode == "File" and not Path(candidate).is_file():
            raise FileNotFoundError(f"File not found: {candidate}")
        if input_mode != "File" and not str(candidate).strip():
            raise ValueError("Nothing to check: the input is empty.")
        is_url = input_mode == "URL"
        path = Path(candidate) if not is_url else None
        is_file = input_mode == "File" and bool(path and path.is_file())
        report(0, "running", StageText(status_text.stage_running(0)))
        static_complete = True
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
            try:
                scan_result = scan_target(
                    str(path), is_file=True, settings=settings, file_data=raw_data
                )
            except TimeoutError:
                # The file analysis ran out of time: keep going with what can be said for sure.
                static_complete = False
                scan_result = ScanResult(
                    target=str(path), heuristic_score=0, ml_risk_score=None, combined_score=0,
                    classification="UNKNOWN", evidence=[],
                    feature_summary={"sha256": hashlib.sha256(raw_data).hexdigest(), "file_size": len(raw_data)},
                    summary="The static file analysis didn't finish within the time limit.",
                    engine_status={"Static analysis": "timeout: didn't finish within the time limit"},
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
        if static_complete:
            report(0, "complete", StageText(status_text.stage_static_done(input_mode, len(raw_data) if is_file else len(candidate))))
        else:
            words = status_text.text("stage.static.timeout", "The file analysis didn't finish within the time limit",
                                     "لم يكتمل تحليل الملف ضمن الحد الزمني", "partial")
            report(0, "partial", StageText(words))
            incomplete.append({**words, "stage": 0, "critical": True})

        entropy: dict[str, Any] | None = None
        if expired():
            skip(1, "entropy.skipped_time_limit")
        else:
            report(1, "running", StageText(status_text.stage_running(1)))
            if is_file and settings.get("entropy_analysis", True):
                entropy = scan_result.feature_summary.get("entropy_topography")
            if entropy is None:
                entropy = (
                    NextGenCyberEngine.analyze_entropy_topography(raw_data)
                    if settings.get("entropy_analysis", True)
                    else None
                )
        entropy = entropy or _empty_entropy()
        text_input = looks_like_text(raw_data)
        # Instruction patterns mean something only in a program; read as x86, a picture or a
        # PDF yields nonsense "patterns" (false warnings) and can take tens of seconds.
        program = raw_data[:2] == b"MZ" or raw_data[:4] == b"\x7fELF"
        cfg = (
            NextGenCyberEngine.extract_cfg_topology(raw_data)
            if program and not text_input and not expired()
            else text_cfg_summary("text" if text_input else "non-program")
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
        if not any(item.get("stage") == 1 for item in incomplete):
            report(1, "complete", StageText(status_text.stage_entropy_done(
                len(entropy["trajectory"]), bool(settings.get("entropy_analysis", True)))))

        prediction = scan_result.structural_prediction or {
            "status": "untrained",
            "label": None,
            "class_scores": {},
            "infection_score": None,
            "scores_are_calibrated": False,
            "repair_review_candidate": None,
        }
        if expired():
            skip(2, "structure.skipped_time_limit")
            vector = scan_result.structural_embedding or tuple()
        else:
            report(2, "running", StageText(status_text.stage_running(2)))
            vector = scan_result.structural_embedding or self.embedding.embed_bytes(
                raw_data,
                entropy_topography=entropy,
                cfg_topology=cfg,
                pe_features=scan_result.pe_analysis,
            )
            report(2, "complete", StageText(status_text.stage_structure_done(prediction)))

        known: dict[str, Any] | None = None
        if not settings.get("osint_enabled", False):
            # why they're off: Settings (default), the per-scan switch, or the per-visitor limit (web)
            reason = str(settings.get("osint_off_reason") or "disabled")
            intelligence = {**_disabled_intelligence(), "status": reason}
            report(3, "complete", StageText(status_text.osint_text(reason)))
        elif expired():
            intelligence = {**_disabled_intelligence(), "status": "skipped"}
            skip(3, "osint.skipped_time_limit")
        else:
            report(3, "running", StageText(status_text.stage_running(3)))
            indicator = _osint_indicator(candidate, is_url, is_file, raw_data)
            hash_lookup: dict[str, Any] = {}
            worker = None
            if is_file and raw_data:
                # Known-file sources by hash only (CIRCL needs no key; MalwareBazaar / VirusTotal use
                # saved keys), asked at the same time as the public feeds rather than after them.
                from core import hash_intel  # noqa: PLC0415

                def lookup() -> None:
                    try:
                        hash_lookup["value"] = hash_intel.assess(
                            hashlib.sha256(raw_data).hexdigest(), hashlib.md5(raw_data).hexdigest(), online=True)  # noqa: S324
                    except Exception:  # noqa: BLE001 - an unreachable source is a status, not a failure
                        hash_lookup["value"] = None

                worker = threading.Thread(target=lookup, name="cyberscan-hash-lookup", daemon=True)
                worker.start()
            # Both lookups run at once under one budget; a source that hasn't answered by then is
            # reported as "didn't answer in time" and the scan carries on without it.
            budget_end = time.monotonic() + max(1.0, min(OSINT_BUDGET_SECONDS, timeout - (time.monotonic() - started_at)))
            feeds: dict[str, Any] = {}

            def query() -> None:
                try:
                    if is_url:
                        # Links: VirusTotal (link + site), Google Safe Browsing, URLhaus, OTX and urlscan.io,
                        # report lookups only, rate-limited and cached (core/external_intel.py).
                        from core import external_intel  # noqa: PLC0415

                        budget = max(1.0, budget_end - time.monotonic() - 0.2)
                        feeds["value"] = external_intel.link_intelligence(external_intel.lookup_link(indicator, budget), indicator)
                    else:
                        feeds["value"] = asyncio.run(GlobalIntelligenceEngine().query_indicator(indicator))
                except Exception:  # noqa: BLE001 - unreachable feeds are a status
                    feeds["value"] = {**_disabled_intelligence(), "status": "unavailable"}

            if indicator:
                feeder = threading.Thread(target=query, name="cyberscan-osint", daemon=True)
                feeder.start()
                feeder.join(timeout=max(0.0, budget_end - time.monotonic()))
                intelligence = feeds.get("value") or {**_disabled_intelligence(), "status": "partial_timeout"}
            else:
                intelligence = _not_applicable_intelligence()
            if worker is not None:
                worker.join(timeout=max(0.0, budget_end - time.monotonic()))
                known = hash_lookup.get("value")
                if known is None and worker.is_alive() and intelligence.get("status") not in {"matched", "partial_timeout"}:
                    intelligence = {**intelligence, "status": "partial_timeout"}
            report(3, "complete", StageText(status_text.osint_text(intelligence.get("status"), file_mode=is_file)))

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
        # Only the strict evidence patterns warn (see NextGenCyberEngine._evidence_patterns).
        if cfg.get("evidence_patterns") and not signed:
            scan_result.evidence.append(
                Finding(
                    "structural",
                    "medium",
                    "Static decoding indicator",
                    ", ".join(str(pattern) for pattern in cfg["evidence_patterns"]),
                    15,
                )
            )
        if known is not None:
            intelligence = {**intelligence, "hash_sources": known["sources"]}
            labels = {item.evidence for item in scan_result.evidence}
            for item in known["findings"]:
                if item["label"] not in labels:
                    scan_result.evidence.append(Finding("intel", item["severity"], item["label"], item["explanation"], item["contribution"],
                                                        engines=[str(item.get("source") or "Online lookups")]))
            if any(item["severity"] == "critical" for item in known["findings"]):
                intelligence["status"] = "matched"
            scan_result.osint_summary = intelligence
        external = []
        if intelligence.get("link_sources"):
            from core import external_intel  # noqa: PLC0415

            external = external_intel.link_findings(intelligence["link_sources"])
            labels = {item.evidence for item in scan_result.evidence}
            for item in external:
                if item["label"] not in labels:
                    scan_result.evidence.append(Finding("osint", item["severity"], item["label"], item["explanation"], item["contribution"],
                                                        engines=[item["source"]]))
        if intelligence.get("status") == "matched" and not external:
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
        if incomplete:
            scan_result.feature_summary["analysis_incomplete"] = incomplete
            if not static_complete and scan_result.classification not in {"SUSPICIOUS", "KNOWN_MALWARE"}:
                scan_result.classification = "UNKNOWN"  # what wasn't read can't be called clean
        scan_result.nextgen_analysis = nextgen
        return scan_result, nextgen, vector, prediction, intelligence, raw_data
