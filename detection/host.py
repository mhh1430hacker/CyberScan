"""The only place ``detection`` calls into the host project (``config`` and ``core``).

``detection`` ships into two different host trees: this desktop checkout and the website
checkout (``CyberScan-web``). Their ``core`` packages have diverged; for example the website's
``evaluate_heuristics`` has no ``scan_content`` keyword and its ``config`` has no
``resolve_settings``. Calling those directly made archive inspection fail silently and the
web entry points raise ``ImportError``. Every host call therefore goes through this module,
which adapts to the host's signatures and degrades to a documented fallback.
"""
from __future__ import annotations

import inspect
from typing import Any

DEFAULT_MAXIMUM_FILE_SIZE = 50 * 1024 * 1024


def core_content_findings(text: str) -> list[dict[str, Any]]:
    """Run the host's heuristic rules on decoded content; [] if the host has none."""
    try:
        from core.heuristic_engine import evaluate_heuristics
    except ImportError:
        return []
    try:
        if "scan_content" in inspect.signature(evaluate_heuristics).parameters:
            raw = evaluate_heuristics(text, scan_content=True).get("findings", [])
        else:
            raw = evaluate_heuristics(text).get("findings", [])
    except Exception:  # a host rule bug must not hide detection's own findings
        return []
    # Hosts disagree on the finding shape (the website's findings have no "explanation"); normalise it.
    findings = []
    for item in raw if isinstance(raw, list) else []:
        if not isinstance(item, dict) or not item.get("label"):
            continue
        label = str(item["label"])
        findings.append({
            "label": label,
            "severity": str(item.get("severity", "low")),
            "contribution": int(item.get("contribution", 0) or 0),
            "explanation": str(item.get("explanation") or label),
        })
    return findings


def resolve_host_settings(overrides: dict[str, Any] | None = None) -> dict[str, Any]:
    """Complete settings dict from the host's defaults, whichever API the host config offers."""
    try:
        import config
    except ImportError:
        config = None
    if config is not None and hasattr(config, "resolve_settings"):
        return dict(config.resolve_settings(overrides))
    merged: dict[str, Any] = dict(getattr(config, "DEFAULT_SETTINGS", {}) or {})
    merged.update(overrides or {})
    merged.setdefault("maximum_file_size", getattr(config, "MAX_FILE_SIZE", DEFAULT_MAXIMUM_FILE_SIZE))
    return merged


def host_capabilities() -> dict[str, Any]:
    """What the host provides. Exposed so an integrator can show it on a health/status endpoint."""
    report: dict[str, Any] = {}
    try:
        from core.heuristic_engine import evaluate_heuristics
        report["heuristic_engine"] = "content-aware" if "scan_content" in inspect.signature(evaluate_heuristics).parameters else "basic"
    except ImportError:
        report["heuristic_engine"] = "missing"
    for module, attribute, key in (("core.file_analyzer", "analyze_file", "file_analyzer"),
                                   ("core.scanner", "scan_target", "scanner"),
                                   ("core.qr_scanner", "analyze_qr_image", "qr_decoder")):
        try:
            report[key] = "available" if hasattr(__import__(module, fromlist=[attribute]), attribute) else "missing"
        except ImportError:
            report[key] = "missing"
    try:
        import pefile  # noqa: F401
        report["pefile"] = "available"
    except ImportError:
        report["pefile"] = "missing (PE structure analysis disabled)"
    try:
        import zxingcpp  # noqa: F401
        report["zxingcpp"] = "available"
    except ImportError:
        report["zxingcpp"] = "missing (QR decoding disabled)"
    return report
