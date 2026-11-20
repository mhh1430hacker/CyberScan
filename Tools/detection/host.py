"""The only place ``detection`` calls into the host project (``config`` and ``core``).

``detection`` ships into two different host trees: this desktop checkout and the website
checkout (``CyberScan-web``). Their ``core`` packages have diverged; for example the website's
``evaluate_heuristics`` has no ``scan_content`` keyword and its ``config`` has no
``resolve_settings``. Calling those directly made archive inspection fail silently and the
web entry points raise ``ImportError``. Every host call therefore goes through this module,
which adapts to the host's signatures and degrades to a documented fallback.

The host is located from this file's path (``<root>/Tools/detection`` -> ``<root>/Web``),
never from the working directory or from whatever happens to be on ``sys.path``, so the
engine behaves the same from any checkout path and from the mobile bundle, where no host
exists at all.
"""
from __future__ import annotations

import inspect
import math
import sys
from pathlib import Path
from typing import Any

DEFAULT_MAXIMUM_FILE_SIZE = 50 * 1024 * 1024


def _project_root() -> Path | None:
    """The checkout that owns this engine, or None when it is not on disk.

    ``detection`` is imported from ``Tools/detection`` in this checkout and from
    the extracted mobile bundle (``/home/pyodide``) on a phone. The root is
    found from the file location, never from the working directory.
    """
    for candidate in Path(__file__).resolve().parents:
        if (candidate / "Tools" / "detection").is_dir():
            return candidate
    return None


def _host_import(module: str) -> Any:
    """Import a host module (``core.*``, ``config``) from the Web checkout.

    The host is only reachable when the Web component is part of the same
    checkout; otherwise the caller falls back to the documented behaviour.
    """
    try:
        return __import__(module, fromlist=["*"])
    except ImportError:
        root = _project_root()
        if root is None:
            raise
        web_root = str(root / "Web")
        if web_root not in sys.path:
            sys.path.insert(0, web_root)
        return __import__(module, fromlist=["*"])


# Public name used by engine.py; the host is resolved on every call because
# the Web checkout may be added to sys.path after this module is imported.
host_import = _host_import


def shannon_entropy(data: bytes | bytearray | memoryview) -> float:
    """Shannon entropy in bits per byte, rounded to three decimals.

    Uses the host's implementation when one is importable so results stay
    identical to the website, and an equivalent local computation otherwise
    (the mobile bundle and a standalone ``Tools`` checkout have no host).
    """
    try:
        host_entropy = _host_import("core.entropy").shannon_entropy
    except (ImportError, AttributeError):
        host_entropy = None
    if host_entropy is not None:
        return host_entropy(data)
    view = memoryview(data).cast("B")
    length = len(view)
    if not length:
        return 0.0
    counts = [0] * 256
    for value in view:
        counts[value] += 1
    weighted = math.fsum(count * math.log2(count) for count in counts if count > 0)
    return round(max(0.0, min(8.0, math.log2(length) - weighted / length)), 3)


def core_content_findings(text: str) -> list[dict[str, Any]]:
    """Run the host's heuristic rules on decoded content; [] if the host has none."""
    try:
        evaluate_heuristics = _host_import("core.heuristic_engine").evaluate_heuristics
    except (ImportError, AttributeError):
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
        config = _host_import("config")
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
        evaluate_heuristics = _host_import("core.heuristic_engine").evaluate_heuristics
        report["heuristic_engine"] = "content-aware" if "scan_content" in inspect.signature(evaluate_heuristics).parameters else "basic"
    except (ImportError, AttributeError):
        report["heuristic_engine"] = "missing"
    for module, attribute, key in (("core.file_analyzer", "analyze_file", "file_analyzer"),
                                   ("core.scanner", "scan_target", "scanner"),
                                   ("core.qr_scanner", "analyze_qr_image", "qr_decoder")):
        try:
            report[key] = "available" if hasattr(_host_import(module), attribute) else "missing"
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
