from __future__ import annotations

import json
from pathlib import Path
from typing import Any

try:
    import yara
except Exception:  # pragma: no cover - optional dependency
    yara = None

from core import protection
from core.heuristic_engine import evaluate_heuristics

RULES_DIR = Path(__file__).resolve().parents[1] / "rules"


def discover_yara_rules(rules_dir: str | Path | None = None) -> list[Path]:
    base_dir = Path(rules_dir) if rules_dir else RULES_DIR
    if not base_dir.exists():
        return []
    return sorted([
        path for path in base_dir.rglob("*.yar") if path.is_file()
    ] + [
        path for path in base_dir.rglob("*.yara") if path.is_file()
    ], key=lambda p: p.name)


def load_yara_rules(rules_dir: str | Path | None = None) -> list[Path]:
    return discover_yara_rules(rules_dir)


_compiled: dict[tuple, Any] = {}


def _compile(rule_files: list[Path]) -> Any:
    """Compile once per set of rule files (and their change times), not on every scan."""
    key = tuple((str(p), p.stat().st_mtime_ns) for p in rule_files)
    if key not in _compiled:
        _compiled.clear()
        _compiled[key] = yara.compile(filepaths={path.stem: str(path) for path in rule_files})
    return _compiled[key]


def _with_forge(result: dict[str, Any], data: bytes, timeout_seconds: int) -> dict[str, Any]:
    """Add the YARA-Forge rule set (YARA-X) when this installation has it."""
    forge = protection.forge_scan(data, timeout_seconds)
    if not forge["available"]:
        return result
    seen = {m["rule_name"] for m in result["matches"]}
    result["matches"] += [m for m in forge["matches"] if m["rule_name"] not in seen]
    result["rules_loaded"] = int(result.get("rules_loaded") or 0) + int(forge["rules_loaded"] or 0)
    result["available"] = True
    if forge["error"] and not result.get("error"):
        result["error"] = forge["error"]
    elif result.get("error") and result["error"].startswith("yara-python is not installed"):
        result["error"] = None   # the bundled rules need yara-python; YARA-Forge ran without it
    return result


def scan_bytes_with_yara(
    data: bytes,
    rules_dir: str | Path | None = None,
    *,
    timeout_seconds: int = 10,
) -> dict[str, Any]:
    if yara is None:
        return _with_forge({
            "available": False,
            "error": "yara-python is not installed.",
            "matches": [],
            "rules_loaded": 0,
        }, data, timeout_seconds)

    rule_files = discover_yara_rules(rules_dir)
    if not rule_files:
        return {
            "available": True,
            "error": "No .yar rules were found in the configured rules directory.",
            "matches": [],
            "rules_loaded": 0,
        }

    try:
        compiled = _compile(rule_files)
        matches = compiled.match(data=data, timeout=timeout_seconds)
    except Exception as exc:  # pragma: no cover - runtime dependency issue
        return {
            "available": False,
            "error": f"Rule compilation failed: {exc}",
            "matches": [],
            "rules_loaded": len(rule_files),
        }

    structured_matches: list[dict[str, Any]] = []
    for match in matches:
        metadata = getattr(match, "meta", {}) or {}
        structured_matches.append({
            "rule_name": match.rule,
            "tags": list(getattr(match, "tags", []) or []),
            "description": metadata.get("description", "No description available."),
            "matched_strings": [
                "{}:{}".format(item[0], item[1]) if isinstance(item, tuple) and len(item) >= 2 else str(item)
                for item in getattr(match, "strings", [])
            ],
            "meta": dict(metadata),
        })

    return _with_forge({
        "available": True,
        "error": None,
        "matches": structured_matches,
        "rules_loaded": len(rule_files),
    }, data, timeout_seconds)


def scan_file_for_yara(
    file_path: str | Path,
    rules_dir: str | Path | None = None,
    *,
    data: bytes | None = None,
    timeout_seconds: int = 10,
) -> dict[str, Any]:
    path = Path(file_path)
    if data is None and not path.exists():
        return {
            "available": False,
            "error": f"File not found: {path}",
            "matches": [],
            "rules_loaded": 0,
        }
    if data is None:
        try:
            data = path.read_bytes()
        except OSError as exc:
            return {
                "available": False,
                "error": f"Unable to read file for YARA scan: {exc}",
                "matches": [],
                "rules_loaded": 0,
            }
    return scan_bytes_with_yara(data, rules_dir=rules_dir, timeout_seconds=timeout_seconds)


def yara_evidence_from_matches(yara_result: dict[str, Any]) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    for item in yara_result.get("matches", []):
        evidence.append({
            "rule_name": item.get("rule_name", "Unknown Rule"),
            "tags": item.get("tags", []),
            "description": item.get("description", "No description available."),
            "matched_strings": item.get("matched_strings", []),
        })
    return evidence
