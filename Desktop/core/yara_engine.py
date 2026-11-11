from __future__ import annotations

from pathlib import Path
from typing import Any

try:
    import yara
except Exception:  # pragma: no cover - optional dependency
    yara = None

RULES_DIR = Path(__file__).resolve().parents[1] / "rules"

# Compiled rules are cached per (rules dir, file mtimes) so scans do not recompile every time.
_COMPILED_CACHE: dict[tuple, Any] = {}


def discover_yara_rules(rules_dir: str | Path | None = None) -> list[Path]:
    base_dir = Path(rules_dir) if rules_dir else RULES_DIR
    if not base_dir.exists():
        return []
    found = {path for pattern in ("*.yar", "*.yara") for path in base_dir.rglob(pattern) if path.is_file()}
    return sorted(found, key=lambda path: str(path))


def load_yara_rules(rules_dir: str | Path | None = None) -> list[Path]:
    return discover_yara_rules(rules_dir)


def _compile(rule_files: list[Path]) -> Any:
    key = tuple((str(path), path.stat().st_mtime_ns) for path in rule_files)
    compiled = _COMPILED_CACHE.get(key)
    if compiled is None:
        # Index-prefixed namespaces avoid collisions between same-named files in sub-folders.
        compiled = yara.compile(filepaths={f"r{index}_{path.stem}": str(path) for index, path in enumerate(rule_files)})
        _COMPILED_CACHE.clear()
        _COMPILED_CACHE[key] = compiled
    return compiled


def _describe_string_match(item: Any) -> str:
    """Support both yara-python >= 4.3 (StringMatch objects) and older tuple results."""
    if isinstance(item, tuple) and len(item) >= 3:
        return f"{item[1]}@{item[0]}"
    identifier = getattr(item, "identifier", None)
    instances = getattr(item, "instances", None)
    if identifier is not None and instances is not None:
        offsets = [getattr(instance, "offset", None) for instance in instances][:5]
        return f"{identifier}@" + ",".join(str(offset) for offset in offsets)
    return str(item)


def _normalize_tags(match: Any, metadata: dict[str, Any]) -> list[str]:
    tags = list(getattr(match, "tags", []) or [])
    meta_tags = metadata.get("tags")
    if isinstance(meta_tags, str):
        tags.extend(tag.strip() for tag in meta_tags.split(",") if tag.strip())
    return sorted(set(tags))


def scan_bytes_with_yara(data: bytes, rules_dir: str | Path | None = None) -> dict[str, Any]:
    if yara is None:
        return {"available": False, "error": "yara-python is not installed.", "matches": [], "rules_loaded": 0}

    rule_files = discover_yara_rules(rules_dir)
    if not rule_files:
        return {
            "available": True,
            "error": "No .yar rules were found in the configured rules directory.",
            "matches": [],
            "rules_loaded": 0,
        }

    try:
        matches = _compile(rule_files).match(data=data)
    except Exception as exc:  # pragma: no cover - runtime dependency issue
        return {
            "available": False,
            "error": f"Rule compilation failed: {exc}",
            "matches": [],
            "rules_loaded": len(rule_files),
        }

    structured_matches: list[dict[str, Any]] = []
    for match in matches:
        metadata = dict(getattr(match, "meta", {}) or {})
        structured_matches.append({
            "rule_name": match.rule,
            "tags": _normalize_tags(match, metadata),
            "description": metadata.get("description", "No description available."),
            "matched_strings": [_describe_string_match(item) for item in getattr(match, "strings", [])],
            "meta": metadata,
        })

    return {"available": True, "error": None, "matches": structured_matches, "rules_loaded": len(rule_files)}


def scan_file_for_yara(
    file_path: str | Path,
    rules_dir: str | Path | None = None,
    max_bytes: int | None = None,
) -> dict[str, Any]:
    path = Path(file_path)
    if not path.exists():
        return {"available": False, "error": f"File not found: {path}", "matches": [], "rules_loaded": 0}
    try:
        with path.open("rb") as handle:
            data = handle.read() if max_bytes is None else handle.read(max_bytes)
    except OSError as exc:
        return {"available": False, "error": f"Unable to read file for YARA scan: {exc}", "matches": [], "rules_loaded": 0}
    return scan_bytes_with_yara(data, rules_dir=rules_dir)


def yara_evidence_from_matches(yara_result: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "rule_name": item.get("rule_name", "Unknown Rule"),
            "tags": item.get("tags", []),
            "description": item.get("description", "No description available."),
            "matched_strings": item.get("matched_strings", []),
        }
        for item in yara_result.get("matches", [])
    ]
