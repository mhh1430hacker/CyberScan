from __future__ import annotations

import json
from pathlib import Path

import pytest

from safe_repair import repair_file, validate_reference


ROOT = Path(__file__).resolve().parent
FIXTURES = ROOT / "fixtures"
REFERENCE = FIXTURES / "trusted_reference.json"
MANIFEST = FIXTURES / "trusted_reference_manifest.json"


def _write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def _current_hash(path: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def test_unchanged_file_requires_no_repair(tmp_path):
    candidate = tmp_path / "candidate.json"
    _write_json(candidate, {"name": "demo", "mode": "safe", "retries": 2})
    _write_json(REFERENCE, {"name": "demo", "mode": "safe", "retries": 2})
    manifest = {"files": {REFERENCE.name: {"sha256": _current_hash(REFERENCE), "trusted": True}}}
    MANIFEST.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")

    result = repair_file(candidate, REFERENCE, MANIFEST)

    assert result.accepted is True
    assert result.action_taken is False
    assert result.restored is False
    assert result.backup_path is None


def test_modified_file_restores_verified_reference(tmp_path):
    candidate = tmp_path / "candidate.json"
    _write_json(candidate, {"name": "demo", "mode": "unsafe", "retries": 9})
    _write_json(REFERENCE, {"name": "demo", "mode": "safe", "retries": 2})
    manifest = {"files": {REFERENCE.name: {"sha256": _current_hash(REFERENCE), "trusted": True}}}
    MANIFEST.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
    output = tmp_path / "restored.json"

    result = repair_file(candidate, REFERENCE, MANIFEST, output_path=output)

    assert result.accepted is True
    assert result.restored is True
    assert result.backup_path is not None
    assert output.exists()
    assert _load_json(output) == _load_json(REFERENCE)


def test_missing_reference_is_refused(tmp_path):
    candidate = tmp_path / "candidate.json"
    _write_json(candidate, {"name": "demo", "mode": "unsafe"})
    missing = tmp_path / "missing_reference.json"
    with pytest.raises(FileNotFoundError):
        validate_reference(missing, MANIFEST)


def test_invalid_reference_is_refused(tmp_path):
    candidate = tmp_path / "candidate.json"
    _write_json(candidate, {"name": "demo"})
    invalid = tmp_path / "invalid_reference.json"
    invalid.write_text("{not valid json}", encoding="utf-8")
    with pytest.raises(ValueError):
        validate_reference(invalid, MANIFEST)


def test_integrity_check_failure_refuses_repair(tmp_path):
    candidate = tmp_path / "candidate.json"
    _write_json(candidate, {"name": "demo", "mode": "unsafe"})
    clean = tmp_path / "clean.json"
    _write_json(clean, {"name": "demo", "mode": "safe"})
    manifest = {"files": {clean.name: {"sha256": "00" * 32, "trusted": True}}}
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError):
        validate_reference(clean, manifest_path)


def test_failed_repair_keeps_original_intact(tmp_path):
    candidate = tmp_path / "candidate.json"
    original = {"name": "demo", "mode": "unsafe"}
    _write_json(candidate, original)
    reference = tmp_path / "reference.json"
    _write_json(reference, {"name": "demo", "mode": "safe"})
    manifest = {"files": {reference.name: {"sha256": _current_hash(reference), "trusted": True}}}
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    output = tmp_path / "missing_dir" / "restored.json"

    with pytest.raises(ValueError):
        repair_file(candidate, reference, manifest_path, output_path=output)

    assert json.loads(candidate.read_text(encoding="utf-8")) == original
    assert candidate.exists()


def _load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))
