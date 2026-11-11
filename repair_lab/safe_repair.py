from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class RepairAction:
    step: str
    outcome: str
    detail: str
    path: str | None = None


@dataclass
class RepairOutcome:
    accepted: bool
    action_taken: bool
    restored: bool
    reason: str
    backup_path: str | None = None
    restored_path: str | None = None
    original_hash: str | None = None
    reference_hash: str | None = None
    restored_hash: str | None = None
    actions: list[RepairAction] = field(default_factory=list)


def _sha256(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _load_json(path: str | Path) -> Any:
    with Path(path).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _load_trust_manifest(manifest_path: str | Path | None) -> dict[str, Any]:
    if manifest_path is None:
        return {}
    path = Path(manifest_path)
    if not path.exists():
        raise FileNotFoundError(f"Trust manifest missing: {path}")
    try:
        payload = _load_json(path)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Trust manifest is invalid JSON: {path}") from exc
    if not isinstance(payload, dict):
        raise ValueError("Trust manifest must be a JSON object")
    return payload


def validate_reference(reference_path: str | Path, manifest_path: str | Path | None = None) -> dict[str, Any]:
    reference = Path(reference_path)
    if not reference.exists():
        raise FileNotFoundError(f"Trusted reference is missing: {reference}")
    if reference.suffix.lower() != ".json":
        raise ValueError("This prototype only supports JSON configuration files for verified repair.")
    try:
        payload = _load_json(reference)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Reference file is not valid JSON: {reference}") from exc
    if not isinstance(payload, dict):
        raise ValueError("Reference file must contain a JSON object to be considered a valid configuration.")

    manifest = _load_trust_manifest(manifest_path)
    entry = manifest.get("files", {}).get(reference.name)
    if manifest and (entry is None or not entry.get("trusted")):
        raise ValueError(f"Reference is not trusted or is missing from the manifest: {reference.name}")
    if entry:
        expected_hash = entry.get("sha256")
        if not isinstance(expected_hash, str):
            raise ValueError(f"Manifest entry for {reference.name} is missing sha256.")
        actual_hash = _sha256(reference)
        if actual_hash != expected_hash:
            raise ValueError(f"Reference hash mismatch: manifest says {expected_hash}, actual file hash is {actual_hash}.")
    return payload


def repair_file(
    candidate_path: str | Path,
    reference_path: str | Path,
    manifest_path: str | Path | None,
    *,
    output_path: str | Path | None = None,
) -> RepairOutcome:
    candidate = Path(candidate_path)
    reference = Path(reference_path)
    if not candidate.exists():
        raise FileNotFoundError(f"Candidate file is missing: {candidate}")
    if candidate.suffix.lower() != ".json" or reference.suffix.lower() != ".json":
        raise ValueError("This prototype only supports JSON configuration files.")

    reference_payload = validate_reference(reference, manifest_path)
    candidate_payload = _load_json(candidate)
    if not isinstance(candidate_payload, dict):
        raise ValueError("Candidate file must contain a JSON object to be repairable by this workflow.")

    original_hash = _sha256(candidate)
    reference_hash = _sha256(reference)
    actions: list[RepairAction] = []

    if candidate_payload == reference_payload:
        return RepairOutcome(
            accepted=True,
            action_taken=False,
            restored=False,
            reason="Candidate already matches a trusted clean reference; repair not needed.",
            backup_path=None,
            restored_path=None,
            original_hash=original_hash,
            reference_hash=reference_hash,
            restored_hash=reference_hash,
            actions=[RepairAction("integrity_check", "ok", "Candidate matches the trusted reference.")],
        )

    if output_path is None:
        output_path = candidate.with_name(f"{candidate.stem}.restored.json")
    output_file = Path(output_path)
    if not output_file.parent.exists():
        raise ValueError(f"Refusing to write repaired output because the parent directory does not exist: {output_file.parent}")
    if output_file.exists():
        raise ValueError(f"Refusing to overwrite an existing output file: {output_file}")

    backup_path = candidate.with_name(f"{candidate.name}.backup")
    if backup_path.exists():
        backup_path.unlink()
    backup_path.write_bytes(candidate.read_bytes())
    actions.append(RepairAction("backup", "ok", "Original candidate preserved before repair.", str(backup_path)))

    try:
        reference_bytes = reference.read_bytes()
        output_file.write_bytes(reference_bytes)
        restored_hash = _sha256(output_file)
        if restored_hash != reference_hash:
            raise ValueError("Verified restoration failed: output hash does not match the trusted reference.")
        actions.append(RepairAction("restore", "ok", "Trusted reference bytes were restored to a new output file.", str(output_file)))
        actions.append(RepairAction("verify", "ok", "Restored output matched the trusted reference hash.", str(output_file)))
        return RepairOutcome(
            accepted=True,
            action_taken=True,
            restored=True,
            reason="Repair completed with a verified trusted-reference restore.",
            backup_path=str(backup_path),
            restored_path=str(output_file),
            original_hash=original_hash,
            reference_hash=reference_hash,
            restored_hash=restored_hash,
            actions=actions,
        )
    except Exception as exc:  # pragma: no cover - exercised in tests via failure-path assertions.
        if output_file.exists():
            output_file.unlink()
        actions.append(RepairAction("restore", "failed", f"Repair refused or failed: {exc}", str(output_file)))
        return RepairOutcome(
            accepted=True,
            action_taken=False,
            restored=False,
            reason=f"Repair did not complete safely: {exc}",
            backup_path=str(backup_path),
            restored_path=None,
            original_hash=original_hash,
            reference_hash=reference_hash,
            restored_hash=None,
            actions=actions,
        )
