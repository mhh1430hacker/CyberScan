from __future__ import annotations

import csv
import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

VALID_LABELS = {"clean", "suspicious", "malware"}


def compute_sha256(path: Path) -> str:
    """Compute SHA-256 hash of a file."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

@dataclass
class ManifestEntry:
    path: str
    label: str
    sha256: str
    source: str
    collection_date: str | None = None
    family: str | None = None
    verification_status: str = "uncertain"
    provenance_notes: str = ""

    def __post_init__(self) -> None:
        self.path = self.path.strip()
        self.label = self.label.strip().lower()
        self.sha256 = self.sha256.strip().lower()
        self.source = self.source.strip()


@dataclass
class ValidationResult:
    is_valid: bool = False
    valid_entries: list[ManifestEntry] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    missing_files: list[str] = field(default_factory=list)
    duplicate_hashes: dict[str, list[ManifestEntry]] = field(default_factory=dict)
    invalid_labels: dict[str, list[str]] = field(default_factory=dict)
    manifest_hash: str | None = None


def validate_manifest(
    manifest_path: Path,
    dataset_root: Path,
    compute_hashes: bool = True,
) -> ValidationResult:
    """Validate a dataset manifest against the filesystem and schema."""
    result = ValidationResult()
    result.manifest_hash = _compute_file_hash(manifest_path)

    if not manifest_path.is_file():
        result.errors.append(f"Manifest not found: {manifest_path}")
        return result

    seen_hashes: dict[str, list[ManifestEntry]] = {}
    row_num = 0

    try:
        with manifest_path.open("r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            if reader.fieldnames is None:
                result.errors.append("Empty manifest CSV")
                return result

            required_fields = {"path", "label", "source"}
            if compute_hashes:
                required_fields.add("sha256")
            missing_fields = required_fields - set(reader.fieldnames)
            if missing_fields:
                result.errors.append(f"Missing required columns: {sorted(missing_fields)}")
                return result

            for row in reader:
                row_num += 1
                path = row.get("path", "").strip()
                label = row.get("label", "").strip().lower()
                sha256 = row.get("sha256", "").strip().lower()
                source = row.get("source", "").strip()
                collection_date = row.get("collection_date", "").strip() or None
                family = row.get("family", "").strip() or None
                verification_status = row.get("verification_status", "uncertain").strip().lower()
                provenance_notes = row.get("provenance_notes", "").strip()

                if not path:
                    result.errors.append(f"Row {row_num}: Empty path")
                    continue
                if not label:
                    result.errors.append(f"Row {row_num}: Empty label")
                    continue
                if compute_hashes:
                    if not sha256:
                        result.errors.append(f"Row {row_num}: Empty SHA-256")
                        continue
                    if len(sha256) != 64 or not all(c in "0123456789abcdef" for c in sha256):
                        result.errors.append(f"Row {row_num}: SHA-256 must be 64 hex characters, got: {sha256}")
                        continue
                if not source:
                    result.errors.append(f"Row {row_num}: Empty source")
                    continue

                if label not in VALID_LABELS:
                    result.invalid_labels.setdefault(label, []).append(path)
                    result.errors.append(f"Row {row_num}: Invalid label '{label}' (valid: {VALID_LABELS})")
                    continue

                full_path = (dataset_root / path).resolve()
                if not full_path.is_relative_to(dataset_root.resolve()):
                    result.errors.append(f"Row {row_num}: Path escapes dataset root: {path}")
                    continue

                if not full_path.is_file():
                    result.missing_files.append(str(full_path))
                    result.errors.append(f"Row {row_num}: File not found: {full_path}")
                    continue

                if compute_hashes:
                    actual_hash = _compute_file_hash(full_path)
                    if actual_hash != sha256:
                        result.errors.append(
                            f"Row {row_num}: SHA-256 mismatch for {path}: expected {sha256}, got {actual_hash}"
                        )
                        continue

                entry = ManifestEntry(
                    path=path,
                    label=label,
                    sha256=sha256,
                    source=source,
                    collection_date=collection_date,
                    family=family,
                    verification_status=verification_status,
                    provenance_notes=provenance_notes,
                )
                result.valid_entries.append(entry)
                seen_hashes.setdefault(sha256, []).append(entry)

    except csv.Error as e:
        result.errors.append(f"CSV parsing error: {e}")
        return result

    for hash_val, entries in seen_hashes.items():
        if compute_hashes and len(entries) > 1:
            result.duplicate_hashes[hash_val] = entries
            paths = [e.path for e in entries]
            labels = {e.label for e in entries}
            if len(labels) > 1:
                result.errors.append(f"Conflicting labels {labels} for identical SHA-256 {hash_val[:16]}... across paths: {paths}")
            else:
                result.errors.append(f"Duplicate SHA-256 {hash_val[:16]}... across paths: {paths}")
    if not result.valid_entries:
        result.errors.append("No valid entries in manifest")
    else:
        label_counts: dict[str, int] = {}
        for entry in result.valid_entries:
            label_counts[entry.label] = label_counts.get(entry.label, 0) + 1
        for label in VALID_LABELS:
            if label not in label_counts:
                result.warnings.append(f"No samples for label: {label}")

    result.is_valid = len(result.errors) == 0
    return result


def _compute_file_hash(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def load_manifest(
    manifest_path: Path,
    dataset_root: Path,
    compute_hashes: bool = True,
) -> list[ManifestEntry]:
    """Load and validate a manifest, returning only valid entries."""
    result = validate_manifest(manifest_path, dataset_root, compute_hashes=compute_hashes)
    if not result.is_valid:
        raise ValueError(f"Manifest validation failed: {result.errors}")
    return result.valid_entries