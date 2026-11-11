"""Tests for dataset manifest validation and leakage detection."""

import json
import tempfile
from pathlib import Path

import pytest

from ml.dataset_manifest import (
    ManifestEntry,
    validate_manifest,
    compute_sha256,
)
from ml.dataset_loader import (
    prepare_dataset,
    check_leakage,
)


def test_manifest_validation_rejects_missing_file():
    """Missing files must be rejected."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        dataset_root = tmp_path / "data"
        dataset_root.mkdir()
        manifest_path = dataset_root / "manifest.csv"

        # Write manifest referencing a non-existent file
        with manifest_path.open("w", encoding="utf-8") as f:
            f.write("path,label,sha256,source\n")
            f.write("nonexistent.bin,clean,0000000000000000000000000000000000000000000000000000000000000000,internal\n")

        result = validate_manifest(manifest_path, dataset_root, compute_hashes=False)
        assert not result.is_valid
        assert any("File not found" in issue for issue in result.errors)


def test_manifest_validation_rejects_invalid_sha256():
    """Malformed SHA-256 must be rejected."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        dataset_root = tmp_path / "data"
        dataset_root.mkdir()
        manifest_path = dataset_root / "manifest.csv"
        sample_path = dataset_root / "sample.bin"
        sample_path.write_bytes(b"test content")

        with manifest_path.open("w", encoding="utf-8") as f:
            f.write("path,label,sha256,source\n")
            f.write("sample.bin,clean,not_a_valid_sha256,internal\n")

        result = validate_manifest(manifest_path, dataset_root, compute_hashes=True)
        assert not result.is_valid
        assert any("SHA-256" in issue for issue in result.errors)


def test_manifest_validation_rejects_duplicate_hashes():
    """Duplicate SHA-256 hashes must be flagged."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        dataset_root = tmp_path / "data"
        dataset_root.mkdir()
        manifest_path = dataset_root / "manifest.csv"

        # Create two files with identical content
        (dataset_root / "a.bin").write_bytes(b"identical content")
        (dataset_root / "b.bin").write_bytes(b"identical content")

        with manifest_path.open("w", encoding="utf-8") as f:
            f.write("path,label,sha256,source\n")
            f.write("a.bin,clean,15bbe85aac4518db7da507997bd8b9baa07ddea5d0a08d098f85f1bf08c02521,internal\n")
            f.write("b.bin,malware,15bbe85aac4518db7da507997bd8b9baa07ddea5d0a08d098f85f1bf08c02521,internal\n")

        result = validate_manifest(manifest_path, dataset_root, compute_hashes=True)
        assert not result.is_valid
        assert any("Conflicting labels" in issue for issue in result.errors)

def test_manifest_validation_accepts_valid_entries():
    """Valid manifest should pass validation."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        dataset_root = tmp_path / "data"
        dataset_root.mkdir()
        manifest_path = dataset_root / "manifest.csv"
        (dataset_root / "sample.bin").write_bytes(b"unique content")

        with manifest_path.open("w", encoding="utf-8") as f:
            f.write("path,label,sha256,source\n")
            f.write("sample.bin,clean,0000000000000000000000000000000000000000000000000000000000000000,internal\n")

        result = validate_manifest(manifest_path, dataset_root, compute_hashes=False)
        assert result.is_valid
        assert len(result.errors) == 0


def test_dataset_loader_prevents_hash_leakage():
    """Group-aware split must prevent hash leakage between splits."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        dataset_root = tmp_path / "data"
        dataset_root.mkdir()
        manifest_path = dataset_root / "manifest.csv"

        # Create files with unique content and explicit families
        # Need enough groups for 3 splits with 0.7/0.15/0.15 ratios
        # 10 groups -> train=7, val=1, test=2
        labels = ["clean", "suspicious", "malware"] * 4  # 12 samples
        for i, label in enumerate(labels):
            filename = f"sample_{i}.bin"
            content = f"unique content {i}".encode()
            (dataset_root / filename).write_bytes(content)

        with manifest_path.open("w", encoding="utf-8") as f:
            f.write("path,label,sha256,source,family\n")
            for i, label in enumerate(labels):
                filename = f"sample_{i}.bin"
                sha256 = compute_sha256(dataset_root / filename)
                family = f"family_{i}"
                f.write(f"{filename},{label},{sha256},internal,{family}\n")

        bundle = prepare_dataset(manifest_path, dataset_root, split_method="group_aware", seed=42)
        issues = check_leakage(bundle)
        assert not issues, f"Leakage detected: {issues}"


def test_dataset_loader_group_aware_split_fails_with_insufficient_groups():
    """Group-aware split should fail when too few independent groups exist."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        dataset_root = tmp_path / "data"
        dataset_root.mkdir()
        manifest_path = dataset_root / "manifest.csv"

        # Create only 2 families for 3 splits - should fail
        for i in range(6):
            filename = f"sample_{i}.bin"
            content = f"content {i}".encode()
            (dataset_root / filename).write_bytes(content)

        with manifest_path.open("w", encoding="utf-8") as f:
            f.write("path,label,sha256,source,family\n")
            for i in range(6):
                filename = f"sample_{i}.bin"
                sha256 = compute_sha256(dataset_root / filename)
                # Only 2 families total
                family = "family_A" if i < 3 else "family_B"
                f.write(f"{filename},clean,{sha256},internal,{family}\n")

        with pytest.raises(ValueError, match="empty partition"):
            prepare_dataset(manifest_path, dataset_root, split_method="group_aware", seed=42)


def test_manifest_entry_compute_sha256():
    """SHA-256 computation must be correct."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"hello world")
        expected = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        assert compute_sha256(test_file) == expected