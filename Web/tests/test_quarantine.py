import pytest

from core.scanner import quarantine_file, restore_quarantined_file


def test_quarantine_encrypts_and_authenticates_before_restore(tmp_path):
    pytest.importorskip("cryptography")
    source = tmp_path / "sample.bin"
    original = b"fixture content that must not remain in plaintext"
    source.write_bytes(original)

    assert quarantine_file(source, bytes(range(32)), tmp_path / "vault") is None
    assert source.read_bytes() == original

    encrypted = quarantine_file(
        source,
        bytes(range(32)),
        tmp_path / "vault",
        dry_run=False,
        authorized=True,
    )

    assert not source.exists()
    assert encrypted.read_bytes() != original
    restored = restore_quarantined_file(
        encrypted,
        tmp_path / "restored.bin",
        bytes(range(32)),
    )
    assert restored.read_bytes() == original


def test_quarantine_restore_rejects_wrong_key_without_publishing_plaintext(tmp_path):
    pytest.importorskip("cryptography")
    source = tmp_path / "sample.bin"
    source.write_bytes(b"private fixture")
    encrypted = quarantine_file(
        source,
        b"k" * 32,
        tmp_path / "vault",
        dry_run=False,
        authorized=True,
    )
    destination = tmp_path / "restored.bin"

    with pytest.raises(ValueError, match="authentication failed"):
        restore_quarantined_file(encrypted, destination, b"x" * 32)

    assert not destination.exists()


def test_quarantine_requires_explicit_authorization_for_mutation(tmp_path):
    pytest.importorskip("cryptography")
    source = tmp_path / "sample.bin"
    original = b"keep source until authorized"
    source.write_bytes(original)

    with pytest.raises(PermissionError, match="explicit authorization"):
        quarantine_file(
            source,
            b"k" * 32,
            tmp_path / "vault",
            dry_run=False,
        )

    assert source.read_bytes() == original
    assert not (tmp_path / "vault").exists()


def test_restore_never_overwrites_an_existing_file(tmp_path):
    pytest.importorskip("cryptography")
    source = tmp_path / "sample.bin"
    source.write_bytes(b"original")
    encrypted = quarantine_file(
        source,
        b"k" * 32,
        tmp_path / "vault",
        dry_run=False,
        authorized=True,
    )
    destination = tmp_path / "restored.bin"
    destination.write_bytes(b"unrelated existing content")

    with pytest.raises(FileExistsError):
        restore_quarantined_file(encrypted, destination, b"k" * 32)

    assert destination.read_bytes() == b"unrelated existing content"
