"""Quarantine a scanned file on the user's request, and give it back.

Uses the project's encrypted quarantine (``core.scanner.quarantine_file``,
AES-GCM, explicit authorization required). The vault key is 32 random bytes
created once and stored encrypted for the current Windows user with DPAPI
(``ui.secrets.protect``), so only this account on this machine can restore.
Nothing is ever deleted unencrypted: the file is sealed first, then removed.
"""
from __future__ import annotations

import secrets
from pathlib import Path

from core.scanner import quarantine_file, restore_quarantined_file
from ui.secrets import SecretsUnavailable, protect, unprotect


def _key(data_dir: Path) -> bytes:
    path = Path(data_dir) / "quarantine.key"
    if path.is_file():
        return unprotect(path.read_bytes())
    key = secrets.token_bytes(32)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(protect(key))
    return key


def quarantine(path: str | Path, data_dir: Path, vault_dir: Path) -> Path:
    """Encrypt ``path`` into ``vault_dir`` and remove it. Raises on any problem;
    the original stays where it was unless the sealed copy was written."""
    key = _key(data_dir)
    sealed = quarantine_file(path, key, vault_dir, dry_run=False, authorized=True)
    if sealed is None:
        raise RuntimeError("Quarantine did not produce a sealed copy.")
    return sealed


def restore(sealed: str | Path, original: str | Path, data_dir: Path) -> Path:
    """Decrypt a quarantined file back to ``original`` (never over an existing file)."""
    target = Path(original)
    if target.exists():
        raise FileExistsError(target)
    return restore_quarantined_file(sealed, target, _key(data_dir))


__all__ = ["SecretsUnavailable", "quarantine", "restore"]
