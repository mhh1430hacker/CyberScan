from __future__ import annotations

import hashlib
import os
import secrets
import time
import uuid
import math
from pathlib import Path
from typing import Callable, TypeVar

from config import DEFAULT_SETTINGS
from core.file_analyzer import analyze_file
from core.mitre_mapper import map_findings_to_mitre
from core.models import Finding, ScanResult
from core.risk_engine import finalize_result
from core.text_analyzer import analyze_text_target
from core.url_analyzer import analyze_url

_VAULT_MAGIC = b"CSQ1"
_VAULT_NONCE_SIZE = 12
_VAULT_TAG_SIZE = 16
_CHUNK_SIZE = 1024 * 1024
_T = TypeVar("_T")


def _validate_vault_key(key: bytes) -> None:
    if not isinstance(key, bytes) or len(key) not in {16, 24, 32}:
        raise ValueError("AES-GCM key must be 16, 24, or 32 bytes and supplied by the caller.")


def _retry_file_operation(
    operation: Callable[[], _T],
    retries: int,
    retry_delay: float,
) -> _T:
    for attempt in range(retries + 1):
        try:
            return operation()
        except OSError as exc:
            winerror = getattr(exc, "winerror", None)
            is_transient_lock = isinstance(exc, PermissionError) or winerror in {32, 33}
            if not is_transient_lock or attempt == retries:
                raise
            time.sleep(retry_delay * (attempt + 1))
    raise RuntimeError("File operation retry loop ended unexpectedly.")


def quarantine_file(
    file_path: str | Path,
    key: bytes,
    destination_directory: str | Path | None = None,
    *,
    dry_run: bool = True,
    authorized: bool = False,
    retries: int = 3,
    retry_delay: float = 0.1,
) -> Path | None:
    """Plan by default; on explicit authorization, encrypt then remove the source.

    The key is intentionally never written to disk. Keep it in a secure
    external store; losing it makes the quarantined file unrecoverable. A
    non-dry-run operation also requires ``authorized=True``.
    """
    _validate_vault_key(key)
    if not isinstance(dry_run, bool) or not isinstance(authorized, bool):
        raise TypeError("dry_run and authorized must be booleans.")
    if isinstance(retries, bool) or not isinstance(retries, int) or retries < 0:
        raise ValueError("retries must be a non-negative integer.")
    if (
        isinstance(retry_delay, bool)
        or not isinstance(retry_delay, (int, float))
        or not math.isfinite(retry_delay)
        or retry_delay < 0
    ):
        raise ValueError("retry_delay must be a non-negative number.")

    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError as exc:
        raise RuntimeError("The cryptography package is required for encrypted quarantine.") from exc

    source = Path(file_path)
    if source.is_symlink():
        raise ValueError("Quarantine does not accept symbolic-link sources.")
    if not source.is_file():
        raise FileNotFoundError(source)
    if dry_run:
        return None
    if not authorized:
        raise PermissionError("Quarantine requires explicit authorization.")

    destination_dir = Path(
        destination_directory or DEFAULT_SETTINGS["quarantine_directory"]
    )
    destination_dir.mkdir(parents=True, exist_ok=True)
    destination = destination_dir / f"{source.name}.{uuid.uuid4().hex}.csq"
    temporary = destination.with_name(f".{destination.name}.tmp")

    def encrypt_to_temporary() -> tuple[int, int, int, int, str]:
        nonce = secrets.token_bytes(_VAULT_NONCE_SIZE)
        try:
            with source.open("rb") as input_file, temporary.open("xb") as output_file:
                initial_stat = os.fstat(input_file.fileno())
                source_digest = hashlib.sha256()
                output_file.write(_VAULT_MAGIC + nonce)
                encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
                while True:
                    chunk = input_file.read(_CHUNK_SIZE)
                    if not chunk:
                        break
                    source_digest.update(chunk)
                    output_file.write(encryptor.update(chunk))
                output_file.write(encryptor.finalize())
                output_file.write(encryptor.tag)
                output_file.flush()
                os.fsync(output_file.fileno())
                final_stat = os.fstat(input_file.fileno())
        except OSError:
            temporary.unlink(missing_ok=True)
            raise
        if (
            initial_stat.st_size,
            initial_stat.st_mtime_ns,
            initial_stat.st_dev,
            initial_stat.st_ino,
        ) != (
            final_stat.st_size,
            final_stat.st_mtime_ns,
            final_stat.st_dev,
            final_stat.st_ino,
        ):
            raise RuntimeError("Source file changed while it was being quarantined.")
        return (
            initial_stat.st_size,
            initial_stat.st_mtime_ns,
            initial_stat.st_dev,
            initial_stat.st_ino,
            source_digest.hexdigest(),
        )

    try:
        initial_size, initial_mtime, initial_device, initial_inode, initial_digest = _retry_file_operation(
            encrypt_to_temporary, retries, float(retry_delay)
        )
        os.replace(temporary, destination)

        def remove_source() -> None:
            if source.is_symlink():
                raise RuntimeError("Source path changed to a symbolic link before removal.")
            current_stat = source.stat()
            if (
                current_stat.st_size,
                current_stat.st_mtime_ns,
                current_stat.st_dev,
                current_stat.st_ino,
            ) != (
                initial_size,
                initial_mtime,
                initial_device,
                initial_inode,
            ):
                raise RuntimeError("Source file changed before plaintext removal.")
            current_digest = hashlib.sha256()
            with source.open("rb") as current_file:
                opened_stat = os.fstat(current_file.fileno())
                if (opened_stat.st_dev, opened_stat.st_ino) != (
                    initial_device,
                    initial_inode,
                ):
                    raise RuntimeError("Source file was replaced before plaintext removal.")
                while True:
                    chunk = current_file.read(_CHUNK_SIZE)
                    if not chunk:
                        break
                    current_digest.update(chunk)
            if current_digest.hexdigest() != initial_digest:
                raise RuntimeError("Source contents changed before plaintext removal.")
            source.unlink()

        _retry_file_operation(remove_source, retries, float(retry_delay))
    finally:
        temporary.unlink(missing_ok=True)
    return destination


def restore_quarantined_file(
    encrypted_path: str | Path,
    destination_path: str | Path,
    key: bytes,
) -> Path:
    """Authenticate and restore an encrypted quarantine item atomically."""
    _validate_vault_key(key)
    try:
        from cryptography.exceptions import InvalidTag
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError as exc:
        raise RuntimeError("The cryptography package is required for quarantine restore.") from exc

    encrypted = Path(encrypted_path)
    destination = Path(destination_path)
    if not encrypted.is_file():
        raise FileNotFoundError(encrypted)
    if destination.exists():
        raise FileExistsError(destination)
    file_size = encrypted.stat().st_size
    if file_size < len(_VAULT_MAGIC) + _VAULT_NONCE_SIZE + _VAULT_TAG_SIZE:
        raise ValueError("Quarantine file is truncated or has an invalid format.")

    temporary = destination.with_name(f".{destination.name}.{uuid.uuid4().hex}.tmp")
    try:
        with encrypted.open("rb") as input_file:
            header = input_file.read(len(_VAULT_MAGIC) + _VAULT_NONCE_SIZE)
            if len(header) != len(_VAULT_MAGIC) + _VAULT_NONCE_SIZE or not header.startswith(_VAULT_MAGIC):
                raise ValueError("Quarantine file has an unsupported format.")
            nonce = header[len(_VAULT_MAGIC):]
            input_file.seek(-_VAULT_TAG_SIZE, os.SEEK_END)
            tag = input_file.read(_VAULT_TAG_SIZE)
            ciphertext_size = file_size - len(header) - _VAULT_TAG_SIZE
            input_file.seek(len(header))
            decryptor = Cipher(
                algorithms.AES(key),
                modes.GCM(nonce, tag),
            ).decryptor()
            destination.parent.mkdir(parents=True, exist_ok=True)
            with temporary.open("xb") as output_file:
                remaining = ciphertext_size
                while remaining:
                    chunk = input_file.read(min(_CHUNK_SIZE, remaining))
                    if not chunk:
                        raise ValueError("Quarantine file ended before its authentication tag.")
                    remaining -= len(chunk)
                    output_file.write(decryptor.update(chunk))
                output_file.write(decryptor.finalize())
                output_file.flush()
                os.fsync(output_file.fileno())
        # Linking publishes only the authenticated temporary file and refuses
        # to overwrite a destination created after the initial existence check.
        os.link(temporary, destination)
    except InvalidTag as exc:
        raise ValueError("Quarantine authentication failed; the key or file is invalid.") from exc
    finally:
        temporary.unlink(missing_ok=True)
    return destination


def scan_target(
    target: str,
    is_file: bool = False,
    settings: dict | None = None,
    *,
    file_data: bytes | None = None,
) -> ScanResult:
    settings = DEFAULT_SETTINGS if settings is None else settings
    if is_file:
        result = analyze_file(target, settings=settings, file_data=file_data)
        return result
    if target.startswith(("http://", "https://")):
        data = analyze_url(target, enable_heuristics=settings.get("heuristic_rules", True))
        techniques = map_findings_to_mitre(findings=[str(item.get("label", "")) for item in data.get("findings", [])])
        findings = [
            Finding("url", str(item.get("severity", "info")), str(item["label"]), str(item["label"]), int(item.get("contribution", 0)))
            for item in data.get("findings", [])
        ]
        result = ScanResult(
            target=target,
            heuristic_score=int(data["score"]),
            ml_risk_score=None,
            combined_score=int(data["score"]),
            classification=str(data["classification"]),
            evidence=findings,
            feature_summary={},
            model_status="Trained structural classifier not available.",
            limitations="Static analysis active; trained structural classifier not available.",
            summary=f"URL checked with static heuristics; classification: {data['classification']}.",
            mitre_techniques=techniques,
            engine_status={"Heuristics": "enabled" if settings.get("heuristic_rules", True) else "disabled", "OSINT": "not requested"},
        )
        return finalize_result(
            result,
            heuristic_weight=float(settings.get("heuristic_weight", 1.0)),
            ml_weight=float(settings.get("ml_weight", 0.0)),
        )
    data = analyze_text_target(target, enable_heuristics=settings.get("heuristic_rules", True))
    techniques = map_findings_to_mitre(findings=[str(item.get("label", "")) for item in data.get("findings", [])])
    findings = [
        Finding("text", str(item.get("severity", "info")), str(item["label"]), str(item["label"]), int(item.get("contribution", 0)))
        for item in data.get("findings", [])
    ]
    result = ScanResult(
        target=target,
        heuristic_score=int(data["score"]),
        ml_risk_score=None,
        combined_score=int(data["score"]),
        classification=str(data["classification"]),
        evidence=findings,
        feature_summary={},
        model_status="Trained structural classifier not available.",
        limitations="Static analysis active; trained structural classifier not available.",
        summary=str(data["summary"]),
        mitre_techniques=techniques,
        engine_status={"Heuristics": "enabled" if settings.get("heuristic_rules", True) else "disabled", "OSINT": "not requested"},
    )
    return finalize_result(
        result,
        heuristic_weight=float(settings.get("heuristic_weight", 1.0)),
        ml_weight=float(settings.get("ml_weight", 0.0)),
    )
