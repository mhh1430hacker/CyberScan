"""Which structural model may run, and why not when it may not.

A model runs only after a person approves it: ``python -m ml.approve_model``
records the artifact's path and SHA-256 digest in the trusted-models registry
(``config.TRUSTED_MODELS_FILE``). At scan time the artifact is loaded through
the digest-first safe loader against that recorded digest; any change to the
file after approval makes it fail closed. Nothing is approved by default, and
there is no fallback to another model.

States:
    ready       an approved artifact loaded and verified
    disabled    the user switched the learning model off
    unapproved  no model has been approved yet
    missing     the approved file is no longer there
    rejected    the file failed verification (digest, format, schema)
    error       the registry itself could not be read
"""
from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import config
from ml.forest_format import ModelFormatError, normalize_sha256
from ml.structural_classifier import StructuralClassifier

REGISTRY_KEY = "structural"
READY_STATUS = "4096-D supervised structural classifier loaded; class scores are uncalibrated."
DISABLED_STATUS = "ML analysis disabled by settings."
UNAPPROVED_STATUS = "Structural model unavailable: no approved model is installed; static evidence only."


@dataclass(frozen=True)
class ModelState:
    state: str
    detail: str
    path: str = ""
    sha256: str = ""


class RegistryError(ValueError):
    pass


_lock = threading.Lock()
_cache: dict[tuple[str, str, int, int], StructuralClassifier] = {}


def registry_path() -> Path:
    return Path(config.TRUSTED_MODELS_FILE)


def read_registry() -> dict[str, str] | None:
    """The approved structural model entry, or None when nothing is approved."""
    path = registry_path()
    if not path.is_file():
        return None
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RegistryError(f"unreadable ({exc})") from exc
    if not isinstance(document, dict):
        raise RegistryError("not a JSON object")
    entry = document.get(REGISTRY_KEY)
    if entry is None:
        return None
    if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
        raise RegistryError("the structural entry has no path")
    try:
        digest = normalize_sha256(entry.get("sha256"))
    except ModelFormatError as exc:
        raise RegistryError(str(exc)) from exc
    return {"path": entry["path"], "sha256": digest, "approved_at": str(entry.get("approved_at", ""))}


def _resolve(path_text: str) -> Path:
    path = Path(path_text)
    return path if path.is_absolute() else Path(config.ROOT_DIR) / path


def load_approved(enabled: bool = True) -> tuple[StructuralClassifier | None, ModelState]:
    """The approved classifier, verified, or None with the reason."""
    if not enabled:
        return None, ModelState("disabled", DISABLED_STATUS)
    try:
        entry = read_registry()
    except RegistryError as exc:
        return None, ModelState("error", f"Structural model unavailable: the approved-model registry is {exc}; static evidence only.")
    if entry is None:
        return None, ModelState("unapproved", UNAPPROVED_STATUS)
    path = _resolve(entry["path"])
    digest = entry["sha256"]
    try:
        stat = path.stat()
    except OSError:
        return None, ModelState(
            "missing",
            f"Structural model unavailable: the approved file {path.name} is missing; static evidence only.",
            str(path),
            digest,
        )
    key = (str(path), digest, stat.st_mtime_ns, stat.st_size)
    with _lock:
        cached = _cache.get(key)
    if cached is not None:
        return cached, ModelState("ready", READY_STATUS, str(path), digest)
    classifier = StructuralClassifier(path)
    if not classifier.load(path, expected_sha256=digest):
        reason = classifier.metadata.get("load_error", "verification failed")
        return None, ModelState("rejected", f"Structural model rejected: {reason} Static evidence remains active.", str(path), digest)
    with _lock:
        _cache.clear()
        _cache[key] = classifier
    return classifier, ModelState("ready", READY_STATUS, str(path), digest)


class ApprovedStructuralClassifier(StructuralClassifier):
    """A classifier whose argument-less ``load()`` loads only the approved model.

    ``state`` records why it did or did not load. Explicit
    ``load(path, expected_sha256=...)`` calls behave exactly as in the base class.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.state: ModelState | None = None

    def load(self, path: str | Path | None = None, *, expected_sha256: str | None = None) -> bool:
        if path is not None or expected_sha256 is not None:
            return super().load(path, expected_sha256=expected_sha256)
        loaded, self.state = load_approved(True)
        if loaded is None:
            self.forest = None
            self.artifact_sha256 = None
            return False
        self.model_path = loaded.model_path
        self.forest = loaded.forest
        self.artifact_sha256 = loaded.artifact_sha256
        self.metadata = dict(loaded.metadata)
        return True


def model_state(enabled: bool = True) -> ModelState:
    return load_approved(enabled)[1]


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def approve(path: Path) -> dict[str, Any]:
    """Record ``path`` as the approved structural model, after verifying it.

    The artifact must load through the safe loader with its own digest, so a
    file that is not a valid model for this schema can never be approved.
    """
    path = path.resolve()
    digest = file_sha256(path)
    classifier = StructuralClassifier(path)
    if not classifier.load(path, expected_sha256=digest):
        raise ValueError(classifier.metadata.get("load_error", "the file is not a valid structural model"))
    root = Path(config.ROOT_DIR).resolve()
    stored = str(path.relative_to(root)) if path.is_relative_to(root) else str(path)
    entry = {
        "path": stored,
        "sha256": digest,
        "approved_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    target = registry_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix(".tmp")
    temporary.write_text(json.dumps({REGISTRY_KEY: entry}, indent=2), encoding="utf-8")
    temporary.replace(target)
    with _lock:
        _cache.clear()
    return {**entry, "metadata": dict(classifier.metadata)}


def revoke() -> bool:
    target = registry_path()
    with _lock:
        _cache.clear()
    if target.is_file():
        target.unlink()
        return True
    return False
