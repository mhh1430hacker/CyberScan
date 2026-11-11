"""Explicit, checksum-pinned local GGUF model installation and inference."""
from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any


LOGGER = logging.getLogger(__name__)
MODEL_CATALOG_PATH = Path(__file__).with_name("model_catalog.json")
MAX_MODEL_BYTES = 5 * 1024 * 1024 * 1024
MAX_CONTEXT_LENGTH = 8192
MAX_GENERATION_TOKENS = 1024


class ModelManagerError(RuntimeError):
    """A model could not be safely located, installed, or loaded."""


@dataclass(frozen=True)
class ModelSpec:
    model_id: str
    name: str
    repository: str
    revision: str
    filename: str
    size_bytes: int
    sha256: str
    license: str
    model_card_languages_claim: str
    native_context_length: int
    recommended_context_length: int
    model_card_url: str
    quantized_artifact_url: str
    license_url: str
    quantized_artifact_license_url: str


@dataclass(frozen=True)
class RuntimeStatus:
    runtime_available: bool
    model_installed: bool
    model_verified: bool
    model_id: str
    model_path: str
    model_size_bytes: int
    runtime_name: str
    device: str
    message: str
    download_required: bool
    model_license: str


def _read_catalog() -> tuple[str, dict[str, ModelSpec]]:
    try:
        raw = json.loads(MODEL_CATALOG_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ModelManagerError(f"Model catalog could not be read: {type(exc).__name__}.") from exc
    default_id = raw.get("default_model_id")
    models = raw.get("models")
    if not isinstance(default_id, str) or not isinstance(models, list):
        raise ModelManagerError("Model catalog has an invalid structure.")
    parsed: dict[str, ModelSpec] = {}
    for item in models:
        try:
            spec = ModelSpec(**item)
        except (TypeError, ValueError) as exc:
            raise ModelManagerError("Model catalog contains an invalid entry.") from exc
        if (
            not spec.model_id
            or Path(spec.filename).name != spec.filename
            or not 0 < spec.size_bytes <= MAX_MODEL_BYTES
            or len(spec.sha256) != 64
            or any(character not in "0123456789abcdef" for character in spec.sha256)
            or not spec.revision
        ):
            raise ModelManagerError(f"Model catalog entry {spec.model_id!r} failed validation.")
        if spec.model_id in parsed:
            raise ModelManagerError(f"Duplicate model ID: {spec.model_id}.")
        parsed[spec.model_id] = spec
    if default_id not in parsed:
        raise ModelManagerError("The default model ID is not in the model catalog.")
    return default_id, parsed


def default_model_dir() -> Path:
    configured = os.environ.get("CYBERSCAN_AI_MODEL_DIR")
    if configured:
        return Path(configured).expanduser().resolve()
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
        return base / "CyberScan" / "models"
    return Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / "cyberscan" / "models"


class LocalModelManager:
    """Manage a small allowlisted model; never download or load without a call."""

    def __init__(
        self,
        model_dir: str | Path | None = None,
        *,
        runtime_factory: Any | None = None,
    ) -> None:
        self.model_dir = Path(model_dir).expanduser().resolve() if model_dir else default_model_dir()
        self.default_model_id, self.models = _read_catalog()
        self._runtime_factory = runtime_factory
        self._runtime: Any | None = None
        self._loaded_model_id: str | None = None
        self._loaded_config: tuple[int, int, bool] | None = None
        self._device = "unloaded"
        self._load_warning: str | None = None
        self._lock = threading.RLock()
        self._verified_stat: tuple[int, int, int] | None = None
        self._cached_verified = False

    def spec(self, model_id: str | None = None) -> ModelSpec:
        selected = model_id or self.default_model_id
        try:
            return self.models[selected]
        except KeyError as exc:
            raise ModelManagerError(f"Model {selected!r} is not in the local allowlist.") from exc

    def model_path(self, model_id: str | None = None) -> Path:
        return self.model_dir / self.spec(model_id).filename

    @staticmethod
    def _hash_file(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        return digest.hexdigest()

    def status(self, model_id: str | None = None) -> RuntimeStatus:
        spec = self.spec(model_id)
        path = self.model_path(spec.model_id)
        installed = path.is_file() and not path.is_symlink()
        verified = False
        size = 0
        message = "Model is not installed."
        if installed:
            info = path.stat()
            size = info.st_size
            fingerprint = (info.st_size, info.st_mtime_ns, info.st_ino)
            if fingerprint != self._verified_stat:
                self._cached_verified = size == spec.size_bytes and self._hash_file(path) == spec.sha256
                self._verified_stat = fingerprint
            verified = self._cached_verified
            message = "Installed model checksum verified." if verified else "Installed model failed size or SHA-256 verification."
        available = self._runtime_factory is not None or self._runtime_importable()
        return RuntimeStatus(
            runtime_available=available,
            model_installed=installed,
            model_verified=verified,
            model_id=spec.model_id,
            model_path=str(path),
            model_size_bytes=size,
            runtime_name="llama.cpp (llama-cpp-python)",
            device=self._device,
            message=self._load_warning or message,
            download_required=not verified,
            model_license=spec.license,
        )

    @staticmethod
    def _runtime_importable() -> bool:
        try:
            import llama_cpp
        except ImportError:
            return False
        return callable(getattr(llama_cpp, "Llama", None))

    def install(self, model_id: str | None = None, *, confirm: bool = False) -> Path:
        """Download the catalog-pinned public artifact only after explicit consent."""
        if confirm is not True:
            raise ModelManagerError("Model installation requires explicit confirm=True.")
        spec = self.spec(model_id)
        self.model_dir.mkdir(parents=True, exist_ok=True)
        destination = self.model_path(spec.model_id)
        if destination.is_symlink():
            raise ModelManagerError("Refusing to overwrite a model path that is a symbolic link.")
        if destination.exists():
            state = self.status(spec.model_id)
            if state.model_verified:
                return destination
            raise ModelManagerError("A model file already exists but failed verification; it was not overwritten.")
        partial = destination.with_name(destination.name + ".part")
        if partial.exists() or partial.is_symlink():
            raise ModelManagerError("A previous or unexpected partial download exists; it was not overwritten.")

        url = (
            f"https://huggingface.co/{spec.repository}/resolve/{spec.revision}/"
            f"{spec.filename}?download=true"
        )
        request = urllib.request.Request(
            url,
            headers={"User-Agent": "CyberScan-LocalAI/1.0", "Accept-Encoding": "identity"},
        )
        digest = hashlib.sha256()
        received = 0
        try:
            with urllib.request.urlopen(request, timeout=30) as response, partial.open("xb") as output:
                content_length = response.headers.get("Content-Length")
                if content_length and int(content_length) != spec.size_bytes:
                    raise ModelManagerError("Model server reported an unexpected content length.")
                while True:
                    block = response.read(1024 * 1024)
                    if not block:
                        break
                    received += len(block)
                    if received > spec.size_bytes or received > MAX_MODEL_BYTES:
                        raise ModelManagerError("Model download exceeded its catalog size limit.")
                    digest.update(block)
                    output.write(block)
                output.flush()
                os.fsync(output.fileno())
            if received != spec.size_bytes:
                raise ModelManagerError(f"Model download was incomplete ({received} of {spec.size_bytes} bytes).")
            if digest.hexdigest() != spec.sha256:
                raise ModelManagerError("Downloaded model SHA-256 does not match the pinned catalog digest.")
            partial.replace(destination)
            self._verified_stat = (destination.stat().st_size, destination.stat().st_mtime_ns, destination.stat().st_ino)
            self._cached_verified = True
        except (OSError, urllib.error.URLError, ValueError, ModelManagerError) as exc:
            try:
                partial.unlink(missing_ok=True)
            except OSError:
                LOGGER.exception("Could not remove incomplete model download %s", partial)
            if isinstance(exc, ModelManagerError):
                raise
            raise ModelManagerError(f"Model download failed: {type(exc).__name__}.") from exc
        return destination

    def load(
        self,
        model_id: str | None = None,
        *,
        context_length: int = 4096,
        threads: int | None = None,
        use_gpu: bool = False,
    ) -> RuntimeStatus:
        spec = self.spec(model_id)
        if not 512 <= context_length <= min(MAX_CONTEXT_LENGTH, spec.native_context_length):
            raise ModelManagerError(f"context_length must be between 512 and {min(MAX_CONTEXT_LENGTH, spec.native_context_length)}.")
        if threads is not None and not 1 <= threads <= 128:
            raise ModelManagerError("threads must be between 1 and 128.")
        path = self.model_path(spec.model_id)
        if path.is_symlink() or not path.is_file():
            raise ModelManagerError("Model is missing or unverified; explicitly install it before loading.")
        try:
            before = path.stat()
            digest = self._hash_file(path)
            after = path.stat()
        except OSError as exc:
            raise ModelManagerError(f"Model could not be verified before loading: {type(exc).__name__}.") from exc
        fingerprint = (after.st_size, after.st_mtime_ns, after.st_ino)
        self._verified_stat = fingerprint
        self._cached_verified = (
            before.st_size == spec.size_bytes
            and fingerprint == (before.st_size, before.st_mtime_ns, before.st_ino)
            and digest == spec.sha256
        )
        if not self._cached_verified:
            raise ModelManagerError("Model is missing or unverified; explicitly install it before loading.")
        effective_threads = threads or max(1, (os.cpu_count() or 2) - 1)
        requested_config = (context_length, effective_threads, use_gpu)
        if self._loaded_model_id == spec.model_id and self._runtime is not None:
            if self._loaded_config != requested_config:
                raise ModelManagerError("Model is already loaded; unload it before changing inference settings.")
            return self.status(spec.model_id)
        if self._runtime_factory is None:
            try:
                import llama_cpp
            except ImportError as exc:
                raise ModelManagerError("llama-cpp-python is not installed; inference is unavailable.") from exc
            runtime_factory = llama_cpp.Llama
            gpu_supported = bool(getattr(llama_cpp, "llama_supports_gpu_offload", lambda: False)())
        else:
            runtime_factory = self._runtime_factory
            gpu_supported = bool(getattr(runtime_factory, "gpu_supported", False))

        n_gpu_layers = -1 if use_gpu and gpu_supported else 0
        warning = (
            "GPU offload was requested but this llama.cpp build does not report GPU support; using CPU."
            if use_gpu and not gpu_supported else None
        )
        device = "nvidia-gpu" if n_gpu_layers else "cpu"
        try:
            runtime = runtime_factory(
                model_path=str(self.model_path(spec.model_id)),
                n_ctx=context_length,
                n_threads=effective_threads,
                n_gpu_layers=n_gpu_layers,
                n_batch=min(512, context_length),
                verbose=False,
            )
        except (OSError, RuntimeError, ValueError) as exc:
            if not n_gpu_layers:
                self._runtime = None
                self._loaded_model_id = None
                self._device = "unloaded"
                raise ModelManagerError(f"Local model could not be loaded: {type(exc).__name__}.") from exc
            LOGGER.warning("GPU model loading failed; retrying on CPU: %s", type(exc).__name__)
            warning = f"GPU initialization failed ({type(exc).__name__}); loaded using CPU fallback."
            try:
                runtime = runtime_factory(
                    model_path=str(self.model_path(spec.model_id)),
                    n_ctx=context_length,
                    n_threads=effective_threads,
                    n_gpu_layers=0,
                    n_batch=min(512, context_length),
                    verbose=False,
                )
            except (OSError, RuntimeError, ValueError) as cpu_exc:
                self._runtime = None
                self._loaded_model_id = None
                self._device = "unloaded"
                raise ModelManagerError(f"GPU and CPU model loading failed: {type(cpu_exc).__name__}.") from cpu_exc
            device = "cpu-fallback"
        with self._lock:
            self._runtime = runtime
            self._loaded_model_id = spec.model_id
            self._loaded_config = requested_config
            self._device = device
            self._load_warning = warning
        return self.status(spec.model_id)

    def unload(self) -> None:
        with self._lock:
            runtime = self._runtime
            self._runtime = None
            self._loaded_model_id = None
            self._loaded_config = None
            self._device = "unloaded"
            self._load_warning = None
        if runtime is not None:
            del runtime
            try:
                import llama_cpp

                llama_cpp.llama_cpp.llama_backend_free()
            except (ImportError, AttributeError):
                LOGGER.debug("llama.cpp backend unload hook is unavailable.")

    def generate(
        self,
        messages: list[dict[str, str]],
        *,
        max_tokens: int = 512,
        temperature: float = 0.2,
        json_mode: bool = True,
    ) -> str:
        if not 1 <= max_tokens <= MAX_GENERATION_TOKENS:
            raise ModelManagerError(f"max_tokens must be between 1 and {MAX_GENERATION_TOKENS}.")
        if not 0 <= temperature <= 1.5:
            raise ModelManagerError("temperature must be between 0 and 1.5.")
        if not isinstance(messages, list) or not messages or len(messages) > 40:
            raise ModelManagerError("messages must contain between 1 and 40 entries.")
        normalized: list[dict[str, str]] = []
        for item in messages:
            if (
                not isinstance(item, dict)
                or item.get("role") not in {"system", "user", "assistant"}
                or not isinstance(item.get("content"), str)
                or len(item["content"]) > 100_000
            ):
                raise ModelManagerError("Each message must have a supported role and bounded text content.")
            normalized.append({"role": item["role"], "content": item["content"]})
        with self._lock:
            runtime = self._runtime
        if runtime is None:
            raise ModelManagerError("No model is loaded. Install and explicitly load an allowlisted model first.")
        try:
            request_options: dict[str, Any] = {
                "messages": normalized,
                "temperature": temperature,
                "top_p": 0.9,
                "max_tokens": max_tokens,
            }
            if json_mode:
                request_options["response_format"] = {"type": "json_object"}
            response = runtime.create_chat_completion(
                **request_options,
            )
        except (RuntimeError, ValueError, OSError) as exc:
            raise ModelManagerError(f"Local model generation failed: {type(exc).__name__}.") from exc
        try:
            content = response["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise ModelManagerError("Local model returned an invalid response envelope.") from exc
        if not isinstance(content, str) or len(content) > 100_000:
            raise ModelManagerError("Local model returned empty or oversized content.")
        return content
