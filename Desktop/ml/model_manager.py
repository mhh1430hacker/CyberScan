from __future__ import annotations

from pathlib import Path

from config import MODEL_DIR
from ml.anomaly_detector import AnomalyDetector

_CACHE: dict[str, tuple[tuple[int, int], AnomalyDetector]] = {}


def model_path() -> Path:
    return MODEL_DIR / "anomaly_isolation_forest.joblib"


def _signature(path: Path) -> tuple[int, int]:
    """(mtime_ns, size) of the model and its metadata; changes whenever either file changes."""
    signature = []
    for candidate in (path, path.with_suffix(".json")):
        try:
            stat = candidate.stat()
            signature.extend((stat.st_mtime_ns, stat.st_size))
        except OSError:
            signature.extend((0, 0))
    return (hash(tuple(signature[:2])), hash(tuple(signature[2:])))


def get_detector(path: Path | None = None) -> AnomalyDetector:
    """Return a loaded-once detector; it is reloaded only when the model files change.

    Previously every scan re-read and re-verified the model from disk.
    """
    target = Path(path or model_path())
    key = str(target)
    signature = _signature(target)
    cached = _CACHE.get(key)
    if cached and cached[0] == signature:
        return cached[1]
    detector = AnomalyDetector(target)
    detector.load()
    _CACHE[key] = (signature, detector)
    return detector


def clear_cache() -> None:
    _CACHE.clear()


def model_exists() -> bool:
    return get_detector().model_available


def get_model_status() -> str:
    detector = get_detector()
    if detector.model_available:
        return "Curated-benign anomaly model loaded."
    reason = detector.metadata.get("load_error")
    if reason:
        return f"ML model rejected: {reason}"
    return "ML model not available."
