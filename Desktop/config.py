from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT_DIR = Path(__file__).resolve().parent
DATA_DIR = ROOT_DIR / "data"
MODEL_DIR = DATA_DIR / "models"
DATASET_DIR = DATA_DIR / "datasets"
REPORT_DIR = DATA_DIR / "reports"
QUARANTINE_DIR = DATA_DIR / "quarantine"
SAMPLE_DIR = DATA_DIR / "demo_samples"

MAX_FILE_SIZE = 50 * 1024 * 1024
MAX_ANALYSIS_BYTES = 1_000_000  # bytes of a file read into memory for content analysis
MAX_ANALYSIS_TIME = 15.0
MAX_STRING_SCAN_SIZE = 200_000


@dataclass
class ScannerSettings:
    entropy_analysis: bool = True
    heuristic_rules: bool = True
    ml_analysis: bool = True
    # Sending hashes/URLs to third-party feeds is opt-in (privacy).
    osint_lookup: bool = False
    ml_weight: float = 0.30
    heuristic_weight: float = 0.70
    monitoring_enabled: bool = False
    monitoring_directory: str = str(Path.home() / "Downloads")
    maximum_file_size: int = MAX_FILE_SIZE
    max_analysis_bytes: int = MAX_ANALYSIS_BYTES
    analysis_timeout: float = MAX_ANALYSIS_TIME
    quarantine_directory: str = str(QUARANTINE_DIR)
    logging_level: str = "INFO"
    max_string_scan_size: int = MAX_STRING_SCAN_SIZE

    @classmethod
    def from_dict(cls, values: dict[str, Any]) -> "ScannerSettings":
        defaults = cls()
        return cls(**{name: values.get(name, getattr(defaults, name)) for name in cls.__annotations__})

    def to_dict(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in self.__annotations__}


# Single source of truth: the dataclass defaults above.
DEFAULT_SETTINGS: dict[str, Any] = ScannerSettings().to_dict()


def resolve_settings(overrides: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return a complete settings dict; missing keys fall back to defaults."""
    merged = dict(DEFAULT_SETTINGS)
    if overrides:
        merged.update(overrides)
    return merged


def ensure_directories() -> None:
    for path in (DATA_DIR, MODEL_DIR, DATASET_DIR, REPORT_DIR, QUARANTINE_DIR, SAMPLE_DIR):
        path.mkdir(parents=True, exist_ok=True)
