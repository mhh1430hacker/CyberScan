from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT_DIR = Path(__file__).resolve().parent
# Run from source: data/ next to the code. Run as the packaged desktop app (PyInstaller): the
# program folder may be read-only (Program Files), so history and settings live per user.
if getattr(sys, "frozen", False):
    DATA_DIR = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local") / "CyberScan" / "data"
else:
    DATA_DIR = ROOT_DIR / "data"
MODEL_DIR = DATA_DIR / "models"
DATASET_DIR = DATA_DIR / "datasets"
REPORT_DIR = DATA_DIR / "reports"
# Approved structural model (path + SHA-256), written only by ml.approve_model.
TRUSTED_MODELS_FILE = DATA_DIR / "trusted_models.json"

MAX_FILE_SIZE = 50 * 1024 * 1024
MAX_ANALYSIS_TIME = 15.0
MAX_STRING_SCAN_SIZE = 200_000

DEFAULT_SETTINGS = {
    "entropy_analysis": True,
    "heuristic_rules": True,
    "ml_analysis": True,
    "ml_weight": 0.0,
    "heuristic_weight": 1.0,
    "monitoring_enabled": False,
    "monitoring_directory": str(Path.home() / "Downloads"),
    "osint_enabled": False,
    "large_text": False,
    "maximum_file_size": MAX_FILE_SIZE,
    "analysis_timeout": MAX_ANALYSIS_TIME,
    "quarantine_directory": str(ROOT_DIR / "data" / "quarantine"),
    "logging_level": "INFO",
    "max_string_scan_size": MAX_STRING_SCAN_SIZE,
    # Interface preferences (never read by the analysis engines).
    "ai_summary_enabled": True,
    "ai_model": "qwen3:8b",
    "animated_background": True,
}


@dataclass
class ScannerSettings:
    entropy_analysis: bool = True
    heuristic_rules: bool = True
    ml_analysis: bool = True
    ml_weight: float = 0.0
    heuristic_weight: float = 1.0
    monitoring_enabled: bool = False
    monitoring_directory: str = str(Path.home() / "Downloads")
    osint_enabled: bool = False
    maximum_file_size: int = MAX_FILE_SIZE
    analysis_timeout: float = MAX_ANALYSIS_TIME
    quarantine_directory: str = str(ROOT_DIR / "data" / "quarantine")
    logging_level: str = "INFO"
    max_string_scan_size: int = MAX_STRING_SCAN_SIZE

    @classmethod
    def from_dict(cls, values: dict[str, Any]) -> "ScannerSettings":
        return cls(**{field_name: values.get(field_name, getattr(cls, field_name)) for field_name in cls.__annotations__})

    def to_dict(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in self.__annotations__}


def ensure_directories() -> None:
    for path in [DATA_DIR, MODEL_DIR, DATASET_DIR, REPORT_DIR, Path(DEFAULT_SETTINGS["quarantine_directory"])]:
        path.mkdir(parents=True, exist_ok=True)
