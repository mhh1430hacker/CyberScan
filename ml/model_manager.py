from __future__ import annotations

from pathlib import Path

from config import MODEL_DIR
from ml.structural_classifier import StructuralClassifier


def model_path() -> Path:
    return MODEL_DIR / "structural_classifier_4096.json"


def model_exists() -> bool:
    return StructuralClassifier(model_path()).load()


def get_model_status() -> str:
    classifier = StructuralClassifier(model_path())
    if classifier.load():
        return "4096-D supervised three-class structural classifier loaded."
    reason = classifier.metadata.get("load_error")
    if reason:
        return f"Structural classifier rejected: {reason}"
    return "Trained structural classifier not available."
