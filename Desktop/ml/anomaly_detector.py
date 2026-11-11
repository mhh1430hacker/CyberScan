from __future__ import annotations

import hashlib
import json
from pathlib import Path

import numpy as np

try:
    from sklearn.ensemble import IsolationForest
except Exception:  # pragma: no cover
    IsolationForest = None

from config import MODEL_DIR
from ml.feature_schema import FEATURE_ORDER, SCHEMA_VERSION, serialize_feature_vector


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


class AnomalyDetector:
    def __init__(self, model_path: str | Path | None = None):
        self.model_path = Path(model_path or MODEL_DIR / "anomaly_isolation_forest.joblib")
        self.model = None
        self.model_available = False
        self.metadata: dict[str, object] = {}

    def load(self) -> bool:
        if IsolationForest is None:
            return False
        path = self.model_path
        if not path.exists():
            return False
        try:
            metadata_path = path.with_suffix(".json")
            if not metadata_path.exists():
                self.metadata = {"load_error": "Model metadata is missing; refusing an unverified model."}
                return False
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            if metadata.get("schema_version") != SCHEMA_VERSION or metadata.get("feature_order") != FEATURE_ORDER:
                self.metadata = {"load_error": "Model feature schema is incompatible."}
                return False
            if metadata.get("training_data_type") != "curated_benign_manifest":
                self.metadata = {"load_error": "Model provenance is not a curated benign manifest."}
                return False
            # joblib files are pickles: loading one executes arbitrary code. Only load a file whose
            # SHA-256 matches the digest recorded when CyberScan itself trained and saved it.
            expected_digest = metadata.get("model_sha256")
            if not isinstance(expected_digest, str) or file_sha256(path) != expected_digest.lower():
                self.metadata = {"load_error": "Model file integrity check failed (missing or mismatched SHA-256)."}
                return False

            import joblib

            model = joblib.load(path)
            if getattr(model, "n_features_in_", None) != len(FEATURE_ORDER):
                self.metadata = {"load_error": "Model vector dimension does not match the current feature schema."}
                return False
            self.model = model
            self.model_available = True
            self.metadata = metadata
            return True
        except Exception as exc:
            self.model = None
            self.model_available = False
            self.metadata = {"load_error": f"Model could not be loaded: {type(exc).__name__}."}
            return False

    def score_features(self, features: dict[str, object]) -> float | None:
        if not self.model_available or self.model is None:
            return None
        vector = np.array([serialize_feature_vector(features)], dtype=float)
        score = self.model.decision_function(vector)[0]
        return float(score)

    def anomaly_percentage(self, features: dict[str, object]) -> float | None:
        if self.model is None:
            return None
        decision = self.score_features(features)
        if decision is None:
            return None
        # IsolationForest.decision_function is > 0 for inliers and < 0 for outliers (0 = decision
        # boundary, usually within about +/-0.5). Map the boundary to 50 so that values above 50 mean
        # "the model flags this as an outlier". The old mapping scored ordinary inliers around 40%.
        # This is a rescaled anomaly score, not a probability of malware.
        normalized = max(0.0, min(100.0, 50.0 - decision * 100.0))
        return round(normalized, 2)

    def train(
        self,
        dataset: list[dict[str, object]],
        *,
        training_metadata: dict[str, object],
    ) -> None:
        if IsolationForest is None:
            raise RuntimeError("scikit-learn is required for ML training.")
        if not isinstance(training_metadata, dict):
            raise ValueError("training_metadata from a curated labeled manifest is required")
        if training_metadata.get("training_data_type") != "curated_benign_manifest":
            raise ValueError("Only models trained from a curated benign manifest can be persisted as active models.")
        if training_metadata.get("benign_sample_count") != len(dataset) or len(dataset) < 30:
            raise ValueError("Training requires at least 30 verified benign samples matching the manifest count.")
        manifest_sha256 = training_metadata.get("manifest_sha256")
        if not isinstance(manifest_sha256, str) or len(manifest_sha256) != 64:
            raise ValueError("training_metadata must include the manifest SHA-256.")
        vectors = np.array([serialize_feature_vector(item) for item in dataset], dtype=float)
        if vectors.ndim != 2 or vectors.shape[1] != len(FEATURE_ORDER):
            raise ValueError("Training vectors do not match the active feature schema.")
        self.model = IsolationForest(contamination=0.05, random_state=42, n_estimators=300)
        self.model.fit(vectors)
        self.model_available = True
        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        import joblib

        joblib.dump(self.model, self.model_path)
        metadata = {
            **training_metadata,
            "model_sha256": file_sha256(self.model_path),
            "feature_order": FEATURE_ORDER,
            "schema_version": SCHEMA_VERSION,
            "model_type": "IsolationForest",
            "contamination": 0.05,
            "n_estimators": 300,
            "training_sample_count": len(dataset),
        }
        self.metadata = metadata
        self.model_path.with_suffix(".json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    def is_available(self) -> bool:
        return self.model_available or self.model_path.exists()
