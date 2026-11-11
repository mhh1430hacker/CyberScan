#!/usr/bin/env python3
"""
Structural Classifier for CyberScan.

A RandomForest-based multiclass classifier operating on deterministic
4096-dimensional structural embeddings extracted from binary files.

Training uses scikit-learn in memory. Persisted models use the plain-JSON
``cyberscan-forest`` format (``ml.forest_format``): saving exports the fitted
trees with ``ml.forest_export``, and loading is always explicit and requires a
SHA-256 digest from a trusted source. Constructing a classifier never reads a
model file, and no executable deserialization (pickle/joblib) is used.
"""
from __future__ import annotations

import logging
import tempfile
import warnings
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder

from ml.conformal import DEFAULT_ALPHA, ConformalCalibration, calibrate, prediction_set
from ml.feature_schema import FEATURE_SCHEMA_VERSION
from ml.forest_export import export_random_forest, write_model_artifact
from ml.forest_format import FORMAT_NAME, ForestModel, ModelFormatError, load_model

# Suppress sklearn warnings for cleaner output
warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")

logger = logging.getLogger(__name__)

# Model format identifier
MODEL_FORMAT = FORMAT_NAME

# Expected embedding dimension
LATENT_DIMENSION = 4096

# Feature schema that persisted models must declare
EMBEDDING_SCHEMA = FEATURE_SCHEMA_VERSION

# Three-class labels
CLASS_LABELS = ("clean", "suspicious", "malware")

# Default model save location
DEFAULT_MODEL_PATH = Path("models/structural_classifier.json")

# Human-readable prefixes for loader rejection codes (see ml.forest_format).
_LOAD_ERROR_PREFIXES = {
    "unapproved": "Model not approved",
    "io": "Model file could not be read",
    "too_large": "Model file is too large",
    "digest_mismatch": "Model file does not match the approved digest",
    "not_json": "Model file is not a plain JSON model; executable model files are not loaded",
    "schema": "Incompatible model artifact",
    "structure": "Invalid model artifact",
    "values": "Invalid model artifact",
}


def _extract_features_from_bytes(data: bytes) -> np.ndarray:
    """Extract the 4096-dim structural embedding from bytes.

    The same ``HighDimensionalEmbedding`` that ``ml.dataset_loader`` trains on and
    ``core.file_analyzer`` scans with: a model only means something on the
    coordinates it was trained on.
    """
    from core.deep_embedding import HighDimensionalEmbedding

    return np.asarray(HighDimensionalEmbedding().embed_bytes(data), dtype=np.float32)


class StructuralClassifier:
    """
    RandomForest-based structural classifier for binary files.

    Uses the deterministic 4096-dimensional ``HighDimensionalEmbedding`` (byte and
    n-gram statistics, entropy topography, code-graph topology, PE headers). No
    neural network dependencies.

    A classifier holds either an in-memory scikit-learn forest produced by
    ``train`` or a validated ``ForestModel`` produced by ``load``. Constructing
    a classifier does not load anything; call ``load(path, expected_sha256=...)``.
    """

    def __init__(self, model_path: str | Path | None = None):
        """Initialize classifier. ``model_path`` is remembered but never loaded here."""
        self.model_path = Path(model_path) if model_path else DEFAULT_MODEL_PATH
        self.model: RandomForestClassifier | None = None
        self.label_encoder: LabelEncoder | None = None
        self.forest: ForestModel | None = None
        self.artifact_sha256: str | None = None
        self.conformal: ConformalCalibration | None = None
        self.metadata: dict[str, Any] = {
            "format": MODEL_FORMAT,
            "schema_version": 1,
            "embedding_schema": EMBEDDING_SCHEMA,
            "embedding_dimension": LATENT_DIMENSION,
            "classes": list(CLASS_LABELS),
            "training_data_type": "user_reviewed_three_class_manifest",
            "scores_are_calibrated": False,
            "load_error": None,
        }

    @property
    def is_ready(self) -> bool:
        """True when a trained or validated, loaded model can produce predictions."""
        return self.forest is not None or self.model is not None

    def embed_bytes(self, data: bytes) -> np.ndarray:
        """Extract 4096-dim embedding from raw bytes."""
        return _extract_features_from_bytes(data)

    def embed_file(self, file_path: Path | str) -> np.ndarray:
        """Extract 4096-dim embedding from file."""
        path = Path(file_path)
        with path.open("rb") as f:
            data = f.read()
        return self.embed_bytes(data)

    def _validate_input(self, X: np.ndarray) -> None:
        """Validate input array shape and finiteness."""
        if X.ndim != 2:
            raise ValueError(f"Expected 2D array, got {X.ndim}D")
        if X.shape[1] != LATENT_DIMENSION:
            raise ValueError(f"Expected {LATENT_DIMENSION} features, got {X.shape[1]}")
        if not np.all(np.isfinite(X)):
            raise ValueError("Input contains non-finite values (NaN or Inf)")

    def train(
        self,
        X: np.ndarray,
        y: list[str],
        *,
        n_estimators: int = 200,
        max_depth: int | None = 20,
        min_samples_split: int = 5,
        min_samples_leaf: int = 2,
        random_state: int = 42,
        sample_weight: np.ndarray | None = None,
    ) -> dict:
        """
        Train the classifier on embeddings and labels.

        Args:
            X: Training embeddings, shape (n_samples, 4096)
            y: Labels as strings (must match CLASS_LABELS)
            sample_weight: Optional per-sample weights (the self-audit up-weights
                samples whose verdict rested on a meaningless region)

        Returns:
            Training metadata dict
        """
        X = np.asarray(X)
        if X.ndim == 1:
            X = X.reshape(1, -1)
        self._validate_input(X)

        # Encode labels
        self.label_encoder = LabelEncoder()
        self.label_encoder.fit(CLASS_LABELS)
        # Accept both string labels and integer labels
        y = np.asarray(y)
        if y.dtype.kind in ('i', 'u', 'f'):  # integer or float
            # Convert integer labels to strings
            int_to_label = {i: label for i, label in enumerate(CLASS_LABELS)}
            y_str = np.array([int_to_label[int(v)] for v in y])
            y_encoded = self.label_encoder.transform(y_str)
        else:
            y_encoded = self.label_encoder.transform(y)

        # Train RandomForest
        self.model = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            min_samples_split=min_samples_split,
            min_samples_leaf=min_samples_leaf,
            max_features="sqrt",
            class_weight="balanced",
            random_state=random_state,
            n_jobs=-1,
        )
        self.model.fit(X, y_encoded, sample_weight=sample_weight)
        self.forest = None
        self.artifact_sha256 = None
        self.conformal = None

        # Update metadata
        self.metadata["training_samples"] = int(X.shape[0])
        self.metadata["classes"] = list(CLASS_LABELS)

        return {
            "training_samples": int(X.shape[0]),
            "classes": self.metadata["classes"],
            "n_estimators": self.model.n_estimators,
        }

    def _trained_class_labels(self) -> list[str]:
        """Label names for each entry of the in-memory forest's ``classes_``."""
        assert self.model is not None and self.label_encoder is not None
        return [str(name) for name in self.label_encoder.inverse_transform(self.model.classes_)]

    def calibrate_conformal(self, X: np.ndarray, y: list[str], alpha: float = DEFAULT_ALPHA) -> ConformalCalibration:
        """Fit the abstention threshold on examples the forest was not trained on."""
        if not self.is_ready:
            raise RuntimeError("Train or load a model before calibrating it.")
        true_index = [CLASS_LABELS.index(str(label)) for label in y]
        self.conformal = calibrate(self.predict_proba(X), true_index, alpha)
        return self.conformal

    def predict(self, X: np.ndarray) -> dict:
        """
        Predict class labels with detailed scores.

        Returns dict with status, label, class_scores, scores_are_calibrated, repair_review_candidate.
        - If untrained: status="untrained", label=None, infection_score=None, class_scores={}
        - If trained or loaded: status="classified", label=predicted class,
          class_scores={class: score%} for the first sample, in CLASS_LABELS order.
        """
        X = np.asarray(X)
        if X.ndim == 1:
            X = X.reshape(1, -1)
        self._validate_input(X)

        if not self.is_ready:
            return {
                "status": "untrained",
                "label": None,
                "infection_score": None,
                "class_scores": {},
                "scores_are_calibrated": False,
                "repair_review_candidate": None,
            }

        proba = self.predict_proba(X)
        if self.forest is not None:
            labels = self.forest.predict(X)
        else:
            labels = [
                str(label)
                for label in self.label_encoder.inverse_transform(self.model.predict(X))
            ]
        present = set(self.forest.classes if self.forest is not None else self._trained_class_labels())
        class_scores = {
            class_name: float(proba[0, index]) * 100
            for index, class_name in enumerate(CLASS_LABELS)
            if class_name in present
        }

        result = {
            "status": "classified",
            "label": labels[0] if len(labels) == 1 else labels,
            "infection_score": None,
            "class_scores": class_scores,
            "scores_are_calibrated": False,
            "repair_review_candidate": None,
        }
        if self.conformal is not None and X.shape[0] == 1:
            # The model commits only when calibration rules out every other class.
            candidates = prediction_set(proba[0], self.conformal, CLASS_LABELS)
            result.update({
                "prediction_set": candidates,
                "abstained": len(candidates) != 1,
                "conformal_coverage_target": round(1.0 - self.conformal.alpha, 4),
                "conformal_calibration_size": self.conformal.calibration_size,
            })
        return result

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Return raw class scores, shape (n_samples, 3), columns in CLASS_LABELS order.

        Classes absent from an in-memory training set have a score of 0.
        """
        X = np.asarray(X)
        if X.ndim == 1:
            X = X.reshape(1, -1)
        self._validate_input(X)

        if self.forest is not None:
            return self.forest.predict_proba(X)
        if self.model is None:
            n_classes = len(CLASS_LABELS)
            return np.ones((X.shape[0], n_classes), dtype=np.float32) / n_classes

        raw = self.model.predict_proba(X)
        ordered = np.zeros((X.shape[0], len(CLASS_LABELS)), dtype=np.float64)
        for column, class_name in enumerate(self._trained_class_labels()):
            ordered[:, CLASS_LABELS.index(class_name)] = raw[:, column]
        return ordered

    def labels_and_scores(self, X: np.ndarray) -> tuple[list[str], np.ndarray]:
        """Labels and CLASS_LABELS-ordered scores for a batch (used by ml.orbit and ml.counterfactual)."""
        proba = self.predict_proba(X)
        return [CLASS_LABELS[index] for index in np.argmax(proba, axis=1)], proba

    def predict_with_scores(self, X: np.ndarray) -> dict:
        """Predict with detailed class scores. Returns dict matching test expectations."""
        return self.predict(X)

    def save(self, path: str | Path | None = None, metadata: Mapping[str, Any] | None = None) -> Path:
        """Export the in-memory forest to the safe JSON format.

        ``metadata`` entries are stored as informational provenance and must be
        strings, numbers, booleans, or None. The artifact's SHA-256 is stored in
        ``artifact_sha256`` for review; saving never approves a model.
        """
        save_path = Path(path) if path else self.model_path

        if self.model is None:
            raise RuntimeError("Cannot save untrained model")

        provenance: dict[str, Any] = {}
        for key, value in (metadata or {}).items():
            if value is not None and not isinstance(value, (bool, int, float, str)):
                raise ValueError(
                    f"Model metadata {key!r} must be a string, number, boolean, or None."
                )
            provenance[str(key)] = value
        if self.conformal is not None:
            provenance.update(self.conformal.as_provenance())

        document = export_random_forest(
            self.model,
            class_labels=self._trained_class_labels(),
            provenance=provenance,
        )
        self.artifact_sha256 = write_model_artifact(document, save_path)
        logger.info("Model saved to %s (sha256 %s)", save_path, self.artifact_sha256)
        return save_path

    def load(self, path: str | Path | None = None, *, expected_sha256: str | None = None) -> bool:
        """
        Load a model artifact through the safe, digest-first loader.

        ``expected_sha256`` must come from a trusted source outside the
        artifact. Without it nothing is read. Returns True on success, False on
        failure (see metadata["load_error"]). A failed load discards any
        previously loaded artifact.
        """
        load_path = Path(path) if path else self.model_path
        self.model_path = load_path
        self.forest = None
        self.artifact_sha256 = None
        self.conformal = None

        try:
            forest = load_model(
                load_path,
                expected_sha256,
                expected_feature_schema=EMBEDDING_SCHEMA,
                expected_n_features=LATENT_DIMENSION,
                expected_classes=CLASS_LABELS,
            )
        except ModelFormatError as exc:
            prefix = _LOAD_ERROR_PREFIXES.get(exc.code, "Model rejected")
            self.metadata["load_error"] = f"{prefix}: {exc}"
            logger.warning("Structural model not loaded (%s): %s", exc.code, exc)
            return False

        self.forest = forest
        self.artifact_sha256 = forest.sha256
        self.conformal = ConformalCalibration.from_provenance(forest.provenance)
        self.metadata = {
            "format": MODEL_FORMAT,
            "schema_version": 1,
            "embedding_schema": forest.feature_schema,
            "embedding_dimension": forest.n_features,
            "embedding_dim": forest.n_features,
            "classes": list(forest.classes),
            "labels": list(forest.classes),
            "n_estimators": len(forest.trees),
            "training_examples": forest.provenance.get("training_examples"),
            "provenance": dict(forest.provenance),
            "artifact_sha256": forest.sha256,
            "scores_are_calibrated": False,
            "load_error": None,
        }
        return True


def extract_structural_embedding(file_path: Path | str) -> np.ndarray:
    """Extract 4096-dim structural embedding from binary file (module-level function)."""
    path = Path(file_path)
    with path.open("rb") as f:
        data = f.read()
    return _extract_features_from_bytes(data)


if __name__ == "__main__":
    # Quick self-test in a temporary directory
    clf = StructuralClassifier()
    test_data = b"MZ\x90\x00" + b"test" * 100
    emb = clf.embed_bytes(test_data)
    print(f"Embedding shape: {emb.shape}")
    print(f"Embedding finite: {np.all(np.isfinite(emb))}")

    # Test untrained prediction
    pred = clf.predict(emb)
    print(f"Untrained prediction: {pred}")

    # Train on dummy data
    X = np.random.randn(10, LATENT_DIMENSION).astype(np.float32)
    y = ["clean", "suspicious", "malware"] * 3 + ["clean"]
    clf.train(X, y)

    pred = clf.predict(emb)
    print(f"Trained prediction: {pred}")

    # Save and reload with the digest reported by save()
    with tempfile.TemporaryDirectory() as directory:
        test_model = Path(directory) / "test_model.json"
        clf.save(test_model)
        clf2 = StructuralClassifier()
        assert clf2.load(test_model, expected_sha256=clf.artifact_sha256)
        pred2 = clf2.predict(emb)
    print(f"Reloaded prediction: {pred2}")
    assert pred["label"] == pred2["label"]
