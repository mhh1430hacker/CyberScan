"""Benign-only IsolationForest over the compact feature vector of ``ml.anomaly_features``.

The fitted forest is stored as plain JSON (thresholds, children and leaf sample
counts), never with pickle/joblib, and is only read back when the caller supplies
the file's SHA-256 from a trusted source. Scoring reimplements Liu et al. (2008)
exactly as scikit-learn does, so a reloaded model gives the same scores.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import numpy as np

try:
    from sklearn.ensemble import IsolationForest
except Exception:  # pragma: no cover
    IsolationForest = None

from config import MODEL_DIR
from ml.anomaly_features import FEATURE_ORDER, SCHEMA_VERSION, serialize_feature_vector

FORMAT_NAME = "cyberscan-isolation-forest"
FORMAT_VERSION = 1
MAX_MODEL_BYTES = 64 * 1024 * 1024
_EULER_GAMMA = 0.5772156649015329


def average_path_length(n: np.ndarray) -> np.ndarray:
    """c(n): mean depth of an unsuccessful search in a binary search tree of n points."""
    n = np.asarray(n, dtype=np.float64)
    result = np.zeros_like(n)
    result[n == 2] = 1.0
    big = n > 2
    result[big] = 2.0 * (np.log(n[big] - 1.0) + _EULER_GAMMA) - 2.0 * (n[big] - 1.0) / n[big]
    return result


class _Tree:
    __slots__ = ("left", "right", "feature", "threshold", "leaf_path")

    def __init__(self, document: dict[str, Any], n_features: int):
        self.left = np.asarray(document["left"], dtype=np.int64)
        self.right = np.asarray(document["right"], dtype=np.int64)
        self.feature = np.asarray(document["feature"], dtype=np.int64)
        self.threshold = np.asarray(document["threshold"], dtype=np.float64)
        n_samples = np.asarray(document["n_samples"], dtype=np.float64)
        depth = np.asarray(document["depth"], dtype=np.float64)
        size = self.left.shape[0]
        if not (size and all(array.shape == (size,) for array in (self.right, self.feature, self.threshold, n_samples, depth))):
            raise ValueError("Tree arrays must be non-empty and the same length.")
        internal = self.left >= 0
        if np.any(self.left[internal] >= size) or np.any(self.right[internal] >= size) or np.any(self.right[internal] < 0):
            raise ValueError("Tree children must point inside the tree.")
        if np.any(self.feature[internal] < 0) or np.any(self.feature[internal] >= n_features):
            raise ValueError("Tree features must index the feature vector.")
        if not np.all(np.isfinite(self.threshold[internal])):
            raise ValueError("Tree thresholds must be finite.")
        # Path length to a leaf: its depth plus c(samples left in it), as in the paper.
        self.leaf_path = depth + average_path_length(n_samples)

    def path_lengths(self, X: np.ndarray) -> np.ndarray:
        node = np.zeros(X.shape[0], dtype=np.int64)
        rows = np.arange(X.shape[0])
        for _ in range(self.left.shape[0]):
            active = self.left[node] >= 0
            if not active.any():
                break
            current = node[active]
            go_left = X[rows[active], self.feature[current]] <= self.threshold[current]
            node[active] = np.where(go_left, self.left[current], self.right[current])
        return self.leaf_path[node]


class AnomalyDetector:
    def __init__(self, model_path: str | Path | None = None):
        self.model_path = Path(model_path or MODEL_DIR / "anomaly_isolation_forest.json")
        self.model = None
        self.trees: list[_Tree] = []
        self.max_samples = 0
        self.model_available = False
        self.metadata: dict[str, object] = {}

    # -- persistence -----------------------------------------------------------------------

    def _document(self) -> dict[str, Any]:
        trees = []
        for estimator, features in zip(self.model.estimators_, self.model.estimators_features_):
            tree = estimator.tree_
            if not np.array_equal(np.asarray(features), np.arange(len(FEATURE_ORDER))):
                raise ValueError("Feature subsampling is not supported by the JSON format.")
            trees.append({
                "left": tree.children_left.tolist(),
                "right": tree.children_right.tolist(),
                "feature": tree.feature.tolist(),
                "threshold": tree.threshold.tolist(),
                "n_samples": tree.n_node_samples.tolist(),
                # compute_node_depths counts the root as 1; the paper counts edges.
                "depth": (np.asarray(tree.compute_node_depths(), dtype=np.int64) - 1).tolist(),
            })
        return {
            "format": FORMAT_NAME,
            "format_version": FORMAT_VERSION,
            "schema_version": SCHEMA_VERSION,
            "feature_order": FEATURE_ORDER,
            "max_samples": int(self.model.max_samples_),
            "trees": trees,
            "metadata": self.metadata,
        }

    def load(self, path: str | Path | None = None, *, expected_sha256: str | None = None) -> bool:
        """Read a JSON model whose SHA-256 the caller vouches for. Without a digest, nothing is read."""
        self.model_path = Path(path) if path else self.model_path
        self.model_available = False
        self.trees = []
        if not expected_sha256 or len(expected_sha256) != 64:
            self.metadata = {"load_error": "An approved SHA-256 is required; refusing an unverified model."}
            return False
        try:
            if self.model_path.stat().st_size > MAX_MODEL_BYTES:
                raise ValueError("Model file is too large.")
            raw = self.model_path.read_bytes()
            if hashlib.sha256(raw).hexdigest() != expected_sha256.lower():
                raise ValueError("Model file does not match the approved digest.")
            document = json.loads(raw.decode("utf-8"))
            if document.get("format") != FORMAT_NAME or document.get("format_version") != FORMAT_VERSION:
                raise ValueError("Not a CyberScan IsolationForest JSON model.")
            if document.get("schema_version") != SCHEMA_VERSION or document.get("feature_order") != FEATURE_ORDER:
                raise ValueError("Model feature schema is incompatible.")
            metadata = document.get("metadata") or {}
            if metadata.get("training_data_type") != "curated_benign_manifest":
                raise ValueError("Model provenance is not a curated benign manifest.")
            max_samples = int(document["max_samples"])
            if max_samples < 2 or not document.get("trees"):
                raise ValueError("Model has no usable trees.")
            self.trees = [_Tree(tree, len(FEATURE_ORDER)) for tree in document["trees"]]
        except (OSError, ValueError, KeyError, TypeError) as exc:
            self.trees = []
            self.metadata = {"load_error": str(exc)}
            return False
        self.max_samples = max_samples
        self.metadata = metadata
        self.model_available = True
        return True

    # -- scoring ---------------------------------------------------------------------------

    def _anomaly_scores(self, X: np.ndarray) -> np.ndarray:
        """s(x) = 2^(-E[h(x)] / c(max_samples)), in (0, 1]; about 0.5 is ordinary, near 1 isolated."""
        if self.trees:
            # scikit-learn compares float32 features with its thresholds; do the same.
            X32 = X.astype(np.float32).astype(np.float64)
            depths = sum(tree.path_lengths(X32) for tree in self.trees)
            denominator = len(self.trees) * float(average_path_length(np.array([self.max_samples]))[0])
            return 2.0 ** (-depths / denominator) if denominator else np.ones(X.shape[0])
        return -self.model.score_samples(X)

    def score_features(self, features: dict[str, object]) -> float | None:
        """Higher is more ordinary, matching IsolationForest.score_samples (= -s(x))."""
        if not self.model_available:
            return None
        vector = np.array([serialize_feature_vector(features)], dtype=float)
        return -float(self._anomaly_scores(vector)[0])

    def anomaly_percentage(self, features: dict[str, object]) -> float | None:
        # s(x) itself, as a percentage. (Mapping decision_function as if it spanned
        # -1..1 pinned every result between 25% and 75%: it spans about -0.5..0.5.)
        score = self.score_features(features)
        if score is None:
            return None
        return round(max(0.0, min(100.0, -score * 100.0)), 2)

    # -- training --------------------------------------------------------------------------

    def train(
        self,
        dataset: list[dict[str, object]],
        *,
        training_metadata: dict[str, object],
    ) -> str:
        """Fit on curated benign samples, write the JSON model and return its SHA-256."""
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
        self.metadata = {
            **training_metadata,
            "feature_order": FEATURE_ORDER,
            "schema_version": SCHEMA_VERSION,
            "model_type": "IsolationForest",
            "contamination": 0.05,
            "n_estimators": 300,
            "training_sample_count": len(dataset),
        }
        raw = json.dumps(self._document(), separators=(",", ":")).encode("utf-8")
        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        self.model_path.write_bytes(raw)
        digest = hashlib.sha256(raw).hexdigest()
        self.trees = []
        self.model_available = True
        return digest

    def is_available(self) -> bool:
        return self.model_available
