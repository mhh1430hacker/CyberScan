"""Export a fitted scikit-learn random forest to the safe CyberScan JSON format.

The exporter reads each fitted tree's node arrays directly from memory
(``children_left``, ``children_right``, ``feature``, ``threshold``, ``value``)
and writes plain JSON data. No pickle, joblib, or base64 payload is produced
or consumed. Leaf values are copied unchanged: scikit-learn 1.9's
``DecisionTreeClassifier.predict_proba`` returns ``tree_.value[leaf]`` as-is,
so copying them preserves its probabilities exactly. Class columns are
reordered from the estimator's ``classes_`` order (alphabetical for string
labels) into ``MODEL_CLASS_ORDER``.

Every exported document is parsed back with ``ml.forest_format`` before it is
returned, so the exporter cannot emit an artifact the loader would reject.
Exporting does not approve a model; approval is a separate, reviewed step.

scikit-learn is imported lazily, only when a forest is exported.
"""
from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import numpy as np

from ml.feature_schema import FEATURE_SCHEMA_VERSION, LATENT_DIMENSION, MODEL_CLASS_ORDER
from ml.forest_format import (
    AGGREGATION,
    DECISION_RULE,
    FORMAT_NAME,
    FORMAT_VERSION,
    MODEL_TYPE,
    encode_document,
    parse_model,
)

EXPORTER_ID = "ml.forest_export/1"


def export_random_forest(
    forest: Any,
    *,
    class_labels: Sequence[str] | None = None,
    provenance: Mapping[str, Any] | None = None,
    feature_schema: str = FEATURE_SCHEMA_VERSION,
    n_features: int = LATENT_DIMENSION,
) -> dict[str, Any]:
    """Return a validated model document for a fitted ``RandomForestClassifier``.

    ``class_labels`` names each entry of ``forest.classes_`` in order. It is
    required when the forest was fitted on encoded (non-string) labels.
    """
    import sklearn
    from sklearn.ensemble import RandomForestClassifier

    if not isinstance(forest, RandomForestClassifier):
        raise TypeError("Only scikit-learn RandomForestClassifier models can be exported.")
    if not hasattr(forest, "estimators_"):
        raise ValueError("The forest has not been fitted.")
    if getattr(forest, "n_outputs_", None) != 1:
        raise ValueError("Only single-output forests can be exported.")
    if getattr(forest, "n_features_in_", None) != n_features:
        raise ValueError(
            f"The forest expects {getattr(forest, 'n_features_in_', None)} features; "
            f"the schema requires {n_features}."
        )

    labels = [str(label) for label in (forest.classes_ if class_labels is None else class_labels)]
    if len(labels) != len(forest.classes_):
        raise ValueError("class_labels must name every entry of forest.classes_.")
    if sorted(labels) != sorted(MODEL_CLASS_ORDER) or len(set(labels)) != len(labels):
        raise ValueError(
            f"Forest classes {labels} must be a permutation of {list(MODEL_CLASS_ORDER)}."
        )
    column_order = [labels.index(name) for name in MODEL_CLASS_ORDER]

    trees = []
    for index, estimator in enumerate(forest.estimators_):
        tree = estimator.tree_
        if tree.n_outputs != 1 or tree.value.shape[2] != len(labels):
            raise ValueError(f"Tree {index} has an unexpected output shape {tree.value.shape}.")
        values = np.asarray(tree.value[:, 0, :], dtype=np.float64)[:, column_order]
        trees.append({
            "children_left": [int(item) for item in tree.children_left],
            "children_right": [int(item) for item in tree.children_right],
            "feature": [int(item) for item in tree.feature],
            "threshold": [float(item) for item in tree.threshold],
            "value": [[float(item) for item in row] for row in values],
        })

    params = forest.get_params(deep=False)
    record: dict[str, Any] = {
        "exporter": EXPORTER_ID,
        "sklearn_version": sklearn.__version__,
        "numpy_version": np.__version__,
        "n_estimators": len(forest.estimators_),
        "random_state": _scalar(params.get("random_state")),
        "max_depth": _scalar(params.get("max_depth")),
        "min_samples_split": _scalar(params.get("min_samples_split")),
        "min_samples_leaf": _scalar(params.get("min_samples_leaf")),
        "max_features": _scalar(params.get("max_features")),
        "class_weight": _scalar(params.get("class_weight")),
        "bootstrap": _scalar(params.get("bootstrap")),
    }
    for key, value in (provenance or {}).items():
        if key in record:
            raise ValueError(f"Provenance key {key!r} is reserved by the exporter.")
        record[key] = value

    document = {
        "format": FORMAT_NAME,
        "format_version": FORMAT_VERSION,
        "model_type": MODEL_TYPE,
        "feature_schema": feature_schema,
        "n_features": n_features,
        "classes": list(MODEL_CLASS_ORDER),
        "decision_rule": DECISION_RULE,
        "aggregation": AGGREGATION,
        "trees": trees,
        "provenance": record,
    }
    data = encode_document(document)
    parse_model(
        data,
        sha256=hashlib.sha256(data).hexdigest(),
        expected_feature_schema=feature_schema,
        expected_n_features=n_features,
    )
    return document


def write_model_artifact(document: Mapping[str, Any], path: str | Path) -> str:
    """Write a model document as canonical JSON and return its SHA-256.

    The digest is reported for review only; writing never approves a model.
    """
    data = encode_document(document)
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(target.name + ".tmp")
    temporary.write_bytes(data)
    temporary.replace(target)
    return hashlib.sha256(data).hexdigest()


def _scalar(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, np.generic):
        return value.item()
    return str(value)
