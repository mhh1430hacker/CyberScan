"""Safe, strictly validated JSON format for CyberScan random-forest models.

A model artifact is plain JSON data: per-tree node arrays plus class
distributions. It is never deserialized into executable objects. Loading is
ordered so that untrusted bytes are checked as cheaply and as early as
possible:

1. The file size is bounded before and during the read.
2. The SHA-256 of the raw bytes must equal a digest supplied by the caller
   from a trusted source (the approved-model registry). The artifact's own
   contents are never used as a trust anchor. A mismatch is rejected before
   any parsing happens.
3. The JSON is parsed strictly: duplicate keys, NaN/Infinity, overflowing
   numbers, unknown fields, and wrong types are rejected.
4. Every tree is validated structurally (bounded size and depth, forward-only
   child references, exactly one parent per non-root node, feature indices in
   range, finite thresholds, valid class distributions).

A matching digest proves artifact identity, not model quality, and it does not
protect against an attacker who can modify both the application code and the
approved-model registry.

Prediction semantics match scikit-learn's ``RandomForestClassifier``: inputs
are cast to float32, a sample goes to the left child when
``x[feature] <= threshold``, and class probabilities are the mean of the leaf
class distributions over all trees.

This module must not import scikit-learn, joblib, pickle, or any legacy model
loader.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np

from ml.feature_schema import FEATURE_SCHEMA_VERSION, LATENT_DIMENSION, MODEL_CLASS_ORDER

FORMAT_NAME = "cyberscan-forest"
FORMAT_VERSION = 1
MODEL_TYPE = "random_forest_classifier"
DECISION_RULE = "float32_input_le_threshold"
AGGREGATION = "mean_leaf_distribution"

LEAF_CHILD = -1
LEAF_FEATURE = -2
LEAF_THRESHOLD = -2.0

TOP_LEVEL_KEYS = frozenset({
    "format",
    "format_version",
    "model_type",
    "feature_schema",
    "n_features",
    "classes",
    "decision_rule",
    "aggregation",
    "trees",
    "provenance",
})
TREE_KEYS = frozenset({"children_left", "children_right", "feature", "threshold", "value"})

_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True)
class ForestLimits:
    """Upper bounds applied to every artifact before and during validation."""

    max_file_bytes: int = 32 * 1024 * 1024
    max_trees: int = 1000
    max_nodes_per_tree: int = 65_535
    max_total_nodes: int = 500_000
    max_depth: int = 64
    max_abs_threshold: float = 1e3
    distribution_tolerance: float = 1e-6
    max_provenance_entries: int = 64
    max_provenance_string: int = 1024


DEFAULT_LIMITS = ForestLimits()


class ModelFormatError(ValueError):
    """Raised when an artifact is unapproved, oversized, malformed, or incompatible.

    ``code`` is one of: ``unapproved``, ``io``, ``too_large``,
    ``digest_mismatch``, ``not_json``, ``schema``, ``structure``, ``values``,
    ``input``.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class ForestTree:
    children_left: np.ndarray
    children_right: np.ndarray
    feature: np.ndarray
    threshold: np.ndarray
    value: np.ndarray
    depth: int


@dataclass(frozen=True)
class ForestModel:
    classes: tuple[str, ...]
    n_features: int
    feature_schema: str
    trees: tuple[ForestTree, ...]
    provenance: Mapping[str, Any]
    sha256: str

    @property
    def node_count(self) -> int:
        return sum(len(tree.feature) for tree in self.trees)

    def predict_proba(self, X: Any) -> np.ndarray:
        """Return mean leaf class distributions, shape (n_samples, n_classes)."""
        samples = _validate_input(X, self.n_features)
        total = np.zeros((samples.shape[0], len(self.classes)), dtype=np.float64)
        rows = np.arange(samples.shape[0])
        for tree in self.trees:
            node = np.zeros(samples.shape[0], dtype=np.int64)
            for _ in range(tree.depth):
                left = tree.children_left[node]
                internal = left != LEAF_CHILD
                if not internal.any():
                    break
                feature = tree.feature[node]
                values = samples[rows, np.where(internal, feature, 0)]
                go_left = values <= tree.threshold[node]
                next_node = np.where(go_left, left, tree.children_right[node])
                node = np.where(internal, next_node, node)
            total += tree.value[node]
        return total / len(self.trees)

    def predict(self, X: Any) -> list[str]:
        """Return the highest-probability class per sample.

        Ties resolve to the class that appears first in ``classes``.
        """
        probabilities = self.predict_proba(X)
        return [self.classes[index] for index in np.argmax(probabilities, axis=1)]


def normalize_sha256(value: Any) -> str:
    """Return a lowercase SHA-256 hex digest, or raise ``unapproved``."""
    if not isinstance(value, str) or not _SHA256_PATTERN.fullmatch(value.lower()):
        raise ModelFormatError(
            "unapproved", "No valid approved SHA-256 digest was supplied for this model."
        )
    return value.lower()


def read_model_bytes(
    path: str | Path,
    expected_sha256: Any,
    *,
    limits: ForestLimits = DEFAULT_LIMITS,
) -> bytes:
    """Read a bounded artifact and verify it against the trusted digest."""
    expected = normalize_sha256(expected_sha256)
    model_path = Path(path)
    try:
        size = model_path.stat().st_size
        if size > limits.max_file_bytes:
            raise ModelFormatError(
                "too_large",
                f"Model file is {size} bytes; the limit is {limits.max_file_bytes} bytes.",
            )
        with model_path.open("rb") as handle:
            data = handle.read(limits.max_file_bytes + 1)
    except ModelFormatError:
        raise
    except OSError as exc:
        raise ModelFormatError("io", f"Model file could not be read: {exc}") from exc
    if len(data) > limits.max_file_bytes:
        raise ModelFormatError("too_large", "Model file grew beyond the size limit while being read.")
    actual = hashlib.sha256(data).hexdigest()
    if not hmac.compare_digest(actual, expected):
        raise ModelFormatError(
            "digest_mismatch",
            "Model file SHA-256 does not match the approved digest.",
        )
    return data


def load_model(
    path: str | Path,
    expected_sha256: Any,
    *,
    expected_feature_schema: str = FEATURE_SCHEMA_VERSION,
    expected_n_features: int = LATENT_DIMENSION,
    expected_classes: Sequence[str] = MODEL_CLASS_ORDER,
    limits: ForestLimits = DEFAULT_LIMITS,
) -> ForestModel:
    """Read, verify, parse, and validate an approved model artifact."""
    data = read_model_bytes(path, expected_sha256, limits=limits)
    return parse_model(
        data,
        sha256=hashlib.sha256(data).hexdigest(),
        expected_feature_schema=expected_feature_schema,
        expected_n_features=expected_n_features,
        expected_classes=expected_classes,
        limits=limits,
    )


def parse_model(
    data: bytes,
    *,
    sha256: str,
    expected_feature_schema: str = FEATURE_SCHEMA_VERSION,
    expected_n_features: int = LATENT_DIMENSION,
    expected_classes: Sequence[str] = MODEL_CLASS_ORDER,
    limits: ForestLimits = DEFAULT_LIMITS,
) -> ForestModel:
    """Parse and validate artifact bytes whose digest was already verified."""
    if len(data) > limits.max_file_bytes:
        raise ModelFormatError("too_large", "Model data exceeds the size limit.")
    document = _strict_json(data)
    return _build_model(
        document,
        sha256=sha256,
        expected_feature_schema=expected_feature_schema,
        expected_n_features=expected_n_features,
        expected_classes=tuple(expected_classes),
        limits=limits,
    )


def encode_document(document: Mapping[str, Any]) -> bytes:
    """Serialize a model document as canonical UTF-8 JSON (no NaN/Infinity)."""
    return json.dumps(
        document, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def _reject_constant(name: str) -> Any:
    raise ModelFormatError("not_json", f"Non-finite JSON constant {name} is not allowed.")


def _parse_float(text: str) -> float:
    value = float(text)
    if not math.isfinite(value):
        raise ModelFormatError("not_json", f"JSON number {text[:32]} is not finite.")
    return value


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ModelFormatError("not_json", f"Duplicate JSON key: {key[:64]!r}.")
        result[key] = value
    return result


def _strict_json(data: bytes) -> Any:
    if not isinstance(data, (bytes, bytearray)):
        raise ModelFormatError("not_json", "Model data must be bytes.")
    try:
        text = bytes(data).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ModelFormatError("not_json", "Model file is not valid UTF-8.") from exc
    if text.startswith("﻿"):
        raise ModelFormatError("not_json", "Model file must not start with a byte-order mark.")
    try:
        return json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
            parse_float=_parse_float,
        )
    except ModelFormatError:
        raise
    except (ValueError, RecursionError) as exc:
        raise ModelFormatError("not_json", f"Model file is not valid JSON: {exc}") from exc


def _require_keys(obj: Any, expected: frozenset[str], where: str) -> Mapping[str, Any]:
    if not isinstance(obj, dict):
        raise ModelFormatError("schema", f"{where} must be a JSON object.")
    keys = set(obj)
    missing = sorted(expected - keys)
    unknown = sorted(keys - expected)
    if missing or unknown:
        raise ModelFormatError(
            "schema",
            f"{where} fields do not match the schema; missing={missing[:8]}, unknown={[k[:64] for k in unknown[:8]]}.",
        )
    return obj


def _is_int(value: Any) -> bool:
    return type(value) is int


def _is_number(value: Any) -> bool:
    return type(value) in (int, float)


def _expect_equal(document: Mapping[str, Any], key: str, expected: Any) -> None:
    value = document[key]
    if type(value) is not type(expected) or value != expected:
        raise ModelFormatError(
            "schema", f"Unsupported {key}: expected {expected!r}, found {str(value)[:64]!r}."
        )


def _build_model(
    document: Any,
    *,
    sha256: str,
    expected_feature_schema: str,
    expected_n_features: int,
    expected_classes: tuple[str, ...],
    limits: ForestLimits,
) -> ForestModel:
    document = _require_keys(document, TOP_LEVEL_KEYS, "Model document")
    _expect_equal(document, "format", FORMAT_NAME)
    _expect_equal(document, "format_version", FORMAT_VERSION)
    _expect_equal(document, "model_type", MODEL_TYPE)
    _expect_equal(document, "decision_rule", DECISION_RULE)
    _expect_equal(document, "aggregation", AGGREGATION)
    _expect_equal(document, "feature_schema", expected_feature_schema)
    _expect_equal(document, "n_features", expected_n_features)

    classes = document["classes"]
    if (
        not isinstance(classes, list)
        or not all(isinstance(item, str) for item in classes)
        or tuple(classes) != expected_classes
    ):
        raise ModelFormatError(
            "schema", f"Model classes must be exactly {list(expected_classes)} in that order."
        )

    provenance = _validate_provenance(document["provenance"], limits)

    trees = document["trees"]
    if not isinstance(trees, list) or not 1 <= len(trees) <= limits.max_trees:
        raise ModelFormatError(
            "structure", f"Model must contain between 1 and {limits.max_trees} trees."
        )
    parsed: list[ForestTree] = []
    total_nodes = 0
    for index, tree in enumerate(trees):
        node_count = _tree_node_count(tree, index, limits)
        total_nodes += node_count
        if total_nodes > limits.max_total_nodes:
            raise ModelFormatError(
                "structure", f"Model exceeds the limit of {limits.max_total_nodes} total nodes."
            )
        parsed.append(_validate_tree(tree, index, expected_n_features, len(classes), limits))

    return ForestModel(
        classes=tuple(classes),
        n_features=expected_n_features,
        feature_schema=expected_feature_schema,
        trees=tuple(parsed),
        provenance=provenance,
        sha256=sha256,
    )


def _validate_provenance(value: Any, limits: ForestLimits) -> Mapping[str, Any]:
    if not isinstance(value, dict) or len(value) > limits.max_provenance_entries:
        raise ModelFormatError(
            "schema",
            f"provenance must be an object with at most {limits.max_provenance_entries} entries.",
        )
    for key, item in value.items():
        if len(key) > limits.max_provenance_string:
            raise ModelFormatError("schema", "provenance key is too long.")
        if isinstance(item, str):
            if len(item) > limits.max_provenance_string:
                raise ModelFormatError("schema", f"provenance value for {key[:64]!r} is too long.")
        elif item is not None and type(item) not in (bool, int, float):
            raise ModelFormatError(
                "schema", f"provenance value for {key[:64]!r} must be a string, number, boolean, or null."
            )
    return dict(value)


def _tree_node_count(tree: Any, index: int, limits: ForestLimits) -> int:
    tree = _require_keys(tree, TREE_KEYS, f"Tree {index}")
    lengths = set()
    for key in TREE_KEYS:
        if not isinstance(tree[key], list):
            raise ModelFormatError("schema", f"Tree {index} field {key} must be an array.")
        lengths.add(len(tree[key]))
    if len(lengths) != 1:
        raise ModelFormatError("structure", f"Tree {index} arrays have different lengths.")
    node_count = lengths.pop()
    if not 1 <= node_count <= limits.max_nodes_per_tree:
        raise ModelFormatError(
            "structure",
            f"Tree {index} must have between 1 and {limits.max_nodes_per_tree} nodes.",
        )
    return node_count


def _int_array(values: list[Any], name: str, index: int) -> np.ndarray:
    if not all(_is_int(item) for item in values):
        raise ModelFormatError("schema", f"Tree {index} field {name} must contain integers only.")
    try:
        return np.array(values, dtype=np.int64)
    except OverflowError as exc:
        raise ModelFormatError("values", f"Tree {index} field {name} is out of range.") from exc


def _validate_tree(
    tree: Mapping[str, Any],
    index: int,
    n_features: int,
    n_classes: int,
    limits: ForestLimits,
) -> ForestTree:
    left = _int_array(tree["children_left"], "children_left", index)
    right = _int_array(tree["children_right"], "children_right", index)
    feature = _int_array(tree["feature"], "feature", index)
    if not all(_is_number(item) for item in tree["threshold"]):
        raise ModelFormatError("schema", f"Tree {index} thresholds must be numbers.")
    threshold = np.array(tree["threshold"], dtype=np.float64)

    rows = tree["value"]
    if not all(
        isinstance(row, list) and len(row) == n_classes and all(_is_number(item) for item in row)
        for row in rows
    ):
        raise ModelFormatError(
            "values",
            f"Tree {index} values must be arrays of {n_classes} numbers, one per node.",
        )
    value = np.array(rows, dtype=np.float64).reshape(len(rows), n_classes)

    node_count = len(feature)
    positions = np.arange(node_count)
    leaf = left == LEAF_CHILD
    internal = ~leaf

    if np.any(leaf & ((right != LEAF_CHILD) | (feature != LEAF_FEATURE) | (threshold != LEAF_THRESHOLD))):
        raise ModelFormatError(
            "structure",
            f"Tree {index} leaves must have children -1/-1, feature -2, and threshold -2.0.",
        )
    if np.any(internal & ((left <= positions) | (right <= positions) | (left >= node_count) | (right >= node_count) | (left == right))):
        raise ModelFormatError(
            "structure",
            f"Tree {index} internal nodes must reference two distinct later nodes within the tree.",
        )
    if np.any(internal & ((feature < 0) | (feature >= n_features))):
        raise ModelFormatError(
            "structure", f"Tree {index} uses a feature index outside [0, {n_features})."
        )
    if np.any(internal & ~(np.abs(threshold) <= limits.max_abs_threshold)):
        raise ModelFormatError(
            "values",
            f"Tree {index} has a split threshold outside +/-{limits.max_abs_threshold:g}.",
        )

    references = np.bincount(
        np.concatenate((left[internal], right[internal])), minlength=node_count
    )
    if references[0] != 0 or np.any(references[1:] != 1):
        raise ModelFormatError(
            "structure",
            f"Tree {index} must be a single tree: the root has no parent and every other node exactly one.",
        )

    depth_of = np.zeros(node_count, dtype=np.int64)
    for node in np.flatnonzero(internal):
        child_depth = depth_of[node] + 1
        depth_of[left[node]] = child_depth
        depth_of[right[node]] = child_depth
    depth = int(depth_of.max())
    if depth > limits.max_depth:
        raise ModelFormatError(
            "structure", f"Tree {index} depth {depth} exceeds the limit of {limits.max_depth}."
        )

    if np.any(value < 0) or np.any(np.abs(value.sum(axis=1) - 1.0) > limits.distribution_tolerance):
        raise ModelFormatError(
            "values",
            f"Tree {index} node values must be non-negative class distributions summing to 1.",
        )

    for array in (left, right, feature, threshold, value):
        array.setflags(write=False)
    return ForestTree(
        children_left=left,
        children_right=right,
        feature=feature,
        threshold=threshold,
        value=value,
        depth=depth,
    )


def _validate_input(X: Any, n_features: int) -> np.ndarray:
    try:
        samples = np.asarray(X, dtype=np.float64)
    except (TypeError, ValueError) as exc:
        raise ModelFormatError("input", "Feature vectors must be numeric.") from exc
    if samples.ndim == 1:
        samples = samples.reshape(1, -1)
    if samples.ndim != 2 or samples.shape[1] != n_features:
        raise ModelFormatError(
            "input", f"Expected feature vectors with {n_features} values, got shape {samples.shape}."
        )
    if not np.all(np.isfinite(samples)):
        raise ModelFormatError("input", "Feature vectors must be finite.")
    with np.errstate(over="ignore"):
        as_float32 = samples.astype(np.float32)
    if not np.all(np.isfinite(as_float32)):
        raise ModelFormatError("input", "Feature values exceed the float32 range.")
    return as_float32
