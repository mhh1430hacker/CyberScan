from __future__ import annotations

import ast
import base64
import copy
import hashlib
import json
import pickle
import subprocess
import sys
from pathlib import Path

import numpy as np
import pytest

from ml import forest_format
from ml.feature_schema import FEATURE_SCHEMA_VERSION, LATENT_DIMENSION, MODEL_CLASS_ORDER
from ml.forest_format import ForestLimits, ModelFormatError, encode_document, load_model

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def valid_document() -> dict:
    """A tiny hand-written forest: one stump on feature 0 and one constant leaf."""
    return {
        "format": "cyberscan-forest",
        "format_version": 1,
        "model_type": "random_forest_classifier",
        "feature_schema": FEATURE_SCHEMA_VERSION,
        "n_features": LATENT_DIMENSION,
        "classes": list(MODEL_CLASS_ORDER),
        "decision_rule": "float32_input_le_threshold",
        "aggregation": "mean_leaf_distribution",
        "trees": [
            {
                "children_left": [1, -1, -1],
                "children_right": [2, -1, -1],
                "feature": [0, -2, -2],
                "threshold": [0.5, -2.0, -2.0],
                "value": [[0.5, 0.0, 0.5], [1.0, 0.0, 0.0], [0.0, 0.0, 1.0]],
            },
            {
                "children_left": [-1],
                "children_right": [-1],
                "feature": [-2],
                "threshold": [-2.0],
                "value": [[0.2, 0.8, 0.0]],
            },
        ],
        "provenance": {"note": "hand-written test fixture", "seed": 7},
    }


def write_artifact(directory: Path, content: dict | bytes, name: str = "model.json") -> tuple[Path, str]:
    data = content if isinstance(content, bytes) else encode_document(content)
    path = directory / name
    path.write_bytes(data)
    return path, hashlib.sha256(data).hexdigest()


def vector(first: float) -> np.ndarray:
    values = np.zeros(LATENT_DIMENSION)
    values[0] = first
    return values


def chain_tree(depth: int) -> dict:
    """A chain of the given depth: each split has a leaf on the left and continues right."""
    left, right, feature, threshold, value = [], [], [], [], []
    for level in range(depth):
        node = 2 * level
        left.append(node + 1)
        right.append(node + 2)
        feature.append(1)
        threshold.append(0.0)
        value.append([1.0, 0.0, 0.0])
        left.append(-1)
        right.append(-1)
        feature.append(-2)
        threshold.append(-2.0)
        value.append([0.0, 1.0, 0.0])
    left.append(-1)
    right.append(-1)
    feature.append(-2)
    threshold.append(-2.0)
    value.append([0.0, 0.0, 1.0])
    return {
        "children_left": left,
        "children_right": right,
        "feature": feature,
        "threshold": threshold,
        "value": value,
    }


# --- Valid artifacts -------------------------------------------------------


def test_valid_artifact_loads_and_predicts_mean_leaf_distribution(tmp_path):
    path, digest = write_artifact(tmp_path, valid_document())

    model = load_model(path, digest)

    assert model.classes == MODEL_CLASS_ORDER
    assert model.sha256 == digest
    assert model.node_count == 4
    probabilities = model.predict_proba(np.stack([vector(0.2), vector(0.9)]))
    np.testing.assert_allclose(probabilities, [[0.6, 0.4, 0.0], [0.1, 0.4, 0.5]])
    assert model.predict(np.stack([vector(0.2), vector(0.9)])) == ["clean", "malware"]


def test_single_vector_is_accepted_and_digest_case_is_normalized(tmp_path):
    path, digest = write_artifact(tmp_path, valid_document())

    model = load_model(path, digest.upper())

    assert model.predict(vector(0.2)) == ["clean"]


def test_split_uses_float32_input_and_less_or_equal(tmp_path):
    document = valid_document()
    document["trees"][0]["threshold"][0] = 0.1
    path, digest = write_artifact(tmp_path, document)
    model = load_model(path, digest)

    # float32(0.1) rounds up above the float64 threshold 0.1, so it goes right,
    # matching scikit-learn's float32 cast before tree traversal.
    assert model.predict_proba(vector(0.1))[0, 2] == pytest.approx(0.5)
    # A value exactly representable in float32 and equal to the threshold goes left.
    document["trees"][0]["threshold"][0] = 0.5
    path, digest = write_artifact(tmp_path, document, "exact.json")
    assert load_model(path, digest).predict_proba(vector(0.5))[0, 0] == pytest.approx(0.6)


def test_ties_resolve_to_first_class_in_declared_order(tmp_path):
    document = valid_document()
    document["trees"][1]["value"] = [[0.0, 1.0, 0.0]]
    path, digest = write_artifact(tmp_path, document)

    model = load_model(path, digest)

    np.testing.assert_allclose(model.predict_proba(vector(0.2)), [[0.5, 0.5, 0.0]])
    assert model.predict(vector(0.2)) == ["clean"]


def test_loaded_arrays_are_read_only(tmp_path):
    path, digest = write_artifact(tmp_path, valid_document())
    model = load_model(path, digest)

    with pytest.raises(ValueError):
        model.trees[0].threshold[0] = 99.0


# --- Isolation from executable deserialization -----------------------------


def test_module_source_does_not_import_executable_loaders():
    source = (PROJECT_ROOT / "ml" / "forest_format.py").read_text(encoding="utf-8")
    imported: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert not imported & {"pickle", "joblib", "sklearn", "dill", "cloudpickle", "marshal", "shelve"}
    assert "ml.structural_classifier" not in source


def test_importing_module_does_not_import_sklearn_or_joblib():
    code = (
        "import sys; import ml.forest_format; "
        "print(sorted(m for m in sys.modules if m.split('.')[0] in {'sklearn', 'joblib'}))"
    )
    completed = subprocess.run(
        [sys.executable, "-c", code],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    assert completed.stdout.strip() == "[]"


@pytest.fixture
def forbid_pickle(monkeypatch):
    calls: list[str] = []

    def forbidden(name):
        def _raise(*_args, **_kwargs):
            calls.append(name)
            raise AssertionError(f"{name} must never be called by the model loader")

        return _raise

    monkeypatch.setattr(pickle, "load", forbidden("pickle.load"))
    monkeypatch.setattr(pickle, "loads", forbidden("pickle.loads"))
    monkeypatch.setattr(pickle, "Unpickler", forbidden("pickle.Unpickler"))
    return calls


def legacy_pickle_in_json_document() -> dict:
    """Hand-written replica of the legacy layout; the payload is never decoded."""
    payload = base64.b64encode(b"\x80\x04cos\nsystem\n(S'echo unsafe'\ntR.").decode("ascii")
    return {
        "format": "cyberscan-random-forest-json-v1",
        "model": {"estimators_b64": payload},
        "metadata": {
            "schema_version": 1,
            "embedding_schema": "byte-histogram-entropy-v1",
            "embedding_dimension": 4096,
            "classes": list(MODEL_CLASS_ORDER),
            "_model_hash": "0" * 64,
        },
    }


def test_legacy_pickle_in_json_payload_is_rejected_without_deserialization(tmp_path, forbid_pickle):
    path, digest = write_artifact(tmp_path, legacy_pickle_in_json_document())

    with pytest.raises(ModelFormatError) as error:
        load_model(path, digest)

    assert error.value.code == "schema"
    assert forbid_pickle == []


def test_raw_pickle_bytes_are_rejected_without_deserialization(tmp_path, forbid_pickle):
    path, digest = write_artifact(tmp_path, b"\x80\x04cos\nsystem\n.")

    with pytest.raises(ModelFormatError) as error:
        load_model(path, digest)

    assert error.value.code == "not_json"
    assert forbid_pickle == []


# --- Approval, integrity, and size are checked before parsing --------------


@pytest.mark.parametrize("approved", [None, "", "abc", "g" * 64, 123, "0" * 63])
def test_missing_or_malformed_approval_is_unapproved(tmp_path, approved):
    path, _digest = write_artifact(tmp_path, valid_document())

    with pytest.raises(ModelFormatError) as error:
        load_model(path, approved)

    assert error.value.code == "unapproved"


def test_digest_embedded_in_the_artifact_is_not_a_trust_anchor(tmp_path):
    document = valid_document()
    embedded = hashlib.sha256(encode_document(document)).hexdigest()
    document["provenance"]["sha256"] = embedded
    path, _actual = write_artifact(tmp_path, document)

    with pytest.raises(ModelFormatError) as error:
        load_model(path, embedded)

    assert error.value.code == "digest_mismatch"


def test_tampered_artifact_is_rejected_before_parsing(tmp_path):
    path, digest = write_artifact(tmp_path, valid_document())
    path.write_bytes(b"{ this is not json and would fail parsing")

    with pytest.raises(ModelFormatError) as error:
        load_model(path, digest)

    assert error.value.code == "digest_mismatch"


def test_single_byte_change_is_detected(tmp_path):
    path, digest = write_artifact(tmp_path, valid_document())
    data = bytearray(path.read_bytes())
    data[data.index(b"0.2")] = ord("1")
    path.write_bytes(bytes(data))

    with pytest.raises(ModelFormatError) as error:
        load_model(path, digest)

    assert error.value.code == "digest_mismatch"


def test_oversized_artifact_is_rejected_before_reading(tmp_path, monkeypatch):
    path, digest = write_artifact(tmp_path, valid_document())
    limits = ForestLimits(max_file_bytes=64)

    def no_open(*_args, **_kwargs):
        raise AssertionError("an oversized file must not be opened")

    monkeypatch.setattr(Path, "open", no_open)
    with pytest.raises(ModelFormatError) as error:
        load_model(path, digest, limits=limits)

    assert error.value.code == "too_large"


def test_missing_file_is_reported_as_io_error(tmp_path):
    with pytest.raises(ModelFormatError) as error:
        load_model(tmp_path / "absent.json", "0" * 64)

    assert error.value.code == "io"


# --- Strict JSON parsing ---------------------------------------------------


def _replace_once(data: bytes, old: bytes, new: bytes) -> bytes:
    assert old in data
    return data.replace(old, new, 1)


@pytest.mark.parametrize(
    ("mutate", "fragment"),
    [
        pytest.param(lambda d: _replace_once(d, b'"seed":7', b'"seed":7,"seed":8'), "Duplicate JSON key", id="duplicate-key"),
        pytest.param(lambda d: _replace_once(d, b"0.5,-2.0", b"NaN,-2.0"), "Non-finite", id="nan"),
        pytest.param(lambda d: _replace_once(d, b"0.5,-2.0", b"Infinity,-2.0"), "Non-finite", id="infinity"),
        pytest.param(lambda d: _replace_once(d, b"0.5,-2.0", b"-Infinity,-2.0"), "Non-finite", id="negative-infinity"),
        pytest.param(lambda d: _replace_once(d, b"0.5,-2.0", b"1e999,-2.0"), "not finite", id="overflow-to-inf"),
        pytest.param(lambda d: b"\xef\xbb\xbf" + d, "byte-order mark", id="byte-order-mark"),
        pytest.param(lambda d: d[: len(d) // 2], "not valid JSON", id="truncated"),
        pytest.param(lambda _d: b"", "not valid JSON", id="empty"),
        pytest.param(lambda _d: b"\xff\xfe\x00", "not valid UTF-8", id="not-utf8"),
        pytest.param(lambda _d: b"[" * 100_000 + b"]" * 100_000, "not valid JSON", id="deep-nesting"),
    ],
)
def test_strict_json_rejections(tmp_path, mutate, fragment):
    data = mutate(encode_document(valid_document()))
    path, digest = write_artifact(tmp_path, data)

    with pytest.raises(ModelFormatError) as error:
        load_model(path, digest)

    assert error.value.code == "not_json"
    assert fragment in str(error.value)


# --- Schema ----------------------------------------------------------------


def _mutated(change) -> dict:
    document = copy.deepcopy(valid_document())
    change(document)
    return document


SCHEMA_MUTATIONS = {
    "unknown-top-level-field": lambda d: d.update({"extra": 1}),
    "missing-top-level-field": lambda d: d.pop("aggregation"),
    "unknown-tree-field": lambda d: d["trees"][0].update({"weights": [1, 1, 1]}),
    "missing-tree-field": lambda d: d["trees"][0].pop("value"),
    "wrong-format": lambda d: d.update({"format": "cyberscan-random-forest-json-v1"}),
    "wrong-version": lambda d: d.update({"format_version": 2}),
    "version-as-float": lambda d: d.update({"format_version": 1.0}),
    "version-as-bool": lambda d: d.update({"format_version": True}),
    "wrong-model-type": lambda d: d.update({"model_type": "gradient_boosting"}),
    "wrong-decision-rule": lambda d: d.update({"decision_rule": "float64_input_lt_threshold"}),
    "wrong-aggregation": lambda d: d.update({"aggregation": "majority_vote"}),
    "wrong-feature-schema": lambda d: d.update({"feature_schema": "byte-histogram-entropy-v1"}),
    "wrong-feature-count": lambda d: d.update({"n_features": 4095}),
    "reordered-classes": lambda d: d.update({"classes": ["clean", "malware", "suspicious"]}),
    "renamed-class": lambda d: d.update({"classes": ["clean", "suspicious", "infected"]}),
    "extra-class": lambda d: d.update({"classes": [*MODEL_CLASS_ORDER, "unknown"]}),
    "feature-as-float": lambda d: d["trees"][0]["feature"].__setitem__(0, 0.0),
    "child-as-bool": lambda d: d["trees"][0]["children_left"].__setitem__(1, True),
    "threshold-as-string": lambda d: d["trees"][0]["threshold"].__setitem__(0, "0.5"),
    "provenance-not-object": lambda d: d.update({"provenance": ["x"]}),
    "provenance-nested": lambda d: d["provenance"].update({"nested": {"a": 1}}),
    "provenance-too-long": lambda d: d["provenance"].update({"note": "x" * 2000}),
}


@pytest.mark.parametrize("name", sorted(SCHEMA_MUTATIONS))
def test_schema_violations_are_rejected(tmp_path, name):
    path, digest = write_artifact(tmp_path, _mutated(SCHEMA_MUTATIONS[name]))

    with pytest.raises(ModelFormatError) as error:
        load_model(path, digest)

    assert error.value.code == "schema"


def test_top_level_array_is_rejected(tmp_path):
    path, digest = write_artifact(tmp_path, json.dumps([valid_document()]).encode("utf-8"))

    with pytest.raises(ModelFormatError) as error:
        load_model(path, digest)

    assert error.value.code == "schema"


# --- Tree structure --------------------------------------------------------


def _set(tree_index: int, field: str, node: int, value):
    return lambda d: d["trees"][tree_index][field].__setitem__(node, value)


LATER_NODES = "reference two distinct later nodes"
LEAF_SHAPE = "leaves must have children -1/-1"
FEATURE_RANGE = "feature index outside"
SINGLE_TREE = "must be a single tree"

STRUCTURE_MUTATIONS = {
    "feature-negative": (_set(0, "feature", 0, -1), "structure", FEATURE_RANGE),
    "feature-at-dimension": (_set(0, "feature", 0, LATENT_DIMENSION), "structure", FEATURE_RANGE),
    "feature-huge": (_set(0, "feature", 0, 10**30), "values", "out of range"),
    "child-points-backward": (_set(0, "children_right", 0, 0), "structure", LATER_NODES),
    "child-self-reference": (_set(0, "children_left", 0, 0), "structure", LATER_NODES),
    "child-out-of-range": (_set(0, "children_right", 0, 3), "structure", LATER_NODES),
    "children-identical": (_set(0, "children_right", 0, 1), "structure", LATER_NODES),
    "leaf-with-one-child": (_set(0, "children_right", 1, 2), "structure", LEAF_SHAPE),
    "leaf-with-feature": (_set(0, "feature", 1, 0), "structure", LEAF_SHAPE),
    "leaf-with-threshold": (_set(0, "threshold", 1, 0.25), "structure", LEAF_SHAPE),
    "arrays-different-lengths": (
        lambda d: d["trees"][0]["feature"].append(-2),
        "structure",
        "different lengths",
    ),
    "empty-tree": (
        lambda d: d["trees"][0].update(
            {"children_left": [], "children_right": [], "feature": [], "threshold": [], "value": []}
        ),
        "structure",
        "must have between 1 and",
    ),
    "no-trees": (lambda d: d.update({"trees": []}), "structure", "between 1 and"),
    "orphan-node": (
        lambda d: d["trees"][1].update(
            {
                "children_left": [-1, -1],
                "children_right": [-1, -1],
                "feature": [-2, -2],
                "threshold": [-2.0, -2.0],
                "value": [[0.2, 0.8, 0.0], [1.0, 0.0, 0.0]],
            }
        ),
        "structure",
        SINGLE_TREE,
    ),
    # Nodes 1 and 2 both point at nodes 3 and 4 (a DAG, not a tree).
    "shared-children": (
        lambda d: d.update(
            {
                "trees": [
                    {
                        "children_left": [1, 3, 4, -1, -1],
                        "children_right": [2, 4, 3, -1, -1],
                        "feature": [0, 1, 2, -2, -2],
                        "threshold": [0.5, 0.5, 0.5, -2.0, -2.0],
                        "value": [[1.0, 0.0, 0.0]] * 5,
                    }
                ]
            }
        ),
        "structure",
        SINGLE_TREE,
    ),
}


@pytest.mark.parametrize("name", sorted(STRUCTURE_MUTATIONS))
def test_invalid_tree_structures_are_rejected(tmp_path, name):
    mutation, code, fragment = STRUCTURE_MUTATIONS[name]
    path, digest = write_artifact(tmp_path, _mutated(mutation))

    with pytest.raises(ModelFormatError) as error:
        load_model(path, digest)

    assert error.value.code == code
    assert fragment in str(error.value)


def test_depth_limit_is_measured_not_trusted(tmp_path):
    limits = ForestLimits(max_depth=3)
    ok_path, ok_digest = write_artifact(tmp_path, _mutated(lambda d: d.update({"trees": [chain_tree(3)]})), "ok.json")
    deep_path, deep_digest = write_artifact(tmp_path, _mutated(lambda d: d.update({"trees": [chain_tree(4)]})), "deep.json")

    assert load_model(ok_path, ok_digest, limits=limits).trees[0].depth == 3
    with pytest.raises(ModelFormatError) as error:
        load_model(deep_path, deep_digest, limits=limits)
    assert error.value.code == "structure"


def test_tree_count_and_node_limits_are_enforced(tmp_path):
    path, digest = write_artifact(tmp_path, valid_document())

    for limits in (
        ForestLimits(max_trees=1),
        ForestLimits(max_nodes_per_tree=2),
        ForestLimits(max_total_nodes=3),
    ):
        with pytest.raises(ModelFormatError) as error:
            load_model(path, digest, limits=limits)
        assert error.value.code == "structure"


# --- Values ----------------------------------------------------------------


SHAPE = "values must be arrays of 3 numbers"
DISTRIBUTION = "non-negative class distributions summing to 1"

VALUE_MUTATIONS = {
    "threshold-out-of-bounds": (_set(0, "threshold", 0, 1e6), "split threshold outside"),
    "distribution-too-short": (_set(0, "value", 1, [1.0, 0.0]), SHAPE),
    "distribution-too-long": (_set(0, "value", 1, [1.0, 0.0, 0.0, 0.0]), SHAPE),
    "distribution-not-array": (_set(0, "value", 1, 1.0), SHAPE),
    "distribution-string": (_set(0, "value", 1, ["1", "0", "0"]), SHAPE),
    "distribution-negative": (_set(0, "value", 1, [1.5, -0.5, 0.0]), DISTRIBUTION),
    "distribution-not-normalized": (_set(0, "value", 1, [0.5, 0.0, 0.0]), DISTRIBUTION),
    "distribution-counts": (_set(0, "value", 1, [3, 0, 0]), DISTRIBUTION),
}


@pytest.mark.parametrize("name", sorted(VALUE_MUTATIONS))
def test_invalid_values_are_rejected(tmp_path, name):
    mutation, fragment = VALUE_MUTATIONS[name]
    path, digest = write_artifact(tmp_path, _mutated(mutation))

    with pytest.raises(ModelFormatError) as error:
        load_model(path, digest)

    assert error.value.code == "values"
    assert fragment in str(error.value)


# --- Prediction inputs -----------------------------------------------------


@pytest.mark.parametrize(
    "features",
    [
        pytest.param(np.zeros(LATENT_DIMENSION - 1), id="too-few"),
        pytest.param(np.zeros((2, LATENT_DIMENSION + 1)), id="too-many"),
        pytest.param(np.zeros((1, 2, LATENT_DIMENSION)), id="three-dimensional"),
        pytest.param(np.full(LATENT_DIMENSION, np.nan), id="nan"),
        pytest.param(np.full(LATENT_DIMENSION, np.inf), id="inf"),
        pytest.param(np.full(LATENT_DIMENSION, 1e300), id="beyond-float32"),
        pytest.param(["a"] * LATENT_DIMENSION, id="non-numeric"),
    ],
)
def test_invalid_feature_vectors_are_rejected(tmp_path, features):
    path, digest = write_artifact(tmp_path, valid_document())
    model = load_model(path, digest)

    with pytest.raises(ModelFormatError) as error:
        model.predict_proba(features)

    assert error.value.code == "input"


def test_encode_document_refuses_non_finite_numbers():
    document = valid_document()
    document["trees"][0]["threshold"][0] = float("nan")

    with pytest.raises(ValueError):
        encode_document(document)


def test_encoded_artifacts_round_trip_through_strict_parser():
    data = encode_document(valid_document())
    model = forest_format.parse_model(data, sha256=hashlib.sha256(data).hexdigest())

    assert json.loads(data) == valid_document()
    assert model.predict(vector(0.9)) == ["malware"]
