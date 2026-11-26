"""Evaluate a LightGBM text model (``Booster.save_model`` format, v3/v4) without lightgbm.

Pure Python, so the same code runs on the website (Lambda), on the desktop and on the phone
(Pyodide). Only what prediction needs is read: per tree ``split_feature``, ``threshold``,
``decision_type``, ``left_child``/``right_child``, ``leaf_value`` and, for categorical splits,
``cat_boundaries``/``cat_threshold``. The decision rules follow LightGBM's ``tree.h``:

* numerical split: a NaN becomes 0 unless the node's missing type is NaN; a value that is
  "missing" for the node (zero for missing type Zero, NaN for missing type NaN) goes to the
  default side (decision_type bit 1); otherwise ``value <= threshold`` goes left;
* categorical split (decision_type bit 0): NaN goes right when the missing type is NaN (else it
  is category 0), a negative value goes right, otherwise the category goes left when its bit is
  set in the node's bitset ``cat_threshold[cat_boundaries[i]:cat_boundaries[i+1]]``;
* a child index < 0 is leaf ``~index``; the model output is the sum of the trees' leaves
  (leaf values already include the learning rate), passed through the sigmoid for a binary
  objective (``objective=binary sigmoid:k`` gives ``1 / (1 + exp(-k * raw))``).

Tests compare it with the lightgbm package (to ~1e-9).
"""
from __future__ import annotations

import gzip
import math
from dataclasses import dataclass
from pathlib import Path

ZERO_THRESHOLD = 1e-35


@dataclass
class Tree:
    split_feature: list[int]
    threshold: list[float]
    decision_type: list[int]
    left_child: list[int]
    right_child: list[int]
    leaf_value: list[float]
    cat_boundaries: list[int]
    cat_threshold: list[int]

    def predict(self, x) -> float:
        if not self.split_feature:
            return self.leaf_value[0]
        node = 0
        split, thresholds, kinds = self.split_feature, self.threshold, self.decision_type
        left, right = self.left_child, self.right_child
        while True:
            value = x[split[node]]
            kind = kinds[node]
            missing = (kind >> 2) & 3
            if kind & 1:                                    # categorical
                if value != value:                          # NaN
                    if missing == 2:
                        child = right[node]
                    else:
                        child = self._category(node, 0)
                else:
                    category = int(value)
                    child = right[node] if category < 0 else self._category(node, category)
            else:                                           # numerical
                if value != value and missing != 2:
                    value = 0.0
                if (missing == 1 and -ZERO_THRESHOLD <= value <= ZERO_THRESHOLD) or (missing == 2 and value != value):
                    child = left[node] if kind & 2 else right[node]
                else:
                    child = left[node] if value <= thresholds[node] else right[node]
            if child < 0:
                return self.leaf_value[~child]
            node = child

    def _category(self, node: int, category: int) -> int:
        index = int(self.threshold[node])
        start, end = self.cat_boundaries[index], self.cat_boundaries[index + 1]
        word = category // 32
        if word < end - start and (self.cat_threshold[start + word] >> (category % 32)) & 1:
            return self.left_child[node]
        return self.right_child[node]


class LightGBMModel:
    def __init__(self, text: str):
        self.header: dict[str, str] = {}
        self.trees: list[Tree] = []
        block: dict[str, str] | None = None
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("Tree="):
                if block is not None:
                    self.trees.append(self._tree(block))
                block = {}
                continue
            if line in ("end of trees",):
                if block is not None:
                    self.trees.append(self._tree(block))
                block = None
                break
            if "=" not in line:
                continue
            key, _, value = line.partition("=")
            (block if block is not None else self.header)[key] = value
        if block:
            self.trees.append(self._tree(block))
        if not self.trees:
            raise ValueError("no trees in the model")
        if int(self.header.get("num_class", "1")) != 1 or int(self.header.get("num_tree_per_iteration", "1")) != 1:
            raise ValueError("only single-output models are supported")
        objective = self.header.get("objective", "")
        self.sigmoid: float | None = None
        if objective.startswith("binary"):
            self.sigmoid = 1.0
            for part in objective.split()[1:]:
                if part.startswith("sigmoid:"):
                    self.sigmoid = float(part.split(":", 1)[1])
        self.average_output = "average_output" in self.header
        self.max_feature_idx = int(self.header.get("max_feature_idx", "-1"))

    @staticmethod
    def _tree(block: dict[str, str]) -> Tree:
        def ints(key: str) -> list[int]:
            return [int(v) for v in block.get(key, "").split()]

        def floats(key: str) -> list[float]:
            return [float(v) for v in block.get(key, "").split()]

        tree = Tree(ints("split_feature"), floats("threshold"), ints("decision_type"), ints("left_child"),
                    ints("right_child"), floats("leaf_value"), ints("cat_boundaries"), ints("cat_threshold"))
        if int(block.get("num_leaves", "1")) > 1 and not (
                len(tree.split_feature) == len(tree.threshold) == len(tree.decision_type)
                == len(tree.left_child) == len(tree.right_child) == len(tree.leaf_value) - 1):
            raise ValueError("inconsistent tree")
        return tree

    @classmethod
    def load(cls, path: str | Path) -> "LightGBMModel":
        path = Path(path)
        data = path.read_bytes()
        if data[:2] == b"\x1f\x8b":
            data = gzip.decompress(data)
        return cls(data.decode("utf-8"))

    def raw_score(self, x) -> float:
        values = [float(v) for v in x]
        if len(values) <= self.max_feature_idx:
            raise ValueError(f"the model reads {self.max_feature_idx + 1} features, got {len(values)}")
        total = math.fsum(tree.predict(values) for tree in self.trees)
        return total / len(self.trees) if self.average_output else total

    def predict(self, x) -> float:
        raw = self.raw_score(x)
        if self.sigmoid is None:
            return raw
        return 1.0 / (1.0 + math.exp(-self.sigmoid * raw))
