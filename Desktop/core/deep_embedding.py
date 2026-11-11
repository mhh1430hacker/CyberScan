from __future__ import annotations

import hashlib
import math
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from numbers import Real
from typing import Any


class HighDimensionalEmbedding:
    """Deterministic 4096-D byte-artifact embedding and incremental k-NN model.

    No pretrained or malicious centroids are bundled. Labels and reference
    vectors enter the model only through ``partial_fit``.
    """

    DIMENSION = 4096
    DEFAULT_NGRAM_SIZES = (2, 3, 4)

    def __init__(
        self,
        *,
        neighbors: int = 5,
        confidence_threshold: float = 0.9995,
        max_samples_per_class: int = 256,
    ) -> None:
        if isinstance(neighbors, bool) or not isinstance(neighbors, int) or neighbors < 1:
            raise ValueError("neighbors must be a positive integer")
        if not math.isfinite(confidence_threshold) or not 0.0 <= confidence_threshold <= 1.0:
            raise ValueError("confidence_threshold must be between 0 and 1")
        if isinstance(max_samples_per_class, bool) or not isinstance(max_samples_per_class, int) or max_samples_per_class < neighbors:
            raise ValueError("max_samples_per_class must be an integer at least as large as neighbors")

        self.neighbors = neighbors
        self.confidence_threshold = confidence_threshold
        self.max_samples_per_class = max_samples_per_class
        self._samples: dict[str, list[tuple[float, ...]]] = defaultdict(list)
        self._sums: dict[str, list[float]] = {}
        self._counts: Counter[str] = Counter()

    @staticmethod
    def _feature_index(feature_name: str) -> tuple[int, float]:
        digest = hashlib.blake2b(
            feature_name.encode("utf-8", errors="surrogatepass"),
            digest_size=16,
            person=b"CyberScanEmbed",
        ).digest()
        index = int.from_bytes(digest[:8], "little") % HighDimensionalEmbedding.DIMENSION
        sign = -1.0 if digest[8] & 1 else 1.0
        return index, sign

    @staticmethod
    def _normalize(values: Sequence[Real]) -> tuple[float, ...]:
        if len(values) != HighDimensionalEmbedding.DIMENSION:
            raise ValueError(f"vectors must have exactly {HighDimensionalEmbedding.DIMENSION} dimensions")
        vector: list[float] = []
        for value in values:
            if isinstance(value, bool) or not isinstance(value, Real):
                raise TypeError("vector coordinates must be real numbers")
            coordinate = float(value)
            if not math.isfinite(coordinate):
                raise ValueError("vector coordinates must be finite")
            vector.append(coordinate)
        magnitude = math.sqrt(math.fsum(value * value for value in vector))
        if magnitude:
            vector = [value / magnitude for value in vector]
        return tuple(vector)

    @staticmethod
    def _bounded_positions(length: int, maximum: int) -> range:
        if length <= maximum:
            return range(length)
        stride = math.ceil(length / maximum)
        return range(0, length, stride)

    @classmethod
    def _derive_entropy(cls, data: bytes) -> dict[str, Any]:
        from core.nextgen_engine import NextGenCyberEngine

        return NextGenCyberEngine.analyze_entropy_topography(data)

    @classmethod
    def _derive_cfg(cls, data: bytes) -> dict[str, Any]:
        from core.nextgen_engine import NextGenCyberEngine

        return NextGenCyberEngine.extract_cfg_topology(data)

    def embed_bytes(
        self,
        data: bytes,
        *,
        entropy_topography: Mapping[str, Any] | None = None,
        cfg_topology: Mapping[str, Any] | None = None,
        ngram_sizes: Sequence[int] = DEFAULT_NGRAM_SIZES,
        max_ngrams_per_size: int = 16384,
    ) -> tuple[float, ...]:
        """Derive and L2-normalize a 4096-coordinate embedding from bytes."""
        if not isinstance(data, bytes):
            raise TypeError("data must be bytes")
        if not isinstance(max_ngrams_per_size, int) or isinstance(max_ngrams_per_size, bool) or max_ngrams_per_size < 1:
            raise ValueError("max_ngrams_per_size must be a positive integer")
        sizes = tuple(ngram_sizes)
        if any(isinstance(size, bool) or not isinstance(size, int) or size < 1 for size in sizes):
            raise ValueError("ngram_sizes must contain positive integers")

        entropy = entropy_topography if entropy_topography is not None else self._derive_entropy(data)
        cfg = cfg_topology if cfg_topology is not None else self._derive_cfg(data)
        vector = [0.0] * self.DIMENSION

        def add_feature(name: str, weight: float) -> None:
            if not math.isfinite(weight) or weight == 0.0:
                return
            index, sign = self._feature_index(name)
            vector[index] += sign * weight

        data_length = len(data)
        if data_length:
            byte_counts = Counter(data)
            for byte_value, count in byte_counts.items():
                add_feature(f"byte:1:{byte_value:02x}", count / data_length)

            for size in sizes:
                window_count = max(0, data_length - size + 1)
                if not window_count:
                    continue
                positions = self._bounded_positions(window_count, max_ngrams_per_size)
                grams: Counter[bytes] = Counter(data[position:position + size] for position in positions)
                sampled_total = sum(grams.values())
                for gram, count in grams.items():
                    add_feature(f"byte:{size}:{gram.hex()}", count / sampled_total)

        trajectory = entropy.get("trajectory", [])
        trajectory_length = len(trajectory)
        for index, value in enumerate(trajectory):
            add_feature(f"entropy:window:{index % 64}", float(value) / 8.0)
        for index, value in enumerate(entropy.get("gradients", [])):
            add_feature(f"entropy:gradient:{index % 64}", float(value) / 8.0)
        for key in ("mean_entropy", "peak_entropy", "gradient_variance"):
            if key in entropy:
                scale = 64.0 if key == "gradient_variance" else 8.0
                add_feature(f"entropy:summary:{key}", float(entropy[key]) / scale)
        add_feature("entropy:summary:window_count", math.log1p(trajectory_length) / 16.0)

        opcode_histogram: Mapping[str, Any] = cfg.get("opcode_frequency", {})
        for opcode, frequency in opcode_histogram.items():
            add_feature(f"opcode:{str(opcode).upper()}", float(frequency))

        numeric_cfg_keys = (
            "basic_block_count",
            "cyclomatic_complexity",
            "graph_density",
            "edge_count",
            "instruction_count",
            "back_edge_count",
            "back_edge_density",
        )
        for key in numeric_cfg_keys:
            if key in cfg:
                value = float(cfg[key])
                scale = max(1.0, math.log1p(data_length)) if key not in {"graph_density", "back_edge_density"} else 1.0
                add_feature(f"cfg:{key}", math.copysign(math.log1p(abs(value)) / scale, value))
        for pattern in cfg.get("detected_patterns", []):
            add_feature(f"cfg:pattern:{str(pattern)}", 1.0)
        add_feature(f"cfg:architecture:{cfg.get('architecture', 'unknown')}", 1.0)

        return self._normalize(vector)

    def embed(self, data: bytes, **artifacts: Any) -> tuple[float, ...]:
        """Alias for ``embed_bytes``."""
        return self.embed_bytes(data, **artifacts)

    def _coerce_training_vectors(
        self,
        vectors: Sequence[Real] | Sequence[Sequence[Real]] | bytes,
        labels: str | Sequence[str],
    ) -> tuple[list[tuple[float, ...]], list[str]]:
        if isinstance(vectors, bytes):
            vector_rows: list[tuple[float, ...]] = [self.embed_bytes(vectors)]
        else:
            if not isinstance(vectors, Sequence) or not vectors:
                raise ValueError("vectors must be a non-empty vector or sequence of vectors")
            first = vectors[0]
            if isinstance(first, Real) and not isinstance(first, bool):
                vector_rows = [self._normalize(vectors)]  # type: ignore[arg-type]
            else:
                vector_rows = [self._normalize(row) for row in vectors]  # type: ignore[arg-type]
        label_rows = [labels] if isinstance(labels, str) else list(labels)
        if len(vector_rows) != len(label_rows):
            raise ValueError("the number of labels must match the number of vectors")
        if any(not isinstance(label, str) or not label.strip() for label in label_rows):
            raise ValueError("labels must be non-empty strings")
        return vector_rows, [label.strip() for label in label_rows]

    def partial_fit(
        self,
        vectors: Sequence[Real] | Sequence[Sequence[Real]] | bytes,
        labels: str | Sequence[str],
    ) -> HighDimensionalEmbedding:
        """Incrementally add labeled vectors and update class centroids.

        Exemplar retention is bounded per label using FIFO replacement. This is
        an online nearest-neighbor model, not a calibrated probability model.
        """
        vector_rows, label_rows = self._coerce_training_vectors(vectors, labels)
        for vector, label in zip(vector_rows, label_rows):
            class_sum = self._sums.setdefault(label, [0.0] * self.DIMENSION)
            for index, coordinate in enumerate(vector):
                class_sum[index] += coordinate
            self._counts[label] += 1
            examples = self._samples[label]
            if len(examples) == self.max_samples_per_class:
                examples.pop(0)
            examples.append(vector)
        return self

    @property
    def labels(self) -> tuple[str, ...]:
        return tuple(sorted(self._samples))

    @property
    def centroids(self) -> dict[str, tuple[float, ...]]:
        return {
            label: self._normalize([coordinate / self._counts[label] for coordinate in self._sums[label]])
            for label in self._samples
        }

    def compare(self, vector: Sequence[Real]) -> dict[str, Any]:
        """Compare a vector to learned centroids; returns untrained when empty."""
        candidate = self._normalize(vector)
        if not self._samples:
            return {"status": "untrained", "nearest_label": None, "cosine_similarity": None, "euclidean_distance": None, "centroid_count": 0}
        centroid_results = []
        for label, centroid in self.centroids.items():
            cosine = max(-1.0, min(1.0, math.fsum(left * right for left, right in zip(candidate, centroid))))
            euclidean = math.sqrt(math.fsum((left - right) ** 2 for left, right in zip(candidate, centroid)))
            centroid_results.append((label, cosine, euclidean))
        label, cosine, euclidean = max(centroid_results, key=lambda item: (item[1], -item[2], item[0]))
        return {
            "status": "trained",
            "nearest_label": label,
            "cosine_similarity": cosine,
            "euclidean_distance": euclidean,
            "centroid_count": len(centroid_results),
            "training_examples": dict(self._counts),
        }

    def classify(self, vector: Sequence[Real]) -> dict[str, Any]:
        """Return an abstaining k-NN classification unless the threshold passes.

        ``confidence`` is local neighbor agreement, not a calibrated probability.
        A high threshold is an acceptance policy, not an accuracy guarantee.
        """
        candidate = self._normalize(vector)
        total_examples = sum(len(examples) for examples in self._samples.values())
        if total_examples < self.neighbors:
            return {
                "status": "untrained" if not total_examples else "insufficient_reference_data",
                "label": None,
                "confidence": None,
                "confidence_kind": "neighbor_agreement_uncalibrated",
                "confidence_threshold": self.confidence_threshold,
                "confidence_is_calibrated": False,
                "neighbors_used": total_examples,
            }

        nearest: list[tuple[float, str]] = []
        for label, examples in self._samples.items():
            for example in examples:
                similarity = math.fsum(left * right for left, right in zip(candidate, example))
                nearest.append((similarity, label))
        nearest.sort(key=lambda item: item[0], reverse=True)
        selected = nearest[:self.neighbors]
        votes = Counter(label for _, label in selected)
        winning_label, winning_votes = max(votes.items(), key=lambda item: (item[1], item[0]))
        agreement = winning_votes / len(selected)
        comparison = self.compare(candidate)
        accepted = agreement >= self.confidence_threshold
        return {
            "status": "classified" if accepted else "abstained",
            "label": winning_label if accepted else None,
            "candidate_label": winning_label,
            "confidence": agreement,
            "confidence_kind": "neighbor_agreement_uncalibrated",
            "confidence_threshold": self.confidence_threshold,
            "confidence_is_calibrated": False,
            "neighbors_used": len(selected),
            "nearest_neighbors": [{"label": label, "cosine_similarity": similarity} for similarity, label in selected],
            "centroid_comparison": comparison,
        }

    def summary(self) -> dict[str, Any]:
        return {
            "dimension": self.DIMENSION,
            "trained": bool(self._samples),
            "labels": list(self.labels),
            "training_examples": dict(self._counts),
            "confidence_threshold": self.confidence_threshold,
            "confidence_is_calibrated": False,
        }
