from __future__ import annotations

import hashlib
import math
import struct
from collections import Counter
from collections.abc import Mapping, Sequence
from numbers import Real
from typing import Any

from ml.feature_schema import LATENT_CHANNEL_DIMENSION, LATENT_DIMENSION


class HighDimensionalEmbedding:
    """Deterministic, non-lossless feature encoding of file bytes into 4096 dimensions."""

    DIMENSION = LATENT_DIMENSION
    DEFAULT_NGRAM_SIZES = (2, 3, 4)

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

    @classmethod
    def _channel_index(cls, channel: int, name: str, width: int = LATENT_CHANNEL_DIMENSION) -> int:
        digest = hashlib.blake2b(
            f"{channel}:{name}".encode("utf-8", errors="surrogatepass"),
            digest_size=8,
            person=b"CSLatentV1",
        ).digest()
        return int.from_bytes(digest, "little") % width

    @staticmethod
    def _resample(values: Sequence[Real], count: int) -> list[float]:
        if not values:
            return [0.0] * count
        if len(values) == 1:
            return [float(values[0])] * count
        result: list[float] = []
        for index in range(count):
            position = index * (len(values) - 1) / max(1, count - 1)
            lower = int(position)
            upper = min(len(values) - 1, lower + 1)
            fraction = position - lower
            result.append(
                float(values[lower]) * (1.0 - fraction)
                + float(values[upper]) * fraction
            )
        return result

    @staticmethod
    def _pe_header_values(data: bytes) -> dict[str, float]:
        values: dict[str, float] = {}
        if len(data) < 64 or data[:2] != b"MZ":
            return values
        pe_offset = int.from_bytes(data[0x3C:0x40], "little")
        if pe_offset < 64 or pe_offset + 24 > len(data) or data[pe_offset:pe_offset + 4] != b"PE\0\0":
            return values
        coff = pe_offset + 4
        machine, section_count = struct.unpack_from("<HH", data, coff)
        optional_size = struct.unpack_from("<H", data, coff + 16)[0]
        optional = coff + 20
        if optional_size < 2 or optional + optional_size > len(data):
            return values
        magic = struct.unpack_from("<H", data, optional)[0]
        values.update({
            "machine": machine / 65535.0,
            "section_count": min(section_count, 96) / 96.0,
            "optional_header_magic": 1.0 if magic == 0x20B else 0.5 if magic == 0x10B else 0.0,
        })
        if magic == 0x10B and optional_size >= 72:
            image_base = struct.unpack_from("<I", data, optional + 28)[0]
            subsystem = struct.unpack_from("<H", data, optional + 68)[0]
        elif magic == 0x20B and optional_size >= 88:
            image_base = struct.unpack_from("<Q", data, optional + 24)[0]
            subsystem = struct.unpack_from("<H", data, optional + 68)[0]
        else:
            image_base = 0
            subsystem = 0
        values["image_base"] = math.log1p(image_base) / 48.0
        values["subsystem"] = min(subsystem, 16) / 16.0

        section_table = optional + optional_size
        for index in range(min(section_count, 96)):
            section = section_table + index * 40
            if section + 40 > len(data):
                break
            raw_size, raw_offset = struct.unpack_from("<II", data, section + 16)
            values[f"section_{index}_raw_size"] = math.log1p(raw_size) / 24.0
            values[f"section_{index}_raw_offset"] = math.log1p(raw_offset) / 24.0
        ascii_data = data[:min(len(data), 1_048_576)].lower()
        api_names = (
            "virtualalloc", "virtualprotect", "writeprocessmemory",
            "createremotethread", "loadlibrarya", "loadlibraryw",
            "getprocaddress", "getsysteminfo", "getcomputername",
            "globalmemorystatusex", "getversionex",
        )
        for api_name in api_names:
            if api_name.encode("ascii") in ascii_data:
                values[f"api:{api_name}"] = 1.0
        return values

    def embed_bytes(
        self,
        data: bytes,
        *,
        entropy_topography: Mapping[str, Any] | None = None,
        cfg_topology: Mapping[str, Any] | None = None,
        pe_features: Mapping[str, Any] | None = None,
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
        channels = [[0.0] * LATENT_CHANNEL_DIMENSION for _ in range(4)]

        def add_feature(channel: int, name: str, weight: float, *, offset: int = 0, width: int = 1024) -> None:
            if not math.isfinite(weight) or weight == 0.0:
                return
            index = offset + self._channel_index(channel, name, width)
            channels[channel][index] += weight

        data_length = len(data)
        if data_length:
            byte_counts = Counter(data)
            for byte_value, count in byte_counts.items():
                channels[0][byte_value] = count / data_length

            for size in sizes:
                window_count = max(0, data_length - size + 1)
                if not window_count:
                    continue
                positions = self._bounded_positions(window_count, max_ngrams_per_size)
                grams: Counter[bytes] = Counter(data[position:position + size] for position in positions)
                sampled_total = sum(grams.values())
                for gram, count in grams.items():
                    add_feature(0, f"ngram:{size}:{gram.hex()}", count / sampled_total, offset=256, width=768)

        trajectory = entropy.get("trajectory", [])
        trajectory_length = len(trajectory)
        entropy_values = self._resample(trajectory, 512)
        gradient_values = self._resample(entropy.get("gradients", []), 512)
        channels[1][:512] = [max(0.0, min(1.0, value / 8.0)) for value in entropy_values]
        channels[1][512:] = [max(-1.0, min(1.0, value / 8.0)) for value in gradient_values]

        opcode_histogram: Mapping[str, Any] = cfg.get("opcode_frequency", {})
        for opcode, frequency in opcode_histogram.items():
            add_feature(0, f"opcode:{str(opcode).upper()}", float(frequency), offset=256, width=768)

        numeric_cfg_keys = (
            "basic_block_count",
            "cyclomatic_complexity",
            "graph_density",
            "edge_count",
            "instruction_count",
            "back_edge_count",
            "back_edge_density",
        )
        for index, key in enumerate(numeric_cfg_keys):
            value = float(cfg.get(key, 0.0))
            scale = max(1.0, math.log1p(data_length)) if key not in {"graph_density", "back_edge_density"} else 1.0
            channels[2][index] = math.copysign(math.log1p(abs(value)) / scale, value)

        adjacency = cfg.get("adjacency", {})
        if isinstance(adjacency, Mapping):
            edges: list[tuple[int, int]] = []
            node_degrees: dict[int, int] = {}
            for source, targets in adjacency.items():
                try:
                    source_index = int(source)
                except (TypeError, ValueError):
                    continue
                if not isinstance(targets, Sequence):
                    continue
                node_degrees[source_index] = len(targets)
                for target in targets:
                    try:
                        edges.append((source_index, int(target)))
                    except (TypeError, ValueError):
                        continue
            node_slots = min(512, max(1, len(adjacency)))
            for slot, degree in enumerate(node_degrees.values()):
                if slot >= node_slots:
                    break
                channels[2][16 + slot] = math.log1p(degree) / 8.0
            for source, target in edges:
                add_feature(2, f"edge:{source}:{target}", 1.0, offset=528, width=496)

        for pattern in cfg.get("detected_patterns", []):
            add_feature(2, f"pattern:{str(pattern)}", 1.0, offset=528, width=496)
        add_feature(2, f"architecture:{cfg.get('architecture', 'unknown')}", 1.0, offset=528, width=496)

        pe_values = self._pe_header_values(data)
        if pe_features:
            header_summary = pe_features.get("header_summary", {})
            if isinstance(header_summary, Mapping):
                for key, value in header_summary.items():
                    if isinstance(value, Real) and math.isfinite(float(value)):
                        pe_values[f"header:{key}"] = float(value)
            for section in pe_features.get("sections", []):
                if isinstance(section, Mapping):
                    name = str(section.get("name", ""))
                    for key in ("virtual_size", "raw_size", "entropy", "high_entropy"):
                        value = section.get(key)
                        if isinstance(value, Real) and math.isfinite(float(value)):
                            pe_values[f"section:{name}:{key}"] = math.log1p(abs(float(value))) / 24.0
            for api in pe_features.get("import_names", []):
                if isinstance(api, str):
                    pe_values[f"import:{api.casefold()}"] = 1.0
        for name, value in pe_values.items():
            add_feature(3, name, float(value))

        vector: list[float] = []
        for channel in channels:
            channel_norm = math.sqrt(math.fsum(value * value for value in channel))
            if channel_norm:
                vector.extend(value / channel_norm for value in channel)
            else:
                vector.extend(channel)
        return self._normalize(vector)

    def embed(self, data: bytes, **artifacts: Any) -> tuple[float, ...]:
        """Alias for ``embed_bytes``."""
        return self.embed_bytes(data, **artifacts)
