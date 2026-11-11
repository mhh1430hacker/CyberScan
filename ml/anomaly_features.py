"""Feature vector for the benign-only IsolationForest (``ml.anomaly_detector``).

Separate from ``ml.feature_schema``, which describes the 4096-D structural embedding.
"""
from __future__ import annotations

import hashlib
import math
from numbers import Real
from typing import Any

SCHEMA_VERSION = 2
EXTENSION_BUCKET_COUNT = 32
NUMERIC_FEATURE_ORDER = [
    "file_size",
    "entropy",
    "is_executable",
    "magic_mismatch",
    "double_extension",
    "section_count",
    "average_section_entropy",
    "max_section_entropy",
    "import_count",
    "suspicious_import_count",
    "string_count",
    "suspicious_string_count",
    "executable_section_count",
    "packing_indicator",
]
FEATURE_ORDER = NUMERIC_FEATURE_ORDER + [
    f"extension_bucket_{index}" for index in range(EXTENSION_BUCKET_COUNT)
]


def serialize_feature_vector(feature_map: dict[str, Any]) -> list[float]:
    values: list[float] = []
    for name in NUMERIC_FEATURE_ORDER:
        value = feature_map.get(name, 0)
        if isinstance(value, bool):
            values.append(1.0 if value else 0.0)
        elif isinstance(value, Real) and math.isfinite(float(value)):
            values.append(float(value))
        else:
            values.append(0.0)

    extension = str(feature_map.get("extension_category", "")).strip().lower()
    extension_values = [0.0] * EXTENSION_BUCKET_COUNT
    if extension:
        digest = hashlib.blake2b(extension.encode("utf-8"), digest_size=8, person=b"CSFeatExt").digest()
        bucket = int.from_bytes(digest, "little") % EXTENSION_BUCKET_COUNT
        extension_values[bucket] = 1.0
    values.extend(extension_values)
    return values
