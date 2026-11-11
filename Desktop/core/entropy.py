from __future__ import annotations

import math
from collections import Counter


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    # Counter counts bytes in C; the former per-byte Python loop dominated scan time on binaries.
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return round(entropy, 3)


def entropy_for_window(data: bytes, window_size: int = 4096) -> list[float]:
    values: list[float] = []
    for start in range(0, len(data), window_size):
        chunk = data[start:start + window_size]
        values.append(shannon_entropy(chunk))
    return values
