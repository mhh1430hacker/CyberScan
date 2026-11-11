from __future__ import annotations

import math
import statistics
from typing import Any

try:
    import numpy as np
except (ImportError, OSError):  # pragma: no cover
    np = None


def _byte_view(data: Any) -> memoryview:
    try:
        view = memoryview(data)
    except TypeError as exc:
        raise TypeError("data must support the buffer protocol") from exc
    if not view.c_contiguous:
        view = memoryview(view.tobytes())
    return view.cast("B")


def _entropy_from_counts(counts: list[int], length: int) -> float:
    if length <= 0:
        return 0.0
    weighted_count = math.fsum(
        count * math.log2(count) for count in counts if count > 0
    )
    return max(0.0, min(8.0, math.log2(length) - weighted_count / length))


def _count_contribution(count: int) -> float:
    return count * math.log2(count) if count > 1 else 0.0


def shannon_entropy(data: bytes | bytearray | memoryview) -> float:
    view = _byte_view(data)
    if not view:
        return 0.0
    if np is not None:
        counts = np.bincount(np.frombuffer(view, dtype=np.uint8), minlength=256)
        nonzero = counts[counts > 0]
        weighted_count = float(np.sum(nonzero * np.log2(nonzero)))
        return round(max(0.0, min(8.0, math.log2(len(view)) - weighted_count / len(view))), 3)
    counts = [0] * 256
    for value in view:
        counts[value] += 1
    return round(_entropy_from_counts(counts, len(view)), 3)


def entropy_topography(
    data: bytes | bytearray | memoryview,
    window_size: int = 4096,
    step_size: int = 1024,
    discontinuity_threshold: float = 1.5,
    high_entropy_threshold: float = 7.2,
) -> dict[str, Any]:
    if isinstance(window_size, bool) or not isinstance(window_size, int) or window_size <= 0:
        raise ValueError("window_size must be a positive integer")
    if isinstance(step_size, bool) or not isinstance(step_size, int) or step_size <= 0:
        raise ValueError("step_size must be a positive integer")
    if not math.isfinite(discontinuity_threshold) or discontinuity_threshold < 0:
        raise ValueError("discontinuity_threshold must be a finite non-negative number")
    if not math.isfinite(high_entropy_threshold) or not 0.0 <= high_entropy_threshold <= 8.0:
        raise ValueError("high_entropy_threshold must be between 0 and 8")

    view = _byte_view(data)
    data_size = len(view)
    if not data_size:
        return {
            "trajectory": [],
            "window_offsets": [],
            "gradients": [],
            "mean_entropy": 0.0,
            "peak_entropy": 0.0,
            "gradient_variance": 0.0,
            "anomalies": [],
            "window_size": window_size,
            "step_size": step_size,
        }

    if math.ceil(data_size / step_size) > 4096:
        step_size = math.ceil(data_size / 4096)
        window_size = min(data_size, max(window_size, 2 * step_size))

    if data_size <= window_size:
        offsets = [0]
    else:
        offsets = list(range(0, data_size - window_size + 1, step_size))
        final_offset = data_size - window_size
        if offsets[-1] != final_offset:
            offsets.append(final_offset)

    trajectory: list[float] = []
    if np is not None:
        byte_array = np.frombuffer(view, dtype=np.uint8)
        for offset in offsets:
            end = min(offset + window_size, data_size)
            counts = np.bincount(byte_array[offset:end], minlength=256)
            nonzero = counts[counts > 0]
            weighted_count = float(np.sum(nonzero * np.log2(nonzero)))
            length = end - offset
            value = math.log2(length) - weighted_count / length if length else 0.0
            trajectory.append(max(0.0, min(8.0, value)))
    else:
        counts = [0] * 256
        weighted_count = 0.0
        first_end = min(window_size, data_size)
        for position in range(first_end):
            value = view[position]
            previous = counts[value]
            counts[value] = previous + 1
            weighted_count += _count_contribution(previous + 1) - _count_contribution(previous)
        previous_offset = 0
        previous_end = first_end
        for index, offset in enumerate(offsets):
            end = min(offset + window_size, data_size)
            if index:
                leaving_end = min(offset, previous_end)
                for position in range(previous_offset, leaving_end):
                    value = view[position]
                    previous = counts[value]
                    counts[value] = previous - 1
                    weighted_count += _count_contribution(previous - 1) - _count_contribution(previous)
                entering_start = max(previous_end, offset)
                for position in range(entering_start, end):
                    value = view[position]
                    previous = counts[value]
                    counts[value] = previous + 1
                    weighted_count += _count_contribution(previous + 1) - _count_contribution(previous)
            length = end - offset
            value = math.log2(length) - weighted_count / length if length else 0.0
            trajectory.append(max(0.0, min(8.0, value)))
            previous_offset = offset
            previous_end = end

    gradients = [
        trajectory[index] - trajectory[index - 1]
        for index in range(1, len(trajectory))
    ]
    anomalies: list[dict[str, Any]] = []
    for index, delta in enumerate(gradients, start=1):
        before = trajectory[index - 1]
        after = trajectory[index]
        crosses_entropy_bands = (
            (before < 3.5 and after >= high_entropy_threshold)
            or (before >= high_entropy_threshold and after < 3.5)
        )
        if abs(delta) < discontinuity_threshold and not crosses_entropy_bands:
            continue
        magnitude = abs(delta)
        anomalies.append({
            "offset_start": offsets[index - 1],
            "offset_end": min(offsets[index] + window_size, data_size),
            "delta": delta,
            "severity": "critical" if magnitude >= 3.0 else "high" if magnitude >= 2.0 else "medium",
            "high_entropy_boundary": crosses_entropy_bands,
        })

    return {
        "trajectory": trajectory,
        "window_offsets": offsets,
        "gradients": gradients,
        "mean_entropy": math.fsum(trajectory) / len(trajectory),
        "peak_entropy": max(trajectory),
        "gradient_variance": statistics.pvariance(gradients) if len(gradients) > 1 else 0.0,
        "anomalies": anomalies,
        "window_size": window_size,
        "step_size": step_size,
    }


def entropy_for_window(
    data: bytes | bytearray | memoryview,
    window_size: int = 4096,
    step_size: int | None = None,
) -> list[float]:
    if step_size is None:
        step_size = max(1, window_size // 4)
    return entropy_topography(data, window_size, step_size)["trajectory"]
