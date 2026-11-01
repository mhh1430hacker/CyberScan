"""The file's real structure, laid out in a cube.

The file is cut into up to 4096 consecutive slices. Each slice gets a place in
a 16 x 16 x 16 cube along a 3-D Hilbert curve, a path that visits every cell
and keeps neighbours together: bytes that are next to each other in the file
are next to each other in the cube, so the file's regions appear as shapes,
like terrain mapped by sonar. Each slice carries a measured value: the
Shannon entropy of its bytes (0..8 bits per byte), the same measure the
engine uses.

Like a sonar echo, which comes back from the walls of a cave, each slice
also gets a *wall* strength: how sharply its entropy differs from the cells
around it in the cube. Uniform stretches of the file stay open space; the
places where the content changes form the walls the picture shows.

Flagged regions are only those the engine itself located, with byte offsets:
the entropy transitions it reported (``position_aware_evidence`` or, for
older reports, ``entropy_topography.anomalies``). Findings without a
location (a file name, a matched rule) are not placed in the cube; nothing
here invents a location or a judgement.

Pure Python and numpy; no Qt.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Mapping

import numpy as np

BITS = 4
SIDE = 1 << BITS
MAX_CELLS = SIDE ** 3
MIN_WINDOW = 256
SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 3}


@dataclass
class Region:
    offset_start: int
    offset_end: int
    severity: str
    delta: float | None
    cells: tuple[int, ...]


@dataclass
class Structure:
    file_size: int
    positions: np.ndarray  # (n, 3) in -0.5 .. 0.5
    entropy: np.ndarray  # (n,) bits per byte, 0 .. 8
    offsets: np.ndarray  # (n, 2) [start, end) per slice
    flags: np.ndarray  # (n,) 0 = none, 1..3 = severity of the strongest region
    regions: tuple[Region, ...]
    walls: np.ndarray | None = None  # (n,) 0 .. 1, how sharply a slice differs from its neighbours
    sections: tuple[tuple[str, int, int, bool], ...] = ()
    source: str = "bytes"  # "bytes" or "windows" (measured windows from a saved report)

    @property
    def count(self) -> int:
        return int(self.entropy.shape[0])

    def cell_at_offset(self, offset: int) -> int:
        index = int(np.searchsorted(self.offsets[:, 1], offset, side="right"))
        return min(index, self.count - 1)


def hilbert_point(index: int, bits: int = BITS) -> tuple[int, int, int]:
    """Cell of the ``index``-th step on a 3-D Hilbert curve (Skilling, 2004)."""
    n = 3
    axes = [0] * n
    for level in range(bits):
        for axis in range(n):
            bit = (index >> (level * n + (n - 1 - axis))) & 1
            axes[axis] |= bit << level
    top = 2 << (bits - 1)
    t = axes[n - 1] >> 1
    for axis in range(n - 1, 0, -1):
        axes[axis] ^= axes[axis - 1]
    axes[0] ^= t
    q = 2
    while q != top:
        p = q - 1
        for axis in range(n - 1, -1, -1):
            if axes[axis] & q:
                axes[0] ^= p
            else:
                t = (axes[0] ^ axes[axis]) & p
                axes[0] ^= t
                axes[axis] ^= t
        q <<= 1
    return axes[0], axes[1], axes[2]


_CURVE = np.array([hilbert_point(i) for i in range(MAX_CELLS)], dtype=np.float32)


def _steps(count: int) -> np.ndarray:
    return (np.arange(count, dtype=np.int64) * MAX_CELLS) // max(1, count)


def _layout(count: int) -> np.ndarray:
    cells = _CURVE[_steps(count)]
    # A fixed sub-cell offset per slice breaks the grid's moire; it never
    # moves a slice out of its own cell, so neighbours stay neighbours.
    jitter = np.random.default_rng(7).uniform(-0.32, 0.32, size=cells.shape).astype(np.float32)
    return (cells + jitter) / (SIDE - 1) - 0.5


def _walls(count: int, entropy: np.ndarray) -> np.ndarray:
    """Largest entropy step from each slice to its six neighbours in the cube, 0..1."""
    cells = _CURVE[_steps(count)].astype(np.int64)
    grid = np.full((SIDE + 2, SIDE + 2, SIDE + 2), np.nan, dtype=np.float32)
    x, y, z = cells[:, 0] + 1, cells[:, 1] + 1, cells[:, 2] + 1
    grid[x, y, z] = entropy
    step = np.zeros(count, dtype=np.float32)
    for dx, dy, dz in ((1, 0, 0), (-1, 0, 0), (0, 1, 0), (0, -1, 0), (0, 0, 1), (0, 0, -1)):
        neighbour = grid[x + dx, y + dy, z + dz]
        step = np.fmax(step, np.abs(np.nan_to_num(neighbour - entropy, nan=0.0)))
    return np.clip(step / 4.0, 0.0, 1.0)


def _slices(size: int) -> np.ndarray:
    count = max(1, min(MAX_CELLS, size))
    edges = (np.arange(count + 1, dtype=np.int64) * size) // count
    return np.stack([edges[:-1], edges[1:]], axis=1)


def _entropy_of(chunk: np.ndarray) -> float:
    if chunk.size == 0:
        return 0.0
    counts = np.bincount(chunk, minlength=256)
    counts = counts[counts > 0].astype(np.float64)
    return float(max(0.0, min(8.0, math.log2(chunk.size) - float(np.sum(counts * np.log2(counts))) / chunk.size)))


def _entropy_from_bytes(data: bytes, offsets: np.ndarray) -> np.ndarray:
    array = np.frombuffer(data, dtype=np.uint8)
    size = array.size
    values = np.empty(offsets.shape[0], dtype=np.float32)
    for index, (start, end) in enumerate(offsets):
        # Tiny slices say little alone; measure a window of at least 256 bytes around them.
        width = max(int(end - start), MIN_WINDOW)
        middle = (int(start) + int(end)) // 2
        low = max(0, min(size - width, middle - width // 2))
        values[index] = _entropy_of(array[low:low + width])
    return values


def _entropy_from_windows(topography: Mapping[str, Any], offsets: np.ndarray) -> np.ndarray | None:
    trajectory = list(topography.get("trajectory") or [])
    window_offsets = list(topography.get("window_offsets") or [])
    if not trajectory or len(window_offsets) != len(trajectory):
        return None
    starts = np.asarray(window_offsets, dtype=np.int64)
    values = np.asarray(trajectory, dtype=np.float32)
    middles = (offsets[:, 0] + offsets[:, 1]) // 2
    nearest = np.clip(np.searchsorted(starts, middles, side="right") - 1, 0, len(values) - 1)
    return values[nearest]


def _located_regions(position: Mapping[str, Any], topography: Mapping[str, Any]) -> list[dict[str, Any]]:
    boundaries = list(position.get("entropy_boundaries") or [])
    if boundaries:
        return [
            {
                "offset_start": item.get("offset_start"),
                "offset_end": item.get("offset_end"),
                "severity": item.get("severity"),
                "delta": item.get("entropy_delta_bits_per_byte"),
            }
            for item in boundaries
            if isinstance(item, Mapping)
        ]
    return [
        {
            "offset_start": item.get("offset_start"),
            "offset_end": item.get("offset_end"),
            "severity": item.get("severity"),
            "delta": item.get("delta"),
        }
        for item in topography.get("anomalies") or []
        if isinstance(item, Mapping)
    ]


def _merge(regions: list[Region]) -> list[Region]:
    """Overlapping or touching ranges are one place to a reader: the engine
    reports sliding windows (0x0-0x1400, 0x400-0x1800 ...), not distinct parts."""
    merged: list[Region] = []
    for region in sorted(regions, key=lambda r: r.offset_start):
        if merged and region.offset_start <= merged[-1].offset_end:
            last = merged[-1]
            worse = region.severity if SEVERITY_RANK.get(region.severity, 2) > SEVERITY_RANK.get(last.severity, 2) else last.severity
            deltas = [d for d in (last.delta, region.delta) if d is not None]
            merged[-1] = Region(last.offset_start, max(last.offset_end, region.offset_end), worse,
                                max(deltas) if deltas else None, tuple(sorted(set(last.cells) | set(region.cells))))
        else:
            merged.append(region)
    return merged


def build_structure(
    raw: bytes | None,
    file_size: int | None,
    topography: Mapping[str, Any] | None,
    position: Mapping[str, Any] | None,
) -> Structure | None:
    """Lay the file out in the cube. None when there is nothing to lay out."""
    topography = topography if isinstance(topography, Mapping) else {}
    position = position if isinstance(position, Mapping) else {}
    size = len(raw) if raw else int(file_size or 0)
    if size <= 0:
        return None
    offsets = _slices(size)
    if raw:
        entropy = _entropy_from_bytes(raw, offsets)
        source = "bytes"
    else:
        entropy = _entropy_from_windows(topography, offsets)
        source = "windows"
        if entropy is None:
            return None
    flags = np.zeros(offsets.shape[0], dtype=np.int8)
    regions: list[Region] = []
    for item in _located_regions(position, topography):
        start, end = item.get("offset_start"), item.get("offset_end")
        if not isinstance(start, int) or not isinstance(end, int) or isinstance(start, bool) or end <= start:
            continue
        start, end = max(0, start), min(size, end)
        if end <= start:
            continue
        hit = np.nonzero((offsets[:, 0] < end) & (offsets[:, 1] > start))[0]
        if hit.size == 0:
            continue
        severity = str(item.get("severity") or "medium").lower()
        rank = SEVERITY_RANK.get(severity, 2)
        flags[hit] = np.maximum(flags[hit], rank)
        delta = item.get("delta")
        regions.append(Region(start, end, severity, float(delta) if isinstance(delta, (int, float)) else None, tuple(int(i) for i in hit)))
    sections = tuple(
        (str(item.get("name", "")).strip("\x00 ") or "?", int(item["file_offset_start"]), int(item["file_offset_end"]), bool(item.get("executable")))
        for item in position.get("pe_sections") or []
        if isinstance(item, Mapping) and isinstance(item.get("file_offset_start"), int) and isinstance(item.get("file_offset_end"), int)
    )
    return Structure(
        file_size=size,
        positions=_layout(offsets.shape[0]),
        entropy=entropy,
        offsets=offsets,
        flags=flags,
        regions=tuple(sorted(_merge(regions), key=lambda r: (-SEVERITY_RANK.get(r.severity, 2), r.offset_start))),
        walls=_walls(offsets.shape[0], entropy),
        sections=sections,
        source=source,
    )
