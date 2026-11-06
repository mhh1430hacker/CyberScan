"""Region maps: every structural part of a file, with exact byte offsets.

A region is a half-open byte range ``[start, end)`` of the file, a ``kind``
(``pe_section``, ``pdf_object``, ``after_eof`` ...), an optional parent
region and free metadata. Parsers only ever *add* regions they could read
from the bytes; anything they could not read goes to ``errors``.

The boundaries of all regions are what model predictions are snapped to
later (Phase 4), so offsets are validated on the way in: a region outside
the file is clamped and the clamp is recorded, never silently trusted.
"""
from __future__ import annotations

import bisect
from dataclasses import dataclass, field
from typing import Any

MAX_REGIONS = 200_000


@dataclass(frozen=True)
class Region:
    start: int
    end: int
    kind: str
    parent: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def size(self) -> int:
        return self.end - self.start

    def as_dict(self) -> dict[str, Any]:
        return {"start": self.start, "end": self.end, "kind": self.kind, "parent": self.parent, "metadata": dict(self.metadata)}


@dataclass
class RegionMap:
    size: int
    format: str = "unknown"
    regions: list[Region] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    truncated: bool = False

    def __post_init__(self) -> None:
        if not self.regions:
            self.regions.append(Region(0, self.size, "file"))

    @property
    def root(self) -> int:
        return 0

    def add(self, start: int, end: int, kind: str, parent: int | None = 0, **metadata: Any) -> int | None:
        """Add ``[start, end)``; returns its index, or None if nothing of it lies in the file."""
        if len(self.regions) >= MAX_REGIONS:
            self.truncated = True
            return None
        if not isinstance(start, int) or not isinstance(end, int) or isinstance(start, bool) or isinstance(end, bool):
            self.errors.append(f"{kind}: non-integer offsets {start!r}..{end!r}")
            return None
        clamped_start, clamped_end = max(0, start), min(self.size, end)
        if clamped_end <= clamped_start:
            if end > start:
                self.errors.append(f"{kind}: [{start}, {end}) lies outside the file ({self.size} bytes)")
            return None
        if (clamped_start, clamped_end) != (start, end):
            metadata = {**metadata, "declared": [start, end]}
            self.errors.append(f"{kind}: [{start}, {end}) clamped to the file ({self.size} bytes)")
        if parent is not None and not 0 <= parent < len(self.regions):
            parent = 0
        self.regions.append(Region(clamped_start, clamped_end, kind, parent, metadata))
        return len(self.regions) - 1

    def of_kind(self, *kinds: str) -> list[Region]:
        return [region for region in self.regions if region.kind in kinds]

    def boundaries(self) -> list[int]:
        return sorted({offset for region in self.regions for offset in (region.start, region.end)})

    def snap(self, start: int, end: int) -> tuple[int, int]:
        """Move a predicted span's ends to the nearest structural boundaries."""
        edges = self.boundaries()

        def nearest(offset: int) -> int:
            index = bisect.bisect_left(edges, offset)
            candidates = edges[max(0, index - 1): index + 1]
            return min(candidates, key=lambda edge: (abs(edge - offset), edge))

        snapped_start, snapped_end = nearest(start), nearest(end)
        if snapped_end <= snapped_start:  # both ends snapped to one edge: keep the next one
            later = [edge for edge in edges if edge > snapped_start]
            snapped_end = later[0] if later else self.size
        return snapped_start, snapped_end

    def as_dict(self) -> dict[str, Any]:
        return {
            "size": self.size,
            "format": self.format,
            "regions": [region.as_dict() for region in self.regions],
            "errors": list(self.errors),
            "truncated": self.truncated,
        }
