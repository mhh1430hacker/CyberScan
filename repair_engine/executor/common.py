from __future__ import annotations

from dataclasses import dataclass


class Refused(Exception):
    """A precondition does not hold; the action would have to guess."""


@dataclass(frozen=True)
class Removed:
    start: int  # offsets in the file as it was before this step
    end: int
    label: str
    data: bytes


def truncate_at(data: bytes, start: int, label: str) -> tuple[bytes, list[Removed]]:
    if not 0 < start < len(data):
        raise Refused(f"cannot truncate at {start} (file is {len(data)} bytes)")
    return data[:start], [Removed(start, len(data), label, data[start:])]
