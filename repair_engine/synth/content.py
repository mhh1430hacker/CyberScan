"""Inert content, and nothing else.

Every byte the injector adds comes from here: uniformly random bytes, zero
padding, or a fixed placeholder sentence. No generator produces code,
shellcode, script or anything a program could act on; ``is_inert`` checks a
payload against exactly these three shapes, and the tests run it over every
injection.
"""
from __future__ import annotations

import math
import random

PLACEHOLDER = b"INERT PLACEHOLDER - SYNTHETIC TRAINING CONTENT - NOT CODE. "
KINDS = ("random", "zeros", "placeholder")


def inert(kind: str, size: int, rng: random.Random) -> bytes:
    if size < 0:
        raise ValueError("size must be >= 0")
    if kind == "random":
        return rng.randbytes(size)
    if kind == "zeros":
        return bytes(size)
    if kind == "placeholder":
        return (PLACEHOLDER * (size // len(PLACEHOLDER) + 1))[:size]
    raise ValueError(f"unknown inert content kind {kind!r}")


def is_inert(payload: bytes, kind: str) -> bool:
    """True if ``payload`` is exactly what ``inert(kind, ...)`` can produce."""
    if kind == "zeros":
        return payload.count(0) == len(payload)
    if kind == "placeholder":
        return payload == inert("placeholder", len(payload), random.Random(0))
    return kind == "random"  # any byte string is a possible random draw; it is never chosen to mean anything


def size_between(rng: random.Random, low: int, high: int) -> int:
    """Log-uniform, so small and large insertions are equally common."""
    low = max(1, low)
    if high <= low:
        return low
    return max(low, min(high, int(round(math.exp(rng.uniform(math.log(low), math.log(high)))))))
