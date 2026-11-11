"""Orbit invariance: the same program in different clothes must get the same verdict.

A Windows loader ignores some parts of a PE file entirely: bytes after the last
section (the overlay), the link timestamp, the header checksum of a
user-mode program, section names, and the compiler's Rich header. Changing
them leaves what the program *does* untouched. All variants reachable this way
form the file's **orbit**.

A detector that changes its mind inside an orbit is reading clothing, not
behaviour, and an attacker can flip it for free (append 4 KB of zeros). This
module

* builds orbit members **in memory only** (never written to disk, never run),
* measures **orbit stability**: how often the verdict survives every
  transformation, per transformation, and
* augments training data with orbit members carrying the original label, so the
  forest learns the invariance instead of the clothing.

Non-PE files have no orbit here: appending bytes to a script or a document can
change what it does, so nothing is claimed for them.
"""
from __future__ import annotations

import hashlib
from collections.abc import Callable, Sequence

import numpy as np

from ml.pe_layout import PELayout, parse_layout

OVERLAY_BYTES = 4096
_FILLER_TEXT = b"This space intentionally left blank. " * 128


def _seed(data: bytes, name: str) -> np.random.Generator:
    digest = hashlib.sha256(name.encode("ascii") + hashlib.sha256(data).digest()).digest()
    return np.random.default_rng(int.from_bytes(digest[:8], "little"))


def _overlay_zeros(data: bytes, layout: PELayout) -> bytes:
    return data + bytes(OVERLAY_BYTES)


def _overlay_random(data: bytes, layout: PELayout) -> bytes:
    return data + _seed(data, "overlay").bytes(OVERLAY_BYTES)


def _overlay_text(data: bytes, layout: PELayout) -> bytes:
    return data + _FILLER_TEXT[:OVERLAY_BYTES]


def _timestamp(data: bytes, layout: PELayout) -> bytes:
    out = bytearray(data)
    out[layout.timestamp_offset:layout.timestamp_offset + 4] = _seed(data, "timestamp").bytes(4)
    return bytes(out)


def _checksum(data: bytes, layout: PELayout) -> bytes:
    out = bytearray(data)
    out[layout.checksum_offset:layout.checksum_offset + 4] = bytes(4)
    return bytes(out)


def _section_names(data: bytes, layout: PELayout) -> bytes:
    out = bytearray(data)
    for index, section in enumerate(layout.sections):
        out[section.header_offset:section.header_offset + 8] = f".s{index}".encode("ascii").ljust(8, b"\0")
    return bytes(out)


def _rich_header(data: bytes, layout: PELayout) -> bytes:
    if layout.rich_header is None:
        return data
    start, end = layout.rich_header
    out = bytearray(data)
    out[start:end] = bytes(end - start)
    return bytes(out)


TRANSFORMS: dict[str, Callable[[bytes, PELayout], bytes]] = {
    "overlay_zeros": _overlay_zeros,
    "overlay_random": _overlay_random,
    "overlay_text": _overlay_text,
    "timestamp": _timestamp,
    "checksum": _checksum,
    "section_names": _section_names,
    "rich_header": _rich_header,
}


def orbit(data: bytes, names: Sequence[str] | None = None) -> list[tuple[str, bytes]]:
    """Loader-equivalent variants of a PE file (empty for anything else)."""
    layout = parse_layout(data)
    if layout is None:
        return []
    members = []
    for name in names or TRANSFORMS:
        variant = TRANSFORMS[name](data, layout)
        if variant != data:
            members.append((name, variant))
    return members


def augment(
    samples: Sequence[bytes],
    labels: Sequence[str],
    embed: Callable[[bytes], Sequence[float]],
    *,
    per_sample: int = 3,
    names: Sequence[str] | None = None,
) -> tuple[np.ndarray, list[str]]:
    """Embeddings of up to ``per_sample`` orbit members per sample, labelled like the original."""
    vectors: list[np.ndarray] = []
    out_labels: list[str] = []
    for data, label in zip(samples, labels):
        members = orbit(data, names)
        if not members:
            continue
        chosen = _seed(data, "augment").permutation(len(members))[:per_sample]
        for index in chosen:
            vectors.append(np.asarray(embed(members[index][1]), dtype=np.float32))
            out_labels.append(label)
    if not vectors:
        return np.zeros((0, 0), dtype=np.float32), []
    return np.stack(vectors), out_labels


def stability(
    samples: Sequence[bytes],
    predict: Callable[[np.ndarray], tuple[list[str], np.ndarray]],
    embed: Callable[[bytes], Sequence[float]],
) -> dict[str, object]:
    """How often the verdict survives each transformation.

    ``predict`` maps a batch of embeddings to (labels, class scores).
    ``label_agreement`` is the share of (sample, transformation) pairs keeping the
    original label; ``mean_score_shift`` is the mean L1 change of the class
    scores; ``fragile_samples`` counts samples flipped by at least one member.
    """
    per_transform: dict[str, list[bool]] = {}
    shifts: list[float] = []
    fragile = 0
    covered = 0
    for data in samples:
        members = orbit(data)
        if not members:
            continue
        covered += 1
        batch = np.stack([np.asarray(embed(data), dtype=np.float32)] + [np.asarray(embed(variant), dtype=np.float32) for _, variant in members])
        labels, scores = predict(batch)
        flipped = False
        for (name, _), label, score in zip(members, labels[1:], scores[1:]):
            same = label == labels[0]
            per_transform.setdefault(name, []).append(same)
            shifts.append(float(np.abs(score - scores[0]).sum()))
            flipped |= not same
        fragile += flipped
    pairs = [kept for results in per_transform.values() for kept in results]
    return {
        "samples_with_orbit": covered,
        "label_agreement": round(float(np.mean(pairs)), 4) if pairs else None,
        "mean_score_shift": round(float(np.mean(shifts)), 4) if shifts else None,
        "fragile_samples": fragile,
        "per_transform": {name: round(float(np.mean(results)), 4) for name, results in sorted(per_transform.items())},
    }
