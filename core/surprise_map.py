"""Compression surprise map: which bytes would honest software never contain *there*?

Plain entropy cannot tell a compressed PNG inside ``.rsrc`` (normal) from an
encrypted payload inside ``.text`` (not normal): both are about 8 bits/byte.
What differs is *where* they are. This module learns, from benign programs
only, the byte "language" of each part of a PE file (headers, code, data,
resources, overlay) and the surprise that is normal for each.

For every 4 KiB window it measures the Kullback-Leibler divergence between the
window's bytes and the benign language of its part: the extra bits per byte it
would cost to compress the window with a code built for honest content of that
kind. A window whose surprise exceeds the benign 99.9th percentile for its part
is foreign there. Encrypted code in ``.text`` is foreign; the same bytes in
``.rsrc`` are not.

The profile is plain JSON (256 byte frequencies and a few quantiles per part),
loaded only with a SHA-256 the caller vouches for. A default profile fitted on
the Windows programs of the development machine ships in ``ml/models``;
``python -m ml.training.fit_surprise`` fits another from any benign set.
Programs from unusual compilers (Go, Delphi, ...) carry code that is
legitimately less like Microsoft's; fit a profile on such programs if they
matter.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np

PROFILE_FORMAT = "cyberscan-surprise-profile"
PROFILE_VERSION = 1
WINDOW = 4096
MIN_WINDOW = 1024
ROLES = ("header", "code", "data", "resource", "overlay")
MAX_REGIONS = 16
MAX_PROFILE_BYTES = 256 * 1024
MIN_FOREIGN_BITS = 0.75  # never flag a window that is less than this far from its part's language
QUANTILES = {"p50": 0.5, "p90": 0.9, "p99": 0.99, "p999": 0.999}
DEFAULT_PROFILE = Path(__file__).resolve().parent.parent / "ml" / "models" / "surprise_profile.json"
DEFAULT_PROFILE_SHA256 = "0" * 64  # replaced when the default profile is (re)fitted


@dataclass(frozen=True)
class Part:
    role: str
    name: str
    start: int
    end: int


@dataclass
class SurpriseProfile:
    q: dict[str, np.ndarray]  # role -> benign byte distribution (sums to 1, no zeros)
    quantiles: dict[str, dict[str, float]]  # role -> surprise quantiles of benign windows
    windows: dict[str, int]
    source: str


# -- layout ------------------------------------------------------------------------------------

def parts_of(file_size: int, pe_analysis: Mapping[str, Any]) -> list[Part]:
    """The file's parts by role, from the PE analysis already done by the scan."""
    if pe_analysis.get("status") != "ok":
        return []
    sections = []
    for section in pe_analysis.get("sections") or []:
        start = int(section.get("raw_offset", 0))
        end = min(file_size, start + int(section.get("raw_data_length", section.get("raw_size", 0)) or 0))
        if end <= start:
            continue
        name = str(section.get("name", "")).strip("\x00 ")
        role = "code" if section.get("executable") else "resource" if name.lower().startswith(".rsrc") else "data"
        sections.append(Part(role, name or "?", start, end))
    if not sections:
        return []
    sections.sort(key=lambda part: part.start)
    parts = [Part("header", "headers", 0, sections[0].start)] if sections[0].start > 0 else []
    parts += sections
    last = max(part.end for part in sections)
    if last < file_size:
        parts.append(Part("overlay", "overlay", last, file_size))
    return parts


def _histograms(data: bytes, part: Part) -> tuple[np.ndarray, np.ndarray]:
    """Byte counts per window of a part (shape windows x 256) and window start offsets."""
    raw = np.frombuffer(data, dtype=np.uint8, count=part.end - part.start, offset=part.start)
    starts = np.arange(0, raw.shape[0], WINDOW)
    lengths = np.minimum(WINDOW, raw.shape[0] - starts)
    keep = lengths >= MIN_WINDOW
    if not keep.any():
        return np.zeros((0, 256)), np.zeros(0, dtype=np.int64)
    rows = np.arange(raw.shape[0]) // WINDOW
    counts = np.bincount(rows * 256 + raw, minlength=starts.shape[0] * 256).reshape(starts.shape[0], 256)
    return counts[keep].astype(np.float64), starts[keep] + part.start


def _divergence(counts: np.ndarray, q: np.ndarray) -> np.ndarray:
    """KL(window || q) in bits per byte, for each row of byte counts."""
    p = counts / counts.sum(axis=1, keepdims=True)
    with np.errstate(divide="ignore", invalid="ignore"):
        terms = np.where(p > 0, p * np.log2(p / q), 0.0)
    return terms.sum(axis=1)


# -- fitting -----------------------------------------------------------------------------------

def fit(samples: Iterable[tuple[bytes, Mapping[str, Any]]], source: str, *, second_pass: Iterable[tuple[bytes, Mapping[str, Any]]]) -> SurpriseProfile:
    """Fit from benign (data, pe_analysis) pairs. ``second_pass`` must yield the same samples again.

    Pass one learns each role's byte distribution; pass two measures how far
    benign windows stray from it, which sets the per-role thresholds.
    """
    totals = {role: np.ones(256) for role in ROLES}  # Laplace smoothing: no byte is impossible
    for data, pe in samples:
        for part in parts_of(len(data), pe):
            counts, _ = _histograms(data, part)
            totals[part.role] += counts.sum(axis=0)
    q = {role: totals[role] / totals[role].sum() for role in ROLES}
    divergences: dict[str, list[np.ndarray]] = {role: [] for role in ROLES}
    for data, pe in second_pass:
        for part in parts_of(len(data), pe):
            counts, _ = _histograms(data, part)
            if counts.shape[0]:
                divergences[part.role].append(_divergence(counts, q[part.role]))
    quantiles, windows = {}, {}
    for role in ROLES:
        values = np.concatenate(divergences[role]) if divergences[role] else np.zeros(0)
        windows[role] = int(values.shape[0])
        if values.shape[0] >= 100:
            quantiles[role] = {name: round(float(np.quantile(values, level)), 4) for name, level in QUANTILES.items()}
    return SurpriseProfile(q, quantiles, windows, source)


def save_profile(profile: SurpriseProfile, path: Path) -> str:
    document = {
        "format": PROFILE_FORMAT, "version": PROFILE_VERSION, "source": profile.source, "window": WINDOW,
        "roles": {
            role: {"q": [round(float(value), 9) for value in profile.q[role]], "windows": profile.windows.get(role, 0),
                   "quantiles": profile.quantiles.get(role)}
            for role in ROLES
        },
    }
    raw = json.dumps(document, separators=(",", ":"), sort_keys=True).encode("utf-8")
    path.write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


def load_profile(path: Path = DEFAULT_PROFILE, expected_sha256: str = DEFAULT_PROFILE_SHA256) -> SurpriseProfile:
    raw = Path(path).read_bytes()[:MAX_PROFILE_BYTES + 1]
    if len(raw) > MAX_PROFILE_BYTES or hashlib.sha256(raw).hexdigest() != str(expected_sha256).lower():
        raise ValueError("Surprise profile does not match its approved digest.")
    document = json.loads(raw.decode("utf-8"))
    if document.get("format") != PROFILE_FORMAT or document.get("version") != PROFILE_VERSION or document.get("window") != WINDOW:
        raise ValueError("Not a compatible surprise profile.")
    q, quantiles, windows = {}, {}, {}
    for role in ROLES:
        entry = document["roles"][role]
        values = np.asarray(entry["q"], dtype=np.float64)
        if values.shape != (256,) or not np.all(np.isfinite(values)) or np.any(values <= 0):
            raise ValueError(f"Invalid byte distribution for {role}.")
        q[role] = values / values.sum()
        windows[role] = int(entry.get("windows", 0))
        if entry.get("quantiles"):
            quantiles[role] = {name: float(entry["quantiles"][name]) for name in QUANTILES}
    return SurpriseProfile(q, quantiles, windows, str(document.get("source", "")))


# -- scanning ----------------------------------------------------------------------------------

def surprise_map(data: bytes, pe_analysis: Mapping[str, Any], profile: SurpriseProfile) -> dict[str, Any]:
    """Per-part surprise and the regions that are foreign to their part."""
    parts = parts_of(len(data), pe_analysis)
    if not parts:
        return {"status": "not_applicable", "reason": "Only PE programs have parts with a known role."}
    summary: dict[str, dict[str, Any]] = {}
    flagged: list[dict[str, Any]] = []
    for part in parts:
        counts, starts = _histograms(data, part)
        if not counts.shape[0]:
            continue
        surprise = _divergence(counts, profile.q[part.role])
        limits = profile.quantiles.get(part.role)
        entry = summary.setdefault(part.role, {"windows": 0, "max_bits": 0.0, "foreign_windows": 0})
        entry["windows"] += int(surprise.shape[0])
        entry["max_bits"] = round(max(entry["max_bits"], float(surprise.max())), 3)
        if limits is None:
            continue
        threshold = max(limits["p999"], MIN_FOREIGN_BITS)
        foreign = surprise > threshold
        entry["foreign_windows"] += int(foreign.sum())
        entry["benign_p999"] = limits["p999"]
        index = 0
        while index < foreign.shape[0]:
            if not foreign[index]:
                index += 1
                continue
            end = index
            while end + 1 < foreign.shape[0] and foreign[end + 1]:
                end += 1
            flagged.append({
                "offset_start": int(starts[index]),
                "offset_end": int(min(part.end, starts[end] + WINDOW)),
                "role": part.role,
                "part": part.name,
                "surprise_bits_per_byte": round(float(surprise[index:end + 1].max()), 3),
                "benign_p999": limits["p999"],
                "severity": "medium" if part.role == "code" else "low",
            })
            index = end + 1
    flagged.sort(key=lambda region: -region["surprise_bits_per_byte"])
    return {
        "status": "ok",
        "profile": profile.source,
        "window_bytes": WINDOW,
        "parts": summary,
        "regions": flagged[:MAX_REGIONS],
        "regions_omitted": max(0, len(flagged) - MAX_REGIONS),
    }
