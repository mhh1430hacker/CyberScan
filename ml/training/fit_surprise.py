# Claude (AI assistant, Anthropic) worked on this file, 2026-11-06: --seed for a reproducible uniform sample of benign programs.
"""Fit the compression surprise profile (``core.surprise_map``) from benign programs only.

    python -m ml.training.fit_surprise --directory C:\\Windows\\System32 --output ml/models/surprise_profile.json
    python -m ml.training.fit_surprise --manifest data/datasets/manifest.csv --output my_profile.json

With a manifest, only rows labelled ``clean`` (or ``benign``) are read. Every
eligible file is read twice (once for each pass) and never run. The printed
SHA-256 is what a scan needs: set ``surprise_profile`` and
``surprise_profile_sha256`` in the settings, or update
``DEFAULT_PROFILE_SHA256`` when refitting the shipped default.
"""
from __future__ import annotations

import argparse
import random
from collections.abc import Iterator
from pathlib import Path

from core.pe_decompiler import analyze_pe_file
from core.surprise_map import fit, save_profile
from ml.training.fit_dissonance import _benign_paths

MAX_SAMPLE_BYTES = 32 * 1024 * 1024


def _eligible(paths, limit: int, seed: int | None = None) -> list[Path]:
    """Benign programs of a usable size; with a seed, a uniform sample instead of the first found.

    Directory walks list one product's files together, so the first ``limit`` of
    them can all come from one compiler. A seeded shuffle of a larger pool keeps
    the profile representative and the fit reproducible.
    """
    pool_limit = limit if seed is None else limit * 20
    chosen = []
    for path in paths:
        try:
            if 4096 <= path.stat().st_size <= MAX_SAMPLE_BYTES:
                chosen.append(path)
        except OSError:
            continue
        if len(chosen) >= pool_limit:
            break
    if seed is not None:
        chosen.sort()
        random.Random(seed).shuffle(chosen)
    return chosen[:limit]


def _samples(paths: list[Path]) -> Iterator[tuple[bytes, dict]]:
    for path in paths:
        try:
            data = path.read_bytes()
        except OSError:
            continue
        pe = analyze_pe_file(path, data=data)
        if pe.get("status") == "ok":
            yield data, pe


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--manifest", type=Path, help="CSV with path,label,source; only clean rows are used")
    parser.add_argument("--directory", type=Path, help="Folder of benign programs (searched recursively)")
    parser.add_argument("--limit", type=int, default=1500, help="At most this many files")
    parser.add_argument("--seed", type=int, default=None, help="Sample uniformly (reproducibly) instead of taking the first files found")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.manifest is None and args.directory is None:
        parser.error("give --manifest or --directory")
    paths = _eligible(_benign_paths(args.manifest, args.directory), args.limit, args.seed)
    if len(paths) < 30:
        raise SystemExit(f"Only {len(paths)} benign programs were found; at least 30 are needed.")
    source = f"{len(paths)} benign programs from {args.manifest or args.directory}"
    profile = fit(_samples(paths), source, second_pass=_samples(paths))
    digest = save_profile(profile, args.output)
    print(f"Profile written to {args.output} ({source}).")
    print("windows per part:", profile.windows)
    print("benign 99.9th percentiles:", {role: q["p999"] for role, q in profile.quantiles.items()})
    print(f"sha256: {digest}")


if __name__ == "__main__":
    main()
