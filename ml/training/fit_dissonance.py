"""Fit the claim-capability profile (``core.dissonance``) from benign programs only.

    python -m ml.training.fit_dissonance --manifest data/datasets/manifest.csv --output models/dissonance.json
    python -m ml.training.fit_dissonance --directory "C:\\Program Files" --output models/dissonance.json

With a manifest, only rows labelled ``clean`` (or ``benign``) are read. The
printed SHA-256 is what a scan needs to use the profile: set
``dissonance_profile`` and ``dissonance_profile_sha256`` in the settings.
Files are only read, never run.
"""
from __future__ import annotations

import argparse
import csv
from collections.abc import Iterator
from pathlib import Path

from core.dissonance import capabilities_of, claim_of, fit_profile, save_profile
from core.pe_decompiler import analyze_pe_file

MAX_SAMPLE_BYTES = 64 * 1024 * 1024
STRING_SCAN_BYTES = 2_000_000


def _benign_paths(manifest: Path | None, directory: Path | None) -> Iterator[Path]:
    if manifest is not None:
        with manifest.open(encoding="utf-8", newline="") as stream:
            for row in csv.DictReader(stream):
                if str(row.get("label", "")).strip().lower() in {"clean", "benign"}:
                    yield (manifest.parent / row["path"]).resolve()
    if directory is not None:
        for pattern in ("*.exe", "*.dll"):
            yield from directory.rglob(pattern)


def observe(paths) -> Iterator[tuple[str, list[str]]]:
    for path in paths:
        try:
            if path.stat().st_size > MAX_SAMPLE_BYTES:
                continue
            data = path.read_bytes()
        except OSError:
            continue
        pe = analyze_pe_file(path, data=data)
        if pe.get("status") != "ok":
            continue
        role = claim_of(path.name, pe.get("version_info"))["role"]
        yield role, capabilities_of(pe.get("import_names") or [], data[:STRING_SCAN_BYTES].decode("latin-1").lower())


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--manifest", type=Path, help="CSV with path,label,source; only clean rows are used")
    parser.add_argument("--directory", type=Path, help="Folder of benign programs (searched recursively)")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.manifest is None and args.directory is None:
        parser.error("give --manifest or --directory")
    observations = list(observe(_benign_paths(args.manifest, args.directory)))
    if len(observations) < 30:
        raise SystemExit(f"Only {len(observations)} benign programs were readable; at least 30 are needed.")
    source = f"{len(observations)} benign programs from {args.manifest or args.directory}"
    digest = save_profile(fit_profile(observations, source), args.output)
    print(f"Profile written to {args.output} ({source}).\nsha256: {digest}")


if __name__ == "__main__":
    main()
