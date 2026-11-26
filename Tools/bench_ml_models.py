"""False-alarm rate and speed of the EMBER2024 models (core/ml_malware.py) on clean files.

    .venv/Scripts/python.exe Tools/bench_ml_models.py [--per-group 400] [--json out.json]

Clean files only, from this machine: Windows programs (.exe/.dll/.pyd/.sys) in the project's
virtual environment, in C:\\Windows\\System32 and in Program Files, and PDF documents in the
project, its virtual environment and Program Files. No malware is used, so this measures how
often clean files reach each threshold (the numbers in intel/data/ml/models.json), not how much
malware is caught. Each file is read, never run.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core import ml_malware  # noqa: E402

PROGRAMS = (".exe", ".dll", ".pyd", ".sys")


def files(roots: list[Path], suffixes: tuple[str, ...]) -> list[Path]:
    out = []
    for root in roots:
        for folder, _dirs, names in os.walk(root):
            out += [Path(folder) / n for n in names if n.lower().endswith(suffixes)]
    return out


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--per-group", type=int, default=400)
    parser.add_argument("--json")
    args = parser.parse_args()
    windows = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    program_files = [Path(p) for p in (os.environ.get("ProgramFiles"), os.environ.get("ProgramFiles(x86)")) if p]
    groups = {
        "Programs in .venv": (files([ROOT / ".venv"], PROGRAMS), "PE"),
        "Programs in System32": (files([windows / "System32"], PROGRAMS), "PE"),
        "Programs in Program Files": (files(program_files, PROGRAMS), "PE"),
        "PDF documents": (files([ROOT, *program_files], (".pdf",)), "PDF"),
    }
    rng = random.Random(1430)
    report = {}
    for name, (paths, kind) in groups.items():
        rng.shuffle(paths)
        scores, seconds = [], []
        for path in paths:
            if len(scores) >= args.per_group:
                break
            try:
                if not 0 < path.stat().st_size <= ml_malware.MAX_BYTES:
                    continue
                data = path.read_bytes()
            except OSError:
                continue
            started = time.perf_counter()
            result = ml_malware.assess(data)
            if result.get("status") != "scored" or result.get("kind") != kind:
                continue
            seconds.append(time.perf_counter() - started)
            scores.append(result["score"])
        entry = ml_malware.manifest()["models"][kind]
        high = sum(s >= entry["threshold_high"] for s in scores)
        review = sum(s >= entry["threshold_review"] for s in scores)
        report[name] = {"files": len(scores), "at_or_above_review": review, "at_or_above_high": high,
                        "median_seconds": round(statistics.median(seconds), 3) if seconds else None,
                        "p95_seconds": round(sorted(seconds)[int(len(seconds) * 0.95) - 1], 3) if seconds else None}
        print(f"{name}: {len(scores)} files; >= review ({entry['threshold_review']}): {review}; "
              f">= high ({entry['threshold_high']}): {high}; median {report[name]['median_seconds']} s, "
              f"p95 {report[name]['p95_seconds']} s")
    if args.json:
        Path(args.json).write_text(json.dumps(report, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
