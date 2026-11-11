"""Isolate the fixed cost of each analysis stage for a tiny input.

Read-only: calls the same public functions the pipeline calls.
"""
from __future__ import annotations

import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT), str(ROOT / "web_v")]

from config import DEFAULT_SETTINGS  # noqa: E402
from core import feature_extractor, file_analyzer, hashing, heuristic_engine  # noqa: E402
from core import pe_decompiler, position_aware, yara_engine, archive_inspector  # noqa: E402
from core.nextgen_engine import NextGenCyberEngine  # noqa: E402


def bench(fn, reps=5):
    vals = []
    for _ in range(reps):
        t = time.perf_counter()
        fn()
        vals.append((time.perf_counter() - t) * 1000)
    return statistics.median(vals)


def main() -> None:
    path = ROOT / "qa" / "artifacts" / "fixtures" / "tiny_text.txt"
    if not path.exists():
        path.write_text("hello world\n", encoding="utf-8")
    data = path.read_bytes()
    s = dict(DEFAULT_SETTINGS)

    stages = {
        "hashing.compute_file_sha256": lambda: hashing.compute_file_sha256(str(path)),
        "feature_extractor.extract_file_features": lambda: feature_extractor.extract_file_features(
            data, path.name, max_string_scan_size=200_000, include_topography=True),
        "archive_inspector.inspect_zip": lambda: archive_inspector.inspect_zip(data),
        "heuristic_engine.evaluate_heuristics": lambda: heuristic_engine.evaluate_heuristics(
            data.decode("latin-1"), file_name=path.name),
        "yara_engine.scan_file_for_yara": lambda: yara_engine.scan_file_for_yara(str(path), data=data, timeout_seconds=5),
        "pe_decompiler.analyze_pe_file": lambda: pe_decompiler.analyze_pe_file(str(path), data=data),
        "nextgen.analyze_entropy_topography": lambda: NextGenCyberEngine.analyze_entropy_topography(data),
        "nextgen.generate_forensic_storyline": lambda: NextGenCyberEngine.generate_forensic_storyline(
            path.name, len(data), {"trajectory": [], "mean_entropy": 0, "peak_entropy": 0, "gradient_variance": 0, "anomalies": []},
            {"cyclomatic_complexity": 0, "detected_patterns": [], "evidence_patterns": []}, 0),
    }
    total = 0.0
    print(f"input: {path.name} ({len(data)} bytes), median of 5\n")
    for name, fn in stages.items():
        ms = bench(fn)
        total += ms
        print(f"  {name:<44} {ms:>8.1f} ms")
    print(f"  {'sum of stages':<44} {total:>8.1f} ms")
    full = bench(lambda: file_analyzer.analyze_file(str(path), settings=s), reps=5)
    print(f"  {'file_analyzer.analyze_file (all of the above)':<44} {full:>8.1f} ms")


if __name__ == "__main__":
    main()
