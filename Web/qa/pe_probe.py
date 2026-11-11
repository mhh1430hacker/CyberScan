"""Why does analyze_pe_file cost ~70 ms on a 13-byte text file?

Times the function on non-PE data and looks for per-call setup work.
"""
from __future__ import annotations

import statistics
import sys
import time
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT)]

from core import pe_decompiler  # noqa: E402


def bench(fn, reps=7):
    vals = []
    for _ in range(reps):
        t = time.perf_counter()
        fn()
        vals.append((time.perf_counter() - t) * 1000)
    return statistics.median(vals), min(vals), max(vals)


def main() -> None:
    text = b"hello world\n"
    pe = ROOT / "qa" / "artifacts" / "fixtures" / "truncated_pe.bin"
    for label, data in (("13-byte text", text), ("truncated MZ", pe.read_bytes() if pe.exists() else b"MZ" + b"\0" * 62)):
        med, lo, hi = bench(lambda d=data: pe_decompiler.analyze_pe_file("x.bin", data=d))
        print(f"  analyze_pe_file({label:<14}) median {med:>7.1f} ms  (min {lo:.1f} / max {hi:.1f})")

    # a real PE, if one is available in System32
    candidate = Path(r"C:\Windows\System32\kernel32.dll")
    if candidate.is_file():
        data = candidate.read_bytes()[:4 * 1024 * 1024]
        med, lo, hi = bench(lambda: pe_decompiler.analyze_pe_file(candidate.name, data=data), reps=3)
        print(f"  analyze_pe_file(kernel32.dll   ) median {med:>7.1f} ms  (min {lo:.1f} / max {hi:.1f})")

    print("\n  -- first call vs second call (module-level state?) --")
    t = time.perf_counter(); pe_decompiler.analyze_pe_file("x.bin", data=text); first = (time.perf_counter() - t) * 1000
    t = time.perf_counter(); pe_decompiler.analyze_pe_file("x.bin", data=text); second = (time.perf_counter() - t) * 1000
    print(f"  first {first:.1f} ms, second {second:.1f} ms  -> per-call cost: {second > 0.5 * first}")

    print("\n  -- call profile (top 8 by tottime) --")
    import cProfile
    import pstats
    import io
    pr = cProfile.Profile()
    pr.enable()
    for _ in range(5):
        pe_decompiler.analyze_pe_file("x.bin", data=text)
    pr.disable()
    buf = io.StringIO()
    pstats.Stats(pr, stream=buf).sort_stats("tottime").print_stats(8)
    print("\n".join(buf.getvalue().splitlines()[:22]))


if __name__ == "__main__":
    main()
