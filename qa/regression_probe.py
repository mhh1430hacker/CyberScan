"""Targeted re-checks of the specific defects found in the QA cycle.

Each check is written against the *current* source so it can be run after every
change (these are the regression tests requested in the QA report, kept outside
tests/ so Agent 1's suite is untouched).
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT)]

from config import DEFAULT_SETTINGS  # noqa: E402
from ui.scan_service import ScanService  # noqa: E402

FIX = ROOT / "qa" / "artifacts" / "fixtures"
results: list[tuple[str, str, str]] = []


def check(rid: str, name: str, ok: bool, detail: str) -> None:
    results.append((rid, "PASS" if ok else "FAIL", f"{name}: {detail}"))


def main() -> None:
    settings = dict(DEFAULT_SETTINGS)

    # QA-002: a missing file in File mode must not be scanned as text
    try:
        ScanService().analyze(str(FIX / "nope.bin"), "File", settings)
        check("QA-002", "missing file rejected", False, "no exception raised")
    except FileNotFoundError as exc:
        check("QA-002", "missing file rejected", True, f"FileNotFoundError: {exc}")
    except Exception as exc:  # noqa: BLE001
        check("QA-002", "missing file rejected", False, f"wrong type {type(exc).__name__}: {exc}")

    # QA-003: empty text must be rejected rather than scanned
    try:
        ScanService().analyze("", "Text", settings)
        check("QA-003", "empty text rejected", False, "no exception raised")
    except ValueError as exc:
        check("QA-003", "empty text rejected", True, f"ValueError: {exc}")

    # QA-004: analysis_timeout is advisory - measure the overshoot on a 4 MiB file
    big = FIX / "random_4194304.bin"
    if big.is_file():
        tight = {**settings, "analysis_timeout": 0.05}
        t = time.perf_counter()
        try:
            ScanService().analyze(str(big), "File", tight)
            outcome = "completed without honouring the deadline"
        except TimeoutError:
            outcome = "TimeoutError"
        took = (time.perf_counter() - t) * 1000
        # A 50 ms deadline must be met within a small, fixed margin - not 3-4x over it.
        check("QA-004", "deadline honoured (50 ms budget)",
              took <= 100, f"{outcome} after {took:.0f} ms -> overshoot x{took / 50:.1f} "
                           "(checked only between stages; see QA-004)")

    # QA-005: a file blocked by OS antivirus must not be reported as "does not exist"
    blocked = FIX / "defender_probe.bin"
    blocked.write_bytes(b"harmless")
    try:
        ScanService().analyze(str(blocked), "File", settings)
        check("QA-005", "OS-blocked file distinguished from missing", True, "scan completed")
    except FileNotFoundError as exc:
        exists = blocked.exists()
        check("QA-005", "OS-blocked file distinguished from missing", not exists,
              f"FileNotFoundError while os.path.exists={exists} -> message is misleading")
    finally:
        blocked.unlink(missing_ok=True)

    # QA-006: zero-byte file completes
    zero = FIX / "zero.bin"
    zero.write_bytes(b"")
    result, nextgen, vector, *_ = ScanService().analyze(str(zero), "File", settings)
    check("QA-006", "zero-byte file", nextgen["file_size"] == 0 and result.combined_score == 0,
          f"size={nextgen['file_size']} score={result.combined_score} vector={len(vector)}")

    for rid, outcome, detail in results:
        print(f"[{outcome}] {rid} {detail}")
    failed = [r for r in results if r[1] == "FAIL"]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
