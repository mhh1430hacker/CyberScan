"""Run the repository's own test suite in isolated chunks and summarise.

A single-process run aborted inside the PySide6 test file (see
qa/artifacts/suite_baseline_crash.txt). Each module is therefore run in its
own process so one native crash cannot destroy the rest of the evidence.

    .venv\\Scripts\\python.exe qa\\run_suite.py
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
QA = Path(__file__).resolve().parent
OUT = QA / "artifacts" / "suite"
OUT.mkdir(parents=True, exist_ok=True)

TIMEOUT_S = 900


def modules() -> list[Path]:
    return sorted((ROOT / "tests").glob("test_*.py"))


def main() -> None:
    results = []
    for module in modules():
        rel = module.relative_to(ROOT).as_posix()
        log = OUT / f"{module.stem}.log"
        t0 = time.perf_counter()
        try:
            proc = subprocess.run(
                [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
                 "--timeout=180", "--timeout-method=thread", "-rf", rel],
                cwd=ROOT, capture_output=True, text=True, timeout=TIMEOUT_S,
            )
            out, err, rc = proc.stdout, proc.stderr, proc.returncode
        except subprocess.TimeoutExpired as exc:
            out = (exc.stdout or b"").decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            err = "HARNESS TIMEOUT"
            rc = -9
        wall = time.perf_counter() - t0
        log.write_text(f"$ {rel}\n\n--- stdout ---\n{out}\n--- stderr ---\n{err}\n", encoding="utf-8")

        summary = re.findall(r"(\d+) (passed|failed|error|errors|skipped|xfailed|xpassed)", out)
        counts = {kind: int(n) for n, kind in summary}
        if rc == 0 and counts:
            verdict = "PASS"
        elif "access violation" in err or "Windows fatal exception" in err or rc in (3221225477, -1073741819):
            verdict = "CRASH"
        elif rc == -9:
            verdict = "TIMEOUT"
        elif "ModuleNotFoundError" in err or "errors during collection" in out:
            verdict = "COLLECTION ERROR"
        else:
            verdict = "FAIL"
        results.append({"module": rel, "verdict": verdict, "exit_code": rc, "wall_s": round(wall, 1),
                        "counts": counts, "last_line": (out.strip().splitlines() or [""])[-1][:200],
                        "stderr_head": err.strip().splitlines()[:2]})
        print(f"[{verdict:<16}] {rel:<48} {wall:>7.1f}s rc={rc:<12} {counts}", flush=True)

    (OUT / "suite_summary.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    total = sum(r["counts"].get("passed", 0) for r in results)
    print(f"\npassed in total: {total}")
    for r in results:
        if r["verdict"] != "PASS":
            print(f"  {r['verdict']}: {r['module']} -> qa/artifacts/suite/{Path(r['module']).stem}.log")


if __name__ == "__main__":
    main()
