# Deliverable D — Independent QA Test Suite & Fixtures

Everything here is **Agent 3's** work and lives outside the application folders. `qa/artifacts/` is
git-ignored; the scripts and this README are safe to keep.

> **Note on commit history:** these scripts were created while Agent 1 was fixing input validation.
> Agent 1's commit `17939e5` swept `qa/*.py` and this README into git (and added `qa/` to
> `.gitignore`). Nothing in `core/`, `ui/`, `tests/` or `config.py` was altered by QA.

## Layout

| Path                  | Purpose                                                                                                                   |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| `qa_harness.py`       | Main driver: `functional`, `bench`, `security`, `all`. `--timebox N` hard-caps a run.                                     |
| `run_suite.py`        | Runs the repository's own pytest suite **one module per process** (a native crash in one module cannot destroy the rest). |
| `regression_probe.py` | One regression check per defect (QA-002…QA-006). **4/5 pass**; QA-004 fails by design.                                    |
| `arch_probe.py`       | Falsifiable checks of the 4096-D vector (dimension, NaN/inf, per-block occupancy, availability mask).                     |
| `stage_probe.py`      | Per-stage cost for a 13-byte input — exposes the fixed overhead.                                                          |
| `pe_probe.py`         | Why the PE stage costs ~70 ms on non-PE data (`gc.collect()` per call).                                                   |
| `net_bench.py`        | OSINT latency, HTTP API latency, concurrency scaling.                                                                     |
| `security_probe.py`   | Raw-socket HTTP abuse cases (CRLF in filename, NUL, length abuse, slow body, constant-time token).                        |
| `sec02_probe.py`      | Reproduces the disconnect-during-reply connection reset (SEC-02).                                                         |
| `artifacts/`          | All generated JSON/log evidence. **Git-ignored.**                                                                         |

## Quick start

```powershell
cd C:\Users\mahdi\Desktop\dist

# 1. Functional + edge cases  (~1 min)
.\.venv\Scripts\python.exe qa\qa_harness.py functional --timebox 300

# 2. Targeted regression checks
.\.venv\Scripts\python.exe qa\regression_probe.py

# 3. Performance (each phase writes its JSON immediately)
.\.venv\Scripts\python.exe qa\qa_harness.py bench --timebox 700
.\.venv\Scripts\python.exe qa\net_bench.py
.\.venv\Scripts\python.exe qa\stage_probe.py

# 4. Security (local server only, 127.0.0.1)
.\.venv\Scripts\python.exe qa\qa_harness.py security --timebox 400
.\.venv\Scripts\python.exe qa\security_probe.py
.\.venv\Scripts\python.exe qa\sec02_probe.py

# 5. Repository suite, crash-isolated
.\.venv\Scripts\python.exe qa\run_suite.py
```

Requirements beyond the project's own: `psutil` (CPU/RSS sampling), `pytest-timeout`, and
`pip-audit` (optional). Install into the project venv only when benchmarking:

```powershell
.\.venv\Scripts\python.exe -m pip install psutil pytest-timeout pip-audit
```

## Fixtures (`qa/artifacts/fixtures/`, generated on demand)

| Fixture                             | Bytes                     | Purpose                                                                                |
| ----------------------------------- | ------------------------- | -------------------------------------------------------------------------------------- |
| `zero.bin`                          | 0                         | zero-byte path                                                                         |
| `note.txt`                          | 13                        | fixed-overhead measurement                                                             |
| `repetitive.bin`                    | 256 KiB `0x00`            | entropy-0 baseline                                                                     |
| `random_{1K,16K,256K,1M,4M,8M}.bin` | seeded `random.randbytes` | latency/throughput scaling                                                             |
| `truncated_pe.bin`                  | 62                        | `e_lfanew` past EOF                                                                    |
| `ملف-テスト-ñ.bin`                  | 4 KiB                     | Unicode filename                                                                       |
| `AAAA…A.bin`                        | 1 KiB                     | 200-char filename                                                                      |
| `script.ps1`                        | 118                       | PowerShell download cradle (harmless text)                                             |
| `eicar.com`                         | 68                        | EICAR test string — **deleted by host antivirus on write**; kept to document that path |

No sample is malicious. No sample is executable code that the application runs.

## Design constraints baked in

- **Write-ahead results** — a phase persists its JSON after every case, so a killed process never
  loses completed measurements (the host environment terminates long child processes).
- **Bounded runs** — `--timebox` and per-case counts chosen to finish in a single invocation.
- **No modification of the app** — the harness imports `ui.scan_service`, `core.*`, `web_v.server`
  and calls public functions only. The web probes use `create_server(0)` on a random port.
- **Honest thresholds** — assertions encode the requirement (e.g. a 50 ms deadline must be met within
  100 ms), not whatever the code happens to do.
