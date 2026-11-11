# Deliverable A — Software Quality Report

## CyberScan NextGen · Independent QA (Agent 3)

| Field                           | Value                                                                                          |
| ------------------------------- | ---------------------------------------------------------------------------------------------- |
| Report date                     | 2026-11-09                                                                                     |
| Assessed revision               | `17939e5` — _"Add the 'Science behind CyberScan' section, scan input checks and pending work"_ |
| Baseline revision (start of QA) | `44c61e0`                                                                                      |
| Branch                          | `sonar-cube-repair-mode`                                                                       |
| Working tree at report time     | clean except the QA folder (`qa/`)                                                             |
| Assessor                        | Independent QA agent — no write access to application code was exercised                       |

---

## 1. Scope, method and honesty statement

This assessment is **non-invasive**. Nothing in `core/`, `ui/`, `web_v/`, `ml/`, `tests/` or
`config.py` was modified. All test code, fixtures and results live in `qa/` (the application
folder only; `qa/artifacts/` is git-ignored).

**Coordination note:** Agent 1 was actively committing during this assessment. My functional harness
was run against `44c61e0` and re-run against `17939e5`. Agent 1's `17939e5` commit explicitly cites
QA harness IDs F-14/F-19 as the reason for input-validation fixes — i.e. _the fixes were made in
response to this QA run_. Both versions are reported where behaviour changed (§5.3).

**What could not be verified** is listed in §8 rather than glossed over.

---

## 2. Architecture overview (as actually implemented)

```
 Input                Orchestration                  Analysis engines                          Output
 ─────                ─────────────                  ────────────────                          ──────
 file path ─┐                                     ┌─ feature_extractor (entropy topography,
 text      ─┼─► ui/scan_service.ScanService ────► │   string scan, bounded to 200 000 B)
 URL       ─┘     .analyze()                     ├─ core/heuristic_engine (rules)
                     │                            ├─ core/yara_engine  (yara-python rules)
                     │ wraps                    ├─ core/pe_decompiler (pefile + capstone)
                     │                            ├─ core/position_aware (entropy→byte ranges)
                     │                            ├─ core/dissonance + core/surprise_map (JSON profile)
                     │                            ├─ ml/structural_classifier (RandomForest→JSON trees)
                     │                            └─ core/global_intelligence (aiohttp OSINT, opt-in)
                     ▼
            core/scanner.scan_target  ──► core/risk_engine.finalize_result
                     │                            │  score = max(strongest evidence, weighted)
                     ▼                            ▼
        core/nextgen_engine                 ScanResult (evidence, engine_status, nextgen_analysis)
        (entropy, CFG, 4096-D, storyline)
```

Two front-ends share the pipeline:

- **Desktop** — `main.py` → `ui/qt_app.py` (PySide6).
- **Web** — `web_v/run.py` → `web_v/server.py` (`ThreadingHTTPServer`, 27 routes under `/api/`).

### 2.1 Implemented **versus** described

The brief describes a platform involving _"latent vector embeddings"_ and _"multi-source OSINT
correlation"_. Measured reality:

| Claimed element                  | Actual implementation                                                                                                                                                                  | Evidence                                                                                                       |
| -------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| "Latent vector embeddings"       | A **deterministic handcrafted 4096-D projection**: 4 × 1024 blocks (bytes/opcodes, entropy, CFG, PE). Not a learned embedding, not a neural network. README says so; code agrees.      | `qa/arch_probe.py`: block✱ zero counts 1024/**1023/5/0**; PE block silently all-zero with no availability mask |
| "Control Flow Graph analysis"    | Bounded static **linear-sweep disassembly heuristics** (capstone) — cyclomatic complexity + pattern labels. Not a reconstructable CFG.                                                 | `docs/implementation_status.md` §Model and feature report                                                      |
| "Zero-execution"                 | **Holds.** No `exec`/`eval`/`shell=True` on analysed content; the only subprocesses use fixed argv (`services.pick` uses `python -I -c <constant>`; `reveal` uses explorer).           | `grep` census + `modes.py` static scan                                                                         |
| "Multi-source OSINT correlation" | Three providers (ThreatFox, URLhaus, OTX) queried **concurrently with a 0.45 s per-feed budget**. Two of three are _anonymous-tier_ and return `authentication_required` without keys. | §6.3 of Deliverable B                                                                                          |
| "Latent embeddings" in reports   | `structural_prediction` is `status: untrained` — **no trained model ships**.                                                                                                           | `models/`, `ml/models/` contain only synthetic fixtures                                                        |

**Duplicate work (implemented but wasteful):** `ScanService.analyze()` calls
`scan_target()` (which runs `analyze_file()`, and inside it entropy topography **and** a 4096-D
embedding), then _re-computes_ entropy topography, CFG, the embedding and the forensic storyline in
the wrapper, and discards the native evidence list only partially. Verified: for a 1 MiB file
`scan_target` alone costs 571 ms of a 973 ms end-to-end scan.

---

## 3. Test methodology

| Area                      | Method                                                                                      | Artifact                                                               |
| ------------------------- | ------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------- |
| Functional / edge cases   | 19-case harness driving only public entry points                                            | `qa/qa_harness.py functional` → `qa/artifacts/functional_results.json` |
| Regression (repo suite)   | Repo's own `pytest` suite, unmodified; per-module execution because a single process aborts | `qa/run_suite.py` → `qa/artifacts/suite/`                              |
| Architecture/claim checks | Static census + numeric probes of the feature vector                                        | `qa/arch_probe.py`, `qa/stage_probe.py`, `qa/pe_probe.py`              |
| Targeted regression tests | 6 checks, one per defect found                                                              | `qa/regression_probe.py`                                               |
| Performance               | See Deliverable B                                                                           | `qa/artifacts/benchmark*.json`                                         |
| Security                  | See Deliverable C                                                                           | `qa/artifacts/security_*.json`                                         |

**Test data:** synthetic only. Random bytes (seeded), zero-filled, MZ-truncated headers, Unicode and
200-character filenames, 200 000-character text, PowerShell indicator text. **No live malware was
downloaded, stored or executed.** The industry-standard EICAR test string was written once and was
removed by the host's antivirus before it could be opened (§5.2 F-07).

---

## 4. Functional test results

Run against `17939e5`. **18 / 19 pass**; the one error is environmental (host AV), not a product crash.

| ID   | Case                               | Expected            | Observed                                                                | Result              |
| ---- | ---------------------------------- | ------------------- | ----------------------------------------------------------------------- | ------------------- |
| F-01 | zero-byte file                     | completes           | score 0, class `NO_INDICATORS_OBSERVED`, vector 4096                    | PASS                |
| F-02 | 13-byte text file                  | completes           | score 0                                                                 | PASS                |
| F-03 | 256 KiB zero-filled                | completes, bounded  | score 0, 278 ms                                                         | PASS                |
| F-04 | truncated `MZ` (e_lfanew past EOF) | no crash            | score 25 `REVIEW`, 2 findings                                           | PASS                |
| F-05 | Unicode filename                   | handled             | score 0                                                                 | PASS                |
| F-06 | 200-char filename                  | handled             | score 10 `REVIEW`                                                       | PASS                |
| F-07 | EICAR test string                  | completes           | `OSError [Errno 22]` — **file removed by Windows Defender before open** | ERROR (environment) |
| F-08 | PowerShell download-cradle text    | flagged             | score 70 `SUSPICIOUS`, 4 findings                                       | PASS                |
| F-10 | same file twice                    | identical           | score + 4096-D vector byte-identical                                    | PASS                |
| F-11 | ordinary text                      | accepted            | score 0, `text-content` profile                                         | PASS                |
| F-12 | valid URL                          | accepted            | score 0                                                                 | PASS                |
| F-13 | malformed URL `ht!tp://////`       | no crash            | score 0                                                                 | PASS                |
| F-14 | empty text                         | **rejected**        | `ValueError: Nothing to check…` (fixed in `17939e5`)                    | PASS                |
| F-15 | 200 000-char text                  | accepted            | 200 000 bytes                                                           | PASS                |
| F-16 | Unicode / RTL / bidi               | byte length correct | 91 bytes                                                                | PASS                |
| F-17 | file over `maximum_file_size`      | rejected            | `ValueError: exceeds`                                                   | PASS                |
| F-18 | timeout 0 / −1 / NaN / ∞           | rejected            | all `ValueError`                                                        | PASS                |
| F-19 | File mode, missing path            | **explicit error**  | `FileNotFoundError` (fixed in `17939e5`)                                | PASS                |
| F-20 | zero-byte through full pipeline    | completes           | score 0                                                                 | PASS                |

### 4.1 Behaviour change introduced by `17939e5` (observed)

On `44c61e0`, `ScanService.analyze("<path>", "File", …)` with a **nonexistent** path silently fell
through to `core.scanner.scan_target(target, is_file=False)` → `analyze_text_target()`, producing a
_text_ result for a _file_ request (no error, class `NO_INDICATORS_OBSERVED`). On `17939e5` it raises
`FileNotFoundError` **and** empty text raises `ValueError`.

**Residual risk (QA-006):** `core/scanner.scan_target(..., is_file=False)` still accepts any string
and scans it as text. That is the correct behaviour for its own contract, but callers other than
`ScanService` (e.g. a future automation hook) get the old silent behaviour. A file-mode flag on the
public function would prevent regression.

---

## 5. Edge-case results

| Case                                 | Result                                                                       | Note                                                                    |
| ------------------------------------ | ---------------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| Zero-byte file                       | Correct and safe                                                             | `latin-1` decode of `b""` is safe                                       |
| Truncated PE header                  | Handled; `status: not_pe`                                                    | 2 findings produced (conservative)                                      |
| Invalid file signature               | Handled                                                                      | magic-byte mismatch path exercised by repo tests                        |
| Highly repetitive binary             | score 0, class NONE                                                          | Entropy 0 → no false alarm (good)                                       |
| Random binary (256 KiB–4 MiB)        | **score 18 – `REVIEW`**                                                      | Flagged for entropy discontinuity — see QA-007 (false-positive concern) |
| Extremely long filename (2000 chars) | Accepted / truncated to 120 on web upload                                    | Web side truncates to `[:120]`                                          |
| Unicode filenames (Arabic, Japanese) | Handled                                                                      |                                                                         |
| Concurrent scans (8 parallel)        | No failure; **no speedup** (see B §7)                                        |                                                                         |
| Interrupted / oversized requests     | Rejected (`413`), connection closed, no state corruption                     |                                                                         |
| Network timeouts (OSINT)             | `partial_timeout` after 0.45 s                                               | Never blocks longer than the budget                                     |
| Missing OSINT responses              | `authentication_required` / `timeout` surfaced per feed                      |                                                                         |
| Host-AV-blocked file                 | **QA-005**: reported as "File not found" although `os.path.exists()` is True | misleading message (Low)                                                |

---

## 6. Regression results (existing suite)

Command: `qa/run_suite.py` (same `pytest.ini`, unmodified expectations).

**607 tests collect** when `tests/test_shield.py` is excluded.

| Result                                                                                                                                                     | Detail                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **14 modules verified green (181 passed)**                                                                                                                 | archive_inspector 11, dataset_validation 7, downloads_monitor 4, entropy 4, evidence_calibration 19, exhibit 10, features 1, file_analyzer_evidence 4, finding_text_and_ai 21, forest_export 22, forest_format 87, galaxy 6, hashing 2, heuristics 2                                                                                                                                                                                                                                                                        |
| **415 tests passed** in a run covering every non-GUI module up to and including `test_repair_engine_synth.py` before the process was externally terminated | `qa/suite-part1.log`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| **COLLECTION ERROR — `tests/test_shield.py`**                                                                                                              | `ModuleNotFoundError: No module named 'shield'` — the module `web_v/shield/` does **not exist** in the repository or in `saif_final.zip`. This one file aborts the _entire default run_ (`pytest.ini` → `testpaths = tests`).                                                                                                                                                                                                                                                                                               |
| **NATIVE CRASH — GUI suite**                                                                                                                               | `Windows fatal exception: access violation` in `shiboken6.abi3.dll`, thread stack in `ui/qt_app.py:1865 eventFilter`, during teardown of `tests/conftest.py::window` → `qt_app.py:1911 closeEvent`. An `AiWorker` thread was simultaneously blocked in `socket.create_connection` (`ui/ai_summary.py:121`). Evidence: `qa/artifacts/suite_baseline_crash.txt`.                                                                                                                                                              |
| **Not completed (unverified)**                                                                                                                             | `test_interface.py`, `test_magic_bytes.py`, `test_model_runtime.py`, `test_nextgen_features.py`, `test_pipeline_consistency.py`, `test_plain_language.py`, `test_polish.py`, `test_position_aware.py`, `test_quarantine.py`, `test_reasoning_engines.py`, `test_report_generation.py`, `test_result_view.py`, `test_risk_engine.py`, `test_scan_flow.py`, `test_scan_service.py`, `test_shield.py`, `test_structural_classifier*.py`, `test_structure_sonar_repair.py`, `test_ui_persistence.py`, `test_ux_review_fixes.py` |

**Honest status:** I can assert "181 tests pass in the modules I fully executed; 415 passed before
interruption". I **cannot** assert "the suite is green". The documentation claim in
`docs/implementation_status.md` ("65 passed") is stale; the commit message for `17939e5` was written
while the suite was still green.

### 6.1 Integration coverage gap

`web_v/server.py` (27 API routes, the whole public attack surface) has **no test file at all**.
`tests/test_shield.py` targets a module that does not exist. The entire HTTP layer is untested by the
repository's own suite — my `qa/security_probe.py` is currently its only executable coverage.

### 6.2 Reproducibility notes

- A single-process run is **not reproducible** in this environment: the PySide6 crash kills the run,
  and the tooling environment terminates long child processes. Per-module execution is required.
- The first scan in a fresh process costs ~1.1–2.1 s (lazy imports of pefile/capstone/yara + one
  forced `gc.collect()` inside the PE stage). Any "first scan" timing must be excluded or stated.

---

## 7. Prioritised defect list

Severity: **Critical** = wrong conclusion or unrecoverable state · **High** = likely user harm or
credible abuse path · **Medium** = degraded reliability/perf · **Low** = polish/misleading message.

| ID         | Sev                             | Defect                                                                                                                                                                                                            | Component                                                            | Deterministic?                | Status                                                   |
| ---------- | ------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------- | ----------------------------- | -------------------------------------------------------- |
| **QA-001** | **Critical** (release-blocking) | Default `pytest` run cannot collect: `tests/test_shield.py` imports a non-existent `shield` module                                                                                                                | `tests/`, `pytest.ini`                                               | Yes (100%)                    | **Open**                                                 |
| **QA-008** | **High**                        | Native access violation in `shiboken6.abi3.dll` during GUI test teardown while an `AiWorker` thread is in a blocking socket connect                                                                               | `tests/conftest.py`, `ui/qt_app.py` `closeEvent`, `ui/ai_summary.py` | Yes — 2/2 full-suite attempts | **Open**                                                 |
| **QA-002** | High → **Fixed**                | File mode with a missing path silently scanned as text                                                                                                                                                            | `ui/scan_service.py` + `core/scanner.py`                             | Yes                           | **Fixed in `17939e5`**; residual in `scan_target` (§4.1) |
| **QA-003** | Medium → **Fixed**              | Empty text scanned instead of rejected                                                                                                                                                                            | `ui/scan_service.py`                                                 | Yes                           | **Fixed in `17939e5`**                                   |
| **QA-004** | Medium                          | `analysis_timeout` is advisory: checked only _between_ stages. 50 ms budget → **192 ms** actual (3.8×); a stuck native parser cannot be interrupted                                                               | `ui/scan_service.py`, `core/file_analyzer.py`, native parsers        | Yes                           | Open                                                     |
| **QA-005** | Low                             | A file blocked by host antivirus is reported as "File not found" (`OSError` not distinguished from missing file)                                                                                                  | `ui/scan_service.py` (formerly line 141)                             | Yes                           | Open                                                     |
| **QA-006** | Low                             | `scan_target(..., is_file=False)` accepts a filesystem path and scans it as text — the contract that caused QA-002 is still reachable                                                                             | `core/scanner.py`                                                    | Yes                           | Open                                                     |
| **QA-007** | Low/Medium                      | 256 KiB–8 MiB of **uniform random** content yields score 18 → `REVIEW` ("Entropy discontinuity"). Random data is not evidence of malice; this is the highest-volume false-positive class for downloads monitoring | `ui/scan_service.py` (anomaly → Finding 12 pts)                      | Yes                           | Open (needs product decision)                            |
| **QA-009** | Medium                          | **Duplicate pipeline**: `scan_target` result is re-derived (entropy, CFG, 4096-D, storyline) and native evidence partially recomputed. `scan_target` is 571/973 ms of a 1 MiB scan                                | `ui/scan_service.py:147–216`                                         | Yes                           | Open                                                     |
| **QA-010** | Medium                          | **No concurrency gain**: 8 parallel scans take 7.20 s vs 7.01 s sequential (1.00×). GIL-bound; no process pool. Web server advertises `ThreadingHTTPServer`                                                       | `core/`, `web_v/server.py`, `services.py` `_pick_lock`               | Yes                           | Open                                                     |
| **QA-011** | Low                             | Process heap grows ~48 MB after a single 4 MiB scan (PE stage forces `gc.collect()` every call, full-heap sweep)                                                                                                  | `core/pe_decompiler.py`                                              | Yes                           | Open                                                     |
| **QA-012** | Info                            | `docs/implementation_status.md` still reports "65 passed" and "`web_v/server.py` untested" claims that conflict with current reality                                                                              | docs                                                                 | —                             | Stale                                                    |

### 7.1 Minimal fix recommendations

- **QA-001** — Either delete `tests/test_shield.py` (module absent from the repo) or add
  `--ignore=tests/test_shield.py` to `pytest.ini` `addopts`; ideally restore `web_v/shield/` if it is
  intended to exist. _This alone restores a collectable suite._
- **QA-008** — In `qt_app.closeEvent`, signal the `AiWorker` to stop and `join()` it (or make its
  socket connect non-blocking with a short timeout) **before** the QWidget hierarchy is destroyed;
  in `conftest.window`, process events after `close()`.
- **QA-004** — Enforce the deadline in a worker process/thread with a hard `join(timeout)` and report
  "deadline exceeded (partial result)" instead of claiming the budget is honoured; or document the
  budget as _per stage_.
- **QA-005** — Catch `OSError` separately: "The file could not be read (it may be blocked by
  antivirus or another process)".
- **QA-009** — Have `ScanService` reuse `scan_target`'s computed `nextgen_analysis` instead of
  recomputing; expected saving ≈ 40–50 % of median latency.
- **QA-010** — If concurrency matters (multi-user web), run analysis in a `ProcessPoolExecutor`
  (each scan is CPU-bound and already returns plain data).

### 7.2 Regression tests (delivered)

`qa/regression_probe.py` — one check per defect, current result **4/5** (QA-004 intentionally fails).
Run: `.venv\Scripts\python.exe qa\regression_probe.py`.

---

## 8. Known limitations of this assessment

1. **`tests/test_shield.py` could not be evaluated** — the module it imports does not exist.
2. **~20 test modules were not executed to completion** (listed in §6). No claim is made about them.
3. **A single-process full-suite run is not reproducible here** (QA-008 + hostile host environment).
4. **No real-malware detection quality was measured.** Only benign synthetic fixtures were used, by
   design. The repo's own `reports/evaluation/results.json` reports any-warning F1 0.964 / FPR 2.86 %
   on _benign + synthetic positives_ — that is **not** malware detection performance and is not
   endorsed by this report.
5. **Web UI not exercised through a browser** in this run; only its HTTP contract was exercised.
6. **Desktop GUI not exercised interactively**; only the test suite touched it.

---

## 9. Verdict inputs for Deliverable E

- Core static pipeline: **functional and deterministic** on 18/19 cases; 4096-D output stable.
- No data loss or accidental modification paths found in the scan pipeline (quarantine is dry-run by
  default, requires explicit authorisation, refuses symlinks and short keys — verified S-14…S-16).
- Release-blocking: **QA-001** (suite does not collect) and **QA-008** (native crash in teardown).
- Performance: **not** "sub-1.5 second" for files ≥1 MiB (see Deliverable B).
