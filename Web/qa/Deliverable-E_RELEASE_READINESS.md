# Deliverable E — Release Readiness Assessment

## CyberScan NextGen @ `17939e5`

# Status: **NOT READY** (for a release artefact)

> **Scope of this decision.** "Release" here means _shipping this revision as the project's
> deliverable artefact_ — the thing a reviewer, a student evaluator or a user would receive. It is
> **not** a judgement on the science, the design, or the honesty of the documentation, all of which
> scored well. Two release-blocking engineering defects make the artefact unshippable today; both
> are small, local fixes.

---

## 1. Decision

| Gate                                                                           | Result                                                                                                                      |
| ------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------- |
| Core static pipeline works on the supported inputs                             | ✅ 18/19 functional cases pass, deterministic                                                                               |
| No crash on adversarial file inputs (4–8 MiB MZ, truncated headers, zero-byte) | ✅                                                                                                                          |
| No silent data loss / no unauthorised file modification                        | ✅ quarantine dry-run + authorisation gating verified                                                                       |
| **The project's own test suite can run**                                       | ❌ **fails at collection** (`tests/test_shield.py` → `No module named 'shield'`)                                            |
| **The project's own test suite completes when it _can_ start**                 | ❌ **native access violation** in `shiboken6` during GUI teardown                                                           |
| Documented performance claims reproducible                                     | ⚠️ OSINT median 0.43–0.46 s (claim of ≤1.5 s: not breached at median, P95 1.40 s); **no** file-scan figure supports "1.5 s" |
| Security posture acceptable for a local tool                                   | ✅ with Medium finding SEC-01 documented for any public deployment                                                          |

**Verdict: NOT READY.** If the two blocking defects are fixed, this becomes
**READY WITH LIMITATIONS** immediately — see §4. The limitations that would remain (performance,
detection-quality absence, no sandbox) are already stated accurately in `README.md` and
`docs/implementation_status.md`, and are _acceptable_ for a research prototype.

---

## 2. Blocking defects (must fix)

### B1 — The test suite does not collect (`QA-001`)

```
$ .venv\Scripts\python.exe -m pytest -q
E   ModuleNotFoundError: No module named 'shield'
ERROR tests/test_shield.py
!!! Interrupted: 1 error during collection !!!
```

`pytest.ini` sets `testpaths = tests`; `tests/test_shield.py` does `from shield import core, engine, …`.
`web_v/shield/` **does not exist** in the working tree, in git history, or inside `saif_final.zip`.

**Why this blocks release:** the first thing any reviewer runs is `pytest`. It fails. It also
invalidates the "65 passed" claim in `docs/implementation_status.md`.

**Fix (5 minutes):** restore `web_v/shield/` **or** delete `tests/test_shield.py` **or** add
`--ignore=tests/test_shield.py` to `addopts`. Also refresh the stale pass count in the docs.

### B2 — Native crash when the suite does start (`QA-008`)

```
Windows fatal exception: access violation
Current thread 0x… (most recent call first):
  File "…\shiboken6\…", line 0
  File "…\ui\qt_app.py", line 1865 in eventFilter
  File "…\ui\qt_app.py", line 1911 in closeEvent
  File "…\tests\conftest.py", line … in window
```

Reproduced **2 of 2** times, at the same location, while an `AiWorker` thread was blocked in
`socket.create_connection` (`ui/ai_summary.py:121`). Full trace:
`qa/artifacts/suite_baseline_crash.txt`.

**Why this blocks release:** it means closing the application while an AI-summary request is in
flight can crash the **desktop app** — not just the test. The user-facing risk is data loss of the
current scan and an ugly crash dialog.

**Fix (small):** in `closeEvent`, request cancellation of the `AiWorker` and `join()` it (with a
bounded timeout) _before_ destroying widgets; make the summary socket connect non-blocking with a
short timeout. Then re-run `tests/test_interface.py` to confirm.

---

## 3. Evidence supporting "not ready" vs. "the rest is fine"

| Positive evidence                                                                   | Source                                       |
| ----------------------------------------------------------------------------------- | -------------------------------------------- |
| Deterministic output (identical score + 4096-D vector for repeat scans)             | F-10                                         |
| Bounded file reads; size-limit enforcement; timeout validation                      | F-17, F-18, repo 415 passing tests           |
| Zero-execution property holds (no `exec`/`eval`/`shell=True`)                       | grep census + repo `modes.py`                |
| Quarantine cannot delete without `authorized=True`; rejects short keys and symlinks | S-14…S-16                                    |
| Path traversal, header injection, type confusion, oversized bodies all resisted     | S-02…S-12, S-19…S-23                         |
| No `pickle`/`joblib.load` in the active model path                                  | S-13                                         |
| Honest documentation of limits and absent capabilities                              | `README.md`, `docs/implementation_status.md` |

| Negative evidence                                                            | Impact on readiness                                                         |
| ---------------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| Entropy on 256 KiB–8 MiB of **random** data → `REVIEW` (score 18)            | Every randomish/compressed download will be "reviewed": noise, not risk     |
| `analysis_timeout` overshoot 3.8× (50 ms → 192 ms); one stage can take 4.5 s | A hostile 4 MiB `MZ` file can hold a request far past the advertised budget |
| 8 parallel scans: 0.98×                                                      | The web product cannot serve concurrent users on one process                |
| Cold start 1.4–2.1 s                                                         | First-scan UX/Lambda cold-start exceed any "1.5 s" framing                  |
| ~12–15× input size in RSS, raw bytes retained per job                        | 32 × 50 MiB → > 1.6 GB worst case                                           |

These are **limitations**, documented and acceptable for a prototype — not blockers.

---

## 4. Required actions before lifting the block

| #   | Action                                                                                    | Effort           | Owner             |
| --- | ----------------------------------------------------------------------------------------- | ---------------- | ----------------- |
| 1   | Fix `test_shield.py` collection (B1)                                                      | 5 min            | Agent 1           |
| 2   | Fix GUI teardown crash (B2); verify `test_interface.py` passes                            | 1–2 h            | Agent 1           |
| 3   | Re-run the full suite in one process and record the real count                            | 30 min           | Agent 1           |
| 4   | Correct the "65 passed" figure and the `web_v/shield` references in docs                  | 10 min           | Agent 1           |
| 5   | (Recommended) Decision on QA-007: entropy of random data should not imply `REVIEW`        | product decision | Agent 1 / Agent 2 |
| 6   | (Recommended) `ScanService` should reuse `scan_target`'s results (QA-009) — ≈40 % latency | 2 h              | Agent 1           |

**Predicted status after actions 1–4: READY WITH LIMITATIONS.**

---

## 5. Status definitions applied

| Status                 | Meaning                                                 | Applies?                                                   |
| ---------------------- | ------------------------------------------------------- | ---------------------------------------------------------- |
| READY                  | Critical functionality passes the defined tests         | no — suite does not run                                    |
| READY WITH LIMITATIONS | Core works, documented issues remain                    | **not yet** — blocked by B1/B2                             |
| **NOT READY**          | Critical defects or unresolved reliability risks remain | **yes**                                                    |
| INSUFFICIENT EVIDENCE  | Implementation/access insufficient for a conclusion     | no — the pipeline was tested directly; the evidence exists |

---

## 6. What this assessment deliberately does **not** say

- It does **not** claim a detection rate. No malware was used. Any accuracy figure (including the
  repo's own F1 0.964 on benign + synthetic positives) is not a malware-detection result.
- It does **not** endorse "98 % accuracy", "zero false positives" or "sub-1.5-second correlation".
  §7 of Deliverable B explains exactly what can be claimed instead.
- It does **not** claim the suite is green. 181 tests are verified green; ~20 modules are
  **unverified** because of B2 and the environment (see Deliverable A §8).
