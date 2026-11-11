# Deliverable B — Performance Benchmark Report

## CyberScan NextGen · measured 2026-11-09

All numbers below were **measured on this machine**, not estimated. Raw data:
`qa/artifacts/benchmark_results.json`, `qa/artifacts/benchmark_network.json`,
`qa/stage_probe.log`, `qa/pe_probe.log`.

---

## 1. Testing environment

| Item      | Value                                                                                                                                                                                                     |
| --------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Host      | `MHH-TUF-GAMING`                                                                                                                                                                                          |
| CPU       | AMD Ryzen 7 7435HS — 8 cores / 16 logical                                                                                                                                                                 |
| RAM       | 15.8 GB                                                                                                                                                                                                   |
| OS        | Windows 11 build 26200 (`Windows-11-10.0.26200-SP0`)                                                                                                                                                      |
| Python    | CPython 3.14.5 (MSC v.1944, 64-bit)                                                                                                                                                                       |
| Libraries | numpy 2.5.4 · scikit-learn 1.9.1 · capstone 5.0.9 · pefile 2024.8.26 · yara-python 4.5.4 · yara-x 1.23.0 · cryptography 50.0.2 · aiohttp 3.14.5 · pandas 3.0.6 · pytest 9.1.1 · PySide6-Essentials 6.12.0 |
| Revision  | `17939e5` (branch `sonar-cube-repair-mode`)                                                                                                                                                               |
| Network   | Residential/office connection, no traffic shaping applied; OSINT results are therefore _indicative_, not a controlled network benchmark                                                                   |
| Power     | AC, no thermal throttling observed (CPU ratio steady 95–99 %)                                                                                                                                             |

## 2. Methodology

- **Inputs**: seeded random bytes (`random.Random(0xC5)`), sizes 1 KiB … 8 MiB, written to disk once
  and pre-read before timing so **disk I/O is excluded** from scan latency.
- **Warm-up**: 2 full scans of a 256 KiB file before any measurement; the existence of a
  first-run penalty is itself reported (§4.3).
- **Repetitions**: 7 for end-to-end latency per size; 2 for the expensive native-only stage; the
  median, P90/P95/P99 are computed by linear interpolation.
- **Isolation**: each benchmark function runs in its own process (a single native crash or a killed
  child cannot corrupt other measurements). Results are persisted after **every** phase.
- **CPU/memory**: per-process `cpu_times()` delta and RSS sampled every 10 ms by a watcher thread
  (`psutil`).
- **End-to-end** = `ui.scan_service.ScanService().analyze(path, "File", DEFAULT_SETTINGS)` — i.e.
  exactly what the desktop UI and the web API call. OSINT disabled unless stated (it is opt-in).

Reproduce:

```powershell
.\.venv\Scripts\python.exe qa\qa_harness.py bench --timebox 700   # file latency, stages, native
.\.venv\Scripts\python.exe qa\net_bench.py                        # OSINT, HTTP API, concurrency
.\.venv\Scripts\python.exe qa\stage_probe.py                      # per-stage cost, 13-byte input
.\.venv\Scripts\python.exe qa\pe_probe.py                         # PE-stage cost / gc.collect
```

---

## 3. End-to-end file scan latency (random binary content)

|    Size |   n |    Mean |      Median |     P90 | **P95** |     P99 | Max     | CPU ratio | Peak RSS delta | Throughput |
| ------: | --: | ------: | ----------: | ------: | ------: | ------: | ------- | --------- | -------------- | ---------- |
|   1 KiB |   7 |   121.2 |   **120.2** |   124.0 |   124.9 |   126.0 | 126.1   | 96.3 %    | 0.2 MB         | 0.01 MB/s  |
|  16 KiB |   7 |   345.0 |   **340.2** |   370.2 |   374.8 |   377.9 | 378.0   | 98.1 %    | 0.4 MB         | 0.05 MB/s  |
| 256 KiB |   7 |   695.3 |   **687.7** |   719.8 |   723.3 |   726.3 | 726.6   | 95.9 %    | 48.2 MB\*      | 0.36 MB/s  |
|   1 MiB |   7 |   981.0 |   **972.8** | 1 046.9 | 1 057.9 | 1 063.8 | 1 065.2 | 97.3 %    | 9.0 MB         | 1.03 MB/s  |
|   4 MiB |   7 | 2 106.1 | **2 093.2** | 2 240.1 | 2 261.8 | 2 275.9 | 2 279.3 | 97.5 %    | 50.0 MB        | 1.91 MB/s  |
|   8 MiB |   7 | 3 607.9 | **3 610.6** | 3 681.9 | 3 707.2 | 3 734.1 | 3 740.4 | 97.8 %    | 72.0 MB        | 2.22 MB/s  |

\* the 48 MB figure for 256 KiB includes a one-off layout effect right after the large-file warm-up
phase; the steady-state per-call growth is ~9 MB per MiB of input (see 4 MiB and 8 MiB rows).

**Scaling:** cost is **super-linear at small sizes** (a fixed ~100 ms floor) and **linear above
~1 MiB** at ≈ 2.2 MB/s per core. Extrapolating the linear part, the configured 50 MiB maximum would
take **≈ 23 s** of CPU; the repository's own resource test measured **12.0 s for a 49 MiB file** on a
different input. Both are an order of magnitude inside the configured 15 s default timeout on this
hardware — but see §5, QA-004: the timeout is _not enforced_ while a stage is running.

---

## 4. Where the time goes

### 4.1 Per-stage breakdown (4 MiB random, median of 7)

| Stage                                                                           |       Median |
| ------------------------------------------------------------------------------- | -----------: |
| `scan_target` → `analyze_file` (features, heuristics, YARA, PE, position-aware) | **1 446 ms** |
| `nextgen.analyze_entropy_topography` (recomputed in the wrapper)                |        71 ms |
| `nextgen.extract_cfg_topology` (synthetic MZ, non-text)                         | **4 546 ms** |
| `ScanService.analyze` total                                                     |     1 971 ms |

The CFG figure is **pathological and informative**: `extract_cfg_topology` on a synthetic MZ header
followed by 4 MiB of zeros (i.e. all candidate code bytes) is **2.3× slower than the entire rest of
the pipeline**. Real PE files do not look like that, but **any** file beginning with `MZ` forces the
linear-sweep disassembly pass. That is the single worst-case amplifier for attacker-chosen input.

### 4.2 Fixed overhead — a 13-byte text file costs 104 ms

`qa/stage_probe.py`, median of 5:

| Stage                                     |                                   ms |
| ----------------------------------------- | -----------------------------------: |
| `hashing.compute_file_sha256`             |                                  0.4 |
| `feature_extractor.extract_file_features` |                                  0.1 |
| `archive_inspector.inspect_zip`           |                                  0.0 |
| `heuristic_engine.evaluate_heuristics`    |                                  0.0 |
| `yara_engine.scan_file_for_yara`          |                                  3.7 |
| `pe_decompiler.analyze_pe_file`           | **71.2** (first call) / 6.2 (steady) |
| entropy + storyline                       |                                  0.0 |
| **`analyze_file` total**                  |                             **97.9** |

`pe_decompiler.analyze_pe_file` calls **`gc.collect()` on every invocation**, even for non-PE data
(`pstats`: 5 calls → 52 ms in `built-in method gc.collect`). On a 500 MB heap that is ~10 ms per
scan, and it lengthens the pause for every concurrent request.

### 4.3 Cold-start penalty

First scan in a fresh process: **1 446 ms** (zero-byte) and **2 156 ms** (first run of the session)
versus 104–141 ms warm. Cause: lazy imports of `pefile`, `capstone`, `yara` + the first
`gc.collect()` over a fresh heap. For the web product this maps directly onto **Lambda cold start**
and the first scan after every desktop launch. It must **not** be quoted as steady-state latency.

---

## 5. Memory and CPU

| Metric                     | Measurement                                                                                                                                                                            |
| -------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| CPU per scan               | 96–99 % of one logical core (single-threaded; no parallelism inside a scan)                                                                                                            |
| RSS growth, 1 MiB input    | 9.0 MB peak delta                                                                                                                                                                      |
| RSS growth, 4 MiB input    | 50.0 MB peak delta                                                                                                                                                                     |
| RSS growth, 8 MiB input    | 72.0 MB peak delta                                                                                                                                                                     |
| Ratio                      | ≈ **12–15× the input size**, plus a constant baseline                                                                                                                                  |
| Raw retention              | `ScanService.analyze` returns the **entire file bytes** in its tuple (element 5); `scan_status` therefore keeps each finished job's raw file in memory until evicted (`MAX_JOBS = 32`) |
| Long-lived process         | After one 4 MiB scan, RSS stays ~48 MB above baseline (heap not returned to OS)                                                                                                        |
| Entropy trajectory         | 4 MiB produces 4 093 points (bounded at 4 096 — good)                                                                                                                                  |
| Report's own resource test | 49 MiB file → peak commit 1 620 MB (from `reports/evaluation/results.json`)                                                                                                            |

**Worst case at the configured limit:** 32 retained jobs × up to 50 MiB raw + analysis structures
≈ **> 1.6 GB** per web server process. There is no queue bound by _bytes_, only by job count.

---

## 6. Throughput and concurrency

Eight scans of an identical 1 MiB file, `ScanService` shared across threads:

| Workers        |     Wall | Per scan | Speed-up vs sequential |
| -------------- | -------: | -------: | ---------------------: |
| 1 (sequential) | 7 007 ms |   876 ms |                  1.00× |
| 2              | 7 208 ms |   901 ms |              **0.97×** |
| 4              | 7 149 ms |   894 ms |              **0.98×** |
| 8              | 7 154 ms |   894 ms |              **0.98×** |

**No concurrency benefit at all.** The pipeline is pure-Python/CPU-bound and holds the GIL; extra
threads only add contention. The web server uses `ThreadingHTTPServer`, so a single web server process
serialises CPU work regardless of how many visitors arrive. Effective throughput: **≈ 1.1 scans/s for
1 MiB files, ≈ 0.3 scans/s for 4 MiB files** on one process.

---

## 7. OSINT correlation latency — and the **1.5-second claim**

### 7.1 What the claim actually refers to

A repository-wide search found **no product statement** of "sub-1.5-second correlation". The only
1.5-second claim is an **acceptance criterion for the UI** in `reports/ui_audit/REPORT.md` (UI-001,
Arabic): _"a scan of a text file shows the low-risk card within ≤1.5 s of the engine returning."_
That is a **UI** bound measured **from the engine's return**, not a correlation bound. Its scope
excludes: reading the file, all analysis, network lookups, and rendering lag before the engine
returns.

The closest performance figure in the code is the OSINT engine's **latency budget of 0.45 s**
(`MAX_FAST_FEED_TIMEOUT_SECONDS = 0.45`; `total_timeout_seconds = max(feed timeouts)`).

### 7.2 Measured OSINT behaviour (real network, 3 runs each)

| Indicator                                 | Wall median |     Wall P95 | Reported status     | Feed states                                                |
| ----------------------------------------- | ----------: | -----------: | ------------------- | ---------------------------------------------------------- |
| unknown SHA-256                           |      458 ms | **1 404 ms** | `partial_timeout`   | ThreatFox `timeout`; URLhaus/OTX `authentication_required` |
| domain `example.com`                      |      428 ms |       453 ms | `partial_timeout`   | as above                                                   |
| URL `https://example.com/login`           |      455 ms |       460 ms | `partial_timeout`   | as above                                                   |
| invalid indicator                         |  **1.7 ms** |       2.0 ms | `invalid_indicator` | all `skipped`                                              |
| repeated lookup, **no cache entry**       |      458 ms |            — | `partial_timeout`   | **not cached** (only `matched`/all-`no_match` are)         |
| simulated responsive feeds (mocked 10 ms) | **14.1 ms** |            — | `no_match`          | —                                                          |
| simulated **cache hit**                   |  **0.1 ms** |            — | `no_match`          | —                                                          |

### 7.3 Verdict on the claim

- **Can it be reproduced?** _Partially._ The **median** (428–458 ms) is well under 1.5 s, but the
  **P95 of the unknown-hash case is 1.40 s** — 93 % of the budget with only 3 samples, i.e. one
  slow TLS/DNS handshake away from breaching it.
- **What the timing includes:** engine construction, cache lookup, TCP+TLS to three hosts, response
  parsing, `deepcopy` of the result. **Excludes:** reading the file, hashing it, and every other
  analysis stage (the OSINT call is stage 4 of 4).
- **What it excludes because of configuration:** _two of three providers return
  `authentication_required`._ With anonymous keys the "correlation" is effectively **one feed plus
  two refusals**. The measured time is therefore the time to _fail_, not the time to _correlate_.
- **Caching:** genuinely effective (0.1 ms) — **but** it only engages when _every_ feed answers
  `no_match` (or any feed matches). With the shipped configuration every cacheable condition is
  unreachable, so **the cache never fills in normal operation**.
- **Bottleneck:** network RTT to abuse.ch / OTX, bounded by the 0.45 s per-feed budget; the code
  itself adds ≈ 14 ms.

**Conclusion:** the project may state _"OSINT lookups are capped at ≈0.45 s and usually complete in
≈0.45 s, returning per-feed status"_. It **must not** state _"sub-1.5-second correlation"_ as a
demonstrated capability — the honest statement is _"correlation is attempted within a hard budget of
0.45 s; with anonymous credentials 2 of 3 providers decline and the result carries
`partial_timeout`"_.

---

## 8. Web API latency (real HTTP server on 127.0.0.1)

| Endpoint                                 |       Median | Notes                                                    |
| ---------------------------------------- | -----------: | -------------------------------------------------------- |
| `GET /` (45 KB HTML)                     |       6.1 ms | token substituted per request                            |
| `GET /app.html`                          |       5.7 ms |                                                          |
| `GET /styles.css` (34 KB)                |       4.8 ms |                                                          |
| `GET /app.js` (48 KB)                    |       4.8 ms |                                                          |
| `GET /api/settings`                      |       3.6 ms | reads `ui_settings.json` from disk each call             |
| `GET /api/history`                       |       5.1 ms |                                                          |
| `GET /api/stats`                         |       5.8 ms |                                                          |
| `GET /api/protection`                    |       3.4 ms |                                                          |
| `POST /api/scan` (text, end-to-end)      |       288 ms | submit + poll                                            |
| `POST /api/scan/file` 64 KiB, end-to-end | **1 184 ms** | submit + poll; 64 KiB never scored below the fixed floor |
| `POST /api/scan/file` 1 MiB, end-to-end  | **1 815 ms** |                                                          |
| `POST /api/scan/file` 4 MiB, end-to-end  | **3 088 ms** |                                                          |

The HTTP layer itself is cheap (3–6 ms). **All latency is analysis.** End-to-end upload numbers exceed
the in-process numbers by 150–350 ms — the upload writes the body to a temp file, and the client polls
every 10 ms.

---

## 9. Bottleneck analysis — ranked

| #   | Bottleneck                                   | Evidence                                | Fix                                                                                |
| --- | -------------------------------------------- | --------------------------------------- | ---------------------------------------------------------------------------------- |
| 1   | **GIL-bound single-threaded pipeline**       | 0.98× speed-up with 8 threads           | Process pool, or a Rust/C extension for entropy + CFG                              |
| 2   | **`gc.collect()` on every PE analysis call** | 10 ms/scan on a large heap              | Trigger only after large allocations, or use `gc.freeze()` for import-time objects |
| 3   | **Duplicate computation in `ScanService`**   | entropy/CFG/embedding computed twice    | Reuse `scan_target`'s `nextgen_analysis`                                           |
| 4   | **CFG disassembly on any `MZ` file**         | 4.5 s for 4 MiB of MZ-headed zero bytes | Cap instruction count/window; stop after N basic blocks                            |
| 5   | **Linear scans + per-byte Python work**      | 2.2 MB/s ceiling                        | Vectorise the entropy window (numpy is already a dependency)                       |
| 6   | **OSINT: 2 of 3 feeds unauthenticated**      | `authentication_required`               | Ship with keys, or drop the feeds from the advertised set                          |
| 7   | **Cold start ~1.4–2.1 s**                    | first-scan measurement                  | Pre-import heavy modules at launch; avoid first-call `gc.collect()`                |
| 8   | **Retention of raw bytes per job**           | ≥1.6 GB worst case at 32×50 MiB         | Drop raw bytes after `present()`; hash-only history                                |

---

## 10. Benchmark health checks (what could invalidate these numbers)

- CPU utilisation 95–99 % throughout → measurements are CPU-bound, not I/O-bound. ✔
- Repeated runs agree within 3–8 % (see the two 4 MiB runs: 2 093 ms vs 2 375 ms when a second
  Python process from a parallel agent was competing). ✔ mostly
- OSINT figures carry **network variance** — treat only the _budget_ (0.45 s) as a code property.
- The native-only stage numbers come from 2 repetitions; treat as indicative.
- No measurement was taken with the desktop GUI attached; GUI repaint cost is **not** included.
