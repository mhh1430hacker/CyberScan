# Repair engine — Phase 1 downloads: RUNNING

**Resumed:** 2026-11-05 06:47, steps `ember sorel tools benign ember_big`, log in
`C:\CyberScanData\logs\resume_2026-11-05.txt`. The run left going overnight on 2026-11-04
had lost its line: from 21:17 every SOREL sample failed on a dropped connection or DNS
lookup and was skipped (134,436 skip events over repeated passes; 86 of 2,000 binaries on
disk). The connection here is intermittent: some hosts answer while others time out in
the same minute. `fetch.retrying` now waits and retries network drops (5 s up to 15 min,
about 50 min in all) and resumes `.part` files, so only a real server answer (404, a
hash mismatch) skips a sample. Skipped samples were never marked done; this run retries them.

**2026-11-04:** EMBER2024 small files all downloaded, SHA-256-verified and vectorised;
SOREL `meta.db` verified, 4,041 rows selected, then deleted. Free on C: on 2026-11-05: 36 GB.

**Paused:** 2026-11-01 21:03 (by request, to move on to the next phases).
**Data folder:** `C:\CyberScanData` (outside the repo; `samples\` denies execute to Everyone).
**Free on C: at pause:** 27 GB. **Measured line speed:** ~0.16–0.6 MB/s total
(the connection itself; parallel connections do not help). The approved
selection (~17 GB) needs roughly 8–15 hours.

## Resume

Everything resumes from where it stopped (partial `.part` files continue
with HTTP ranges; finished items are skipped):

```powershell
Start-Process powershell -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','repair_engine\data\resume.ps1' -WindowStyle Hidden
```

`resume.ps1` restarts the run whenever it stops early, and runs on its own,
independent of any editor or chat session. On 2026-11-05 and 2026-11-06 the run died
each time the laptop went to sleep on battery (System log, Kernel-Power 42/187),
so keep the charger in and the lid open while it runs; on AC the machine never
idle-sleeps, on battery it does after 1 hour. A single direct run:

```bash
.venv/Scripts/python.exe -u -m repair_engine.data.phase1 tools ember sorel benign
```

Then, once ClamAV signatures are in place and `clamd` is running (see
"Verification setup"):

```bash
.venv/Scripts/python.exe -u -m repair_engine.data.phase1 verify ember_big manifest
```

## Status by item

Tags: `[DONE]` finished and verified · `[PARTIAL]` part file on disk ·
`[PENDING]` not started · `[MANUAL]` needs you · `[EXCLUDED]` deliberately not fetched.

| Tag | Item | Size | Verified against | State at pause |
|---|---|---|---|---|
| `[PARTIAL]` | ClamAV `clamav-1.5.4.win.x64.zip` (GitHub Cisco-Talos release) | 225.8 MB | release SHA-256 `0d9e0228…c395` | 211.8 / 225.8 MB in `downloads\` |
| `[PENDING]` | YARA Forge `yara-forge-rules-core.zip` (release 20261101) | 1.7 MB | release SHA-256 `c6d6915f…783b` | — |
| `[PENDING]` | ClamAV signatures via `freshclam` | ~300 MB | ClamAV's own signed CVDs | — |
| `[DONE]` | EMBER2024 `Win64_test.zip` (HF `joyce8/EMBER2024`) | 1.18 GB | HF LFS SHA-256 `52a5a05c…` | verified, 240,000 rows vectorised |
| `[DONE]` | EMBER2024 `PDF_train.zip`, `PDF_test.zip`, `ELF_train.zip`, `ELF_test.zip`, `challenge.zip` | 0.27 GB | HF LFS SHA-256 | verified and vectorised |
| `[PENDING]` | EMBER2024 `Win64_train.zip` (vectorise 250k, then delete) | 5.85 GB | HF LFS SHA-256 `7b050100…` | — (step `ember_big`) |
| `[DONE]` | SOREL-20M `processed-data/meta.db` (keep 2,000 rows, then delete) | 3.79 GB | S3 multipart ETag `f1a8b94f…-452` | verified; 4,041 rows kept; db deleted |
| `[PARTIAL]` | SOREL-20M 2,000 disarmed binaries (stay zlib-compressed) | ~2.2 GB | per-object S3 ETag (MD5) | 86 / 2,000; downloading |
| `[PENDING]` | Govdocs1 `zipfiles/000.zip`, `001.zip`, `002.zip` | 3 × 0.49 GB | published MD5 list | — |
| `[PENDING]` | NapierOne small: DLL DOC DOCX ELF XLS XLSX HTML | ~1.2 GB | published per-archive SHA-256 | — |
| `[PENDING]` | NapierOne tiny: EXE PDF PPT PPTX GIF | ~0.9 GB | published per-archive SHA-256 | — |
| `[PENDING]` | Assemblage_PE: first 2,000 PEs streamed from `binaries.tar.xz` | ~1 GB | ClamAV + YARA + parse only (archive hash needs the full 33.8 GB) | — |
| `[MANUAL]` | FFT-75 (IEEE DataPort, DOI 10.21227/kfxw-8084) | 0.83–3.2 GB (512-byte scenarios) | — | needs your IEEE login; put the archive in `C:\CyberScanData\downloads\` |
| `[EXCLUDED]` | NapierOne `EXTRA` (ransomware-encrypted outputs), `*-ENCRYPTED`, `*-PASSWORD`, `*-NOMAGIC` | — | — | not clean benign data |
| `[EXCLUDED]` | SOREL feature LMDB (72 GB), PE metadata LMDB (480 GB), binaries beyond 2,000 | — | — | do not fit |
| `[EXCLUDED]` | EMBER2024 Win32 train/test (14.9 GB) | — | — | do not fit with the rest |

## Verification setup (once, before the `verify` step)

After the `tools` step, `C:\CyberScanData\tools\clamav\clamav-1.5.4.win.x64\`
holds `freshclam.conf` and `clamd.conf` (written by the tools step). Run:

```powershell
cd C:\CyberScanData\tools\clamav\clamav-1.5.4.win.x64
.\freshclam.exe --config-file=freshclam.conf
.\clamd.exe --config-file=clamd.conf
```

`clamd` listens on 127.0.0.1:3310 only. The engine sends file bytes over
that socket; no sample path is passed to any program.

## Decisions already made (2026-11-01)

- Recommended set; 2,000 SOREL binaries; portable ClamAV; Assemblage slice of 2,000.
- Budget in `repair_engine/config/data.yaml`: data folder ≤ 18 GB, ≥ 6 GB always free.
- Splits: EMBER2024 official (temporal); SOREL by its own first-seen
  boundaries; benign sets by hash (80/10/10), since they carry no trustworthy dates.
