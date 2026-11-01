# Repair engine — Phase 1 downloads: PAUSED

**Paused:** 2026-11-01 21:03 (by request, to move on to the next phases).
**Data folder:** `C:\CyberScanData` (outside the repo; `samples\` denies execute to Everyone).
**Free on C: at pause:** 27 GB. **Measured line speed:** ~0.16–0.6 MB/s total
(the connection itself; parallel connections do not help). The approved
selection (~17 GB) needs roughly 8–15 hours.

## Resume

Everything resumes from where it stopped (partial `.part` files continue
with HTTP ranges; finished items are skipped):

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
| `[PARTIAL]` | EMBER2024 `Win64_test.zip` (HF `joyce8/EMBER2024`) | 1.18 GB | HF LFS SHA-256 `52a5a05c…` | 43.0 MB / 1.18 GB |
| `[PENDING]` | EMBER2024 `PDF_train.zip`, `PDF_test.zip`, `ELF_train.zip`, `ELF_test.zip`, `challenge.zip` | 0.27 GB | HF LFS SHA-256 | — |
| `[PENDING]` | EMBER2024 `Win64_train.zip` (vectorise 250k, then delete) | 5.85 GB | HF LFS SHA-256 `7b050100…` | — (step `ember_big`) |
| `[PENDING]` | SOREL-20M `processed-data/meta.db` (keep 2,000 rows, then delete) | 3.79 GB | S3 multipart ETag `f1a8b94f…-452` | — |
| `[PENDING]` | SOREL-20M 2,000 disarmed binaries (stay zlib-compressed) | ~2.2 GB | per-object S3 ETag (MD5) | — |
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
