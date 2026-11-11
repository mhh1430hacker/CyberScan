# Changelog

## Detection intelligence (SENTINEL, 2026-11-10)

### New capabilities (`detection/` package)
- Content-sniffed static analyzers for PDF (with bounded stream inflation), OOXML, legacy OLE/VBA (MS-CFB reader +
  MS-OVBA decompression), Outlook `.msg`, RTF, ZIP archives, APK (binary manifest parser), browser extensions, PE and ELF.
- Offline URL/phishing intelligence: typosquatting, homoglyph and IDN homograph detection, brand impersonation,
  obfuscated IPs, user-info tricks, redirect-parameter chains, risky schemes and downloads.
- Email/SMS fraud analysis (English + common Arabic phrases) with header spoofing and SPF/DKIM/DMARC checks.
- Script/LOLBin tradecraft rules; secret and payment-card discovery reported as a separate, redacted privacy section.
- QR-code images are analyzed through Guardian's `core.qr_scanner` (quishing).
- `detection.engine.analyze_upload(bytes, name)` and `analyze_text_json(value)`: JSON-serialisable entry points for a web
  backend. `ScanResult` gains `content_analysis`; the JSON export includes it.

### False-positive reductions (measured on local System32 binaries and benign documents)
- "Suspicious PE imports" fired when a binary imported *any* of IsDebuggerPresent/OpenProcess/CreateProcessW/VirtualAlloc,
  which the MSVC runtime imports. Replaced by capability combinations, skipped for API-provider DLLs (kernel32 etc.).
  `pe_analysis.suspicious_imports` now lists only APIs that complete a capability, so ATT&CK mapping no longer reports
  T1622 for ordinary binaries.
- YARA `SuspiciousProcessInjection` now requires remote allocate + write + execute APIs.
- "High entropy" is no longer evidence for compressed-by-design formats (ZIP, PDF, images, gzip, 7z, …).
- `Invoke-Expression`/`IEX` alone weighs 25 (was 35); with a download primitive it still reaches SUSPICIOUS.

### Scoring
- File evidence is fused with noisy-OR instead of a capped sum; correlated findings (same fact seen by two engines) count once.
- Results report `evidence_agreement` across independent categories.

### Other
- `core.entropy.shannon_entropy` counts bytes with `collections.Counter`, which removed about 45% of the per-binary scan time.
- Test suite: 41 → 181 tests (synthetic, inert fixtures; mutation fuzzing of every container parser).

## Review pass

### Security
- **Removed hard-coded API keys** (abuse.ch and AlienVault OTX) from `core/global_intelligence.py`. Keys now come from
  environment variables only. **Revoke and re-issue the old keys**: they were stored in plain text in the archive.
- Model files are verified against a SHA-256 recorded at training time before `joblib` (pickle) loads them.
- Online IOC lookups are **opt-in** (new `osint_lookup` setting, default off). Free text is no longer hashed and sent to feeds.
- The unverified legacy model artifact (`anomaly_isolation_forest.joblib`, already rejected by the loader) was removed
  from the package.
- `save_report` cannot write outside the reports directory.

### Detection correctness
- File **content** is now run through the heuristic rules. Before, the SHA-256 string was passed instead, so content rules never fired.
- Heuristic patterns use word boundaries: `-exec`, `Get-Index`, and any text containing `@` no longer match.
  Duplicate rules that double-counted the same indicator were merged; encoded PowerShell still scores as SUSPICIOUS.
- URL analysis no longer counts shorteners / raw-IP / credential markers twice.
- URL and text scans now return evidence items (they returned an empty list) and MITRE mapping.
- ML anomaly score rescaled so the model's decision boundary is 50 (ordinary inliers previously showed about 40%).
- MITRE mapper: removed reverse-substring matches (e.g. "process"), fixed `IsDebuggerPresent` (T1622), added
  masquerading, packing, ingress-tool-transfer and exfiltration mappings; techniques are de-duplicated with merged evidence.
- More container signatures in the magic-byte check (docx/xlsx/pptx/jar/apk/gz/rar/7z/rtf).
- Text-like input skips x86 disassembly inside the engine (the storyline already described this but the engine never did it).

### Correctness / robustness
- Settings are honoured: `heuristic_rules`, `ml_analysis`, `entropy_analysis`, `ml_weight`, `heuristic_weight`.
- Report "SHA-256" line printed the file path; `ScanResult` now carries the real hash. JSON export includes YARA, PE,
  MITRE, features and summary.
- Downloads monitor: ignores files present at start, skips `.crdownload`/`.part`/`.tmp`, waits for a stable size,
  survives callback errors and can be restarted.
- YARA: compiled rules cached; supports yara-python 4.3+ match objects; `meta` tags parsed.
- ML detector is loaded once and cached instead of on every scan.
- GUI: bounded read for entropy/embedding (was up to 50 MB in pure Python), demo samples written under `data/`, not the current directory.
- Feature extraction decodes the buffer once instead of once per pattern.

### Project hygiene
- Removed `__pycache__`, `.pytest_cache`, the stray root `test.py`, and the committed EICAR file (generated on demand by `scripts/make_samples.py`).
- `requirements.txt` (runtime; unused `pandas` and `pytest` removed) and `requirements-dev.txt`; `pytest.ini`, `conftest.py`, `.gitignore`, `.env.example`.
- README corrected (`cd dist` did not exist; project tree now matches the code). Line endings normalised to LF.
- Tests: 21 → 41 (security, content analysis, reports, monitor). The aiohttp-dependent test no longer depends on the environment.
