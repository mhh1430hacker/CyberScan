# Collaboration changelog (append-only; one entry per change set)

## 2026-11-10 — SENTINEL
- Created `collaboration/` with DISCUSSION, TASK_BOARD, DECISIONS and this file.

## 2026-11-10 — GUARDIAN
- Added a bounded, read-only integrity verifier for PNG and ZIP plus explicitly incomplete boundary checks for PDF/JPEG/GIF.
- Integrated digest-consistency and structural-check details into file scan results, desktop output, and text/JSON reports.
- Added harmless fixtures covering valid/corrupted/truncated inputs, archive limits, unsupported formats, and source preservation.

## 2026-11-10 — GUARDIAN
- Hardened integrity verification against parser/decompressor exceptions and separated appended bytes from structural damage.
- Added `core.qr_scanner.analyze_qr_image` using zxing-cpp and Pillow with bounded input/pixel sizes and local URL risk assessment.
- Added a public-site inventory and feature-gap report; production UI/API wiring remains blocked on the website source and Sentinel's agreed web-engine hook.

## 2026-11-10 — SENTINEL
- New `detection/` package: PDF, OOXML, OLE/VBA, RTF, .msg, ZIP, APK, browser-extension, PE/ELF analyzers; offline
  URL/phishing intelligence; email/SMS fraud analysis; script tradecraft rules; redacted secret discovery.
- Web entry points `detection.engine.analyze_upload` / `analyze_text_json`; QR adapter over `core.qr_scanner`.
- False-positive fixes: capability-based PE imports, YARA injection rule, entropy on compressed formats, IEX weight.
- Noisy-OR fusion with correlated-evidence groups; `evidence_agreement` in results.
- Tests 41 → 181. Verified Guardian's verifier fix with 3,000-mutation fuzzing (0 uncaught).

## 2026-11-10 — SENTINEL (Phase 3)
- Located the website source: `Desktop/dist` (GitHub repo, owner's uncommitted work: untouched), the agent clone
  `CyberScan-web` (Guardian integrating; reviewed read-only), and the build `Desktop/cyberscan-lambda.zip`.
- Fixed two engine bugs that only show on the website's `core`: archive analysis dropped (TypeError/KeyError), and
  `analyze_upload`/`analyze_text_json` missing content inspection (+ ImportError on `config.resolve_settings`).
- New `detection/host.py` (host adapter), `detection/service.py` (limits, timeouts, concurrency, error envelopes),
  `detection/INTEGRATION.md` (contracts, dependencies, Lambda notes). Tests 181 → 204.

## 2026-11-10 — GUARDIAN (five-component migration)
- Separated the project into Web, Desktop, Mobile, AI and Tools; moved the frozen detection source to `Tools/detection/`
  and retained Web/Desktop import shims.
- Added the shared static-discovery, hash-approval and execution contract; exposed it through the Mobile worker bridge.
- Moved the Android source/build tree to `Mobile/`, retained Web `/m/` compatibility assets and legacy forwarding scripts,
  and updated root launch/test/dependency entry points.
- Verified Desktop 204, Tools 8, Mobile 2, combined 214, and Web 637 tests passed; one Web test was skipped.
- Android asset/Capacitor sync passed. Rebuilding the debug APK requires Java 21, absent from this environment.
