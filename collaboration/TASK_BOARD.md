# Task board (append rows; update only the Status column of your own rows)

| ID | Owner | Task | Status |
|----|-------|------|--------|
| S-01 | SENTINEL | Offline URL/phishing intelligence (typosquat, homograph, brand impersonation, redirects) | Done (tests pass) |
| S-02 | SENTINEL | Document inspection: PDF, OOXML, legacy OLE/VBA, RTF | Done (tests pass) |
| S-03 | SENTINEL | Archive, APK and browser-extension static inspection | Done (tests pass) |
| S-04 | SENTINEL | Secret / credential exposure detection (redacted output) | Done (tests pass) |
| S-05 | SENTINEL | Email / SMS scam analysis | Done (tests pass) |
| S-06 | SENTINEL | PE/ELF structural checks; reduce PE-import false positives | Done (tests pass) |
| S-07 | SENTINEL | Unified evidence fusion + bytes-in/JSON-out API for web upload handlers | Done (tests pass) |
| S-08 | SENTINEL | Fix `test_feeds_without_keys_report_authentication_required` (delenv raising) | Done (tests pass) |
| G-01 | GUARDIAN | Add bounded read-only file-integrity verification and report integration | Done |
| G-02 | GUARDIAN | Implement bounded QR image decoding with offline URL assessment | Done; browser and authenticated web API integration verified |
| S-09 | SENTINEL | Integrate Guardian QR decoder into detection.engine (quishing) | Done (tests pass) |
| S-10 | SENTINEL | Validate detection against a labeled benign/malicious corpus (needs real samples) | Open |
| G-03 | GUARDIAN | Integrate Sentinel detection and file integrity/repair verification into the web platform | In progress; review requested from Sentinel |
| S-11 | SENTINEL | Phase 3: engine request wrapper (limits/timeouts/concurrency/errors), host compatibility, integration contract | Done (204 tests pass) |
| S-12 | SENTINEL | Review route-level integration in CyberScan-web after Guardian re-syncs detection/ | Pre-implementation review delivered (REVIEW_G03_INTEGRATION.md) |
| S-13 | SENTINEL | Engine freeze (ENGINE_FREEZE.md); review Guardian's Desktop/dist integration plan | Waiting on GUARDIAN plan |
| SH-0 | SHOWCASE | Stage 0: real engine numbers in hero card and story, HUD/FAB overlap, mobile hero readability | r2 patch ready for owner merge review (collaboration/patches/showcase-stage0-r2.patch); r1 superseded |
| SH-2 | SHOWCASE | Stage 2: Nex, the scripted guide | Not started: waits for Stage 0 approval |
| G-04 | GUARDIAN | Reorganize CyberScan into Web, Desktop, Mobile, AI and Tools while preserving existing behavior | Done; regression suites pass |
| G-05 | GUARDIAN | Request Sentinel review of the Tools detection-engine relocation and compatibility shims | Review requested; pending SENTINEL |
| A2-1 | AGENT 2 | Tools 051-100 (network, system, privacy, code, cloud) with tests, manifest, READMEs | Implemented; 275 tests pass; awaiting owner registry change + approval and Agent 1 contract decision |
