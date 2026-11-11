# Decisions (append-only)

## D-001 — Detection work lives in the shared engine, not a UI
Date: 2026-11-10 · Author: SENTINEL
The assignment targets the web platform, but no web code exists in this repository. Detection
capabilities are therefore built in the UI-independent engine (`detection/`, wired into `core/`) and
exposed through `detection.engine.analyze_upload(data, file_name)`, which takes raw upload bytes and
returns a JSON-serialisable dict. A web backend can call it directly. The desktop `ui/` is not modified.

## D-002 — Evidence is fused with noisy-OR, not summed
Date: 2026-11-10 · Author: SENTINEL
Summing contributions lets many weak indicators add up to "SUSPICIOUS" (false positives). New
analyzers combine contributions as `1 - Π(1 - c/100)`: weak signals corroborate each other but
cannot saturate the score on their own.

## D-003 — Privacy findings do not raise the threat score
Date: 2026-11-10 · Author: SENTINEL
An exposed API key in a config file is a privacy/exposure risk, not evidence of malware. Secret
findings are reported in a separate `privacy` section with contribution 0, and secret values are
always redacted in output.

## D-004 — No network access during analysis
Date: 2026-11-10 · Author: SENTINEL
URL, phishing and document-link analysis is fully offline. Online reputation stays behind the
existing opt-in `osint_lookup` setting.

## D-005 — User-approved desktop integration for this task
Date: 2026-11-10 · Author: GUARDIAN
After being told that this workspace contains only the CustomTkinter desktop application and no web
platform, the user explicitly selected proceeding with the existing desktop app. Guardian may
therefore integrate this task's file-integrity report into desktop scan results and exports. This
does not establish that the workspace contains the production website.

## D-006 — Integrity verification is distinct from archive threat inspection
Date: 2026-11-10 · Author: GUARDIAN
Guardian's initial verifier owns bounded, read-only structural checks (including ZIP CRC checks);
Sentinel's S-03 archive task should own threat-oriented inspection of archive contents. This boundary
is proposed pending Sentinel confirmation because the two responsibilities meet at archive parsing.

## D-007 — Content inspection only raises concern; one summary verdict
Date: 2026-11-10 · Author: SENTINEL
Hosts use different verdict vocabularies (desktop SAFE/UNKNOWN/SUSPICIOUS, website
NO_INDICATORS_OBSERVED/REVIEW/...). `detection_summary.classification` is SUSPICIOUS when content
inspection says SUSPICIOUS, otherwise the host verdict. Both inputs are returned. The UI shows the summary.

## D-008 — `detection/` source of truth and host boundary
Date: 2026-11-10 · Author: SENTINEL
`Documents/final/CyberScan/detection/` is the source of truth; website copies are synced whole.
`detection` calls the host project (`core`, `config`) only through `detection/host.py`.

## D-009 — Engine frozen; Desktop/dist is canonical and Guardian-owned
Date: 2026-11-10 · Author: SENTINEL (recording owner instruction)
The owner designated `Desktop/dist` as the canonical website repository, with GUARDIAN responsible for reconciling and
integrating it. `detection/` is frozen at tree digest `ab133507…` (ENGINE_FREEZE.md), baseline 204 passing tests.
SENTINEL does not modify website routes, frontend files or `Desktop/dist`, and nobody commits, pushes or deploys.

## D-010 — `Tools/detection/` is the canonical frozen engine path
Date: 2026-11-10 · Author: GUARDIAN
The owner-authorized five-component migration moves the single frozen engine source to
`Tools/detection/`. This supersedes D-008's root `detection/` source path. Desktop and Web retain
only import-path compatibility shims; they do not carry engine implementations. All 14 files
match the current freeze manifest (`30c15d6a…`). No engine behavior or contents were changed.
