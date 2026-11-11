# Pre-implementation review — G-03 website integration (GUARDIAN)

Reviewer: SENTINEL · Date: 2026-11-10 · Target repo: `Desktop/dist` (canonical, per owner)

**What was reviewed.** Guardian has not posted a separate plan. The proposal is taken as Guardian's working
integration in `Documents/final/CyberScan-web`, which is meant to be ported to `Desktop/dist`:
`git diff` of `web_v/server.py` and `web_v/services.py`, `reports/web_platform_gap_report.md`, and
`tests/test_web_priority1.py`. All read-only. No files in either website checkout were modified.

**Engine reference.** Frozen `detection/`, tree digest `30c15d6a…` (freeze r2) (`collaboration/ENGINE_FREEZE.md`),
baseline 204 tests passing.

## Verdict

Approve the direction, but block the port to `Desktop/dist` until R1–R4 below are addressed. The proposal
does not yet use the current interfaces (`ScanService`, `detection_summary`), and two of its assumptions
about the engine are wrong.

## Interface check

| Interface | Expected | Current proposal | Status |
|---|---|---|---|
| `detection/` copy | identical to the freeze manifest | Code identical (re-synced). `INTEGRATION.md` differs (doc corrected after the sync). | Re-copy the doc |
| `ScanService` (limits / timeout / concurrency / envelope) | every upload and text route | **Not used.** Routes call `services.inspect_uploaded_content` → `inspect_content` directly. | **R1** |
| `detection_summary` | drives the user-facing verdict | **Not used.** `/api/scan/file` shows the website's classification, with `security_inspection` beside it. | **R2** |
| `content_summary` | one JSON shape for `content_analysis` | Custom shape in `services.py`; it includes privacy indicators in `indicators`. | R6 |
| QR contract (`codes[].kind/payload/risk`) | unchanged | unchanged | OK |

## Required before porting

**R1 — Wrap every engine call in `ScanService` (timeouts, concurrency, errors).**
`pdf_tool`, `qr_tool`, `office_tool` and the file-scan path call the engine synchronously, with no time limit
and no concurrency cap. In public mode the request must finish inside `PUBLIC_TIMEOUT = 50 s`, and one upload
already runs the legacy scan, the legacy archive report (up to 64 MiB decompression), the integrity verifier,
`inspect_content`, and up to 8 s (PDF) + 5 s (QR) of worker time. Use
`default_service().inspect_upload(raw, name)` and return `ScanService.http_status(envelope)`.

**Name collision:** `web_v/server.py` already imports `ui.scan_service.ScanService`, a different class.
Import ours by module or alias, e.g. `from detection import service as detection_service` /
`from detection.service import ScanService as DetectionService`. A bare `from detection.service import ScanService`
in `server.py` would silently replace the website's scan service.

**R2 — One verdict.** The UI verdict must be `detection_summary.classification` (or the same rule: content
SUSPICIOUS ⇒ SUSPICIOUS, else the host verdict). Today a macro dropper shows the website's
`NO_INDICATORS_OBSERVED` next to a critical finding. For `/api/scan/file`, either call
`detection.engine.analyze_upload` through `ScanService.analyze_upload`, or compute
`detection.engine.detection_summary(payload)` on the website's payload after adding `content_analysis`.

**R3 — The gap report understates the engine; avoid duplicate work.** It lists "SPF/DKIM/DMARC has no dedicated
analyzer" and "SMS-specific scam indicators unimplemented". Both exist: `detection.messages.analyze_message`
(header spoofing, Reply-To, SPF/DKIM/DMARC, SMS lures incl. Arabic, OTP-sharing requests). They are reachable
through `analyze_text_json` / `ScanService.analyze_text` and, for `.eml`/`.msg` uploads, through `inspect_content`.
Wire the text/link route to `analyze_text` instead of writing new analyzers, and correct the report.

**R4 — The public API is open; add abuse controls outside the app.** In public mode the token defaults to the
constant `"cyberscan-public"` and is embedded in the served page (`server.py:512`, `:758`). That stops other
sites from driving the API, but it is not authentication. The gap report's "token-protected" wording should
not be read as access control. Every tool route is CPU-heavy and reachable by any client. Before public
exposure: Lambda reserved concurrency, API Gateway/CloudFront throttling or WAF rate rules, and request-size
limits at the edge. `ScanService.max_concurrency` only protects a single instance.

## Should fix

- **R5 — Verify process workers on Lambda.** The PDF and QR workers (and `ScanService` `process` mode) use
  `multiprocessing` `spawn` with `Process`+`Pipe`. Lambda has no `/dev/shm`, and each spawned child re-imports
  heavy modules inside the memory limit. Nobody has tested this on Lambda. Add one Lambda smoke test (PDF + QR +
  `ScanService.inspect_upload`) before the port ships. My own docs previously stated this as a known failure;
  that was unverified and has been corrected.
- **R6 — Schema.** Use `detection.engine.content_summary(report)` for `security_inspection` /
  `security_assessment`, so all routes return one shape with privacy kept separate and redacted.
- **R7 — Double archive parsing.** Each upload runs both the legacy `archive_inspector` (caps: 1,000 entries,
  16 MiB/member, 64 MiB total) and `detection.archives` (5,000 entries, 2 MiB/member, 24 MiB total). That is
  acceptable (integrity vs threat, D-006), but budget it inside R1's timeout and state both caps in one place.
- **R8 — Office route.** It rejects by extension before sniffing (fine for UX). Since `inspect_content` returns
  `analyzer_errors` instead of raising, map non-empty `analyzer_errors` to an explicit "incomplete" status in
  the response; don't return a plain 200 that reads as a clean result.

## Tests to add in `Desktop/dist` (route level)

1. Each tool route returns `ScanService` status codes: 413 oversized, 400 empty, 504 on a forced timeout
   (`CYBERSCAN_TIMEOUT=0.001`), 503 with `CYBERSCAN_CONCURRENCY=1` and a held request.
2. `/api/scan/file` with a macro-dropper `.docm` → UI verdict field `SUSPICIOUS` (R2).
3. Text route with a spoofed e-mail and an SMS lure → `detection_summary.content_classification == "SUSPICIOUS"` (R3).
4. The website's existing scan still works and its fields are unchanged (no `ScanService` name collision).
5. A copy-integrity test: `detection/` hashes match `collaboration/ENGINE_FREEZE.md`.
6. Keep this checkout's 204-test baseline green. Engine regressions are tested here, not in the website repo.

## Engine assumptions confirmed

- `detection/` runs on the website's `core/` (verified on a scratch copy; host differences handled by `detection/host.py`).
- `web_v/run.py` has the `__main__` guard, so local `process` isolation is safe.
- Engine limits: 32 MiB deep read, archive caps above, URL ≤ 8,192 chars, text ≤ 200,000 chars (service).
  Combined with `PUBLIC_MAX_UPLOAD = 4 MiB`, public uploads never reach the engine's caps.
