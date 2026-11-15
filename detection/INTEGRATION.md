# Integrating `detection/` into the CyberScan website

Audience: the engineer wiring the website's HTTP routes (`web_v/server.py`) to this package.

## 1. Where things are (verified 2026-11-10)

| Location | What it is | Status |
|---|---|---|
| `Desktop/dist` | Website repository, `origin = github.com/mhh1430hacker/CyberScan`. `web_v/server.py` (stdlib `ThreadingHTTPServer`), `web_v/static/` (frontend), `web_v/aws/` (Lambda build). | **Has the owner's uncommitted work** (`web_v/server.py`, `assistant.py`, …). Not modified by the agents. |
| `Documents/final/CyberScan-web` | Separate clone made on 2026-11-10 for agent work. Guardian is integrating there. | Uncommitted Guardian changes; its commit hashes differ from `Desktop/dist` (e.g. `f84b920` vs `5f1deae` for the same commit message). |
| `Desktop/cyberscan-lambda.zip` | Built deployment package (`lambda_function.handler` → `web_v/server.py` in public mode). | Build output only; never edit. |
| `Documents/final/CyberScan` | Desktop app + shared engine; **source of truth for `detection/`**. | 204 tests pass. |

Nothing has been deployed. Reconcile the two website checkouts before anything is pushed.

## 2. Install

`detection/` is a plain package: copy the directory into the website repository root, next to
`core/` and `config.py`. Check that the copy is identical with `diff -r`.

| Dependency | Needed for | If missing |
|---|---|---|
| Python ≥ 3.10, standard library | everything | — |
| `pefile` (already a website requirement) | PE structure / capability analysis | PE analyzer reports `dependency_missing` |
| `Pillow` + `zxing-cpp`, and Guardian's `core/qr_scanner.py` | QR decoding in images | `qr_codes.status = "decoder_unavailable"` |

**Host functions used** (all calls go through `detection/host.py`, which adapts to both checkouts):

| Host symbol | Use | Required? |
|---|---|---|
| `core.entropy.shannon_entropy(bytes)` | section entropy | yes (present in both hosts) |
| `core.heuristic_engine.evaluate_heuristics` | rules on scripts found inside archives | optional; both signatures supported |
| `core.file_analyzer.analyze_file(path, settings)` | `analyze_upload` only | required for `analyze_upload` |
| `core.scanner.scan_target(value, is_file=False, settings=…)` | `analyze_text_json` only | required for `analyze_text_json` |
| `config.resolve_settings` or `config.DEFAULT_SETTINGS` | `analyze_upload` size limit | optional |

`ScanService().describe()["host"]` reports what the running host actually provides. Expose it on a status endpoint.

## 3. API contract

### Pure functions (`detection.engine`)

| Function | Input | Output |
|---|---|---|
| `inspect_content(data, file_name, total_size=None, path=None)` | file bytes (≤ 32 MB read) | dict; `indicators` are dataclasses, so use `content_summary()` for JSON |
| `analyze_upload(data, file_name, settings=None)` | raw upload bytes | JSON dict: host `ScanResult` fields **+ `content_analysis` + `detection_summary`**. Raises `ValueError` over the host's `maximum_file_size`. |
| `analyze_text_json(value, settings=None)` | URL / message / hash | JSON dict: host fields **+ `content_analysis` + `detection_summary`** |
| `content_summary(report)` | `inspect_content` output | JSON shape of `content_analysis` |

On a host whose analyzer predates `detection/` (the website), `analyze_upload` and `analyze_text_json`
run content inspection themselves. The two required functions therefore mean the same thing on every host.

### `detection_summary` (what the UI should show)

```json
{"classification": "SUSPICIOUS", "needs_attention": true,
 "host_classification": "NO_INDICATORS_OBSERVED", "content_classification": "SUSPICIOUS",
 "content_score": 86, "evidence_agreement": "single-source", "privacy_exposure": "none"}
```

Rule: content inspection only ever *raises* concern. If it says `SUSPICIOUS`, the summary is
`SUSPICIOUS`; otherwise the host's own verdict stands. Show `content_analysis.findings[*].explanation`
as the reasons. `privacy_exposure` is separate from the threat verdict; secret values are always redacted.

### Request wrapper (`detection.service.ScanService`): use this from routes

```python
from detection.service import ScanService, ScanLimits
svc = ScanService(ScanLimits(max_bytes=..., timeout_seconds=..., max_concurrency=..., queue_timeout_seconds=...),
                  isolation="auto")          # "process" | "thread" | "auto"
envelope = svc.inspect_upload(raw, name)    # fast path: content inspection only
envelope = svc.analyze_upload(raw, name)    # full: host analyzer + content inspection
envelope = svc.analyze_text(value)
status = ScanService.http_status(envelope)  # 200 / 400 / 413 / 500 / 503 / 504
```

Envelope (always JSON-serialisable; exceptions never escape):

```json
{"status": "ok|rejected|busy|timeout|error", "result": {...}|null,
 "error": {"code": "empty_input|too_large|busy|timeout|analysis_failed", "message": "..."}|null,
 "elapsed_ms": 412, "engine": {"version": "2026.11.10", "isolation": "thread"}}
```

| Requirement | How it is handled |
|---|---|
| Raw upload bytes | `bytes`/`bytearray`/`memoryview`; nothing else accepted |
| File size limits | `max_bytes` checked before parsing → `413`; container reads capped at 32 MB; per-member and total archive read caps |
| Supported formats | `detection.service.SUPPORTED_FORMATS`; type is sniffed from content, never from the name |
| JSON serialisation | every `result` passes `json.dumps` (tested) |
| Timeouts | `process`: child killed at the limit (hard). `thread`: returns `504` on time; the slot stays busy until the work really ends |
| Processing errors | `error` envelope (`500`) with exception type and message; analyzer bugs inside `inspect_content` become `analyzer_errors` |
| Concurrency | `max_concurrency` slots; extra requests wait `queue_timeout_seconds`, then `503` |
| Safe file handling | client names reduced by `safe_file_name` (no paths, control chars, reserved names); bytes never executed; the temp copy for path-based engines is private (`0700`) and removed in `finally`; archives are never extracted |

`default_service()` builds one process-wide service from `CYBERSCAN_MAX_BYTES`, `CYBERSCAN_TIMEOUT`,
`CYBERSCAN_CONCURRENCY`, `CYBERSCAN_QUEUE_TIMEOUT` and `CYBERSCAN_ISOLATION`.

## 4. Settings for the website

| Deployment | Suggested settings | Why |
|---|---|---|
| AWS Lambda (`lambda_function.py`, `PUBLIC=1`) | `isolation="thread"` (auto-selected when `AWS_LAMBDA_FUNCTION_NAME` is set), `max_bytes = PUBLIC_MAX_UPLOAD` (4 MB), `timeout_seconds = PUBLIC_TIMEOUT - 10` (40 s), `max_concurrency = 1` | Conservative default, **not verified on Lambda**. Lambda has no `/dev/shm`, so `multiprocessing` pools, queues and locks fail; a single `spawn` `Process` + `Pipe` (what `ScanService` and the PDF/QR workers use) may work, but this was never tested there. Each spawned child also re-imports the engine within the function's memory limit. Verify in a Lambda test before choosing `process`. One request per instance. Leave time to serialise the response. |
| Local server (`ThreadingHTTPServer`) | `isolation="process"`, `max_concurrency = 2–4`, `timeout_seconds = 30` | Hard kill on timeout; parser crashes stay in the child. |

**`spawn` caveat.** Process isolation re-imports the program's main module in the child. The entry script
must guard its start-up code with `if __name__ == "__main__":`; without it the child re-runs the
server. Checked 2026-11-10: the website's local entry point `web_v/run.py` has the guard (line 60), so
`process` isolation is safe there. Lambda uses `thread` isolation.

## 5. Route mapping (suggested; Guardian owns the website checkout)

| Existing route | Call | Response |
|---|---|---|
| `POST /api/scan/file` | add `envelope = svc.analyze_upload(raw, name)` result's `content_analysis` + `detection_summary` to the scan JSON | UI verdict = `detection_summary.classification` |
| `POST /api/tools/office`, `/api/tools/pdf`, `/api/tools/qr` | `svc.inspect_upload(raw, safe_name)` | `ScanService.http_status(envelope)`, body = envelope |
| `POST /api/scan` (link/text) | `svc.analyze_text(value)` | same |
| status / health | `svc.describe()` | formats, limits, host capabilities |

Sketch inside `make_handler` (uses the server's existing helpers; adapt names):

```python
from detection.service import default_service

def office_tool(self, query):
    raw = self._raw_body(PUBLIC_MAX_UPLOAD if PUBLIC else 32 * 1024 * 1024)
    envelope = default_service().inspect_upload(raw, unquote(self.headers.get("X-Filename", "document.bin")))
    self._json(ScanService.http_status(envelope), envelope)
```

## 6. Integration tests

- `tests/test_detection_service.py`: envelopes, admission, size limits, thread and process timeouts,
  `503` under load, 12 concurrent requests, Lambda auto-isolation, error envelopes, and host compatibility
  (website-style `evaluate_heuristics` without `scan_content`, `config` without `resolve_settings`, a host
  analyzer without content inspection).
- `tests/test_detection_engine.py`: upload API JSON, temp-dir clean-up, safe names, mutation fuzzing of every container parser.
- Against the real website `core/` (2026-11-10): `detection/` ran on a scratch copy of `CyberScan-web/core`
  and `config.py`. Every fixture classified correctly with no analyzer errors, `analyze_upload` returned
  `SUSPICIOUS` for a macro dropper that the website's own analyzer calls `NO_INDICATORS_OBSERVED`, and both
  isolation modes worked.

Route-level tests (HTTP through `server.make_handler`) belong in the website repository once the routes are wired.
