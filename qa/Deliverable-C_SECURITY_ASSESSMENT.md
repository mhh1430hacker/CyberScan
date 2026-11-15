# Deliverable C — Security Assessment

## CyberScan NextGen · defensive testing of the platform itself

| Field          | Value                                                                                                                                              |
| -------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| Date           | 2026-11-09                                                                                                                                         |
| Revision       | `17939e5`                                                                                                                                          |
| Scope          | Local application only (`core/`, `ui/`, `web_v/`), localhost HTTP server, local fixtures                                                           |
| Out of scope   | Production AWS deployment, CloudFront, the Android APK, third-party services                                                                       |
| Rules followed | Synthetic inputs only · **no live malware** · no destructive tests · no external scanning · findings documented, not exploited beyond verification |

---

## 1. Summary

The platform's **defensive posture is materially better than its documentation suggests**, and far
better than typical student prototypes:

- API is token-gated; `Host` and `Origin` are validated; requests are size-capped; JSON bodies are
  never `eval`'d; settings updates are allow-listed **and type-checked**; static file serving is
  path-confined; uploads are filename-sanitised and written to a per-request temp directory.
- The classifier is loaded from **validated JSON**, with **no `joblib.load`/pickle** anywhere in `ml/`.
- Quarantine is **dry-run by default**, requires `authorized=True` _and_ `dry_run=False` to remove a
  source, rejects symbolic links, rejects keys that are not 16/24/32 bytes, and refuses to overwrite
  on restore.
- `secrets.compare_digest` is used for token comparison.

**Three real weaknesses** were found, all of **Low/Medium** severity, none remotely exploitable on
their own, plus two release-hygiene issues:

| ID     | Severity | Finding                                                                                                                                                  |
| ------ | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| SEC-01 | Medium   | Public mode uses a **static, publicly known API token** (`"cyberscan-public"`), which is embedded in the page HTML.                                      |
| SEC-02 | Low      | Unhandled exceptions violate HTTP/1.1 framing: **no response is sent** and the connection is reset on some error paths.                                  |
| SEC-03 | Low      | **No response truncation** on very long feed/exception text; error strings include the exception **type and message**, which can carry filesystem paths. |
| SEC-04 | Low      | **Resource exhaustion path**: 32 concurrent scans × 50 MiB are accepted with no byte-based queue limit (see Deliverable B §5).                           |
| SEC-05 | Info     | Dependency advisories exist only in **tooling** packages (`pip`, `signify`), not the project's runtime set.                                              |
| SEC-06 | Info     | No per-request logging whatsoever (`log_message` is silenced) and no audit trail of scans.                                                               |

---

## 2. Test matrix and results

All probes run against `create_server(0)` — a local server on a random port. Raw-socket probes:
`qa/security_probe.py`; structured probes: `qa/qa_harness.py security`. Raw output:
`qa/artifacts/security_results.json`, `qa/artifacts/security_raw_results.json`.

### 2.1 Input validation

| ID    | Probe                                                                                                          | Expected                      | Observed                                                | Result                |
| ----- | -------------------------------------------------------------------------------------------------------------- | ----------------------------- | ------------------------------------------------------- | --------------------- |
| S-02  | `GET /../../config.py` (and 4 variants: encoded, backslash, nested)                                            | no source leak                | 404, no `ROOT_DIR`/`MAX_FILE_SIZE` in body              | **PASS**              |
| S-03  | `GET /api/history` **without** token                                                                           | 401                           | 401                                                     | **PASS**              |
| S-04  | `GET /api/settings` with `Host: evil.example.com`                                                              | 403                           | 403                                                     | **PASS**              |
| S-04b | Static page with foreign `Host` (DNS-rebinding)                                                                | 403                           | 403                                                     | **PASS**              |
| S-05  | `POST /api/scan` with `Origin: http://evil.example.com`                                                        | 403                           | 403                                                     | **PASS**              |
| S-06  | 2 MiB JSON body                                                                                                | 413                           | 413                                                     | **PASS**              |
| S-07  | `Content-Length: -5`                                                                                           | 4xx, no hang                  | 413                                                     | **PASS**              |
| S-08  | Upload `X-Filename: ../../../evil.txt`                                                                         | contained in temp dir         | 202, `escaped=False`                                    | **PASS**              |
| S-09  | `PUT /api/settings` with `{"maximum_file_size": true}`, `{"ml_weight": "1e9"}`, `{"maximum_file_size": 1e308}` | 400                           | 400 with precise messages                               | **PASS**              |
| S-10  | `X-Filename` containing `\r\n` (header injection)                                                              | not reflected into headers    | 202, no injected header                                 | **PASS**              |
| S-10b | NUL byte in `X-Filename`                                                                                       | handled                       | 202                                                     | **PASS**              |
| S-10c | 4 000-character `X-Filename`                                                                                   | truncated, no crash           | 202                                                     | **PASS**              |
| S-11  | Scan a non-existent path (error message content)                                                               | no internals                  | `{"error": "That file doesn't exist."}`                 | **PASS**              |
| S-12  | Security headers                                                                                               | CSP, nosniff, referrer-policy | all present                                             | **PASS**              |
| S-18  | Declared `Content-Length: 1 MiB`, sent 10 bytes                                                                | bounded                       | no read deadline → socket held open until client closes | **INFO — see SEC-04** |
| S-19  | Invalid JSON `{not json`                                                                                       | 400                           | 400                                                     | **PASS**              |
| S-20  | `PATCH /api/scan`                                                                                              | 405                           | 501 (server has no `do_PATCH`)                          | **PASS** (acceptable) |
| S-21  | 100 KB query string                                                                                            | rejected                      | 414                                                     | **PASS**              |
| S-22  | Token comparison                                                                                               | constant time                 | `secrets.compare_digest` in source                      | **PASS**              |
| S-23  | `GET /../` on static root                                                                                      | no neighbour files            | 404                                                     | **PASS**              |

### 2.2 File handling & quarantine

| ID        | Probe                                          | Result                                                                      |
| --------- | ---------------------------------------------- | --------------------------------------------------------------------------- |
| S-14      | `quarantine_file(p, key32, dir)` with defaults | returns `None`, **nothing written**, source retained — correct dry-run      |
| S-15      | 5-byte AES key                                 | `ValueError`                                                                |
| S-16      | `dry_run=False` **without** `authorized=True`  | `PermissionError: Quarantine requires explicit authorization.`, source kept |
| Repo eval | symlink source                                 | rejected (code)                                                             |
| Repo eval | restore over existing destination              | refused (code)                                                              |

### 2.3 Unsafe deserialisation

| Check                                          | Result                                                                                         |
| ---------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| `joblib.load` / `pickle` anywhere under `ml/`  | **none** — S‑13 PASS                                                                           |
| Model artifact format                          | bounded JSON trees, validated before traversal (repo tests `test_forest_format.py`, 87 passed) |
| `exec`/`eval`/`__import__` on analysed content | none found                                                                                     |

### 2.4 Dependency vulnerabilities

`pip-audit 2.10.1` against the installed environment:

```
Found 6 known vulnerabilities in 2 packages
  pip      26.1.1  PYSEC-2026-196   → fix 26.1.2
  pip      26.1.1  PYSEC-2026-3721  → fix 26.2
  signify  0.7.1   PYSEC-2026-2278  → fix 0.9.2
  (thrember 0.1.0 — not on PyPI, could not be audited)
```

`pip` and `signify` are **not** runtime dependencies of CyberScan (`signify` arrives transitively via
`pip-audit`/`cryptography` tooling). **No advisory affects `yara-python`, `pefile`, `capstone`,
`cryptography`, `aiohttp`, `numpy`, `scikit-learn` or `PySide6` as installed.** Raw:
`qa/artifacts/pip_audit_env.json`.

> Caveat: `requirements.txt` uses **lower bounds only** (`yara-python>=4.5.1`, `pefile>=2023.2.7`, …).
> A future `pip install` may resolve to different versions than the ones audited here. The repository
> has **no lock file**, so dependency state is not reproducible (see SEC-07).

---

## 3. Findings

### SEC-01 — Static public API token (Medium)

|                      |                                                                                                                                                                                                                                                                                                                            |
| -------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Evidence**         | `web_v/server.py:463` — `self.token = os.environ.get("CYBERSCAN_TOKEN") or ("cyberscan-public" if PUBLIC else secrets.token_urlsafe(32))`; `web_v/server.py:714` — the token is substituted into `index.html` for every visitor. Verified locally: `token in index.html: True` (S-01).                                     |
| **Why it is needed** | The token is a _defence-in-depth_ measure against drive-by POSTs from other sites, not an authentication mechanism — the same page must work behind any Lambda instance. The `Origin`/`Host` checks (S-04/S-05) are the primary control.                                                                                   |
| **Reproduction**     | `CYBERSCAN_PUBLIC=1` → open the landing page → read `const TOKEN = "cyberscan-public"` from the HTML → send `X-CyberScan-Token: cyberscan-public` from any HTTP client. With a matching `Origin` header, the API responds.                                                                                                 |
| **Impact**           | Anyone can script the public scan API directly, bypassing the page. Not confidentiality-impacting (public mode disables history, settings, file-by-path, quarantine). Real impact is **cost and availability**: each request can consume up to `PUBLIC_TIMEOUT` (50 s) and 4 MiB of upload; there is no per-IP rate limit. |
| **Remediation**      | Enforce throttling at the edge (AWS WAF rate-based rule / API Gateway usage plan) — the application cannot do this reliably per-instance. Keep `Origin` validation. Do not describe the token as security.                                                                                                                 |

### SEC-02 — Exception during error reply aborts the connection (Low)

|                    |                                                                                                                                                                                                                                                                                                                                                                                                  |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Evidence**       | During S-19 the server printed `ConnectionAbortedError: [WinError 10053]` from `server.py:551` (`self.wfile.write`), and **no HTTP response reached the client**, although the log shows the `ApiError(400, "invalid JSON")` handler ran. Root cause: `_raw_body()` set `self._consumed = True`; on the `ApiError` path the client had already closed the read side, and the write is unguarded. |
| **Reproduction**   | `qa/sec02_probe.py`: send `POST /api/scan` with `{not json`, shut down the receive side, abort the connection. **6 of 6 attempts** raised `ConnectionResetError [WinError 10054]` out of `server.py:551` (`wfile.write`); the client never received the 400. First observed organically during S-19 as `ConnectionAbortedError [WinError 10053]`. Raw: `qa/sec02.err.log`.                                                                                                                                                                                                                        |
| **Impact**         | Any client disconnecting mid-request makes the handler raise instead of closing cleanly. On this platform it is contained to one request; on keep-alive connections a reset can also terminate the **next** request on the same socket. No data corruption observed.                                                                                                                                                                                                                                                                               |
| **Recommendation** | Wrap `self.wfile.write(body)` in `try/except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError): self.close_connection = True`. One line, no behaviour change.                                                                                                                                                                                                                      |

### SEC-03 — No response truncation; exception type/message reflected (Low)

|                    |                                                                                                                                                                                                                                                           |
| ------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Evidence**       | `web_v/server.py:665` returns `{"error": f"{type(exc).__name__}: {exc}"}` for `OSError`/`ValueError`/`RuntimeError`; `global_intelligence._feed_result(error=...)` embeds the upstream exception text and returns whole feed records without length caps. |
| **Reproduction**   | Trigger a `RuntimeError`/`ValueError` inside any handler (e.g. `POST /api/repair/run` with a malformed key) and read `error`.                                                                                                                             |
| **Impact**         | Filesystem paths and library-internal messages may reach a remote client; a malicious/compromised feed could inflate a response. Currently no secret material was observed in any error string.                                                           |
| **Recommendation** | Log the full exception locally; return a generic message plus a correlation id. Cap every returned string (e.g. 512 chars).                                                                                                                               |

### SEC-04 — Resource exhaustion by concurrent scans (Low, availability)

|                    |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| ------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Evidence**       | `App.start_job` bounds **jobs** (`MAX_JOBS = 32`) but not **bytes**. Each job keeps the raw file (`ScanService.analyze` returns `raw_data`) until evicted; `scan_upload` enforces `maximum_file_size` (50 MiB local, 4 MiB public) _per request_ but there is no global upload budget; `_raw_body` has no read deadline (S-18 confirmed the socket stays open while a partial body is pending). Scans are GIL-bound (Deliverable B §6), so N concurrent scans do not run in parallel — they queue and each connection stays open. |
| **Reproduction**   | Send N < 32 concurrent `POST /api/scan/file` requests of 50 MiB each from a single host and do not read the responses quickly.                                                                                                                                                                                                                                                                                                                                                                                                    |
| **Impact**         | Local/desktop mode: self-inflicted. Public mode: a single client can hold many 50 s slots and memory; combined with SEC-01, this is the realistic abuse path.                                                                                                                                                                                                                                                                                                                                                                     |
| **Recommendation** | (a) set `socket` timeouts on the request socket; (b) add a global byte/queue cap and reject with `429`; (c) drop `raw_data` from the job once `present()` has run; (d) rate-limit per IP at the edge.                                                                                                                                                                                                                                                                                                                             |

### SEC-05 — Dependency advisories in tooling only (Info)

See §2.4. Recommendation: add a lock file (SEC-07) and run `pip-audit` in CI.

### SEC-06 — No request logging / audit trail (Info)

`log_message()` is overridden to do nothing and `record_history` is skipped in public mode. A scan
of a malicious file leaves **no local record** of who requested it or when. For a security product,
an append-only local audit log is expected. Recommendation: structured local log of
`timestamp, action, target-hash, outcome` (never raw content).

### SEC-07 — Unpinned dependencies / no lock file (Info, release hygiene)

`requirements.txt` has `>=` bounds and a commented optional `yara-x`. Builds are not reproducible.
Recommendation: `pip-compile` a `requirements.lock` (hashes) for release artifacts.

---

## 4. Threats explicitly checked and **not** found

| Threat                                                   | Result                                                                                                                                                                                           |
| -------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Path traversal (static, upload, history report paths)    | Resisted. `_report_path` requires the resolved parent to equal `HISTORY_DIR`; uploads sanitised with `re.sub(r"[^\w.\- ]", "_", …)[:120]`; static served only if `STATIC_DIR in target.parents`. |
| Arbitrary code execution via model artifact              | Resisted — JSON-only loader; no pickle in the active path.                                                                                                                                       |
| Command injection                                        | Not found. Subprocesses use fixed argv lists; no `shell=True` in the repository.                                                                                                                 |
| Secrets in source                                        | None (keys read from env or the local secret store).                                                                                                                                             |
| Unsafe error pages exposing a stack trace to the browser | Not found for normal API errors; the full traceback goes to the console only.                                                                                                                    |
| Malicious archive extraction (zip-slip)                  | Archive inspector does **not extract**; it reports unsafe member paths (`core/archive_inspector.py`, repo tests pass).                                                                           |
| Symlink quarantine / TOCTOU on delete                    | Rejected/guarded by stat+digest re-check with retry (documented residual race in `docs/implementation_status.md`).                                                                               |

---

## 5. Residual risk statement

The most important residual risk is **not** in the code I tested: the native parsers (`pefile`,
`capstone`, `yara-python`, `zipfile`) process **attacker-controlled bytes inside the application
process, unsandboxed**. The repository's own fuzzing reports 0 crashes in 3 000 parser mutations and
158 scanner fuzz cases, and my suite ran 4–8 MiB adversarial MZ inputs without a crash — but a
process-wide sandbox (separate low-privilege process with memory/CPU quota, or a WASM build) is the
only way to bound the consequences of a future parser CVE. This is correctly stated as an open gap in
`docs/implementation_status.md`.
