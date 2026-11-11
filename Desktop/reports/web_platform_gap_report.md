# CyberScan web-platform audit and feature gaps

**Audit date:** 2026-11-10  
**Scope:** Public pages at `https://ainex-ai.xyz` and `https://scan.ainex-ai.xyz`, plus all relevant source present in this local CyberScan workspace. No deployment, writes, or upload submissions were performed.

## Executive summary

The public website is a static marketing landing page connected by its visible links to a separate scan application. The scan page's rendered UI has Scan, Protection, History, Repair, and Settings views; its scan composer accepts files, links, or text and exposes batch upload, progress, and structured result panels. Protection advertises file scanning, link/phishing checks, exposed-key checks, an HIBP k-anonymity password check, file repair, and an on-device scan link. The public page describes static analysis and says checked files are not executed.

The local workspace does **not** contain the public site's HTML/CSS/JavaScript source, a web framework/server, HTTP route definitions, authentication implementation, or database. It contains a CustomTkinter desktop UI and a Python analysis engine. Sentinel has added a web-oriented Python API (`detection.engine.analyze_upload` / `analyze_text_json`), but these are callable functions, not HTTP endpoints. The live scan UI's backend routes and persistence/authentication behavior could not be independently verified from local code; the public `openapi.json` request was not retrievable.

Consequently, local analysis work can improve reusable engine functionality, but this workspace cannot safely deliver a dedicated, mobile-responsive website interface or modify the deployed service. No changes were made to production.

## Existing tool and service inventory

| Area | Evidence in local source or public HTML | Status / limits |
|---|---|---|
| File, link, and text scanning | Public scan page tabs; `detection.engine.analyze_upload`, `analyze_text_json` | Python APIs present locally; no local HTTP router or website source |
| PDF security analysis | `detection.documents.inspect_pdf` | Static inspection including actions, embedded content, links, and bounded stream inspection; not a full PDF renderer/validator |
| Office documents | `inspect_ooxml`, `inspect_ole`, `analyze_vba` | OOXML and legacy OLE inspection, macro, external relationship, embedded-object and link checks |
| Archive security | `detection.archives.inspect_archive` | ZIP-family inspection, bounded member reads, nested ZIP-family inspection, traversal/executable/bomb indicators; no local RAR dependency |
| File authenticity / structure | `detection.engine.sniff_type`, `core.magic_bytes`, `core.file_integrity.verify_file_integrity` | Content-sniffed type and existing magic checks; separate PNG/ZIP structural verification and boundary-only PDF/JPEG/GIF checks. No calibrated format-confidence score |
| URLs and phishing indicators | `detection.url_intel.analyze_url_intel`, `core.global_intelligence` | Static offline URL analysis; optional public IOC feeds in existing application require opt-in |
| Email/message analysis | `detection.messages.analyze_message` | Local parsing and static message/link indicators; SPF/DKIM/DMARC evidence is limited to material supplied in the message |
| Sensitive information | `detection.secrets.scan_secrets` | Credential patterns are reported separately with redaction |
| PE/ELF and script indicators | `detection.executables`, `detection.script_rules`, existing YARA/PE code | Static inspection only; no uploaded content is executed |
| QR decoding | `core.qr_scanner.analyze_qr_image` | Added reusable bounded image decoder and offline URL assessment; not connected to a local HTTP or production website route |
| UI routes and history | Public UI has Scan, Protection, History, Repair, Settings; fresh browser showed empty scan history | Scan page Settings says fixed settings, max 4 MB upload and no server-side history. Browser/local persistence behavior was not verified. Only desktop UI source is local |
| Authentication/database | No sign-in control was observed in the scan UI; no matching local server/auth/database implementation | Backend authorization and database implementation cannot be confirmed from this checkout |

The public scan HTML includes a constant `cyberscan-token` value. Treat it as a public client identifier, not a secret or proof of authorization; the backend's enforcement could not be verified. An unauthenticated `openapi.json` fetch was not retrievable, which is not proof that no service API exists.

## Priority 1 disposition

| Tool | Existing capability | Remaining work |
|---|---|---|
| PDF Security Scanner | Present in Sentinel's detection engine | Web route/interface integration and production backend verification |
| Archive Security Scanner | Present for ZIP-family containers and nested checks | RAR is unsupported locally; web route/interface integration remains |
| QR Code Security Scanner | New reusable `analyze_qr_image` helper; 8 MiB input, 16 MP image cap, process isolation, five-second decode timeout, offline URL analysis | Requires integration into the web upload route and a dedicated scan UI |
| File Authenticity Analyzer | Partial support through content sniffing, magic mismatch checks, and structural verification | Add explicit confidence/format evidence and expose it in the web UI |

The QR helper uses bounded image byte and pixel limits, decodes only QR symbols, and analyzes URL payloads locally through Sentinel's existing URL intelligence. It does not open decoded destinations or transmit the image/payload. Decoder errors, missing decoder, timeouts, unsupported images, and no-code results remain distinct outcomes.

## Prioritized gaps and next steps

1. **Obtain the web application source and backend contract.** Identify the actual scan API routes, upload limits, auth model, retention rules, and frontend asset repository before making user-facing production changes.
2. **Integrate Priority 1 engine tools.** Wire the existing PDF/archive APIs and the QR helper into the web backend, return their evidence in a documented schema, and add dedicated responsive UI states and error/progress behavior. Keep Sentinel's URL analysis as the single source of URL threat findings.
3. **Complete file authenticity output.** Report format candidates and explicit confidence basis; surface structural integrity, extension mismatch, and appended data separately from malware risk.
4. **Priority 2.** Verify document metadata coverage, evaluate email authentication headers only when raw headers are supplied, and ensure secret findings stay redacted.
5. **Priority 3.** Add SMS-specific UX, metadata privacy reports, exact/similarity comparison, and file-change comparisons only after contracts and safe upload handling are available.

## Verification

- Local full test suite: **62 passed** after the QR decoder dependency was installed.
- QR tests generate harmless QR images in memory and verify real decoding, offline URL analysis, invalid input handling, pixel limits, and no-code reporting.
- No production requests containing user files or indicators were made.
