# CyberScan

## Project overview

CyberScan is a defensive cybersecurity research prototype that combines static analysis, explainable risk assessment, and an optional machine learning anomaly layer. It is intended for student use, research demonstrations, and educational analysis of suspicious files, URLs, and text-based indicators.

This project is a defensive research prototype and is not a replacement for commercial endpoint security software.

## Problem

Traditional static heuristic checks can provide useful signal, but they are limited by the quality of rules and can produce noisy or misleading results if they are presented as definitive malware detection. Security tools also often overstate capabilities when they cannot demonstrate actual model performance or runtime monitoring.

## Proposed solution

CyberScan separates the problem into several components:

- static evidence extraction
- heuristic rule evaluation
- ML anomaly scoring when a model is available
- explainable risk fusion
- report generation
- optional downloads monitoring

The system is intentionally transparent about limitations and does not claim zero-day detection or complete malware coverage.

## Architecture

The project is organized into modules for scanning, feature engineering, ML, monitoring, reporting, and UI responsibilities.

## Detection pipeline

1. Input is accepted as a file, URL, or text hash.
2. The file or text is analyzed for static features.
3. Heuristic rules are evaluated.
4. A trained anomaly model is used only if a compatible model is present.
5. The heuristic and ML signals are fused into a combined risk score.
6. Evidence and explanations are produced for the user.

## Static analysis

Static analysis checks include:

- file size and hashing
- entropy estimation
- magic-byte and extension mismatch detection
- double-extension detection
- executable extension detection
- suspicious string and command indicators
- suspicious URL indicators

Every finding is treated as evidence, not proof. Single indicators are never interpreted as absolute malware confirmation.

## Detection intelligence (`detection/`)

File type is decided from content (magic bytes), never from the extension, and each type goes to a
dedicated static analyzer. Nothing is executed, rendered or extracted to disk, and nothing uses the network.

| Input | What is inspected |
|---|---|
| PDF | JavaScript and auto-actions (`/OpenAction`, `/AA`), `/Launch`, embedded files, hex-obfuscated names (`/J#61vaScript`), suspicious JS APIs, links. FlateDecode streams are inflated with per-stream and total caps, so JavaScript hidden in compressed objects is found. |
| Office OOXML | VBA macros (source decompressed per MS-OVBA), auto-exec entry points, macro capabilities (execution, download, file write, Win32 API, obfuscation), XLM macro sheets, remote template injection, external OLE objects, DDE fields, embedded objects, metadata. |
| Legacy Office / `.msg` (OLE) | Bounded compound-file reader; VBA, XLM `BOUNDSHEET` macro sheets, OLE `Package` objects, encrypted documents, Outlook body and attachment names. |
| RTF | Embedded objects with `\objupdate`, Equation Editor (CVE-2017-11882 shape), OLE2Link, remote templates. |
| ZIP-family archives | Decompression bombs, Zip Slip paths, double extensions, executables, password-protected executables, script contents (read in memory, capped). |
| APK | Binary `AndroidManifest.xml` parsing; permission audit; banking-trojan combinations (accessibility + overlay/SMS); code hidden in assets. |
| Browser extensions | `manifest.json` permissions, all-site cookie/web-request access, weakened CSP, off-store updates. |
| PE / ELF | Capability-based import analysis (process injection/hollowing, keylogging, downloader), packers, W+X sections, entry-point anomalies, info-stealer paths, UPX/stripped ELF. |
| Images | QR codes decoded by `core.qr_scanner`; decoded links and texts are analyzed (quishing). |
| URLs | Offline typosquatting, homoglyph/IDN homograph, brand impersonation, user-info tricks, obfuscated IPs, redirect parameters (analyzed one level deep), risky schemes and downloads. |
| Email / SMS text | Social-engineering language (English and common Arabic phrases), link scoring, display-name spoofing, Reply-To mismatch, SPF/DKIM/DMARC failures. |
| Any text | Living-off-the-land and script tradecraft (certutil, mshta, regsvr32, Run keys, AMSI bypass, shadow-copy deletion, reverse shells, miners). |

**Privacy.** Exposed secrets (cloud/API keys, tokens, private keys, connection strings, Luhn-valid card
numbers) are reported in a separate `privacy` section with values redacted. They do not raise the
threat score: a leaked key is an exposure risk, not malware.

**Fusion.** Contributions are combined with noisy-OR (`1 - Π(1 - c/100)`) rather than summed, so weak
hints corroborate each other but cannot reach SUSPICIOUS on their own. Findings that observe the same
fact through two engines (for example YARA and import analysis reading the same API names) count once.
Each result also reports `evidence_agreement` (`single-source`, `moderate`, `strong`): how many
independent categories agree. This describes agreement, not a probability.

**False-positive check.** After calibration, a local sweep of 240 Windows System32 binaries and 40
PowerShell scripts produced no SUSPICIOUS result. On benign PDFs, Office documents and JARs, almost
all results were SAFE. This is a sanity check, not a measured false-positive rate.

## File integrity verification

File scans also run a separate, read-only integrity pass and include it in text and JSON reports. It calculates a second SHA-256, checks whether the bytes still match the primary scan snapshot, and applies bounded structural checks to PNG chunks/CRCs and ZIP entries/CRCs. PDF, JPEG, and GIF checks currently inspect only boundary markers; appended bytes are distinguished from structural corruption but leave verification incomplete. Other formats are reported as verification-incomplete. ZIP contents are never extracted, and entry count, expansion size, and expansion ratio are capped. Nested archives are identified but not recursively inspected.

`structurally_valid` means only that the supported structural checks passed. `damage_detected` means a supported check found a structural inconsistency. `verification_incomplete` means the format or part of its structure could not be fully checked, or the source changed. None of these statuses means a file is safe, and the project does not currently repair or rewrite files.

## Reusable web-analysis engine

The UI-independent detection package exposes `detection.engine.analyze_upload(data, file_name)` for bounded bytes-in/JSON-serializable file analysis and `analyze_text_json(value)` for URL or text input. It includes static PDF, Office/OOXML, RTF, OLE, ZIP-family archive, PE/ELF, message, URL and privacy checks. These are Python APIs, not HTTP routes. The local workspace has no website frontend, web server, authentication or database implementation.

`core.qr_scanner.analyze_qr_image(data, file_name="")` decodes QR codes from bounded PNG, JPEG, GIF, TIFF, BMP or WebP images using zxing-cpp and Pillow. Decoding runs in a separate process with a five-second timeout; image bytes and decoded pixel count are capped. URL destinations are evaluated by CyberScan's offline URL analyzer; no QR contents are sent to external services. It returns `decoder_unavailable` if zxing-cpp is missing, and reports a decode error or no-code result explicitly. This helper is not yet wired into the production site's scan route or UI because that source and route are not in this workspace.

## ML anomaly detection

The ML layer is built around an Isolation Forest anomaly detector when scikit-learn is available. The system is designed to support a trained model, but it will not invent a model if none exists.

When no trained model is present, the interface clearly shows:

- ML model not available.
- Static analysis active / ML unavailable.

## Risk fusion

The overall risk is a transparent weighted combination of heuristic and ML scores.

The default weights are:

- heuristic weight: 0.70
- ML weight: 0.30

This is not presented as a scientifically optimal detection formula; it is a configurable research prototype.

## Explainability

Each scan produces explainable evidence and a summary. Findings are described with category, severity, evidence, explanation, and contribution to the heuristic score. This is intended to support manual review and research demonstration rather than black-box classification.

## Downloads monitoring

The application can optionally monitor a Downloads directory. It checks for newly created files, queues them for scanning, and avoids blocking the UI. It does not automatically quarantine or delete files. Users remain in control of the final response.

## Installation

Requires Python 3.10+ (tested on 3.12 and 3.14).

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate     Linux/macOS: source .venv/bin/activate
python -m pip install -r requirements.txt
```

`capstone`, `pefile`, `yara-python` and `aiohttp` are optional engines. If one is missing the
corresponding stage reports that it is unavailable instead of failing.

## Running the application

```bash
python main.py
```

Generate harmless demo files (EICAR test string, a high-entropy mock binary, a spoofed `.txt`)
on demand with `python scripts/make_samples.py`; they are written to `data/demo_samples/`.

## Running the tests

```bash
python -m pip install -r requirements-dev.txt
python -m pytest
```

## Online IOC lookups (optional, off by default)

Sending a hash or URL to ThreatFox, URLhaus or AlienVault OTX is **opt-in**: enable
"Online IOC lookup" in Settings. API keys are read from environment variables only and are never
stored in the source tree (see `.env.example`): `ABUSECH_AUTH_KEY` (or `THREATFOX_API_KEY` /
`URLHAUS_API_KEY`) and `OTX_API_KEY`. A feed without a key reports `authentication_required`.

## Model file integrity

Trained models are stored with `joblib`, which uses pickle and can execute code when loaded.
CyberScan therefore records the model's SHA-256 in the metadata file at training time and refuses
to load any model whose digest is missing or different.

## Training the ML model

CyberScan does not train an active model from synthetic examples. The existing
unverified model artifact is rejected by the loader. To train, prepare a
user-reviewed CSV manifest with columns `path,label,source`; labels must be
`benign` or `malicious`, and `source` should identify the basis for each label.
Paths may be absolute or relative to the manifest. Provide at least 40 unique
benign files and 20 unique malicious files. Samples are read as bytes only and
are never executed. Labels and provenance are user-supplied and are not
independently verified by CyberScan.

```bash
python -m ml.training.train --manifest data/datasets/manifest.csv
```

## Evaluation

Evaluate an already trained model against a separate labeled manifest. The
evaluator rejects manifests containing file hashes used for training.

```bash
python -m ml.training.evaluate --manifest data/datasets/holdout.csv
```

Reported precision, recall, specificity, and F1 apply only to the supplied
holdout set; they are not calibrated confidence or a malware-coverage claim.

## Limitations

- The prototype does not claim zero-day detection.
- Static analysis is heuristic only.
- The ML layer requires a real training dataset and a trained model to be effective.
- Synthetic data is only for software testing and is clearly labeled as synthetic.
- Real-world malware detection requires validation against labeled evaluation data.

## Future work

- add a validated labeled dataset
- experiment with additional model types
- integrate safe sandboxed dynamic analysis in a controlled environment
- add broader export formats and automation hooks

## Project structure

```text
.
├── main.py                  entry point (GUI)
├── config.py                paths and ScannerSettings (single source of defaults)
├── requirements.txt / requirements-dev.txt
├── pytest.ini / conftest.py
├── core/                    scanning pipeline
│   ├── file_analyzer.py     file analysis + evidence + score fusion
│   ├── heuristic_engine.py  transparent text/URL/file-name rules
│   ├── feature_extractor.py, entropy.py, hashing.py, magic_bytes.py
│   ├── yara_engine.py, pe_decompiler.py, mitre_mapper.py
│   ├── nextgen_engine.py    entropy topography + CFG analysis
│   ├── deep_embedding.py    4096-D embedding + incremental k-NN
│   ├── global_intelligence.py  optional IOC feed lookups
│   └── scanner.py, text_analyzer.py, url_analyzer.py, risk_engine.py, models.py
├── detection/               content-type analyzers, URL/phishing, messages, secrets, fusion
│   ├── engine.py            type sniffing, dispatch, analyze_upload / analyze_text_json
│   ├── documents.py, ole.py PDF, OOXML, OLE/VBA, RTF, .msg
│   ├── archives.py          ZIP, APK, browser extensions
│   ├── executables.py       PE/ELF structure and capabilities
│   ├── url_intel.py, messages.py, script_rules.py, secrets.py
│   └── common.py            Indicator type, noisy-OR fusion, resource limits
├── collaboration/           agent coordination log (discussion, decisions, task board)
├── ml/                      anomaly detector, feature schema, model manager, training/
├── monitoring/              downloads monitor
├── reports/                 report generator and exporter
├── rules/                   YARA rules
├── scripts/make_samples.py  creates harmless demo samples on demand
├── tests/
├── ui/                      CustomTkinter GUI and translations (EN/AR)
└── data/                    datasets/, models/, reports/, quarantine/ (runtime output)
```
