# CyberScan

## Project overview

CyberScan is a defensive cybersecurity research prototype that combines static analysis, explainable risk assessment, and an optional supervised three-class structural classifier. It is intended for student use, research demonstrations, and educational analysis of suspicious files, URLs, and text-based indicators.

This project is a defensive research prototype and is not a replacement for commercial endpoint security software.

## Desktop interface

The application launches a native PySide6 interface with a compact analysis
composer, a live evidence workbench, animated risk visualization, structural
charts, scan history, YARA/PE details, MITRE mapping, model status, audit
timeline, settings, and Arabic/English layout direction. The live panels are
populated from the current scan and local application state; the target is
analyzed statically and is never executed.

Install the dependencies from `requirements.txt`, then launch with
`.venv\Scripts\python.exe main.py` on Windows. PySide6 Essentials is used for
the native Core, Gui, and Widgets modules without adding Qt WebEngine.

## Problem

Traditional static heuristic checks can provide useful signal, but they are limited by the quality of rules and can produce noisy or misleading results if they are presented as definitive malware detection. Security tools also often overstate capabilities when they cannot demonstrate actual model performance or runtime monitoring.

## Proposed solution

CyberScan separates the problem into several components:

- static evidence extraction
- heuristic rule evaluation
- supervised three-class structural ML scoring when a trained model is available
- explainable risk fusion
- report generation
- optional downloads monitoring

The system is intentionally transparent about limitations and does not claim zero-day detection or complete malware coverage.

The file analyzer reads file bytes up to a configurable 50 MiB limit and
computes bounded sliding-window entropy topography while limiting string
extraction and disassembly work. The deterministic 4096-coordinate representation has four 1024-coordinate
channels: byte/opcode patterns, entropy topology, CFG topology, and PE/import
structure. A supervised Random Forest can learn three reviewed labels from
these vectors. The projection is not lossless and is not a neural network.
Scores are uncalibrated model scores, not infection probabilities. Compressed
or encrypted data is treated as opaque bytes unless it can be inspected without
keys or executing it.

Public-feed lookups are disabled by default. When explicitly enabled in
Settings, supported URLs, hashes, domains, or IP indicators are submitted to
public services; local files are represented by their SHA-256 hash. Successful
indicator results are cached in-process for five minutes. Feed matches are
correlations, not proof of malware, and a feed miss is not proof of safety.
Feed credentials must be supplied through environment variables or the API;
no credentials are embedded in source code.

## Architecture

The project is organized into modules for scanning, feature engineering, ML, monitoring, reporting, and UI responsibilities.

## Detection pipeline

1. Input is accepted as a file, URL, hash, or text indicator.
2. The file or text is analyzed for static features.
3. Heuristic rules are evaluated.
4. A trained three-class model is used only if a compatible model is present.
5. The user-facing risk score is based on heuristic evidence by default.
   Uncalibrated model scores remain separate and are not mixed into that score
   unless a user explicitly changes the experimental weights.
6. Public intelligence lookups run only if enabled by the user; they submit
   supported indicators, not local file contents.
7. Evidence, engine availability, and limitations are reported. A zero score
   means "no indicators observed", not "proven safe".

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
Training and inference use the same bounded string scan and whole-file numeric
feature extraction. The optional entropy setting controls entropy findings and
visualization; the ML feature schema still computes entropy values when ML is
enabled because they are required by that model.

ZIP archives receive bounded structure inspection without extraction. By
default, inspection is limited to 50 MiB input, 1,000 total entries, 16 MiB
per member, 64 MiB total decompressed content, and two nested levels. Unsafe
paths, symbolic links, encrypted members, malformed ZIP structures, and
resource-limit outcomes are reported. Member hashes and basic content-type
candidates are collected, but archive members are **not** independently
scanned for malware; the result is not a safety verdict. ZIP64 archives are
reported as unsupported. Inspection runs in-process and has no hard
cancellation or memory quota.

File results also carry a separate position-aware evidence summary. It maps
measured entropy transitions to zero-based byte ranges and hashes the
referenced bytes. For parsed PE files, section RVAs and raw file offsets are
kept distinct, and a raw section range is marked verified only when the
parser-returned section bytes match the corresponding input bytes. These are
measured boundaries, not learned malicious-region predictions, instruction
localization, or safe repair scopes; entropy transitions do not prove
maliciousness. Output is capped at 128 entropy boundaries and 16 MiB of region
hash work per file; skipped hashes and excess observations are reported. The
measurements appear in the live evidence panel and text/JSON reports.

## Supervised structural classification

When trained from a reviewed manifest, CyberScan's optional classifier is a
scikit-learn `RandomForestClassifier` over the 4096-D structural vectors
produced from file bytes. It classifies files as
`clean`, `suspicious`, or `malware`. It is not trained on raw bit arrays, and
does not decrypt or execute samples. Its class scores and combined suspicious
plus malware score are uncalibrated and must not be interpreted as probabilities
or used alone to make destructive decisions.
Trained trees are persisted as validated JSON data and evaluated without
deserializing executable Python objects. Legacy executable `.joblib` classifier
files are intentionally not loaded; retrain from a reviewed manifest to create
the current JSON model. The repository's separate anomaly-model `.joblib`
artifact is not used by the active scan pipeline.

When no compatible trained model is present, scanning continues with static
evidence and reports that the structural classifier is unavailable.
The classifier score does not trigger a repair recommendation or a file
modification. Restoration requires explicit approval and a trusted clean
source; a 4096-D vector cannot reconstruct the original.

## Risk scoring

The overall risk is an explainable heuristic indicator, bounded by the
strongest individual evidence contribution. It is not a malware probability.
The three-class ML score is reported separately because its raw scores have
not been calibrated against a representative validation set.

The defaults avoid combining incomparable, uncalibrated quantities:

- heuristic weight: 1.00
- ML weight: 0.00

Changing these settings enables experimental fusion only; no evidence here
establishes that a different weighting improves detection.

## Explainability

Each scan produces explainable evidence and a summary. Findings are described with category, severity, evidence, explanation, and contribution to the heuristic score. This is intended to support manual review and research demonstration rather than black-box classification.

## Downloads monitoring

The application can optionally monitor a Downloads directory. Monitoring
baselines existing files when enabled, waits for newly created or changed files
to stabilize, and then queues them for automatic static scanning without
blocking the UI. Monitoring does not automatically quarantine or delete files.
Files exceeding configured size limits are reported as scan failures.

The interface provides a local scan history and persists interface preferences
under `data/ui_settings.json`. Scan history metadata is stored in
`data/scan_history.json`, with generated JSON reports under
`data/reports/history/`. History removal deletes only the generated report after
checking that it is inside that directory; it never removes the original input.
The history is bounded to the most recent 200 scans. Public OSINT lookups remain
opt-in and disabled by default.

An explicit AES-GCM quarantine operation is available through
`core.scanner.quarantine_file`. The caller must provide a 16-, 24-, or 32-byte
key and is responsible for storing it securely; CyberScan never persists the
key. Calls are dry-run by default. Removing the plaintext source requires both
`dry_run=False` and `authorized=True`; the operation writes an authenticated
encrypted `.csq` file before removal and retries transient Windows file locks.
Symbolic-link sources are rejected. `restore_quarantined_file` authenticates
the ciphertext before publishing a restored file and refuses to overwrite an
existing destination. Keep the quarantine directory's operating-system
permissions restricted. Do not present the encrypted archive as recoverable if
its key has been lost. This API does not provide automatic repair.

## Evaluation claims

CyberScan has no validated evidence supporting a 98% detection accuracy,
zero false positives, or a competition-grade malware detection rate. Such
figures require an independently labeled dataset, a held-out evaluation, and
reported class-specific metrics. The risk score is an explainable indicator,
not a confidence percentage or calibrated probability. CFG measurements are
static decoder heuristics and may be incomplete or misleading for obfuscated,
packed, mixed-architecture, or non-code bytes.

## Installation

CyberScan includes a script to create a synthetic dataset for testing and development purposes. This dataset is clearly labeled as synthetic and does NOT contain real malware.

```bash
cd dist
python -m ml.training.create_synthetic_dataset
```

This creates 30 synthetic samples (10 clean, 10 suspicious, 10 malware) in `data/datasets/synthetic_integration/` with a manifest CSV. The samples are generated byte patterns, not real executables.

## Training the ML model

Samples are grouped by family (when available) or by hash prefix to prevent data leakage.
The `malware` label should only be applied to files confirmed by a trustworthy source.
Do not use high entropy or a model prediction by itself as ground truth.

On Windows, place the reviewed manifest at
`data\datasets\manifest.csv` and run this from the project directory:

```powershell
.\train_model.ps1
```

Pass a different manifest or model output path when needed:

```powershell
.\train_model.ps1 -ManifestPath "C:\Datasets\reviewed-manifest.csv" -ModelPath "data\models\structural_classifier_4096.json"
```

Or run the training module directly:

```bash
cd dist
python -m ml.training.train --manifest data/datasets/synthetic_integration/manifest.csv --output ml/models/synthetic_model.json --split group_aware
```

Options:
- `--manifest`: Path to the manifest CSV (required)
- `--output`: Output path for the trained model JSON (default: ml/models/structural_classifier.json)
- `--split`: Split method: `group_aware` (default) or `random`
- `--train-ratio`: Training ratio (default: 0.7)
- `--val-ratio`: Validation ratio (default: 0.15)
- `--test-ratio`: Test ratio (default: 0.15)
- `--seed`: Random seed (default: 42)
- `--n-estimators`: Number of trees in RandomForest (default: 200)

## Evaluation

Evaluate an already trained model against a labeled manifest. The evaluator checks for data leakage between training and evaluation sets.

```bash
cd dist
python -m ml.training.evaluate --model ml/models/synthetic_model.json --manifest data/datasets/synthetic_integration/manifest.csv --consistency
```

Options:
- `--model`: Path to trained model JSON (required)
- `--manifest`: Path to manifest CSV (required)
- `--dataset-root`: Root directory containing binary files (default: manifest parent)
- `--splits`: Splits to evaluate (default: val test)
- `--output`: Output JSON path for results
- `--consistency`: Run consistency check (reload model and compare predictions)

Reported metrics include accuracy, balanced accuracy, macro-F1, confusion matrix, per-class metrics, one-vs-rest ROC-AUC, and calibration diagnostics. These metrics apply only to the supplied evaluation set. Brier/ECE are computed from raw uncalibrated Random Forest scores and do not make them calibrated probabilities. These metrics are not a malware-coverage claim. A family-disjoint, independently labeled holdout is required for claims about unseen-family generalization.

## Website: trust pages, monitoring, CI and staging

The website (`web_v/`) also serves `/privacy`, `/terms`, `/security`, `/status`, `/tests` and `/changelog`,
per-language addresses (`/ar/`, `/fr/privacy`, … for all 30 languages), `/sitemap.xml` and
`/.well-known/security.txt`. That logic lives in `web_v/site_extras.py`; the server calls it.

| Task | Command |
|---|---|
| Rebuild the public changelog from `git log` | `python tools/changelog.py` |
| Re-measure the engine for `/tests` (writes `web_v/static/data/bench.json`, ~5 min) | `python tools/bench_engine.py` |
| Redraw the social-card images (`web_v/static/og/*.png`) | `python tools/og_images.py` |
| Check every internal link (starts its own server) | `python tools/check_links.py` |

Real-user monitoring stays on the site: `js/vitals.js` (20 % of page views) and `js/errors.js` post to
`/api/vitals` and `/api/errors`. Locally they are appended to `data/rum/*.jsonl` (capped at 2 MB each);
on Lambda they are printed to CloudWatch Logs as lines starting with `CS_VITALS` / `CS_ERRORS`. No IP
address or identifier is stored.

CI (`.github/workflows/ci.yml`) runs on every push and pull request: Python syntax, `pytest`,
`node --check` on every site script and the link checker. It never deploys.

### Staging

Run a staging copy before publishing to the live site:

1. **Locally, in public mode** (same behaviour as Lambda, no AWS):
   `cd web_v && set CYBERSCAN_PUBLIC=1 && set CYBERSCAN_BIND=127.0.0.1 && python run.py`
   (or `python -c "from server import create_server; s,a=create_server(8811); s.serve_forever()"`).
2. **On AWS**, with a second Lambda function that you create once in the console: copy the
   `CyberScan` function's configuration (runtime, handler `lambda_function.handler`, memory, timeout,
   environment variables, role) to a function named `CyberScan-staging`, and give it a Function URL.
   Then:

   ```
   set CYBERSCAN_STAGING_URL=https://<id>.lambda-url.eu-north-1.on.aws/
   python tools/deploy/deploy_aws.py --staging
   ```

   This builds the package exactly like a real deploy (live package + working tree), uploads it to
   `s3://cyberscan-assets/deploy/staging/cyberscan-lambda.zip` and updates only the staging function.
   Production, its package and CloudFront are not touched. Set `CYBERSCAN_SITE_ORIGINS` on the staging
   function to its Function URL, and `CYBERSCAN_STAGING_FUNCTION` here if you chose another name.
   When staging looks right, run `python tools/deploy/deploy_aws.py` (no flag) to publish.

## Limitations
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
├── config.py
├── main.py
├── requirements.txt
├── README.md
├── core/
│   ├── deep_embedding.py
│   ├── feature_extractor.py
│   ├── file_analyzer.py
│   ├── nextgen_engine.py
│   ├── pe_decompiler.py
│   └── scanner.py
├── ml/
│   ├── feature_schema.py
│   ├── structural_classifier.py
│   ├── model_manager.py
│   └── training/
│       ├── evaluate.py
│       └── train.py
├── monitoring/
│   └── downloads_monitor.py
├── reports/
│   ├── exporter.py
│   └── report_generator.py
├── ui/
│   ├── qt_app.py
│   ├── qt_widgets.py
│   └── scan_service.py
├── tests/
│   └── ...
├── docs/
│   └── implementation_status.md
└── data/
    ├── datasets/
    ├── models/
    └── reports/
```
