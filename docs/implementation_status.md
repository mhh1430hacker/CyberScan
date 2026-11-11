# CyberScan implementation, security, and research status

**Status date:** 2026-10-21  
**Scope:** Repository inspection and code changes in this project. This is not
a certification, independent malware-detection evaluation, or complete
literature review.

## Executive audit

### Verified working at baseline

- `main.py` starts the PySide6 application.
- The scan pipeline performs static file, URL, and text-indicator analysis.
- The deterministic feature encoder returns 4,096 coordinates in four
  1,024-coordinate blocks. The encoding is engineered and non-lossless.
- Optional YARA, PE parsing, OSINT, downloads monitoring, local history, and
  reports are wired into the existing application.
- The initial project test suite passed: 56 tests.

### Defects repaired in this change

- The supervised classifier previously used `joblib.load`, which can execute
  code while deserializing an untrusted or tampered artifact. New models are
  stored as bounded JSON tree data, validated before use, and evaluated by a
  small local traversal routine. Executable legacy classifier artifacts are
  rejected. The separate `anomaly_isolation_forest.joblib` file is not used by
  the active scan pipeline.
- The scanner and scan service previously relied on a pre-read size check but
  could read an unexpectedly grown file without a read bound. Reads now stop
  at `maximum_file_size + 1` and fail explicitly if the limit is exceeded.
- The previous default 70/30 fusion mixed heuristic contributions with
  uncalibrated model scores. The default is now 100% heuristic and 0% model;
  model scores remain separately visible. Changing the weights is an
  experimental user override, not a validated operating point.
- The arbitrary below-60 model-score remediation flag has been removed. A
  classifier score never authorizes repair or file modification.
- Dataset loading now bounds manifest size, sample count, and sample reads;
  reports duplicate-content label conflicts explicitly; records class counts;
  and supports deterministic family/group-disjoint validation when the
  manifest provides a `family` column. Random holdout results explicitly warn
  that they do not establish unseen-family generalization.
- Training/evaluation reports include balanced accuracy, per-class
  false-positive rates, ROC-AUC/PR-AUC when all classes are present, and
  Brier/ECE diagnostics computed from uncalibrated scores.
- Quarantine is now a dry run by default. Deleting the plaintext source
  requires both `dry_run=False` and `authorized=True`. Symbolic-link sources
  are rejected, source identity and content are checked before removal, and
  restore refuses to overwrite an existing destination.
- The README now describes these behaviors and their limits.

### Important gaps that remain

- There is no project-specific labeled training dataset and no active trained
  three-class model in the repository. Existing training tests use synthetic
  fixtures strictly for software testing.
- Model outputs have not been calibrated or validated for a particular
  operating environment. There is no validated OOD detector, conformal
  prediction, selective-risk policy, or adaptive analysis selector.
- A separate multi-view contradiction engine and temporal drift monitor have
  not been implemented.
- Family attribution is not implemented. Static API imports or similarity
  scores must not be presented as verified behavior or a malware-family name.
- There is no general repair implementation, structure-aware repair adapter,
  quarantine UI, authenticated restoration provenance report, or quarantine
  state-transition audit trail.
- The code does not run in an OS sandbox. Native parsers and rule engines still
  process attacker-controlled data inside the application process.
- The 4,096-D representation does not encode an explicit per-channel
  availability mask. A zero PE block can mean “not applicable,” not that a PE
  parser successfully observed an empty structure.
- The full prior-art review and required ablation studies are incomplete.

## Model and feature report

| Item | Verified state |
|---|---|
| Model | `sklearn.ensemble.RandomForestClassifier` |
| Classes | `clean`, `suspicious`, `malware` |
| Feature schema | `cyberscan-structural-4096-v1` |
| Feature dimensions | 4,096; four 1,024-coordinate blocks |
| Training defaults | 160 trees, `balanced_subsample`, `min_samples_leaf=2`, seed 42 |
| Scores | Raw forest class scores; not calibrated probabilities |
| Current training status | No real labeled project dataset or active trained classifier present |
| Provenance | The manifest hash and sample hashes are recorded; label provenance is user-supplied and not independently verified |
| Evaluation | Only synthetic-fixture training/reload is covered by automated tests; no detection-performance claim is supported |
| Safe artifact format | Validated JSON; maximum artifact size 64 MiB and 250,000 total nodes |

Feature extraction is deterministic for identical bytes and code version, but
it is a lossy handcrafted projection. CFG values rely on bounded static
disassembly heuristics and are not a reliable control-flow reconstruction for
every file. Packed, encrypted, malformed, unsupported, or non-PE inputs may
provide incomplete semantic evidence.

The evaluation tooling computes Brier and top-label ECE values from the
classifier's raw scores as diagnostics. It does not fit a calibration model or
authorize probability language, automated blocking, or remediation.

## Security report

### Threat model

The input file, manifest paths, model artifact, optional YARA rules, and parser
outputs are treated as untrusted. Ordinary scanning is static and does not
execute the target. Public intelligence lookups remain opt-in; when enabled,
indicators can be sent to providers, while local file contents are not
submitted by that stage.

### Applied protections

- Bounded file reads in the primary analyzer and Qt scan service.
- Bounded model artifact reads and strict schema/tree-index/value checks.
- No executable Python-object deserialization for the active classifier.
- Training sample and manifest bounds, duplicate-content checks, and group
  separation when family/group identifiers are supplied.
- AES-GCM quarantine, explicit authorization for source deletion, and
  no-overwrite restoration.
- Static scanning, reports, and model scores do not trigger automatic repair,
  deletion, quarantine, or blocking.

### Remaining security risks

- Parser and native-library vulnerabilities remain possible; processing is not
  isolated in a disposable sandbox.
- File-size limits bound bytes read, but do not impose a hard process memory or
  CPU quota on every native parser. Timeouts are checked between pipeline
  stages and cannot interrupt a stuck native call.
- Quarantine directory ACLs and key storage are the caller/operator's
  responsibility. The encryption key is never persisted by CyberScan.
- The quarantine API verifies source identity/content before deletion, but
  cannot eliminate every filesystem race on all supported filesystems.
- The encrypted vault is authenticated; the API does not yet produce a
  separately signed audit receipt or durable quarantine state-transition log.
- An optional threat-intelligence lookup can disclose the queried indicator
  to the chosen public provider.

## Research and prior-art note

This was a focused preliminary check of related papers, not a systematic
literature review. The sources below show that several ingredients proposed
for CyberScan already have prior art:

1. Raff et al., **“Malware Detection by Eating a Whole EXE”** (2017),
   [arXiv:1710.09435](https://arxiv.org/abs/1710.09435). Studies raw-byte
   malware classification and long binary sequences. CyberScan's handcrafted
   4,096-coordinate representation is different, but raw-byte ML is not a new
   contribution.
2. Anderson and Roth, **“EMBER: An Open Dataset for Training Static PE
   Malware Machine Learning Models”** (2018),
   [arXiv:1804.04637](https://arxiv.org/abs/1804.04637). Provides a large,
   labeled static-PE benchmark and baselines. It underscores that dataset
   quality, provenance, and reproducible evaluation matter; CyberScan has not
   evaluated on EMBER or another real dataset.
3. Bendale and Boult, **“Towards Open Set Deep Networks”** (2015),
   [arXiv:1511.06233](https://arxiv.org/abs/1511.06233). Introduces OpenMax
   for rejecting unknown classes. It is not a malware-specific validation of
   CyberScan's current classifier.
4. Narayanan et al., **“A Multi-view Context-aware Approach to Android
   Malware Detection and Malicious Code Localization”** (2017),
   [arXiv:1704.01759](https://arxiv.org/abs/1704.01759). Integrates multiple
   views for Android malware analysis. Multi-view analysis itself is therefore
   not a sufficient novelty claim.
5. Saha et al., **“MALIGN: Explainable Static Raw-byte Based Malware Family
   Classification using Sequence Alignment”** (2021),
   [arXiv:2111.14185](https://arxiv.org/abs/2111.14185). Connects static
   byte analysis, family classification, and explanations; CyberScan does not
   currently provide validated family attribution.
6. **“MORPH: Towards Automated Concept Drift Adaptation for Malware
   Detection”** (2024), [arXiv:2401.12790](https://arxiv.org/abs/2401.12790).
   Investigates drift adaptation using malware datasets. CyberScan has no
   drift monitor or automated retraining and should not claim to learn new
   threats from distribution changes.
7. **“CNS-Net: Conservative Novelty Synthesizing Network for Malware
   Recognition in an Open-set Scenario”** (2023),
   [arXiv:2305.01236](https://arxiv.org/abs/2305.01236). Directly studies
   open-set malware-family recognition, so unknown-family rejection is also
   not a new idea by itself.

The scoped search did not establish a complete review of structure-aware file
repair literature. No novelty claim is made. The proposed hypothesis remains
unverified:

> Contradiction-guided analysis combined with calibrated uncertainty and
> adaptive selection of additional analysis improves detection of previously
> unseen malware families at a comparable false-positive rate, relative to
> appropriate fixed-analysis baselines.

Testing it requires legally obtained labeled samples, family-disjoint and
temporal splits, false-positive operating points, calibration/selective-risk
analysis, and ablations. No such experiment was run because no suitable
dataset is present.

## Reproducibility

From the project root on Windows:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe main.py
.\.venv\Scripts\python.exe -m ml.training.train --manifest data\datasets\manifest.csv
.\.venv\Scripts\python.exe -m ml.training.evaluate --manifest data\datasets\holdout.csv
```

The training command requires at least 40 unique samples per class and writes
`data\models\structural_classifier_4096.json`. The optional `family` column
enables family/group-disjoint train/validation splitting. There is no ablation
runner or validated real-data result to report yet.

## Test report

The final full-suite command was `.venv\Scripts\python.exe -m pytest -q`:

- **65 passed**
- **0 failed**
- **0 skipped**

This suite verifies software behavior with benign synthetic fixtures. It does
not measure malware detection, family generalization, calibration, or repair
quality.

## Evidence-based scorecard

Scores are 0–5, where 0 means no evidence/implementation and 5 means
independently validated performance. These are engineering-status ratings,
not product rankings.

| Dimension | Score | Evidence |
|---|---:|---|
| Engineering quality | 3/5 | Modular static pipeline and 64 passing tests; several advanced modules and hard resource isolation remain absent. |
| Detection performance | 0/5 | No labeled project dataset or real-data results. |
| Unseen-family generalization | 1/5 | Group-disjoint splitting is supported when identifiers are provided; it has not been evaluated on real families. |
| Calibration and uncertainty | 1/5 | Raw-score Brier/ECE diagnostics exist; no calibration or validated OOD/abstention policy exists. |
| Explanation quality | 2/5 | Evidence-based static findings exist; family attribution and validated explanation fidelity do not. |
| Remediation reliability | 2/5 | Conservative encrypted quarantine/restore APIs exist; no repair, UI workflow, or independent recovery audit. |
| Security hardening | 3/5 | Bounded reads, safe model format, and gated quarantine; native parsers remain unsandboxed and ACLs are external. |
| Reproducibility | 3/5 | Training/evaluation commands and metadata are available; datasets and ablation runner are absent. |
| Research novelty | 0/5 | Related work exists and no novel contribution has been established experimentally. |
| Production readiness | 1/5 | Prototype only; no real-world validation, sandboxing, or operational assurance. |
