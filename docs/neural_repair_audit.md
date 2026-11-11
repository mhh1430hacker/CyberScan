# CyberScan Repair Prototype Audit

**Audit date:** 2026-10-21  
**Scope:** Existing repository and local `.venv`; no malware samples were
downloaded or executed.

## Baseline

- Project root: `C:\Users\mahdi\Desktop\dist`; it is not a Git repository.
- Runtime: Python 3.14.5.
- Baseline test suite: **65 passed**, with one scikit-learn joblib parallelism
  warning. No tests failed.
- Relevant installed versions: PySide6 Essentials 6.12.0, pefile 2024.8.26,
  Capstone 5.0.9, yara-python 4.5.4, scikit-learn 1.9.1, NumPy 2.5.4,
  pandas 3.0.6, and pytest 9.1.1.
- PyTorch and py7zr are not installed. The current project does not require
  either dependency.
- No training manifest, dataset samples, or active
  `structural_classifier_4096.json` model exists. An anomaly-model joblib file
  exists on disk, but it is not the active supervised three-class classifier.

## Existing architecture

`main.py` starts the PySide6 UI. `core.file_analyzer.analyze_file` performs
bounded static analysis and returns the existing `ScanResult` dataclass.
Feature extraction, heuristics, YARA, PE parsing, risk scoring, optional
structural classification, reports, and UI integrations are already present.
Training and evaluation use a reviewed CSV manifest and deterministic
Random-Forest inference from a bounded JSON model artifact.

The current feature representation has 4,096 engineered coordinates in four
1,024-coordinate blocks. It is lossy. The first block mixes byte histograms,
hashed n-grams, and opcode frequencies; entropy is resampled into the second
block; CFG-like counts and hashed edges populate the third; PE/header-related
values populate the fourth.

## Gaps verified against the requested prototype

- ZIP archives now receive bounded structural inspection, including nested
  ZIPs. This records member paths, content type candidates, SHA-256 hashes,
  duplicate content, and unsafe/encrypted/symlink entries. It does not scan
  archive members for malware.
- File analysis is static and bounded by file size and stage deadlines, but
  there is no hard process isolation or enforceable timeout around native
  parsers.
- The CFG-like representation is not position-aware: instructions are decoded
  from the byte stream start in x86 modes, and the selected decode maximizes
  byte coverage. It does not establish PE section/RVA provenance or reliable
  control flow for arbitrary input.
- Entropy anomalies contain byte offsets, but there is no general
  instruction/basic-block-to-file-offset evidence model or learned region
  localization.
- No trusted-reference repair, scoped rule-based repair, AI repair proposal,
  or independent post-repair verifier exists. Nothing currently authorizes
  arbitrary binary rewriting.
- Training code supports reviewed three-class manifests and group-aware
  holdouts when identifiers are supplied, but it does not generate the
  requested controlled synthetic dataset. No real-world malware efficacy
  claim is supported.
- There is no PyTorch dependency or neural model. Because PyTorch is absent,
  neural-model compatibility is unverified and no installation was attempted.
- Existing Python package declarations are lower bounds rather than a
  fully pinned compatibility matrix. The currently installed stack passed
  tests, but that does not prove compatibility for every allowed resolver
  combination or Python version.

## Implemented slices

`core.archive_inspector.inspect_zip` inspects ZIP structure without filesystem
extraction. Limits are 50 MiB input, 1,000 total entries, 16 MiB per member,
64 MiB total decompressed content, and two nested levels by default. It
validates central-directory counts before the standard-library ZIP parser
builds its entry list. Unsafe paths, symbolic links, encrypted members,
malformed containers, unsupported ZIP64 inputs, and limit outcomes are
reported explicitly. `analyze_file` exposes the summary in its feature data
and engine status.

This slice does not scan archive members with YARA or the normal file
analyzer, classify their contents as malware, repair files, or verify
behavior. ZIP parsing remains in-process and has no hard cancellation or
process-memory quota. Trusted-reference restoration remains future work; no
repair capability is claimed.

`core.position_aware.build_position_aware_evidence` now records bounded,
zero-based half-open byte ranges for entropy transitions, including a hash of
each referenced region and the evidence source. The PE parser reports section
raw offsets and RVAs separately; a raw span is exposed as verified only when
the mapped bytes match the bytes returned by pefile and fit inside the input.
At most 128 transitions are emitted and full-region hashing is capped at 16
MiB per input; omitted hashes and observations are explicit. The evidence is
shown in the Qt evidence panel and text/JSON exports. It does not predict
malicious regions, map instructions/basic blocks, or establish a repair scope.
Entropy transitions remain statistical indicators, not maliciousness evidence
by themselves.

The archive slice added 11 focused tests and the position-aware slice added
ten. The original baseline was **65 passed**. After archive inspection, the
suite passed with **76 passed**; after position-aware evidence was added, the
suite passed with **86 passed**, with no failures or skips. `compileall` passed
for the changed Python files.

## Reproduction

From the project root on Windows:

```powershell
.\.venv\Scripts\python.exe --version
.\.venv\Scripts\python.exe -m pip list --format=freeze
.\.venv\Scripts\python.exe -m pytest -q
```

No dataset was available for training or meaningful security-performance
evaluation during this audit.
