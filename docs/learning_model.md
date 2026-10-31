# The learning model (structural classifier)

CyberScan ships without a trained model, and it never runs one that a person
has not approved. Until you approve one, results say *Learning model: not
available right now* and explain why. Everything else works without it.

A model trained on synthetic or unreviewed files would produce numbers with
no meaning on real files, so none is provided.

## 1. Collect reviewed samples

You need real files in three classes, each label decided by someone who
reviewed it: `clean`, `suspicious` and `malware`. Keep malware in an isolated,
authorised location. CyberScan only reads bytes and never executes a file.

Write a manifest (CSV) with one row per file:

```
path,label,source
samples/clean/setup_notes.pdf,clean,vendor original
samples/suspicious/macro_invoice.docm,suspicious,analyst review 2026-10
samples/malware/sample_0142.bin,malware,MalwareBazaar SHA-256 verified
```

Relative paths resolve from the manifest's folder. Identical files are
deduplicated; conflicting labels for the same bytes are rejected.

## 2. Train

```powershell
.venv\Scripts\python.exe -m ml.training.train --manifest path\to\manifest.csv --output data\models\structural_classifier.approved.json
```

The command prints the holdout metrics and the artifact's SHA-256. The file is
plain JSON (`cyberscan-forest` format): no pickle, nothing executable.

Evaluate on files that were not used for training:

```powershell
.venv\Scripts\python.exe -m ml.training.evaluate --manifest path\to\holdout.csv --model data\models\structural_classifier.approved.json --sha256 <digest>
```

## 3. Approve

```powershell
.venv\Scripts\python.exe -m ml.approve_model data\models\structural_classifier.approved.json
```

The command verifies the file with the safe loader, shows its digest and
training metadata, and asks you to type `yes`. Approval records the path and
SHA-256 in `data\trusted_models.json`. If the file changes afterwards, scans
reject it until you approve it again.

```powershell
.venv\Scripts\python.exe -m ml.approve_model --status   # what is approved now
.venv\Scripts\python.exe -m ml.approve_model --revoke   # stop using it
```

## What the model changes

Its opinion appears under *Learning model* in the result and in the advanced
data. Its scores are uncalibrated and are not probabilities. By default
(`ml_weight` 0.0) it does not change the risk score or the verdict.

The seven legacy model files in the repository are not in this format; they
cannot be approved and are never loaded.
