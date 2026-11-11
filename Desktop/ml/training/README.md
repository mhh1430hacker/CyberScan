# Model training and evaluation

CyberScan has no bundled real malware corpus and does not claim a trained
malware classifier by default. Synthetic examples are not accepted as active
model provenance.

## Training manifest

Create a CSV with the columns `path,label,source`. Labels are `benign` or
`malicious`; `source` records the analyst's label basis. The training command
reads files statically and never executes them. Relative paths resolve from the
manifest directory. Duplicate file hashes are deduplicated, and conflicting
labels for identical bytes are rejected.

Training requires at least 40 unique benign and 20 unique malicious samples.
The data is split with a fixed stratified holdout. IsolationForest is fitted
only on the benign training partition; the malicious partition is reserved for
evaluation. A saved model includes the manifest hash, feature schema version,
sample hashes, and holdout metrics.

```powershell
python -m ml.training.train --manifest data/datasets/manifest.csv
```

The `source` values are user-provided and are not independently verified by
CyberScan. Use an authorized, isolated dataset and keep malware files
quarantined; the analyzer only reads their bytes.

## Independent evaluation

Evaluate with a separate manifest containing both labels. The evaluator rejects
any file hashes that overlap the model's training hashes.

```powershell
python -m ml.training.evaluate --manifest data/datasets/holdout.csv
```

Metrics describe only that holdout set. IsolationForest anomaly scores are not
calibrated probabilities, and these workflows do not establish zero-day
detection, universal antivirus coverage, or generalization to unseen malware.

When a compatible, provenance-bearing model is absent, the application falls
back to static evidence and reports the ML layer as unavailable.
