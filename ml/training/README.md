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

## Engines that check the model's reasoning

These run during every scan and need no malware corpus: they learn what honest
software looks like and measure departures from it.

**Claim-capability dissonance** (`core/dissonance.py`). A program's claim (its
name and version resource) is reduced to a role; its imports and strings to
capabilities. Surprise is `-log2 P(capability | role)` over benign programs,
weighted by harm, plus explicit lies (a program named like a document, an
unsigned Windows process name). It starts from an expert prior; fit it on your
own benign programs with

```powershell
python -m ml.training.fit_dissonance --directory "C:\Program Files" --output models\dissonance.json
```

and set `dissonance_profile` / `dissonance_profile_sha256` in the settings.
On 826 programs installed on the development machine, forced to count as
unsigned, 805 scored low, 21 medium and none high; most mediums were genuine
Windows processes that are catalog-signed in a real scan.

**Compression surprise map** (`core/surprise_map.py`). Per part of a PE file
(headers, code, data, resources, overlay), the benign byte distribution and the
benign quantiles of each 4 KiB window's KL divergence from it. A window beyond
the benign 99.9th percentile of its part is foreign there; foreign code is a
finding, and every foreign window is located in the structure view and galaxy.
The shipped `ml/models/surprise_profile.json` was fitted on Windows System32;
refit with `python -m ml.training.fit_surprise`.

**Conformal abstention** (`ml/conformal.py`). Training calibrates a threshold
on the validation split; the model commits to a class only when calibration
rules out the others, otherwise the scan says the model is not sure and rests
on static evidence. With too few calibration examples for the requested
`--conformal-alpha` it always abstains. `ml.training.evaluate` reports coverage
and abstention on an independent holdout.

**Orbit invariance** (`ml/orbit.py`). Loader-equivalent variants of a PE file
(overlay appended, timestamp, checksum, section names, Rich header) must get
the same verdict. Training reports `orbit_stability` on the validation split;
`--orbit-augment N` adds N variants per training file with the original label.
Variants exist only in memory.

**Counterfactual self-audit** (`ml/counterfactual.py`). For a non-clean verdict,
regions are blanked one at a time, smallest first; the first whose removal
clears the verdict is what it rests on. A verdict resting on a part the loader
ignores is reported as weak. `--self-audit` retrains once after up-weighting
training samples whose verdict rested on such a part.
