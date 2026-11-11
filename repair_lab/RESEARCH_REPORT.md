# Invariant-guided synthetic repair experiment

## 1. Research hypothesis

**Hypothesis:** “If a component is a finite, declarative state transformer and its legitimate behaviors are specified by observable contracts, then a bounded search over minimal action edits can suppress a simulated forbidden effect while preserving the contracted theme, locale, and retry behaviors.”

**Problem.** With no clean reference, one cannot infer arbitrary intended contents from a file. A narrower opportunity exists when behavior is explicit and an independent contract specifies what must remain true.

**Proposed mechanism.** Invariant-Guided Minimal Repair (IGMR) enumerates bounded deletions and value substitutions, filters candidates through behavior and forbidden-effect constraints, groups equally minimal candidates by resulting declared behavior, and abstains if minimal repairs disagree.

**Different from the simple baseline.** A positional “delete the last instruction” patch has no semantic basis; rejecting the whole component prevents the unwanted effect but loses all functionality. IGMR uses a behavioral contract to locate the smallest satisfying edit and preserves the original input object.

**Expected result.** Repair the synthetic `guard_enabled = false` modification in one edit, preserve all six declared cases, leave clean and validly changed components untouched, and refuse ambiguous or unverified repairs.

**Falsification condition.** The hypothesis fails for this experiment if a repaired threat still produces the forbidden write, any declared legitimate case fails, a clean component is edited, an ambiguous case is reported repaired, held-out verification failure is reported as success, or repeated inputs produce different results.

These success criteria were fixed before recording results.

## 2. Established approaches reviewed

- **Program analysis and behavioral monitoring:** execute or analyze a constrained component against explicit input cases and observe its state changes. Coverage is limited to the tested model.
- **Program repair and constrained synthesis:** generate candidate edits, use tests/invariants as constraints, and minimize edits. This general approach is established; this experiment does not claim to invent automated program repair.
- **Integrity verification:** compare observed behavior/output with specified invariants. Unlike a trusted hash, an invariant can describe allowed behavior without a clean file, but is only as complete as its specification.
- **Capability restriction / fault isolation:** restrict a component to declared operations and contain its effects. Here the interpreter supports only local state writes and never performs external I/O.
- **Differential and regression testing:** exercise fixed behavior cases before and after transformation, with separate held-out verification cases.
- **Content Disarm and Reconstruction (CDR):** an established file-processing technique for supported formats; it reconstructs content under format-specific rules, rather than proving arbitrary files safe.

Sources consulted:
- OWASP, [File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html), recommends CDR for applicable formats and emphasizes layered file validation.
- WHATWG, [HTML parsing standard](https://html.spec.whatwg.org/multipage/parsing.html), illustrates why format-aware transformation must account for defined parsing behavior.
- Microsoft, [Safe Attachments overview](https://learn.microsoft.com/en-us/defender-office-365/safe-attachments-about), describes detonation as a detection layer, not a repair guarantee.

The proposed mechanism is an independently assembled, narrowly scoped combination of candidate search, behavioral contracts, and abstention on ambiguity. No broad literature review was performed, so no worldwide novelty claim is made.

## 3. Synthetic setup

The component is JSON data interpreted by a tiny local state-machine runner; fixture content is not executable code. Its legitimate behaviors set a theme, locale, and retry count, with additional held-out theme and locale cases. The simulated harmful modification adds a `startup` write setting `guard_enabled` to `false`. The contract forbids that write and requires startup to leave the guard enabled.

All state exists in memory. The experiment performs no network, credential, startup, operating-system, or user-file operations. The input component is not mutated by repair.

## 4. Mechanism: exact algorithm and decision rules

**Inputs**
- A component containing at most 16 `set` actions. Each action has a trigger (`when`), declared field, and JSON value.
- A contract specifying field value domains, initial state, forbidden writes, training cases, and held-out verification cases.
- Search limits: at most two edits by default and 5,000 explored component states.

**Candidate edit operations**
1. Delete one action.
2. Replace one action's value with another value in that field's declared domain.

Triggers and target fields are immutable. There is no source-code execution or arbitrary patching.

**Decision procedure**
1. Validate the component and contract shape; reject undeclared fields and malformed actions.
2. Execute the unmodified component for training and held-out cases. If every expected output and invariant passes, return `unchanged` with zero edits.
3. Breadth-first enumerate candidate action lists by edit count, stopping at the first count with any training-valid candidate.
4. Reject candidates that violate an expected training output, write a value outside its declared domain, or produce a forbidden write.
5. Group minimum-edit candidates by their complete final states on every declared training and held-out case. If groups differ, return `ambiguous`; do not select a guess.
6. Select deterministically only among candidates in one behavior-equivalence class.
7. Run held-out cases through a separate verification entry point. Return `repaired` only if it passes; otherwise return `verification_failed`.
8. If no candidate is found within the limits, return `refused` and the unmodified component.

The output includes status, edit count, number of minimum training solutions, number of declared behavior classes, number of explored states, verification status, reason, and a SHA-256 identifier for the returned component.

## 5. Experimental results

Exact test command:

```text
python -m pytest -q repair_lab/test_invariant_repair.py
```

Actual result: **8 passed**.

The experiment runner:

```text
python repair_lab/run_experiment.py
```

Actual results:

| Input case | Outcome | Edits | Held-out verification | Result |
|---|---:|---:|---|---|
| Clean component | `unchanged` | 0 | Pass | No false intervention |
| Legitimate theme change (`dark` to allowed `light`) | `unchanged` | 0 | Pass | Valid change preserved |
| Simulated forbidden startup write | `repaired` | 1 | Pass | Forbidden write suppressed; all 6 declared cases pass |
| Threat plus legitimate theme change | `repaired` | 1 | Pass | `light` behavior preserved; all 6 declared cases pass |
| Ambiguous policy value (`standard` or `restricted`) | `ambiguous` | 1 minimum | Not claimed | Two valid behavioral classes; repair refused |
| Three forbidden writes, beyond two-edit bound | `refused` | — | Not claimed | No repair claimed |
| Threat repaired but a held-out theme behavior is broken | `verification_failed` | 1 candidate | Fail | Success correctly withheld |
| Repeated identical mixed input | Same result object | 1 | Pass | Deterministic |

For both successful threat cases, the search found **2** minimum training-valid candidates but only **1** behavior class across all declared cases. The equivalent candidates differ structurally (for example, restoring the value versus deleting a redundant write); the implementation chooses deterministically within that class.

### Baseline comparison

| Baseline | Forbidden effect | Legitimate behavior |
|---|---|---|
| No intervention, threat case | Occurs | Other behaviors execute, but component violates contract |
| No intervention, mixed case | Occurs | Legitimate changed theme executes, but component violates contract |
| Delete last action, threat case | Still occurs | High-contrast case is lost |
| Delete last action, mixed case | Still occurs | High-contrast case is lost |
| Reject entire component | Suppressed by not running | 0 legitimate behaviors available |
| IGMR, threat and mixed cases | Suppressed | All 6 declared cases pass after a one-edit repair |

Within this toy model, the mechanism outperforms both non-intervention and a position-based deletion: it suppresses the defined effect without discarding the required behaviors.

## 6. Functional preservation and failure cases

Each successful repair passes the four training cases (theme, locale, retries, startup) and two held-out cases (high-contrast theme and Arabic locale). The mixed case additionally verifies the legitimate `light` theme value. Tests verify the original fixture remains unchanged.

IGMR abstained in all three intentionally unsafe cases:
- Multiple distinct minimal behaviors: `ambiguous`.
- Required work beyond the edit bound: `refused`.
- Training-valid candidate that violates held-out behavior: `verification_failed`.

These are desired fail-closed outcomes, not successful repairs.

## 7. Evidence and hypothesis assessment

For this finite synthetic component class, the results support the hypothesis: both harmful variants were repaired with one edit; all six declared behaviors passed; the clean and allowed-change fixtures were unchanged; ambiguity and verification failures were not reported as success; and repeated runs were deterministic. The positional-delete baseline failed to suppress the simulated effect and removed a valid high-contrast behavior.

This is evidence only about the specified state machine and contract. It does not demonstrate detection or disinfection of malware. An incomplete, incorrect, or attacker-influenced contract can authorize harmful behavior or reject legitimate behavior.

## 8. Known limitations

- Only declarative, finite `set` actions are modeled; no real program binaries, scripts, control flow, concurrency, persistence, or external side effects.
- Forbidden effects must be known and encoded in advance. Unknown malicious behavior is invisible to this mechanism.
- Contract completeness and trust are unresolved. The experiment assumes the contract is correct; it does not infer one from an untrusted file.
- Search is bounded and may refuse a repair that requires more than two edits or exceeds the state limit.
- Tests cover only the specified cases; passing them does not prove equivalence or safety for untested states.
- Hashing identifies the returned JSON representation; it is not a trust or safety verdict.
- No production-ready parser, sandbox, file replacement, rollback, or integration with CyberScan exists.

## 9. Next experiment before any integration

Extend the synthetic DSL with conditional transitions and side-effect traces, then generate many benign and harmful mutations to measure precision, recall, false intervention, ambiguity rate, and search cost against a fixed held-out corpus. Independently review the behavioral contract and use a mature test/harness framework. Only after that should a format-specific, non-executable configuration use case be considered; do not apply this mechanism to arbitrary executables or claim files are clean.

## 10. Files in this experiment

- `repair_lab/invariant_repair.py` — bounded candidate search, contract evaluation, ambiguity handling, and held-out verification.
- `repair_lab/test_invariant_repair.py` — eight focused tests.
- `repair_lab/run_experiment.py` — reproducible outcome and baseline measurements.
- `repair_lab/README.md` — short reproduction instructions.
- `repair_lab/fixtures/invariant_repair/contract.json` — behavior and invariant contract.
- `repair_lab/fixtures/invariant_repair/ambiguous_contract.json` — intentionally under-specified policy contract.
- `repair_lab/fixtures/invariant_repair/clean.json`
- `repair_lab/fixtures/invariant_repair/threat.json`
- `repair_lab/fixtures/invariant_repair/legitimate_change.json`
- `repair_lab/fixtures/invariant_repair/mixed.json`
- `repair_lab/fixtures/invariant_repair/ambiguous.json`
- `repair_lab/fixtures/invariant_repair/bounded_failure.json`
- `repair_lab/fixtures/invariant_repair/verification_failure.json`

No project files outside `repair_lab` were modified.
