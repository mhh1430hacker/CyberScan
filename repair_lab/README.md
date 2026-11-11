# Invariant-guided synthetic repair experiment

This isolated experiment tests whether a small, declarative component can be minimally repaired without a clean copy. It uses only harmless JSON fixtures and a tiny interpreter; the "harmful" behavior is a deterministic write of `guard_enabled = false` in a simulated preferences component.

The mechanism searches edits to individual `set` actions, keeps only candidates satisfying behavior contracts and forbidden-effect invariants, then abstains if equally minimal candidates imply different declared behavior. It never executes fixture code or accesses files beyond this lab.

## Reproduce

From the project root, run:

```text
python -m pytest -q repair_lab/test_invariant_repair.py
python repair_lab/run_experiment.py
```

`RESEARCH_REPORT.md` records the hypothesis, decision rules, baseline comparison, limitations, and exact measured results. This is a research prototype, not an antivirus or production repair tool.
