"""Approve (or revoke) the structural model CyberScan may use.

    python -m ml.approve_model path/to/model.json      # verify, show, ask, record
    python -m ml.approve_model path/to/model.json --yes
    python -m ml.approve_model --status
    python -m ml.approve_model --revoke

Approval records the file's SHA-256 digest. If the file changes afterwards,
it is rejected at scan time until it is approved again.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from ml import model_runtime
from ml.structural_classifier import StructuralClassifier


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Approve the structural model CyberScan may use.")
    parser.add_argument("model", nargs="?", type=Path, help="model artifact (cyberscan-forest JSON)")
    parser.add_argument("--yes", action="store_true", help="approve without asking")
    parser.add_argument("--status", action="store_true", help="show the current state")
    parser.add_argument("--revoke", action="store_true", help="remove the approval")
    args = parser.parse_args(argv)

    if args.revoke:
        print("Approval removed." if model_runtime.revoke() else "Nothing was approved.")
        return 0
    if args.status or args.model is None:
        state = model_runtime.model_state()
        print(f"{state.state}: {state.detail}")
        if state.sha256:
            print(f"sha256: {state.sha256}\npath:   {state.path}")
        return 0

    path = args.model
    if not path.is_file():
        print(f"No such file: {path}", file=sys.stderr)
        return 2
    digest = model_runtime.file_sha256(path)
    probe = StructuralClassifier(path)
    if not probe.load(path, expected_sha256=digest):
        print(f"Not approvable: {probe.metadata.get('load_error')}", file=sys.stderr)
        return 1
    print(f"File:    {path.resolve()}\nSHA-256: {digest}")
    for key in ("trained_at", "n_samples", "classes_present", "manifest_sha256", "split", "dataset_provenance"):
        if key in probe.metadata:
            print(f"{key}: {probe.metadata[key]}")
    if not args.yes:
        answer = input("Approve this model for CyberScan? Type 'yes' to confirm: ").strip().lower()
        if answer != "yes":
            print("Not approved.")
            return 1
    entry = model_runtime.approve(path)
    print(f"Approved. Registry: {model_runtime.registry_path()}\napproved_at: {entry['approved_at']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
