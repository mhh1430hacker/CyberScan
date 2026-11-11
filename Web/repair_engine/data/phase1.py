"""Run Phase 1, resumably: ``python -m repair_engine.data.phase1 [step ...]``.

Steps, in order of usefulness on a slow connection:
  tools      ClamAV portable build + YARA Forge rules (digest-checked)
  ember      EMBER2024 small files, then Win64 test
  sorel      SOREL meta.db -> 2,000 selected rows -> disarmed binaries
  benign     Govdocs1, NapierOne, Assemblage slice -> samples/pending
  verify     ClamAV (clamd) + YARA over pending -> samples/benign or dropped
  ember_big  EMBER2024 Win64 train (5.85 GB), vectorised then deleted
  manifest   data_root/manifest.parquet

Every step skips work already done, so the command can simply be run again
after an interruption.
"""
from __future__ import annotations

import sys
import time

from repair_engine.data import benign, ember, manifest, sorel, verify
from repair_engine.data.store import GB, DataStore
from repair_engine.data.tools import fetch_tools

BIG = ("Win64_train.zip",)


def _ember(store: DataStore, big: bool) -> None:
    settings = store.config["ember2024"]
    names = [name for name in settings["files"] if (name in BIG) == big]
    ember.run(store, names)


STEPS = {
    "tools": lambda store: (fetch_tools(store), verify.clamd_config(store)),
    "ember": lambda store: _ember(store, big=False),
    "sorel": sorel.run,
    "benign": benign.run,
    "verify": verify.run,
    "ember_big": lambda store: _ember(store, big=True),
    "manifest": manifest.build,
}


def main(argv: list[str]) -> int:
    store = DataStore()
    steps = argv or list(STEPS)
    for step in steps:
        started = time.monotonic()
        print(f"[phase1] {step} ...", flush=True)
        result = STEPS[step](store)
        used, free = store.used_bytes() / GB, store.free_bytes() / GB
        print(f"[phase1] {step} done in {time.monotonic() - started:.0f}s; data_root {used:.2f} GB, free {free:.1f} GB; {result}",
              flush=True)
        store.log("step_done", step=step, seconds=round(time.monotonic() - started), used_gb=round(used, 2), free_gb=round(free, 1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
