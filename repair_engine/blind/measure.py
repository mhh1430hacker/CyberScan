"""Measure blind repair on real clean programs, infected in memory.

    python -m repair_engine.blind.measure [glob ...]

For each clean PE it adds a section with the entry point moved into it (the
injector's ``pe_entry_redirect``), in two variants: the infector leaves the
original checksum (what most real file infectors do) or recomputes it. Only
the infected bytes are handed to ``reconstruct``; the result is compared
with the clean file it never saw. It also runs ``reconstruct`` on the clean
files themselves, where anything other than a refusal or a cut at the
format's end would be a false repair. Nothing is written to disk.
"""
from __future__ import annotations

import collections
import glob
import random
import sys

from repair_engine import pe_layout
from repair_engine.blind import reconstruct
from repair_engine.synth.injector import _pe_add_section

DEFAULT = (r"C:/Windows/System32/*.exe", r"C:/Program Files/7-Zip/*.exe")


def main(patterns: list[str]) -> int:
    paths = [p for pattern in patterns for p in sorted(glob.glob(pattern))[:250]]
    rng, counts, wrong, false_repairs = random.Random(7), collections.Counter(), 0, 0
    for path in paths:
        try:
            clean = open(path, "rb").read()
        except OSError:
            continue
        if len(clean) > 30 << 20:
            continue
        own = reconstruct(clean)
        if own.decision == "repair" and own.best.family != "truncate_to_logical_end":
            false_repairs += 1
            print("FALSE REPAIR on clean file:", path, own.reason)
        for mode in ("checksum_left", "checksum_fixed"):
            made = _pe_add_section(clean, rng, redirect_entry=True)
            if made is None:
                break
            infected, layout = bytearray(made[0]), pe_layout.read(clean)
            if mode == "checksum_left":
                pe_layout.put_u32(infected, layout.checksum_offset, layout.checksum)
            result = reconstruct(bytes(infected))
            outcome = "refused" if result.decision != "repair" else ("exact" if result.data == clean else "WRONG")
            wrong += outcome == "WRONG"
            counts[(mode, "has_checksum" if layout.checksum else "zero_checksum", outcome)] += 1
    for key, value in sorted(counts.items()):
        print(*key, value)
    print(f"wrong repairs: {wrong}; false repairs on clean files: {false_repairs}")
    return 1 if wrong or false_repairs else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:] or list(DEFAULT)))
