"""Architecture probe: does the 'mirror' architecture exist as described?

Checks concrete, falsifiable properties of the shipped source. Read-only.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT)]

import numpy as np


def main() -> None:
    from core.deep_embedding import HighDimensionalEmbedding
    from core.nextgen_engine import NextGenCyberEngine

    print("== 1. 4096-D vector composition ==")
    rng = np.random.default_rng(7)
    data = rng.bytes(64 * 1024)
    ent = NextGenCyberEngine.analyze_entropy_topography(data)
    cfg = NextGenCyberEngine.extract_cfg_topology(b"\x00" * 4096)
    v = np.asarray(HighDimensionalEmbedding().embed_bytes(data, entropy_topography=ent, cfg_topology=cfg, pe_features={}))
    print(f"  dim={v.size} nan={int(np.isnan(v).sum())} inf={int(np.isinf(v).sum())} "
          f"min={v.min():.4f} max={v.max():.4f} zeros={int((v == 0).sum())}")
    blocks = {"bytes/opcodes": v[0:1024], "entropy": v[1024:2048], "cfg": v[2048:3072], "pe": v[3072:4096]}
    for name, blk in blocks.items():
        print(f"  block {name:<14} non_zero={int((blk != 0).sum()):>4}/1024  std={blk.std():.4f}")
    # PA is the same 1024-block algebra: does an empty PE leave a silent zero block?
    print(f"  -> empty PE block is all zeros: {bool((blocks['pe'] == 0).all())} "
          "(no availability mask, as README states)")

    print("\n== 2. determinism across processes ==")
    print(f"  sha-like checksum of vector: {float(v.sum()):.6f}")

    print("\n== 3. attack surface of native parsers (static census) ==")
    native = []
    for f in sorted((ROOT / "core").glob("*.py")):
        text = f.read_text(encoding="utf-8", errors="ignore")
        for lib in ("yara", "pefile", "capstone", "zipfile", "tarfile"):
            if f"import {lib}" in text:
                native.append(f"{f.name}:{lib}")
    print("  " + ", ".join(native))

    print("\n== 4. does an unsandboxed native call respect the deadline? ==")
    print("  Timeouts are checked between stages (ui/scan_service.py check_deadline);")
    print("  a single stuck native call cannot be interrupted - verify by measuring the")
    print("  worst case in the benchmark (stage0 dominates).")


if __name__ == "__main__":
    main()
