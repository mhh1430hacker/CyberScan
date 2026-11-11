"""Generate harmless test samples on demand (nothing here is real malware).

    python scripts/make_samples.py [output_dir]

Creating the files at run time keeps an EICAR file out of the source tree, where
antivirus products would otherwise quarantine or corrupt the project archive.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def main() -> None:
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "data" / "demo_samples"
    out.mkdir(parents=True, exist_ok=True)

    # Standard anti-malware test string: benign by definition.
    (out / "eicar_test.txt").write_bytes(EICAR)

    # Low-entropy header followed by random bytes: exercises the entropy-discontinuity detector.
    header = b"MZ" + b"\x00" * 100 + b"CYBERSCAN_TEST_HEADER_NORMAL_TEXT\n"
    (out / "mock_high_entropy.bin").write_bytes(header + os.urandom(1024))

    # Spoofed extension: PE magic bytes inside a .txt file.
    (out / "spoofed_pe.txt").write_bytes(b"MZ\x00\x00\x00\x00some text data")

    print(f"Samples written to {out}")


if __name__ == "__main__":
    main()
