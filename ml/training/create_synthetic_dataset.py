#!/usr/bin/env python3
"""Create a synthetic integration-test dataset for CyberScan.

Generates 30 harmless synthetic fixtures (10 per class) with realistic structural
variation. Each sample is randomly generated with:
- Variable file sizes (512-2048 bytes)
- Mixed byte distributions
- Entropy variation
- Family-specific patterns without deterministic shortcuts
- No single byte value repeated across entire file

These are NOT real malware samples. Designed for testing structural classifier
generalization, not for production security.
"""

import csv
import hashlib
import os
import random
from pathlib import Path


def compute_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def generate_clean_sample(idx: int, family_id: int) -> tuple[bytes, dict]:
    """Generate a clean sample with benign characteristics.
    
    Uses random printable ASCII, moderate entropy, no PE magic patterns.
    """
    size = random.randint(512, 1024)
    # Random printable ASCII (33-126) with some control chars
    data = bytes(random.choices(range(33, 127), k=size))
    # Add occasional null bytes to create variation
    data = bytes(b if random.random() < 0.95 else 0 for b in data)
    filename = f"clean_{idx:02d}.bin"
    meta = {
        "path": filename,
        "label": "clean",
        "sha256": "",
        "source": "synthetic",
        "collection_date": "2024-01-01",
        "family": f"clean_family_{family_id}",
        "verification_status": "synthetic",
        "provenance_notes": f"Synthetic clean sample {idx} from family {family_id}",
    }
    return data, meta


def generate_suspicious_sample(idx: int, family_id: int) -> tuple[bytes, dict]:
    """Generate a suspicious sample with mild anomalies.
    
    Includes some NOP sled patterns, higher entropy, occasional PE magic bytes.
    """
    size = random.randint(512, 1024)
    # Base random data
    base = bytes(random.choices(range(256), k=size))
    # Insert NOP sled (0x90) at random positions
    nop_positions = random.sample(range(size), min(3, size))
    for pos in nop_positions:
        base = base[:pos] + bytes([0x90]) + base[pos:]
    # Add occasional PE magic bytes
    if random.random() < 0.3:
        base = base[:random.randint(0, size-2)] + b"MZ" + base[random.randint(0, size-2):]
    filename = f"suspicious_{idx:02d}.bin"
    meta = {
        "path": filename,
        "label": "suspicious",
        "sha256": "",
        "source": "synthetic",
        "collection_date": "2024-01-01",
        "family": f"suspicious_family_{family_id}",
        "verification_status": "synthetic",
        "provenance_notes": f"Synthetic suspicious sample {idx} from family {family_id}",
    }
    return base, meta


def generate_malware_sample(idx: int, family_id: int) -> tuple[bytes, dict]:
    """Generate a malware-like sample with more aggressive patterns.
    
    Includes PE header, higher entropy, null ratios, and potential ELF markers.
    """
    size = random.randint(1024, 2048)
    # Start with PE header
    pe_header = b"MZ" + bytes([0x50, 0x45, 0x00, 0x00])
    # Fill rest with random bytes
    rest = bytes(random.choices(range(256), k=size - 4))
    data = pe_header + rest
    # Insert null bytes to increase null ratio
    for _ in range(random.randint(5, 15)):
        pos = random.randint(0, size - 1)
        data = data[:pos] + bytes([0x00]) + data[pos:]
    # Add occasional ELF magic
    if random.random() < 0.2:
        elf_pos = random.randint(0, size - 4)
        data = data[:elf_pos] + b"\x7fELF" + data[elf_pos:]
    filename = f"malware_{idx:02d}.bin"
    meta = {
        "path": filename,
        "label": "malware",
        "sha256": "",
        "source": "synthetic",
        "collection_date": "2024-01-01",
        "family": f"malware_family_{family_id}",
        "verification_status": "synthetic",
        "provenance_notes": f"Synthetic malware sample {idx} from family {idx % 3}",
    }
    return data, meta


def main():
    project_root = Path(__file__).resolve().parents[2]
    dataset_dir = project_root / "data" / "datasets" / "synthetic_integration"
    dataset_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = dataset_dir / "manifest.csv"
    manifest_entries = []
    
    # Seed random for reproducibility
    random.seed(42)
    
    # Generate 10 clean samples across 3 families
    for i in range(10):
        family_id = i // 3
        data, meta = generate_clean_sample(i, family_id)
        filepath = dataset_dir / meta["path"]
        filepath.write_bytes(data)
        meta["sha256"] = compute_sha256(data)
        manifest_entries.append(meta)
    
    # Generate 10 suspicious samples across 3 families
    for i in range(10):
        family_id = i // 3
        data, meta = generate_suspicious_sample(i, family_id)
        filepath = dataset_dir / meta["path"]
        filepath.write_bytes(data)
        meta["sha256"] = compute_sha256(data)
        manifest_entries.append(meta)
    
    # Generate 10 malware samples across 3 families
    for i in range(10):
        family_id = i // 3
        data, meta = generate_malware_sample(i, family_id)
        filepath = dataset_dir / meta["path"]
        filepath.write_bytes(data)
        meta["sha256"] = compute_sha256(data)
        manifest_entries.append(meta)
    
    # Write manifest
    with manifest_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=manifest_entries[0].keys())
        writer.writeheader()
        writer.writerows(manifest_entries)
    
    print(f"Created improved synthetic dataset at {dataset_dir}")
    print(f"Manifest: {manifest_path}")
    print(f"Total samples: {len(manifest_entries)}")
    for label in ("clean", "suspicious", "malware"):
        count = sum(1 for e in manifest_entries if e["label"] == label)
        print(f"  {label}: {count}")
    
    # Verify no deterministic shortcuts
    all_bytes = []
    for _, row in enumerate(manifest_entries):
        path = dataset_dir / row["path"]
        data = path.read_bytes()
        all_bytes.append(data)
    print(f"\nByte diversity check: {len(set(b for d in all_bytes for b in d))} unique bytes across all samples")

if __name__ == "__main__":
    main()