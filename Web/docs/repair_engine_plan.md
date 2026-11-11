# Repair engine: malicious region localization and extraction — plan

**Date:** 2026-11-01 · **Status:** Phase 0 done; Phase 2 in progress.

## What exists today

| Piece | Where | Reused for |
|---|---|---|
| Static scan pipeline (`analyze_file` → `ScanResult`) | `core/file_analyzer.py` | File-level evidence for the report |
| Entropy windows with byte offsets | `core/entropy.py`, `core/position_aware.py` | Entropy track (M2 input), boundary evidence |
| PE parsing (pefile) | `core/pe_decompiler.py` | Same library, used by the PE region parser |
| ZIP member inspection | `core/archive_inspector.py` | Archive regions |
| Bounded, non-executable model format | `ml/forest_format.py`, `ml/model_runtime.py` | The rule that no model loads through pickle/joblib |
| Trusted-reference repair, content disarm, verifier | `repair_lab/` | Executor + validator patterns (backup, hash checks, rollback) |
| Repair screen (read-only preview) | `ui/repair.py` | Later UI for `analyze` / `repair` |

The product is Python 3.14 + PySide6, so the shipped models are called from
Python. They will still be exported to ONNX (run with `onnxruntime`), so no
model is ever loaded through pickle.

## Where the new code lives

```
repair_engine/
  __init__.py          analyze(path) -> report ; repair(path) -> {clean_file, extracted_regions, report}
  regions.py           Region dataclass + RegionMap (exact [start, end) offsets, parent links)
  parsers/             Phase 2: one parser per format, all pure static reads
    __init__.py        parse(data, name) -> RegionMap ; dispatch by magic, never by extension alone
    pe.py elf.py ole.py ooxml.py pdf.py zip.py image.py generic.py
  config/data.yaml     Phase 1 sizes, disk budget, sources (not config/ at the root: it would shadow config.py)
  data/                Phase 1 download + verification scripts, manifest builder
  synth/injector/      Phase 3b inert injection families
  models/              Phase 4 training (M1/M2/M3), ONNX export
  executor/            Phase 4 deterministic per-format repair routines
  validator.py explainer.py
tests/repair_engine/   unit + integration tests (part of the default suite)
```

Data samples never live in the repo. They go under a dedicated directory
(`settings: repair_data_dir`), every binary renamed `<sha256>.bin`.

## Safety rules, and how the code enforces them

- No module in `repair_engine/` imports `subprocess`, `os.system`, `ctypes`,
  `exec`, `eval` or a loader. A test greps the package and fails on any of them.
- Parsers only read bytes they were handed (`bytes` in, `RegionMap` out). They
  never take a path for a dataset sample, so nothing can be opened by another
  program.
- SOREL disarmed headers are never restored. If pefile/LIEF reject a file, the
  parser returns a `generic` map plus a logged `parse_error`; nothing patches
  the bytes to make it parse.
- Synthetic injections (Phase 3b) use only random bytes, zero padding or fixed
  placeholder text. A test checks injected payloads against that whitelist.
- Benign sets: every file is scanned with ClamAV + public YARA rules before it
  enters the manifest; hits are dropped and logged.
- Every download is verified against the official checksum when published.

## Blockers found in Phase 0 (need your decision)

1. **Disk.** C: has about **12 GB free** of 925 GB. E: is a 7 MB read-only
   installer disc. EMBER2024 features alone are tens of GB, and 200k SOREL
   binaries are on the order of a few TB. Phase 1 cannot run here without an
   external or secondary drive. `data.yaml` will carry a hard disk budget, and
   the downloader refuses to start when the budget exceeds free space.
2. **No `noexec` mount on Windows.** Closest equivalent: a dedicated folder
   on a separate volume with an NTFS ACL that denies Execute. Alternatively,
   do Phase 1 inside a Linux VM or WSL with a real `noexec` mount, which is
   what I recommend for the malware-side data.
3. **Missing tools.** ClamAV is not installed (required for benign
   verification). PyTorch, onnx/onnxruntime, LightGBM, SHAP, LIEF, oletools
   and pyarrow are not installed. PyTorch wheels for Python 3.14 should be
   checked; training may need a separate 3.12 environment.
4. **Compute.** RTX 4060 Laptop (8 GB VRAM), Ryzen 7 7435HS, 16 GB RAM.
   Enough for M1 and for a memory-efficient M2 (MalConv2-style chunking,
   small batches) on a subset; not for full SOREL-scale training in
   reasonable time. 16 GB RAM also caps how much of EMBER's feature
   matrix can be loaded at once, so M1 trains from memory-mapped shards.

## Phase order and what can be done now

| Phase | Needs downloads? | Plan |
|---|---|---|
| 2 Parsers | No | Build now with pefile + stdlib (ELF, ZIP, PDF, OLE CFB, OOXML, images). Tests on fixtures built in the tests themselves. |
| 3b Injector | No | Next: inert injection families over generated clean fixtures, saving `(modified, offsets, original)` triples. |
| Executor + validator | No | Next: deterministic per-format removal with checksum/offset fixes, encrypted quarantine of extracted regions, rollback. Verified byte-identical on 3b triples. |
| 1 Data | **Yes (TBs)** | Waits for disk/VM/ClamAV decisions. Scripts + `data.yaml` can be written and dry-run before then. |
| 3a MIL, 4 M1/M2/M3 | Yes | After Phase 1. M1 needs EMBER2024 features only (tens of GB). |
| 5 Evaluation | Yes | Temporal split; release blocker: 0 modified files on held-out benign set. |
| 6 Integration | No | `analyze` / `repair` API is defined in Phase 2 and filled in as phases land. |

## Honest limits up front

Region accuracy on *real* infections cannot be measured with this data:
SOREL/EMBER give file-level labels, and synthetic injections only
approximate real techniques. The README will say so.

## Progress log

### Phase 2 — format-aware parsing: done (2026-11-01)

- `repair_engine/parsers/`: PE, ELF, ZIP/OOXML, OLE, PDF, PNG/JPEG/GIF, plus
  extension/magic mismatch. Format comes from magic bytes; the name is only
  used to report a mismatch. `RegionMap.snap()` moves predicted spans onto
  structural boundaries.
- Tests: `tests/test_repair_engine_parsers.py`, 25 tests. Fixtures are built
  byte by byte in `tests/repair_fixtures.py` with placeholder content only.
  They cover exact offsets for every format, fragmented OLE macro streams,
  mini-stream streams, escaped PDF names, `endstream` inside stream data,
  objects hidden in compressed object streams, indirect `/Length`,
  zip-with-prefix, and truncation/corruption fuzzing (no exception, no region
  outside the file). A test also fails if any engine module imports a
  process, loader or deserialization facility.
- Smoke test on 45 real local files (Windows system PEs, signed vendor
  PEs, JPEG/PNG, PDF manuals, a 44 MB JDK zip): no parse errors after two
  fixes found this way. The fixes were the JPEG end marker at the very end
  of the file, and standalone JPEG markers.
- Speed: PE 5–70 ms (8 MB DLL: 70 ms), JPEG/PNG < 4 ms, ZIP 44 MB with
  28k regions: 0.23 s, PDF about 0.2 s/MB (decompresses every Flate stream).
- Noted for clean-file safety later: MSYS2/Git binaries carry a benign
  overlay (appended symbol data). Overlay alone must never trigger repair.
- Disk/compute used: none beyond the repository (~60 KB of code).

### Phase 1 — data acquisition: built, downloads paused (2026-11-01)

Pipeline in `repair_engine/data/` (store, verified downloads, EMBER2024
vectoriser, SOREL selection, benign collection, ClamAV/YARA verification,
manifest), 9 offline tests. Downloads are paused by request; exact state,
tags and resume commands: `docs/repair_engine_downloads.md`.

### Phase 3b + executor + validator: done (2026-11-01)

- `repair_engine/synth/`: inert content (random / zeros / placeholder only,
  checked by `is_inert`) and 9 injection families with exact offsets and an
  M3 label: `append_after_end`, `high_entropy_block`, `magic_mismatch`,
  `pe_add_section`, `pe_entry_redirect`, `ooxml_vba_part`,
  `ooxml_embedded_object`, `pdf_javascript`, `pdf_embedded_file`.
  Not built yet: `pe_resource_blob`, `ole_vba_stream`,
  `ole_embedded_object`, `elf_add_section` (need a resource-tree / CFB /
  ELF section writer).
- `repair_engine/executor/`: deterministic actions with refusals instead of
  guesses (signed spans, entry point inside the section, PDF updates holding
  other edits, zip64...). Removed bytes are sealed in the project's `CSQ1`
  AES-GCM vault format. `run.repair_file` never touches the original and
  writes output only after validation passes. `remove_ole_stream` refuses
  (not implemented).
- `repair_engine/validator.py`: parse, format structure (PE arithmetic +
  checksum, every ZIP CRC, PDF final xref), optional scorers.
  `clean_confirmed` stays False until M1/M2 exist, so no auto-repair yet.
- Tests: `tests/test_repair_engine_synth.py` (19). Whole engine: 59 tests.
- Oracle round trip (ground-truth plans, so this measures the executor, not
  a model) on 78 real local files (Windows/Git/7-Zip PEs, PDF manuals, Office
  files, JPEG/PNG, text), in memory: 314/315 byte-identical and validated.
  The one miss was a parser gap (zip with >64 KiB appended), now fixed; the
  Office/zip re-run is 70/70.
- `pe_entry_redirect` is labelled `report_only`: the original entry point
  cannot be read from the modified file. With a trusted reference value the
  executor restores it (24/24 byte-identical in the run above).
- Found on this machine: a local antivirus (Avast/Kaspersky/McAfee are
  registered; Defender is off) blocks reading back even the clean, inert
  minimal PE fixture once written to disk (`ERROR_VIRUS_INFECTED`, Errno 22).
  So synthetic PE variants must be generated in memory or stored compressed,
  and the benign pipeline drops files that become unreadable after writing.

### Blind repair (no clean copy): done (2026-11-04)

- `repair_engine/blind/`: witness-constrained reconstruction. Infection
  patterns are undone into candidate originals, and the file's own integrity
  witnesses (PE checksum and size fields, Authenticode digest, zip/PNG CRCs,
  PDF xref offsets) plus the infector's jump back and the host's code shape
  choose between them. It refuses unless there are 16 bits net, two
  independent sources and an 8-bit margin. New executor action
  `blind_reconstruct`. `pe_entry_redirect` is now repairable when the
  infector left the checksum: 184/185 real PEs rebuilt byte-identical,
  0 wrong, 0 false repairs on the clean set. Details and limits:
  `docs/blind_repair.md`.
