# Blind repair: witness-constrained reconstruction

**Date:** 2026-11-04 · **Code:** `repair_engine/blind/` · **Tests:** `tests/test_repair_engine_blind.py`

## The problem

The executor could already undo an infection when a trusted reference
supplied the missing facts. The hard case was a file whose clean copy
exists nowhere, for example a PE whose entry point was moved into an added
section. The plan recorded it as `report_only`, because "the original entry
point cannot be read from the modified file".

## The idea

The infected file still holds facts about its own clean original. Whatever
produced the file wrote integrity data that was computed **over the clean
file, before the infection**:

| Producer | Witness | Strength |
|---|---|---|
| Linker | PE checksum (ones'-complement sum) | ~16 bits |
| Linker | SizeOfCode / SizeOfInitializedData = sum of section sizes | ~8 / 6 bits |
| Signer | Authenticode image digest (SHA-256 / SHA-1) | 256 / 160 bits |
| Zip tool | CRC-32 per member, central directory offset | 32 per member, 16 |
| PNG encoder | CRC-32 per chunk | 32 per chunk |
| PDF writer | xref byte offset of every object | ~6 per object |

Each of these works like a small hash of an original nobody has. An
infector changes bytes but seldom keeps all of them in step, since the
loader ignores most of them. So they can confirm a reconstruction even
though no clean copy exists.

The engine runs in three steps:

1. **Run the infection backwards** (`hypotheses.py`). An infector has only a
   few ways to get into a file and still let the host run: append data, add
   a section and move the entry point there, or prepend itself and carry the
   host behind it. Undoing each one gives candidate originals. Anything the
   file cannot state (the old entry point, where the old file ended) becomes
   an explicit set of alternatives.
2. **Weigh the evidence** (`witnesses.py`, `pe_entry.py`). A candidate earns
   the bits of every witness the infection broke and the candidate restores.
   It also earns the bits of other testimony:
   * *the infector's own code:* to keep its host working it must hand
     control back, so its body contains a `jmp rel32`, a `push va; ret` or a
     `mov reg, va; jmp reg` that lands in the host's code;
   * *the host's code shape:* compiler entry stubs, x64 `.pdata` function
     starts, function alignment.

   A candidate loses the bits of every witness that held before and that it
   breaks.
3. **Decide** (`__init__.py`). `net = earned − broken − log2(alternatives)`.
   A candidate that rests on an inferred value needs `net ≥ 16` bits, which
   means a wrong reconstruction passing by chance is about 1 in 65 536 or
   rarer. It also needs **two independent sources** (integrity / infector
   code / host shape), or one cryptographic witness alone. The best
   candidate must also beat every *different* candidate by 8 bits. If any of
   this fails, the engine refuses and gives the reason. It never guesses.

### The checksum trick

The PE checksum is a ones'-complement sum of 16-bit words plus the file
length. Sum every word once, leaving out the checksum and the entry-point
field. The entry point's two halves are then the only unknown term. Each
candidate is checked in O(1) (`ChecksumSolver`), so thousands of candidates
cost almost nothing. A wrong candidate passes about 1 time in 65 535.

### Invariant preservation

If the infector kept a field consistent (it recomputed the checksum, or
updated SizeOfCode), the reconstruction recomputes it too. If the infector
left a field alone, the reconstruction keeps the stored value, because
that value is the original's. This rule is what makes the outputs
byte-identical rather than merely valid.

## Where it refuses on purpose

* **The entry point moved, and only one source says where.** Measured on real
  binaries, code shape alone picked another stub-shaped function 7 times in
  296. The two-source rule brought that to 0.
* **Two complete files back to back.** A prepender with its host has the same
  bytes as an installer with its payload. The engine keeps neither half
  until the caller says the front part is the infection
  (`front_is_infector=True`, or `Plan("blind_reconstruct", params={"front_is_infector": True})`).
* **Removing a last section without witnesses.** Every PE ends with some
  section, so on its own this proves nothing.
* **A data directory points into the added section** (redirected imports and
  similar). Removal alone would not undo it.

Cutting appended data at the format's own end is a pure undo, with nothing
inferred. It is accepted without witnesses, as `strip_overlay` already is,
so `blind_reconstruct` must only run on a file a detector has flagged.
Benign overlays exist (installers, MSYS2 binaries).

## Measured (2026-11-04, `python -m repair_engine.blind.measure`)

A real clean PE (System32, 7-Zip) gets a section added and its entry point
moved into it, in memory. Only the infected bytes go to the engine:

| Infector behaviour | Exact original rebuilt | Refused | Wrong |
|---|---|---|---|
| Leaves the original checksum (typical of real infectors) | 184 / 185 | 1 | 0 |
| Recomputes the checksum, random body, no jump back | 0 / 185 | 185 | 0 |
| File had no checksum, random body | 0 / 4 | 4 | 0 |

The same 196 clean files, given to the engine uninfected: **0 false repairs**.
A wider run over 420 clean local files (PEs, Git binaries, PDFs, PNGs, ZIPs)
also gave 0 section removals, carves or entry-point changes. The only
accepted change was 57 cuts of benign appended data, which is the pure undo
described above and needs a detector's flag first.

Unit tests: 64 (entry point recovered from the checksum alone, or from the
jump back plus the entry stub; refusals; section, overlay, prepended PE and
prepended zip undone byte-exactly; 40 fuzzed damaged inputs; the executor
action; `repair_file` with the vault).

## Honest limits

* The infections in the measurements are synthetic (random bodies). Real
  infectors that encrypt or hide the jump back give no infector-code
  testimony. They are repaired only when an integrity witness and the host's
  code shape agree.
* Not covered yet: infectors that grow the last section instead of adding
  one, cavity infectors that overwrite host code (the overwritten bytes are
  gone unless they are stored, encrypted, in the body), and changes to
  imports or TLS callbacks.
* The bit values are conservative estimates, not fitted likelihoods.
