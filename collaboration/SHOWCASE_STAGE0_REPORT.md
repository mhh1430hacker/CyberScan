# Showcase — Stage 0 report (honesty fixes)

Author: SHOWCASE · Date: 2026-11-10 · Status: **patch ready for owner review — not applied, not committed**

Patch: `collaboration/patches/showcase-stage0.patch` (SHA-256 `870d61b5…84c9431`, 35 files, +945 / −62).
Base: `Desktop/dist` HEAD `609c26b3`. The patch also applies cleanly on top of the current working tree, including
Guardian's uncommitted edits; both were checked with `git apply --check` on scratch copies.
Work was done in a scratch export of HEAD. `Desktop/dist` was only read; no file there was changed.

## What changed

| Issue | Before | After |
|---|---|---|
| I1 hero card | Score `87`, size `412 KB`, "really a program": all typed in by hand | Score, size and verdict come from `data/story.json`. Each finding line is shown only if the scan reported it. Labelled **ENGINE OUTPUT**, with "one example, not a benchmark" |
| I1 story | Score `87`, random cell colours, hand-placed regions | Real scores before and after repair (**100 → 0**). Each cell is coloured by measured entropy. Red regions sit at the repair engine's real offsets. Labelled, with the file's size and SHA-256 |
| I2 | "Ask the AI" covered the story's last HUD stat at 1440×900 | HUD moved clear of the button. No overlap at 1920, 1440, 1024, 768, 390 or 360 px |
| I3 | Phone headline and intro sat on the particle shield | A soft scrim and text shadow behind the hero copy at ≤1000 px. CSS only; `gl-hero.js` untouched |

**Without the data file**, the card and HUD show "—" and the ENGINE OUTPUT labels stay hidden. The page never shows an invented number.

## Where the numbers come from

`web_v/make_story_data.py` (new; same pattern as `make_science_data.py`):
- Builds `invoice_2026.pdf.exe` (2,220 B) deterministically: a one-page invoice PDF, plus a later incremental update
  that adds an `/OpenAction` JavaScript action, plus 384 pseudo-random bytes after `%%EOF`.
- The script is a text string only. Its "encoded PowerShell" decodes to `Write-Output 'CyberScan demo'`. Nothing is executed.
- Scans it through `detection.service.default_service().analyze_upload`, the same bounded call `/api/scan/file` uses.
  Engine `2026.11.10`, process isolation.
- Repairs it with `repair_engine.analyze.repair`, choosing what a user would choose in the Repair view: roll back the
  update, cut the tail, and rename to match the real content. The copy is then scanned again the same way.
- Two runs give byte-identical output. Run with `--engine-root` to read engines from another checkout.

Real results: **100/100 SUSPICIOUS**.
- Evidence: double extension, header mismatch, data after the end, YARA `EncodedPowerShell`, and a content finding
  "PDF auto-executes JavaScript". ATT&CK T1059.001.
- Repaired copy: 1,475 B, all validation checks passed, rescan **0, `NO_INDICATORS_OBSERVED`**. The page says
  "no indicators found", never "safe".

Copy fixed to match the truth: hero line 1 now reads "Named like a PDF, but ends in .exe" (the file's real content is
a PDF, not a program). The story's three tags were already true, and the engine confirms each one.

## Files

- New: `web_v/make_story_data.py`, `web_v/static/data/story.json`.
- Landing-only: `static/js/story.js`, `static/js/landing.js`, `static/landing.css`, and in `static/index.html` only
  lines inside the LANDING block (hero card, story).
- Shared with the workspace: `static/js/i18n.js` and the 28 `static/i18n/*.js` files. Changes: one landing string
  (`lCardF1`) plus three new landing keys (`provTag`, `cardProv`, `storyProv`), in all 30 languages. No workspace code
  reads these keys.
  - Translations are mine, so a native-speaker review is advisable for languages other than en, ar, de, fr, es.

## Workspace regression (scan.ainex-ai.xyz)

`/app.html` from the patched copy is identical to the base, except for the per-start random session token.
- Of the 23 scripts and stylesheets it loads, only `js/i18n.js` differs: the shared keys above.
- No change to `app.js`, `scan.css`, `fx.css`, `styles.css`, `server.py`, `services.py`, `assistant.py`, `ask.js`,
  `ask.css`, `sw.js`, any API, the apps or `detection/`.

## Tests

- Browser (Chromium, served by the copy's own `run.py`). No console or page errors at any size, in Arabic RTL, with
  reduced motion, or with the data file blocked. No horizontal overflow at 360–1920 px. Screenshots checked: hero
  desktop and phone, story acts scan, vault and rebuilt, RTL story, phone story.
- Web Python tests (`test_interface`, `test_ux_review_fixes`, `test_scan_flow`, `test_assistant`,
  `test_scan_service`): 9 passed / 11 skipped / 1 error, **identical on base and patched copy**. The error is an
  environment gap (`arabic_reshaper` missing in this Python), not a regression.
- Root suite of this checkout: **214 passed**. That is the 204 baseline plus 10 tests that arrived with the
  five-component migration.

## Findings for others (not fixed: outside my scope)

1. **Repair engine (Guardian/owner):** `pdf_update` refuses to roll back an update when the script is in a separate
   stream (`/JS 7 0 R`): "the last update also changes other objects". Real malicious PDFs commonly use that layout.
   `_pdf_update_objects` should also take objects that the chosen ones reference, not only objects that reference
   them. The demo uses an inline `/JS (...)` so the story shows only what the product really does.
2. **Repair engine naming:** the "extension doesn't match the content" fix renames `invoice_2026.pdf.exe` →
   `invoice_2026.pdf.pdf`. The story shows that name as-is, because it's what the product produces.
3. **Pending for SENTINEL:** Guardian's review request on the `Tools/detection/` canonical path (DISCUSSION.md).
   Not done in this stage.

## Review guide (added after the owner approved the results, pending code review)

Status: design and results approved by the owner; **the patch is not approved for merge**. Do not apply it to `Desktop/dist`.

Where the logic is (the rest is data and translations):

| File | What to check |
|---|---|
| `js/story.js` (+60 lines) | Loads `data/story.json` once (shared `window.CS_STORY` promise with landing.js) and validates its shape (320 entropy values, scan, repair). Regions, entropy, scores and repaired name come only from it. With no data or a malformed file, the original choreography plays and the score shows "—" |
| `js/landing.js` (+22 net) | Hero card reads the same promise. Each finding line is shown only if its evidence label is in the scan. Verdict is hidden unless the classification is `SUSPICIOUS`. Score is clamped to 0–100 |
| `landing.css` (+30) | Provenance labels shown only with `.has-engine-data`; HUD offsets (I2); hero scrim at ≤1000 px (I3) |
| `index.html` (+2/−1) | Two provenance paragraphs and the size slot, inside the LANDING block only |
| `make_story_data.py` (new) | Builds the demo file, scans and repairs it, writes the JSON. Fails loudly if engine findings change |

To try it without touching `Desktop/dist`: export HEAD to a scratch folder, run `git apply showcase-stage0.patch`
there, then `python web_v/run.py --port 8792 --no-open`, and open `/` (main site) and `/app.html` (workspace).

**Weakness found on re-read (not fixed; owner's call):** if `story.json` fails to load, the story still plays its
original choreography, with red regions and the three tags. It shows no score and no "engine output" label, but it
also has no "illustrative" label. Proposed fix (a few lines): in that case show an `ILLUSTRATIVE` tag in
`.story-prov`. Say if it should go into this patch or into Stage 2.

Minor: `card.classList.add("no-data")` sets a class nothing uses (harmless).

## Revision r2 (owner code review) — supersedes the patch above

Patch: `collaboration/patches/showcase-stage0-r2.patch` (SHA-256 `82034f13…2c29a06`, 36 files, +1329 / −67).
It applies cleanly to HEAD `609c26b3` and to the current `Desktop/dist` working tree (checked on scratch copies).
`showcase-stage0.patch` (r1) is kept for history only. Do not apply r1.

1. **Missing-data transparency.**
   - Without valid data, the hero card and the story both show an **ILLUSTRATIVE** label (amber tag plus a sentence)
     and no score ("—").
   - The fallback regions, tags and filename are drawn in **amber**, not red, so they can't be mistaken for engine
     findings.
   - The label is visible from first paint and is removed only after validation succeeds.
   - New i18n keys `illusTag`, `cardIllus` and `storyIllus`, in all 30 languages.
2. **One shared validator.** `CSStory.validate` / `CSStory.load()` sits at the top of `story.js`. It is the only fetch
   of `story.json`, and `landing.js` only reads its promise, so the card and the story cannot disagree. It checks:
   - **Entropy:** 320 finite numbers, each from 0 to 8.
   - **Scores:** scan and rescan are integers from 0 to 100.
   - **Classifications:** one of `SUSPICIOUS, REVIEW, UNKNOWN, NO_INDICATORS_OBSERVED, SAFE, CLEAN`.
   - **File:** name pattern, size from 1 to 4 MiB, and a lowercase 64-hex SHA-256.
   - **Regions:** tag indices 0–2 with no duplicates; cell and byte bounds; the cell range matches the byte range;
     no overlaps; at least one byte region.
   - **Repair:** `selected`, `name_after`, `size_after`, `removed_bytes` and `sha256_after` are all present;
     `size_after + removed_bytes = size`; `checks_failed` is empty; the rescan is valid.

   Malformed or unparseable data, a 404 and a network error all produce the same fallback.
3. **Reproducibility.** The `generated` date was removed and the JSON has no timestamp. For the same engine code it is
   byte-identical on any day (two runs compared). The docstring states this; the engine version stays in `scan.engine`.
4. **Entropy method** is documented in the generator docstring, in `story.js`, and in `cells.entropy_method`:
   - Shannon entropy over a 64-byte window centred on each cell, clamped at the file's ends.
   - Cells are about 7 bytes apart, so adjacent windows overlap.

   The visual model is unchanged.

**Tests:**
- `tests/test_story_data.py` (new, 8 tests; Node.js is needed for the validator tests, which are skipped without it):
  - the demo file rebuilt without engines matches the JSON (bytes, SHA-256, every entropy value, region offsets);
  - the JSON has no timestamp;
  - the shared validator accepts the committed data;
  - it rejects missing data (`null`, `{}`, a string) and **34 malformed variants**;
  - `landing.js` doesn't fetch on its own.

  The tests are real: weakening the validator made them fail.
- Browser: `collaboration/patches/showcase-stage0-browser-qa.mjs`. Valid, missing (404), network error,
  unparseable, malformed score and malformed entropy. All five failure cases show ILLUSTRATIVE, amber, "—", and the
  card and story agree. Valid shows ENGINE OUTPUT, red and 100. No page errors. The original size, RTL and
  reduced-motion suite still passes.
- Web Python tests: base 9 passed / 11 skipped / 1 environment error; patched 17 passed (+8 new) / 11 / 1 (same error).
- Workspace: `/app.html` is identical apart from the session token, and only the shared `js/i18n.js` differs among its
  assets (landing-only keys).

Not changed: detection engine, repair engine, workspace code, `Desktop/dist`. No commit, push or deploy.

## Next

Stage 2 (Nex) starts only after the owner approves r2 for merge review.
