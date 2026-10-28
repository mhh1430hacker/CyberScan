# CyberScan — UI Redesign Audit (NOR)

## What actually launches

- Entry point: `main.py` → `ui.qt_app.main()` → `CyberScanApp(QMainWindow)`.
- Dependency: `.venv` at the project root, PySide6.
- Launch command: `.venv\Scripts\python.exe main.py`
  (also `run_app.bat` / `.vscode/launch.json`).
- `ui/app.py` (about 2.6k lines) and `ui/qt_widgets.py` are a **legacy
  Tkinter/Tk-era or unused copy**. They are not imported by the launch
  path. The real UI is `ui/qt_app.py` (one 2.6k-line file).

## Why the previous pass was not perceptible

1. **The previous work WAS live.** The baseline screenshot
   (`shots_before/01_home.png`) shows the status banner, the single
   "Analyze target" primary action, the grouped settings and the new
   composer. Nothing was "not shipped".
2. The change was **too local**. It edited surfaces inside an existing
   composition: same 292 px sidebar, same 8-item flat nav, same
   headline + stat strip + form + lab-panel stack, same one-file
   layout. The page skeleton, navigation model and information
   hierarchy were never redesigned, so the product still read as the
   same app.
3. The design system lived in **one global `APP_STYLE` qss string**
   with per-widget `setStyleSheet()` escapes. There was no token
   layer and no reusable widget library, so visual consistency and
   distinctiveness could not be scaled across pages.
4. Density was uniform: every view was a stack of bordered boxes with
   equal weight, so nothing established a focal point.

## Verified defects found in the live UI

- **Startup language is Arabic** (`العربية`) although the persisted
  default and every test expect English. The language button and the
  RTL auto-detection disagree, so the first frame is mirrored for
  English users. This is the single highest-impact first-run bug.
- `toggle_language()` raised `Internal C++ object already deleted`
  during capture — retranslation touches widgets that were rebuilt,
  so switching language can crash.
- Duplicate language controls (sidebar + top bar).
- Sidebar "New analysis" duplicates the first nav item.
- Decorative grid background plus several competing accent tones.

## Real capabilities available (and verified in code)

- `ScanService.analyze(..., progress=callback)` reports **4 real
  stages** (static evidence, entropy/structure, 4096-D projection,
  intelligence) with running/complete states. Current UI shows them
  as four small progress cards.
- `ScanResult` provides: heuristic score, ML risk score
  (uncalibrated), combined score, `classification`, `evidence`
  (Finding: category/severity/evidence/explanation), `feature_summary`,
  `yara_matches`, `pe_analysis`, `mitre_techniques`, `osint_summary`,
  `engine_status`, `limitations`, `model_status`.
- History persistence, report export, download monitoring, settings
  persistence, Arabic translations.

## Hard constraints (from the test suite — must not break)

- `window.styleSheet() == qt_app.APP_STYLE`
- `"#070b12"` and `"background: transparent"` remain in `APP_STYLE`
- `window.pages.count() == 8`, page objectName `"page"`
- `len(window.stage_labels) == 4`, `len(window.mode_values) == 3`
- `analyze_button.text() == "Analyze target"`
- central widget is `AnimatedBackground`; `BrandMark` inside sidebar
- default language English

## Design direction chosen

A **precision instrument**, not a dashboard: near-black canvas, a
single deep surface family, one accent (signal cyan) used only for the
primary action and live state, semantic severity colours used sparingly,
a real typographic scale (display/section/body/label/mono), and a
navigation that collapses to an icon rail. Composition shifts from
"equally weighted boxes" to a deliberate focal hierarchy: target entry
→ live analysis → verdict.

## Implementation plan

1. Token layer + rebuilt `APP_STYLE` (same attribute name, new design).
2. New shell: rail/brand, contextual page header, single language control.
3. Rebuild the analysis page around one focal composer + integrated
   live stage indicator + verdict-first results.
4. Carry the system across all 8 pages.
5. Fix the language/startup and retranslation defects.
6. Verify with real on-screen capture, UI tests, then full suite.
