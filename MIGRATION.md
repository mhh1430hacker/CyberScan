# CyberScan component migration

## Outcome

The local project has been reorganized around five principal components:

```text
CyberScan/
├── Web/          canonical website worktree copy and Web-only compatibility assets
├── Desktop/      independent Python desktop application
├── Mobile/       Android application and its editable source/assets
├── AI/           future architecture contracts only
└── Tools/        shared catalog, execution interface and Sentinel engine
```

Root-level documentation, collaboration records, a Desktop launcher, and
compatibility test/dependency entry points remain. The duplicated Desktop
source tree at the project root and the duplicate Android project under
`Web/web_v/android/` were retired only after target copies were checked.
Web retains its generated `/m/` assets and small legacy Android forwarding
scripts; it no longer owns the Capacitor/Gradle application.

## Before and after inventory

### Before

```text
Documents/final/CyberScan/
  core/, data/, detection/, ml/, monitoring/, reports/, rules/, scripts/,
  tests/, ui/, config.py, main.py, requirements*.txt       Desktop sources
  Desktop/dist/                                            canonical website
    web_v/                                                 website and APIs
    web_v/static/m/, web_v/static/pyodide/                 served mobile assets
    web_v/android/                                         Android source/build
  collaboration/                                           shared coordination
```

`Desktop/dist` is a separate repository at
`C:\Users\mahdi\Desktop\dist`; it is not the `Desktop/` component directory
created in this project. The project workspace itself was not a Git repository.

### After

```text
CyberScan/
  Web/                 local clone of the canonical website, including its
                       initial dirty/untracked worktree content
  Desktop/             copied desktop application, tests, data and settings
  Mobile/              Android project, offline source/assets and build tools
  AI/                  typed future-agent contracts; no agent or UI
  Tools/               registry, adapter, tests and canonical detection engine
  collaboration/        append-only Sentinel/Guardian records
  main.py               backwards-compatible Desktop launcher
  README.md, ARCHITECTURE.md, MIGRATION.md, CHANGELOG.md
  pytest.ini, conftest.py, requirements*.txt, .gitignore
```

Web keeps `web_v/static/m/` as a generated compatibility copy so existing
`/m/` URLs continue to work. `Web/detection/` and `Desktop/detection/` are
import-path shims to `Tools/detection/`, not engine copies.

## File migration inventory

| Original source | Destination / disposition | Verification |
|---|---|---|
| Root `core/`, `data/`, `ml/`, `monitoring/`, `reports/`, `rules/`, `scripts/`, `ui/`, `tests/`, `config.py`, `.env.example` | `Desktop/` equivalents | 73 non-cache source/config files rechecked with no missing or hash-mismatched copies; Desktop tests pass. |
| Root `detection/` | `Tools/detection/`; Desktop and Web keep shims | All 14 frozen source/documentation files match the recorded SHA-256 manifest. |
| Root launcher | `Desktop/main.py` plus root `main.py` forwarding entry point | Root import resolves to `Desktop.main`; Desktop regression suite passes. |
| Canonical website `C:\Users\mahdi\Desktop\dist` | `Web/` local clone | Initial 77 dirty/untracked paths were copied byte-for-byte; canonical source remains untouched. |
| Website Android project and assets | `Mobile/` | Source files were compared against the canonical Android tree; all differences were confined to generated build/cache outputs or documented wrapper/build changes. |
| Existing served mobile assets | `Mobile/static/` editable source; `Web/web_v/static/m/` generated compatibility copy | 20 files, no missing/extra/hash differences after generation. |
| Tool registry and detection adapter | `Tools/` | Registry suite passes; discovery does not import candidate files and execution requires exact-hash approval. |
| Future agent interfaces | `AI/` | Documentation/contracts only; no model, agent loop, permission bypass or Web interface. |

Mobile's legacy Android folder under Web was reduced to forwarding/pointer
files (`ANDROID.md`, release and asset-generator wrappers). Capacitor, Gradle,
store assets, Android source and build configuration now live under
`Mobile/android/`.

## Shared tool execution contract

The contract and examples are maintained in [`Tools/README.md`](./Tools/README.md).
A tool is a Python module in an approved `Tools/<category>/` directory and
declares a unique ID, descriptive metadata, version, input/output schemas,
privacy/processing declarations, and `run(input_data, options=None)`.

`Tools/registry.json` controls approved categories and trusted source hashes.
Discovery parses literal metadata and the entry-point signature without
importing or executing modules. Duplicate IDs, malformed metadata and import
errors are surfaced as per-tool states/results. A tool is not executable until
an authorized maintainer approves the SHA-256 of its exact source. Web and
Desktop use the same registry API; Mobile packages the same sources and
exposes list/run messages through its existing worker bridge. The included
Sentinel adapter remains disabled until explicitly approved.

## AI foundation

`AI/` defines the future planning, discovery, permission, execution,
orchestration, conversation, context and response contracts. It deliberately
does not implement a fake agent or website interface. The future runtime is
expected to call the same approved `Tools` interface.

## Dependencies and configuration

- No Python or JavaScript package dependency was introduced for the registry
  or migration.
- Desktop dependencies and settings are owned by `Desktop/`; root
  `requirements*.txt` files forward to those manifests for compatibility.
- Root `pytest.ini` selects Desktop, Tools and Mobile tests. Web tests remain
  in the Web component's Python environment.
- Mobile owns the Capacitor and Gradle configuration, release workflow, and
  bundled runtime. Its build scripts can refresh Web's compatibility assets.
- The Web Lambda builder now stages shared Tools and a detection import shim;
  it was syntax-checked, but the packaging task was not executed because it
  fetches external threat data and writes a deployment artifact.
- `Mobile/build_mobile.py` still packages shared runtime modules from the Web
  worktree to preserve the existing mobile bridge behavior. The generated
  engine contains those modules, and Mobile source has no Desktop imports, but
  building the bundle is not yet independent of the Web checkout.
- Android synchronization (`npm run sync`) succeeded. A debug APK from the
  earlier successful build remains at
  `Mobile/android/android/app/build/outputs/apk/debug/app-debug.apk`.
  A fresh Gradle rebuild after synchronization could not run here because the
  machine has no Java 21 JDK; Gradle reports that requirement explicitly.
  No signed release was built.

## Validation results

| Scope | Result |
|---|---|
| Desktop regression suite | **204 passed** |
| Tools registry tests | **8 passed** |
| Mobile bundle/worker tests | **2 passed** |
| Root combined Desktop + Tools + Mobile suites | **214 passed** |
| Full Web suite after migration shims | **637 passed, 1 skipped** |
| Web API / detection-service targeted tests | **6 passed** |
| Android asset generation and Capacitor sync | **Passed** |
| Android debug build | Previously passed; fresh rebuild blocked by missing Java 21 JDK (not a source compile failure) |
| Frozen Sentinel source | **14/14 hashes match** the recorded freeze manifest |
| Root launcher and detection compatibility imports | **Passed** |

The Web suite's known pre-migration backdrop assertion failure did not recur;
the post-migration full suite passed.

## Preserved behavior and limitations

- Website routes, frontend behavior, deployment files, and the original
  uncommitted website work remain in `Web/`; no production source was deployed.
- Desktop features, data, settings, entry point and tests were copied before
  the old root source paths were retired.
- Mobile app identity, Android project, local assets, release/signing setup,
  permissions and existing UI were preserved in `Mobile/`. The release script
  was not run and signing material was not published.
- Sentinel's frozen detection implementation was not edited. Only canonical
  placement and import-path shims changed.
- The engine bundle was extracted and its tool registry/discovery behavior
  tested. An actual Pyodide browser/WebView session was not exercised.
- Sentinel's independent review of the new canonical engine path and
  compatibility shims is pending; no review result is assumed.
- No iOS project was present.
- Mobile bundle generation still reads shared runtime sources from Web, as
  noted above; fully removing this build-time coupling requires a separately
  validated shared-runtime extraction.
- The debug rebuild still requires a Java 21 JDK to repeat in this environment.

## Repository and release state

The canonical website repository remains on its original branch and commit;
its existing dirty/untracked worktree was not changed. No commit, push,
deployment, signed release or publication was performed. The local `Web/`
clone contains intentional migration changes and retains the copied starting
worktree state; no Git history or remote state was modified.
