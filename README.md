# CyberScan

CyberScan is a defensive file and URL analysis project organized into five
independent components:

| Component | Purpose |
|---|---|
| [`Web/`](./Web/) | Website backend, frontend, APIs and deployment configuration |
| [`Desktop/`](./Desktop/) | Independent Python desktop application |
| [`Mobile/`](./Mobile/) | Android application, offline assets and build configuration |
| [`AI/`](./AI/) | Future agent contracts only; no agent or website AI interface |
| [`Tools/`](./Tools/) | Shared, explicitly approved tool catalog and frozen detection engine |

The root `main.py` is a compatibility launcher for the Desktop application.
The detailed desktop capabilities and limitations are documented in
[`Desktop/README.md`](./Desktop/README.md). Tool metadata, safe discovery and
the shared execution contract are documented in [`Tools/README.md`](./Tools/README.md).
The architectural record and verified migration status are in
[`ARCHITECTURE.md`](./ARCHITECTURE.md) and [`MIGRATION.md`](./MIGRATION.md).

## Run and test

- Desktop: `python main.py` (install desktop dependencies with
  `python -m pip install -r Desktop/requirements.txt`).
- Desktop, Tools and Mobile Python regression suites: `python -m pytest -q`
  from the project root.
- Web: follow [`Web/README.md`](./Web/README.md); its test suite uses the Web
  component's own environment.
- Android: follow [`Mobile/android/ANDROID.md`](./Mobile/android/ANDROID.md).
  Building requires the Android SDK and a Java 21 JDK. The signed release
  workflow is not run as part of local validation.

No uploaded file is executed by the static-analysis tools. A tool discovered
from disk remains disabled until its exact source hash is explicitly approved.
