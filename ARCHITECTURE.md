# CyberScan component architecture

The target project root has five principal component directories:

```text
CyberScan/
├── Web/       Website backend, frontend, APIs, static assets and deployment
├── Desktop/   Independent Python desktop application and its tests
├── Mobile/    Independent Android application, assets and build configuration
├── AI/        Future agent contracts only; no model, agent loop or web UI
└── Tools/     Shared tool catalog, trusted execution interface and engines
```

Root-level launchers and project documentation may remain, but application
source is owned by one of these components. Web and Android source are kept in
separate directories. Web keeps generated `/m/` assets as a compatibility
distribution copy; Mobile owns their editable source.

`Tools` is the shared boundary for reusable tools and engines. Discovery reads
metadata without importing tool modules. A tool is executable only after
explicit review and source-hash approval. Desktop, Web and future compatible
Mobile runtimes should call this interface rather than reimplement analysis.

`AI` defines typed interfaces for planning, discovery, authorization,
execution, conversation, context and responses. It intentionally has no
working AI agent or website interface.

## Frozen detection engine

`detection/` is the existing Sentinel engine. During migration its Python
source and behavior are treated as immutable. The intended canonical location
is `Tools/detection/`; compatibility path mapping will be retained wherever an
application or test still imports `detection.*`. A content-hash comparison and
the existing detection tests are required before the old path can be retired.

## Component ownership

- **Web:** the canonical website source and its local changes; HTTP contracts,
  frontend behavior and deployment configuration remain unchanged.
- **Desktop:** the Tkinter desktop entry point, its core modules, settings,
  data, reports, rules, monitoring and tests.
- **Mobile:** Android UI assets, Pyodide runtime assets, Capacitor/Gradle
  project, release configuration, signing material and build scripts.
- **AI:** future architecture contracts only.
- **Tools:** tool metadata, static discovery, explicit approvals and shared
  execution boundary; the existing detection engine is not rewritten.

Mobile has no Desktop source imports. Its current bundle builder packages
shared runtime modules from the Web worktree to preserve the existing mobile
bridge; the generated Mobile engine contains that runtime, but standalone
bundle generation without Web remains a known limitation. The root
`pytest.ini` runs Desktop, Tools and Mobile tests; Web tests run in Web's own
environment.

See [MIGRATION.md](./MIGRATION.md) for source locations, build dependencies,
compatibility paths, baselines and migration status.
