# -*- mode: python ; coding: utf-8 -*-
# CyberScan desktop (Windows): the Qt app (main.py -> ui.qt_app) packaged with PyInstaller.
#
#     .venv\Scripts\pyinstaller.exe build.spec --noconfirm
#
# Output: dist\CyberScan\CyberScan.exe (a folder build: fast start, and far fewer antivirus false
# alarms than a single self-extracting exe). History and settings are written per user to
# %LOCALAPPDATA%\CyberScan\data (config.py), never into the program folder.
import os

from PyInstaller.utils.hooks import collect_submodules

ROOT = os.path.abspath(SPECPATH)

# Runtime data only: interface assets, rules, protection data, model profiles, repair tables.
# (reports/ holds generated reports and is not shipped; tests and caches are skipped.)
DATA_DIRS = ["ui", "rules", "intel/data", "ml/models", "models", "repair_engine/config", "repair_engine/data"]
SKIP_EXT = (".py", ".pyc", ".pyo", ".md")
datas = []
for rel in DATA_DIRS:
    base = os.path.join(ROOT, rel)
    if not os.path.isdir(base):
        continue
    for folder, dirs, files in os.walk(base):
        dirs[:] = [d for d in dirs if d not in ("__pycache__", "tests")]
        for name in files:
            if name.endswith(SKIP_EXT):
                continue
            src = os.path.join(folder, name)
            datas.append((src, os.path.relpath(folder, ROOT)))

# The app imports some engines lazily (only when a scan needs them): name them so they are packed.
hiddenimports = []
for package in ("core", "detection", "ui", "ml", "repair_engine", "reports", "monitoring", "intel"):
    hiddenimports += collect_submodules(
        package,
        # repair_engine.data builds training datasets (pyarrow/parquet, downloads): never used by the app
        filter=lambda name: ".tests" not in name and "test_" not in name and not name.startswith("repair_engine.data"),
    )
hiddenimports += ["yara", "yara_x", "pefile", "capstone", "olefile", "pypdf", "aiohttp", "cryptography", "PIL", "zxingcpp",
                  "sklearn.ensemble", "sklearn.tree", "sklearn.utils._typedefs"]

# Size (2.1.0): the 2.0.0 folder was 583 MB, mostly dataframe libraries nothing in the app uses.
# scikit-learn imports narwhals, and PyInstaller then follows narwhals' optional backends (polars
# 164 MB, pyarrow 84 MB, pandas 13 MB, dask, duckdb...). narwhals only touches a backend when it is
# handed one of its objects, so leaving them out is safe; `CyberScan.exe --self-test` (main.py)
# loads every engine and runs real scans in the frozen build to prove it.
EXCLUDES = [
    "tkinter", "matplotlib", "PyQt5", "PyQt6", "IPython", "pytest", "notebook", "jupyter", "boto3", "botocore",
    "polars", "_polars_runtime_32", "pyarrow", "pandas", "fsspec", "dask", "distributed", "duckdb", "ibis",
    "pyspark", "modin", "sqlframe", "cudf", "lightgbm", "xgboost", "torch", "tensorflow", "sympy", "numba",
    "repair_engine.data", "sklearn.datasets.tests", "scipy.datasets", "pooch", "setuptools", "pip",
    "PIL.ImageQt", "PIL.ImageTk",  # (numpy.f2py stays: numpy imports it at start-up)
]

a = Analysis(
    ["main.py"],
    pathex=[ROOT],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    excludes=EXCLUDES,
    noarchive=False,
)
# Qt's software OpenGL fallback (20 MB): the window paints with QPainter only, no OpenGL/QML.
a.binaries = [b for b in a.binaries if os.path.basename(b[0]).lower() != "opengl32sw.dll"]
# Qt's own translations: keep only English and Arabic (the app translates everything else itself).
def _keep(dest):
    d = dest.replace("\\", "/").lower()
    if "pyside6/translations/" in d:
        return d.endswith(("_ar.qm", "_en.qm"))
    return "/tests/" not in "/" + d  # test data shipped inside packages
a.datas = [x for x in a.datas if _keep(x[0])]

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="CyberScan",
    icon=os.path.join(ROOT, "ui", "assets", "cyberscan.ico"),
    console=False,
    upx=False,          # UPX-packed binaries trigger antivirus heuristics; size isn't worth it
    version=None,
)

coll = COLLECT(exe, a.binaries, a.datas, name="CyberScan", upx=False)
