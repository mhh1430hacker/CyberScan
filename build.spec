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
    hiddenimports += collect_submodules(package, filter=lambda name: ".tests" not in name and "test_" not in name)
hiddenimports += ["yara", "yara_x", "pefile", "capstone", "olefile", "pypdf", "aiohttp", "cryptography", "PIL", "zxingcpp",
                  "sklearn.ensemble", "sklearn.tree", "sklearn.utils._typedefs"]

a = Analysis(
    ["main.py"],
    pathex=[ROOT],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    excludes=["tkinter", "matplotlib", "PyQt5", "PyQt6", "IPython", "pytest", "notebook", "jupyter", "boto3", "botocore"],
    noarchive=False,
)
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
