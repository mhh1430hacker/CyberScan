"""Build the AWS packages for the CyberScan website.

    .venv\\Scripts\\python.exe web_v\\aws\\build_lambda.py

Writes web_v/aws/out/:
  cyberscan-lambda.zip   the function: website + engine + Linux libraries (Python 3.13, x86_64)
  cyberscan-assets.zip   files larger than Lambda may return: Pyodide and the APK (upload to S3)

Everything comes from the last commit (git), so local data, keys, history and
uncommitted work are never packed. See web_v/aws/DEPLOY_AWS.md.
"""
from __future__ import annotations

import io
import json
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT / "web_v"))
import build_mobile  # noqa: E402  (the same engine file list the phone app uses)

OUT = HERE / "out"
BUILD = OUT / "build"
PYTHON = "3.13"
PLATFORM = "manylinux2014_x86_64"
LIBS = ["numpy", "pefile", "cryptography", "capstone"]   # yara: pure-Python reader, see yara_lite.py
ASSET_PREFIXES = ("web_v/static/pyodide/",)


def git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, check=True).stdout


def show(path: str) -> bytes:
    return subprocess.run(["git", "show", f"HEAD:{path}"], cwd=ROOT, capture_output=True, check=True).stdout


def is_asset(path: str) -> bool:
    return path.startswith(ASSET_PREFIXES) or (path.startswith("web_v/static/downloads/") and path.endswith(".apk"))


def main() -> None:
    if git("status", "--porcelain", "--", "web_v").strip():
        print("note: web_v has uncommitted changes; the packages use the last commit.")
    shutil.rmtree(OUT, ignore_errors=True)
    BUILD.mkdir(parents=True)

    # ---------------------------------------------------------------- code
    paths = set(build_mobile.FILES) | set(build_mobile.TREE_FILES)
    for tree in build_mobile.TREES:
        paths |= set(build_mobile.list_tree("HEAD", tree))
    web = [p for p in git("ls-files", "web_v/static").splitlines()]
    assets = [p for p in web if is_asset(p)]
    paths |= {p for p in web if not is_asset(p)}
    paths |= {"config.py"}
    for rel in sorted(paths):
        target = BUILD / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(show(rel))
    (BUILD / "lambda_function.py").write_bytes(show("web_v/aws/lambda_function.py"))
    (BUILD / "yara.py").write_bytes(show("web_v/yara_lite.py"))
    (BUILD / "sklearn").mkdir()
    (BUILD / "sklearn" / "__init__.py").write_text("")
    (BUILD / "sklearn" / "ensemble.py").write_text(build_mobile.SKLEARN_STUB.format(name="RandomForestClassifier"))
    (BUILD / "sklearn" / "preprocessing.py").write_text(build_mobile.SKLEARN_STUB.format(name="LabelEncoder"))
    for pkg in ("core", "ml", "monitoring", "reports", "ui", "repair_engine", "web_v"):
        init = BUILD / pkg / "__init__.py"
        if (BUILD / pkg).is_dir() and not init.exists() and pkg != "web_v":
            init.write_text("")

    # ---------------------------------------------------------------- Linux libraries
    subprocess.run([
        sys.executable, "-m", "pip", "install", "--quiet", "--disable-pip-version-check", "--no-compile",
        "--target", str(BUILD), "--platform", PLATFORM, "--implementation", "cp", "--python-version", PYTHON,
        "--only-binary=:all:", *LIBS,
    ], check=True)
    for junk in list(BUILD.rglob("__pycache__")) + list(BUILD.glob("numpy/**/tests")) + list(BUILD.glob("bin")):
        shutil.rmtree(junk, ignore_errors=True)

    # ---------------------------------------------------------------- zips
    lam = OUT / "cyberscan-lambda.zip"
    with zipfile.ZipFile(lam, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for f in sorted(BUILD.rglob("*")):
            if f.is_file():
                z.write(f, f.relative_to(BUILD).as_posix())
    ast = OUT / "cyberscan-assets.zip"
    with zipfile.ZipFile(ast, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        for rel in assets:
            z.writestr(rel.removeprefix("web_v/static/"), show(rel))
    unzipped = sum(f.stat().st_size for f in BUILD.rglob("*") if f.is_file())
    info = {"python": PYTHON, "platform": PLATFORM, "libs": LIBS, "commit": git("rev-parse", "--short", "HEAD").strip(),
            "lambda_zip_mb": round(lam.stat().st_size / 1e6, 1), "lambda_unzipped_mb": round(unzipped / 1e6, 1),
            "assets_zip_mb": round(ast.stat().st_size / 1e6, 1), "assets": [a.removeprefix("web_v/static/") for a in assets]}
    (OUT / "BUILD.json").write_text(json.dumps(info, indent=1))
    shutil.rmtree(BUILD)
    print(json.dumps({k: v for k, v in info.items() if k != "assets"}, indent=1))


if __name__ == "__main__":
    main()
