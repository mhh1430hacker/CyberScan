"""Copy the Mobile app into Mobile/android/www, the folder Capacitor packs into the APK.

    Web\\.venv\\Scripts\\python.exe Mobile\\build_android_www.py
    cd Mobile\\android && npx cap sync android

Only what the app needs on the phone goes in: the /m/ app, Pyodide and the icon.
The desktop site, the server and the service worker stay out (inside the APK
every file is already on the device, so nothing needs caching).
"""
from __future__ import annotations

import argparse
import shutil
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
STATIC = HERE / "static"
WWW = HERE / "android" / "www"
WEB_STATIC = ROOT / "Web" / "web_v" / "static"

START = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="color-scheme" content="dark"><title>CyberScan</title>
<meta http-equiv="refresh" content="0; url=m/index.html">
<style>html,body{margin:0;height:100%;background:#07051a}</style>
</head><body></body></html>
"""


def sync_web_compat() -> None:
    """Refresh the web-served /m/ assets from Mobile's canonical source."""
    WEB_STATIC.mkdir(parents=True, exist_ok=True)
    shutil.copytree(STATIC / "m", WEB_STATIC / "m", dirs_exist_ok=True)
    shutil.copytree(STATIC / "pyodide", WEB_STATIC / "pyodide", dirs_exist_ok=True)
    shutil.copy2(STATIC / "icon.svg", WEB_STATIC / "icon.svg")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sync-web-compat", action="store_true",
                        help="refresh Web's compatibility copies of Mobile assets")
    args = parser.parse_args()
    if args.sync_web_compat:
        sync_web_compat()
    if WWW.exists():
        shutil.rmtree(WWW)
    WWW.mkdir(parents=True)
    shutil.copytree(STATIC / "m", WWW / "m")
    shutil.copytree(STATIC / "pyodide", WWW / "pyodide")
    shutil.copy2(STATIC / "icon.svg", WWW / "icon.svg")
    (WWW / "index.html").write_text(START, encoding="utf-8")
    size = sum(p.stat().st_size for p in WWW.rglob("*") if p.is_file())
    print(f"www ready: {size / 1e6:.1f} MB in {WWW}")


if __name__ == "__main__":
    main()
