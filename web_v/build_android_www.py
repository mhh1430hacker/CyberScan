"""Copy the phone app into web_v/android/www, the folder Capacitor packs into the APK.

    .venv\\Scripts\\python.exe web_v\\build_android_www.py
    cd web_v\\android && npx cap sync android

Only what the app needs on the phone goes in: the /m/ app, Pyodide and the icon.
The desktop site, the server and the service worker stay out (inside the APK
every file is already on the device, so nothing needs caching).
"""
from __future__ import annotations

import shutil
from pathlib import Path

HERE = Path(__file__).resolve().parent
STATIC = HERE / "static"
WWW = HERE / "android" / "www"

START = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="color-scheme" content="dark"><title>CyberScan</title>
<meta http-equiv="refresh" content="0; url=m/index.html">
<style>html,body{margin:0;height:100%;background:#07051a}</style>
</head><body></body></html>
"""


def main() -> None:
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
