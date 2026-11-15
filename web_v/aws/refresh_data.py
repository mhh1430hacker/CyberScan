"""Put fresh protection data into an existing Lambda package, leaving everything else as it is.

    python web_v/aws/refresh_data.py live.zip fresh-data-dir new.zip

Used by .github/workflows/refresh-protection.yml: the daily job downloads the package the site
is running, replaces only intel/data/ (YARA-Forge rules, malware links, phishing domains, secret
patterns from intel/fetch.py) and uploads the result. The site's code is never rebuilt here.
"""
from __future__ import annotations

import sys
import zipfile
from pathlib import Path

PREFIX = "intel/data/"
# a download that came back empty or cut short must never replace good data
MINIMUM = {"forge.yarx": 2_000_000, "urlhaus.txt.gz": 100_000, "phishing-domains.txt.gz": 500_000,
           "secrets.json": 20_000, "manifest.json": 50}


def main() -> None:
    live, data, out = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
    fresh = {p.name: p.read_bytes() for p in data.iterdir() if p.is_file()}
    for name, least in MINIMUM.items():
        size = len(fresh.get(name, b""))
        if size < least:
            sys.exit(f"{name}: {size} bytes, expected at least {least}; keeping the current data")
    with zipfile.ZipFile(live) as src, zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as dst:
        kept = 0
        for old in src.infolist():
            if old.filename.startswith(PREFIX):
                continue
            info = zipfile.ZipInfo(old.filename, old.date_time)
            info.external_attr = old.external_attr
            info.compress_type = zipfile.ZIP_DEFLATED
            dst.writestr(info, src.read(old.filename))
            kept += 1
        for name, content in sorted(fresh.items()):
            info = zipfile.ZipInfo(PREFIX + name)
            info.external_attr = 0o100644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            dst.writestr(info, content)
    print(f"kept {kept} files, replaced {PREFIX} with {len(fresh)} fresh files")


if __name__ == "__main__":
    main()
