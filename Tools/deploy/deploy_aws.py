"""One-step deploy of the CyberScan website to AWS.

    python tools/deploy/deploy_aws.py            (or double-click deploy.bat)

1. downloads the package that is live now (S3: deploy/cyberscan-lambda.zip);
2. replaces/adds the project's current files in it: the website (web_v/static, server code),
   team photos, the engines (core, detection, repair_engine, Tools, intel data) and the
   pure-Python packages olefile + pypdf; everything else in the package is kept;
3. backs up what was live (dated copy + deploy/cyberscan-lambda-previous.zip);
4. uploads the new package, updates the Lambda function and waits until it is active;
5. clears the CloudFront cache (one distribution serves ainex-ai.xyz, scan.ainex-ai.xyz
   and j.ainex-ai.xyz) and checks that all three answer.

Needs boto3 and AWS credentials allowed to use the bucket, the function and the distribution.
"""
from __future__ import annotations

import datetime as dt
import os
import re
import sys
import tempfile
import time
import urllib.request
import zipfile
from pathlib import Path

import boto3
from botocore.config import Config

REGION, BUCKET, FUNCTION, DISTRIBUTION = "eu-north-1", "cyberscan-assets", "CyberScan", "E2P5IBD320MSWL"
LIVE_KEY = "deploy/cyberscan-lambda.zip"
DOMAINS = ["https://ainex-ai.xyz/", "https://scan.ainex-ai.xyz/", "https://j.ainex-ai.xyz/"]
ROOT = Path(__file__).resolve().parents[2]

SKIP = re.compile(r"(^|/)(__pycache__|\.pytest_cache|tests?)(/|$)|\.pyc$|(^|/)test_[^/]*\.py$"
                  r"|^web_v/static/(pyodide|m)/|^web_v/static/downloads/(?!.*\.json$)|^web_v/(android|aws)/|^web_v/mobile_bridge\.py$")


def project_files() -> dict[str, Path]:
    """Every file the website package should carry from the working tree."""
    files: dict[str, Path] = {}

    def tree(rel: str, pattern: str = r".*") -> None:
        base = ROOT / rel
        if not base.exists():
            return
        for path in base.rglob("*"):
            if path.is_file():
                name = path.relative_to(ROOT).as_posix()
                if not SKIP.search(name) and re.search(pattern, name):
                    files[name] = path

    tree("web_v/static")
    tree("team")
    for rel in ("core", "detection"):
        tree(rel, r"\.py$")
    tree("repair_engine", r"\.(py|json)$")
    tree("Tools")
    for rel in ("web_v/server.py", "web_v/services.py", "web_v/assistant.py", "web_v/assistant_knowledge.md", "web_v/toolbox.py", "web_v/bit_brain.py", "web_v/profile_stats.py",
                "web_v/site_extras.py", "web_v/email_check.py", "web_v/visits.py", "web_v/seo_meta.py",
                "ui/scan_service.py", "ui/secrets.py", "core/external_intel.py", "core/hash_intel.py", "intel/__init__.py", "intel/updater.py", "config.py",
                "intel/data/forge.yarx", "intel/data/manifest.json", "intel/data/malware-hashes.bin",
                "intel/data/urlhaus.txt.gz", "intel/data/phishing-domains.txt.gz", "intel/data/secrets.json"):
        if (ROOT / rel).is_file():
            files[rel] = ROOT / rel
    # pure-Python packages the engines need (taken from this computer's Python)
    for package in ("olefile", "pypdf"):
        try:
            module = __import__(package)
            base = Path(module.__file__).parent
            for path in base.rglob("*"):
                if path.is_file() and "__pycache__" not in path.parts:
                    files[f"{package}/{path.relative_to(base).as_posix()}"] = path
        except ImportError:
            print(f"  note: {package} isn't installed here; the package keeps its current copy")
    return files


def build(live: Path, out: Path) -> None:
    files = project_files()
    norm = lambda b: b.replace(b"\r\n", b"\n")  # noqa: E731
    changed = added = 0
    with zipfile.ZipFile(live) as zin, zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zout:
        names = set(zin.namelist())
        for info in zin.infolist():
            if info.filename in files:
                data = files[info.filename].read_bytes()
                changed += norm(data) != norm(zin.read(info.filename))
                zi = zipfile.ZipInfo(info.filename, date_time=info.date_time)
                zi.external_attr, zi.compress_type = info.external_attr, zipfile.ZIP_DEFLATED
                zout.writestr(zi, data)
            else:
                zout.writestr(info, zin.read(info.filename))
        stamp = dt.datetime.now().timetuple()[:6]
        for name, path in sorted(files.items()):
            if name in names:
                continue
            zi = zipfile.ZipInfo(name, date_time=stamp)
            zi.external_attr, zi.compress_type = 0o644 << 16, zipfile.ZIP_DEFLATED
            zout.writestr(zi, path.read_bytes())
            added += 1
    print(f"  {changed} files changed, {added} added; package {out.stat().st_size / 1048576:.1f} MB")


def main() -> None:
    cfg = Config(retries={"max_attempts": 8, "mode": "standard"}, connect_timeout=20, read_timeout=300, s3={"addressing_style": "path"})
    s3 = boto3.client("s3", region_name=REGION, config=cfg)
    lam = boto3.client("lambda", region_name=REGION, config=cfg)
    cf = boto3.client("cloudfront", config=cfg)
    work = Path(tempfile.mkdtemp(prefix="cyberscan-deploy-"))
    live, new = work / "live.zip", work / "new.zip"
    stamp = dt.datetime.now().strftime("%Y-%m-%d-%H%M")

    print("1/5 downloading the live package…")
    s3.download_file(BUCKET, LIVE_KEY, str(live))
    print("2/5 building the new package from the project…")
    build(live, new)
    print("3/5 backing up what is live…")
    s3.upload_file(str(live), BUCKET, f"deploy/cyberscan-lambda-{stamp}-before.zip")
    s3.upload_file(str(live), BUCKET, "deploy/cyberscan-lambda-previous.zip")
    print("4/5 uploading and updating Lambda…")
    s3.upload_file(str(new), BUCKET, LIVE_KEY)
    lam.update_function_code(FunctionName=FUNCTION, S3Bucket=BUCKET, S3Key=LIVE_KEY)
    lam.get_waiter("function_updated_v2").wait(FunctionName=FUNCTION, WaiterConfig={"Delay": 5, "MaxAttempts": 90})
    state = lam.get_function_configuration(FunctionName=FUNCTION)
    print(f"  Lambda: {state['LastUpdateStatus']} / {state['State']}")
    print("5/5 clearing the CloudFront cache (all three domains)…")
    inv = cf.create_invalidation(DistributionId=DISTRIBUTION, InvalidationBatch={
        "Paths": {"Quantity": 1, "Items": ["/*"]}, "CallerReference": f"deploy-{int(time.time())}"})
    cf.get_waiter("invalidation_completed").wait(DistributionId=DISTRIBUTION, Id=inv["Invalidation"]["Id"],
                                                 WaiterConfig={"Delay": 10, "MaxAttempts": 60})
    failed = 0
    for url in DOMAINS:
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "CyberScan-deploy-check"}), timeout=60) as r:
                print(f"  {r.status} {url}")
        except Exception as exc:  # noqa: BLE001
            failed += 1
            print(f"  FAILED {url}: {exc}")
    print(f"\nDone. Backup: deploy/cyberscan-lambda-{stamp}-before.zip" if not failed else
          f"\n{failed} domain(s) did not answer. To roll back, run: python tools/deploy/deploy_aws.py --rollback")


def rollback() -> None:
    cfg = Config(retries={"max_attempts": 8, "mode": "standard"}, s3={"addressing_style": "path"})
    s3 = boto3.client("s3", region_name=REGION, config=cfg)
    lam = boto3.client("lambda", region_name=REGION, config=cfg)
    s3.copy_object(Bucket=BUCKET, Key=LIVE_KEY, CopySource={"Bucket": BUCKET, "Key": "deploy/cyberscan-lambda-previous.zip"})
    lam.update_function_code(FunctionName=FUNCTION, S3Bucket=BUCKET, S3Key=LIVE_KEY)
    lam.get_waiter("function_updated_v2").wait(FunctionName=FUNCTION)
    boto3.client("cloudfront").create_invalidation(DistributionId=DISTRIBUTION, InvalidationBatch={
        "Paths": {"Quantity": 1, "Items": ["/*"]}, "CallerReference": f"rollback-{int(time.time())}"})
    print("Rolled back to deploy/cyberscan-lambda-previous.zip")


def staging() -> None:
    """--staging: the same package, built on top of what is live, sent to a SECOND Lambda function
    (default name CyberScan-staging, or CYBERSCAN_STAGING_FUNCTION) under its own S3 key. Production
    (the CyberScan function, its package and CloudFront) is not touched. The staging function must
    already exist (create it once in the console, see README "Staging"); this script creates nothing.
    CYBERSCAN_STAGING_URL (its Function URL) is checked at the end when set."""
    function = os.environ.get("CYBERSCAN_STAGING_FUNCTION", "CyberScan-staging")
    key = "deploy/staging/cyberscan-lambda.zip"
    cfg = Config(retries={"max_attempts": 8, "mode": "standard"}, connect_timeout=20, read_timeout=300, s3={"addressing_style": "path"})
    s3 = boto3.client("s3", region_name=REGION, config=cfg)
    lam = boto3.client("lambda", region_name=REGION, config=cfg)
    try:
        lam.get_function_configuration(FunctionName=function)
    except lam.exceptions.ResourceNotFoundException:
        raise SystemExit(f"No Lambda function named {function!r} in {REGION}. Create it first (README: Staging).")
    work = Path(tempfile.mkdtemp(prefix="cyberscan-staging-"))
    live, new = work / "live.zip", work / "new.zip"
    print("1/3 downloading the production package as the base…")
    s3.download_file(BUCKET, LIVE_KEY, str(live))
    print("2/3 building the staging package from the project…")
    build(live, new)
    print(f"3/3 uploading to s3://{BUCKET}/{key} and updating {function}…")
    s3.upload_file(str(new), BUCKET, key)
    lam.update_function_code(FunctionName=function, S3Bucket=BUCKET, S3Key=key)
    lam.get_waiter("function_updated_v2").wait(FunctionName=function, WaiterConfig={"Delay": 5, "MaxAttempts": 90})
    url = os.environ.get("CYBERSCAN_STAGING_URL", "").strip()
    if url:
        with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "CyberScan-deploy-check"}), timeout=60) as r:
            print(f"  {r.status} {url}")
    print("Staging updated. Production was not changed.")


if __name__ == "__main__":
    os.chdir(ROOT)
    if "--rollback" in sys.argv:
        rollback()
    elif "--staging" in sys.argv:
        staging()
    else:
        main()
