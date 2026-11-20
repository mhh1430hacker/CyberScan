"""Download and prepare the open-source protection data that core/protection.py uses.

    python intel/fetch.py                    # into intel/data/
    python intel/fetch.py --out some/dir     # e.g. the website build folder

Needs the yara-x package to compile the YARA-Forge rules (pip install yara-x); without
it the rules are skipped and the rest is still prepared. Sources and licences:

    YARA-Forge core     github.com/YARAHQ/yara-forge          per-rule licences (DRL 1.1, CC BY-SA 4.0, ...)
    URLhaus (online)    urlhaus.abuse.ch via gitlab.com/malware-filter/urlhaus-filter   CC0
    Phishing.Database   github.com/Phishing-Database/Phishing.Database (active domains)  MIT
    gitleaks rules      github.com/gitleaks/gitleaks config/gitleaks.toml                MIT
    Tranco top sites    tranco-list.eu, only to drop popular sites wrongly listed as phishing
    VirusShare          virusshare.com/hashes  MD5 lists of malware samples (latest VIRUSSHARE_FILES lists)
    MalwareBazaar       bazaar.abuse.ch full SHA-256 export, when ABUSECH_AUTH_KEY is set (CC0)
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import gzip
import io
import json
import os
import re
import sys
import time
import tomllib
import urllib.error
import urllib.request
import warnings
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
UA = {"User-Agent": "CyberScan-intel-fetch/1.0"}

FORGE = "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip"
URLHAUS = "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-online.txt"
PHISHING = "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt"
GITLEAKS = "https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml"
TRANCO = "https://tranco-list.eu/top-1m.csv.zip"
TOP_SITES = 50_000
VIRUSSHARE = "https://virusshare.com/hashes"
VIRUSSHARE_FILES = 24          # each list holds ~65,000 malware MD5s; 24 lists = ~1.5 million samples
BAZAAR_FULL = "https://bazaar.abuse.ch/export/txt/sha256/full/"

# Official service host names on the most popular sites (sites.google.com, docs.google.com ...):
# phishing pages are hosted there, but the host itself must never be marked as phishing.
SERVICE_LABELS = {
    "www", "m", "mobile", "sites", "docs", "drive", "mail", "accounts", "account", "login", "support", "help", "forms",
    "storage", "app", "apps", "web", "api", "cdn", "static", "blog", "blogs", "news", "shop", "store", "play", "outlook",
    "onedrive", "sharepoint", "dl", "download", "downloads", "images", "img", "maps", "translate", "groups", "script",
    "firebasestorage", "raw", "gist", "pages", "community", "developer", "developers", "en", "ar", "my", "secure",
}


def get(url: str, timeout: int = 120, headers: dict | None = None, tries: int = 3) -> bytes:
    for attempt in range(tries):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers={**UA, **(headers or {})}), timeout=timeout) as res:
                return res.read()
        except urllib.error.HTTPError:
            raise
        except OSError:
            if attempt == tries - 1:
                raise
            time.sleep(2 * (attempt + 1))
    raise OSError("unreachable")


def replace_file(path: Path, data: bytes) -> None:
    """Write next to the target, then swap it in: a scan never reads a half-written file."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, path)


def write_lines(path: Path, lines: list[str]) -> None:
    with gzip.open(path, "wt", encoding="utf-8", compresslevel=9) as fh:
        fh.write("\n".join(lines) + "\n")


# ---------------------------------------------------------------- YARA-Forge
def forge(out: Path, info: dict) -> None:
    try:
        import yara_x  # noqa: PLC0415
    except ImportError:
        print("yara-x is not installed: YARA-Forge rules skipped (pip install yara-x)")
        return
    archive = zipfile.ZipFile(io.BytesIO(get(FORGE)))
    name = next(n for n in archive.namelist() if n.endswith(".yar"))
    source = archive.read(name).decode("utf-8", "replace")
    compiler = yara_x.Compiler(relaxed_re_syntax=True)
    compiler.add_source(source)
    rules = compiler.build()
    buffer = io.BytesIO()
    rules.serialize_into(buffer)
    replace_file(out / "forge.yarx", buffer.getvalue())
    version = re.search(r"Creation Date: (\S+)", source)
    info["forge_rules"] = len(re.findall(r"^(?:private )?rule \w+", source, re.M))
    info["forge_version"] = version.group(1) if version else ""
    print(f"YARA-Forge core: {info['forge_rules']} rules, {(out / 'forge.yarx').stat().st_size // 1024} KB compiled")


# ---------------------------------------------------------------- link lists
def top_sites() -> set[str]:
    try:
        archive = zipfile.ZipFile(io.BytesIO(get(TRANCO)))
        rows = csv.reader(io.TextIOWrapper(archive.open(archive.namelist()[0]), encoding="utf-8"))
        return {row[1].lower() for _, row in zip(range(TOP_SITES), rows)}
    except Exception as exc:  # noqa: BLE001 - optional: only makes the phishing list safer
        print(f"Tranco list unavailable ({exc}); using the built-in short list")
        return {"google.com", "microsoft.com", "apple.com", "amazon.com", "facebook.com", "github.com", "github.io",
                "dropbox.com", "weebly.com", "wixsite.com", "blogspot.com", "vercel.app", "netlify.app", "pages.dev",
                "web.app", "firebaseapp.com", "workers.dev", "r2.dev", "amazonaws.com", "cloudfront.net", "live.com",
                "office.com", "sharepoint.com", "linktr.ee", "forms.gle", "bit.ly", "t.co", "ipfs.io", "000webhostapp.com"}


def link_lists(out: Path, info: dict) -> None:
    top = top_sites()
    urls = []
    for line in get(URLHAUS).decode("utf-8", "replace").splitlines():
        line = line.strip()
        if not line or line.startswith(("!", "#")):
            continue
        entry = line.removeprefix("||").split("^")[0].split("$")[0].lower().rstrip("/")
        host = entry.split("/")[0]
        if "/" not in entry and host in top:
            continue   # never mark a whole popular site
        urls.append(entry)
    write_lines(out / "urlhaus.txt.gz", sorted(set(urls)))
    info["urlhaus"] = len(set(urls))

    domains = []
    for line in get(PHISHING).decode("utf-8", "replace").splitlines():
        host = line.strip().lower().rstrip(".")
        if not host or host.startswith("#") or host in top:
            continue
        first, _, rest = host.partition(".")
        if rest in top and first in SERVICE_LABELS:
            continue
        domains.append(host)
    write_lines(out / "phishing-domains.txt.gz", sorted(set(domains)))
    info["phishing"] = len(set(domains))
    print(f"URLhaus: {info['urlhaus']} entries; Phishing.Database: {info['phishing']} domains")


# ---------------------------------------------------------------- gitleaks
def go_to_python(pattern: str) -> str:
    """Go (RE2) allows (?i) in the middle of a group; Python wants it scoped: (?i:...)."""
    while True:
        at = pattern.find("(?i)")
        if at <= 0:
            return pattern
        depth, end = 0, len(pattern)
        i = at + 4
        while i < len(pattern):
            ch = pattern[i]
            if ch == "\\":
                i += 2
                continue
            if ch == "[":
                j = i + 1
                while j < len(pattern) and pattern[j] != "]":
                    j += 2 if pattern[j] == "\\" else 1
                i = j + 1
                continue
            if ch == "(":
                depth += 1
            elif ch == ")":
                if depth == 0:
                    end = i
                    break
                depth -= 1
            i += 1
        pattern = pattern[:at] + "(?i:" + pattern[at + 4:end] + ")" + pattern[end:]


WORDS = {"api": "API", "aws": "AWS", "gcp": "GCP", "pat": "access token", "jwt": "JWT", "ssh": "SSH", "id": "ID",
         "github": "GitHub", "gitlab": "GitLab", "openai": "OpenAI", "npm": "npm", "pypi": "PyPI", "url": "URL",
         "oauth": "OAuth", "sdk": "SDK", "ai": "AI", "hashicorp": "HashiCorp", "huggingface": "Hugging Face"}


def title(rule_id: str) -> str:
    return " ".join(WORDS.get(w, w.capitalize()) for w in rule_id.split("-"))


def secrets(out: Path, info: dict) -> None:
    spec = tomllib.loads(get(GITLEAKS).decode("utf-8"))
    rules, skipped = [], 0
    for rule in spec.get("rules", []):
        if not rule.get("regex"):
            continue
        regex = go_to_python(rule["regex"])
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                re.compile(regex)
        except re.error:
            skipped += 1
            continue
        allow_regexes, stop = [], []
        for allow in rule.get("allowlists", []):
            if allow.get("condition", "OR") != "OR" or allow.get("regexTarget", "secret") != "secret":
                continue
            for p in allow.get("regexes", []):
                p = go_to_python(p)
                try:
                    re.compile(p)
                    allow_regexes.append(p)
                except re.error:
                    pass
            stop += allow.get("stopwords", [])
        rid = rule["id"]
        rules.append({
            "id": rid, "title": title(rid),
            "description": rule.get("description", "").strip(), "regex": regex,
            "keywords": [k.lower() for k in rule.get("keywords", [])], "entropy": rule.get("entropy"),
            "group": rule.get("secretGroup"), "allow_regexes": allow_regexes, "stopwords": stop,
        })
    allow = spec.get("allowlist") or {}
    glob_regexes = []
    for p in allow.get("regexes", []):
        p = go_to_python(p)
        try:
            re.compile(p)
            glob_regexes.append(p)
        except re.error:
            pass
    data = {"rules": rules, "allow_regexes": glob_regexes, "stopwords": allow.get("stopwords", [])}
    replace_file(out / "secrets.json", json.dumps(data).encode("utf-8"))
    info["secret_rules"] = len(rules)
    print(f"gitleaks: {len(rules)} rules ({skipped} skipped)")


# ---------------------------------------------------------------- known-malware hashes
def hashes(out: Path, info: dict) -> None:
    sys.path.insert(0, str(HERE.parent))
    from core.hash_intel import build_prefix_table  # noqa: PLC0415

    digests: list[str] = []
    sources = []
    page = get(VIRUSSHARE).decode("utf-8", "replace")
    names = sorted(set(re.findall(r"hashfiles/(VirusShare_\d+\.md5)", page)))[-VIRUSSHARE_FILES:]
    for name in names:
        body = get(f"https://virusshare.com/hashfiles/{name}", timeout=90).decode("ascii", "replace")
        digests += [line.strip().lower() for line in body.splitlines() if re.fullmatch(r"[0-9a-fA-F]{32}", line.strip())]
    if names:
        sources.append(f"VirusShare {names[0][11:16]}-{names[-1][11:16]}")
    key = os.getenv("ABUSECH_AUTH_KEY", "")
    if key:
        try:
            archive = zipfile.ZipFile(io.BytesIO(get(BAZAAR_FULL, timeout=300, headers={"Auth-Key": key})))
            text = archive.read(archive.namelist()[0]).decode("ascii", "replace")
            found = [line.strip().lower() for line in text.splitlines() if re.fullmatch(r"[0-9a-fA-F]{64}", line.strip())]
            digests += found
            sources.append(f"MalwareBazaar {len(found)}")
        except Exception as exc:  # noqa: BLE001 - optional source
            print(f"MalwareBazaar export unavailable ({exc})")
    if not digests:
        raise RuntimeError("no hash source answered")
    table = build_prefix_table(digests)
    replace_file(out / "malware-hashes.bin", table)
    info["malware_hashes"] = len(table) // 8
    info["hash_sources"] = sources
    info["hashes_updated"] = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%MZ")
    print(f"known-malware hashes: {info['malware_hashes']} ({', '.join(sources)})")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, default=HERE / "data")
    parser.add_argument("--skip", nargs="*", default=[], choices=["forge", "lists", "secrets", "hashes"])
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    info = {}
    if args.skip:   # a partial refresh keeps what the other steps recorded
        try:
            info = json.loads((args.out / "manifest.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass
    if {"forge", "lists", "secrets"} - set(args.skip):   # "updated" dates the rules and lists, not the hashes
        info["updated"] = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d")
    failed = []
    for name, step in STEPS:
        if name in args.skip:
            continue
        try:
            step(args.out, info)
        except Exception as exc:  # noqa: BLE001 - one source being down must not stop a deploy
            failed.append(name)
            print(f"{name} failed: {type(exc).__name__}: {exc}", file=sys.stderr)
    info["failed"] = failed
    replace_file(args.out / "manifest.json", json.dumps(info, indent=1).encode("utf-8"))
    print(json.dumps(info))


STEPS = (("forge", forge), ("lists", link_lists), ("secrets", secrets), ("hashes", hashes))

if __name__ == "__main__":
    main()
