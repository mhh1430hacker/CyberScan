"""Fetch the verification tools (ClamAV portable build, YARA Forge rules),
each checked against the SHA-256 digest GitHub publishes for the release
asset. Starting freshclam/clamd is done by hand once (see the README); no
code in the engine starts a program."""
from __future__ import annotations

import zipfile
from pathlib import Path

import requests

from repair_engine.data.fetch import HEADERS, TIMEOUT, download
from repair_engine.data.store import DataStore


def _release_asset(api: str, match) -> dict:
    release = requests.get(api, timeout=TIMEOUT, headers=HEADERS).json()
    for asset in release["assets"]:
        if match(asset["name"]):
            return {**asset, "tag": release["tag_name"]}
    raise LookupError(f"no matching asset in {api}")


def _safe_extract(archive: Path, target: Path) -> None:
    with zipfile.ZipFile(archive) as bundle:
        root = target.resolve()
        for member in bundle.infolist():
            destination = (target / member.filename).resolve()
            if root not in destination.parents and destination != root:
                raise ValueError(f"{archive.name}: member escapes the folder: {member.filename}")
        bundle.extractall(target)


def fetch_tools(store: DataStore) -> dict[str, Path]:
    settings = store.config["verification"]
    found = {}
    for key, match in (
        ("clamav", lambda name: name.endswith(settings["clamav"]["asset_suffix"])),
        ("yara", lambda name: name == settings["yara"]["asset_name"]),
    ):
        api = settings[key]["release_api"]
        asset = _release_asset(api, match)
        digest = (asset.get("digest") or "").removeprefix("sha256:")
        if not digest:
            raise LookupError(f"{asset['name']}: the release publishes no digest; refusing to use it")
        archive = download(store, asset["browser_download_url"], store.downloads / asset["name"],
                           size=asset["size"], sha256=digest)
        target = store.tools / key
        if not target.exists():
            _safe_extract(archive, target)
        archive.unlink()
        store.log("tool_ready", tool=key, release=asset["tag"], asset=asset["name"], sha256=digest)
        found[key] = target
    return found
