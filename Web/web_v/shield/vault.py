"""The quarantine ("virus chest"): every sealed file, where it came from, and why.

Files are sealed with the existing encrypted vault (AES-GCM, key protected by Windows
DPAPI for this account). This module keeps a small index next to the sealed files so the
page can show the original location, the reason and the date, and restore or delete them.
"""
from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any

from config import DATA_DIR

VAULT_DIR = Path(DATA_DIR) / "quarantine"
INDEX = VAULT_DIR / "index.json"
_lock = threading.Lock()


def _load() -> dict[str, Any]:
    try:
        data = json.loads(INDEX.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save(index: dict[str, Any]) -> None:
    VAULT_DIR.mkdir(parents=True, exist_ok=True)
    tmp = INDEX.with_suffix(".tmp")
    tmp.write_text(json.dumps(index, ensure_ascii=False, indent=1), encoding="utf-8")
    tmp.replace(INDEX)


def seal(path: str | Path, reason: str = "", threat: str = "", source: str = "manual", sha256: str = "") -> dict[str, Any]:
    from ui import vault  # noqa: PLC0415

    target = Path(path)
    size = target.stat().st_size
    sealed = vault.quarantine(target, Path(DATA_DIR), VAULT_DIR)
    item = {"original": str(target), "reason": reason[:500], "threat": threat[:120], "source": source,
            "at": time.time(), "size": size, "sha256": sha256}
    with _lock:
        index = _load()
        index[sealed.name] = item
        _save(index)
    return {"id": sealed.name, **item}


def listing(history: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    """Everything in the vault, newest first. Items sealed from the scan history are
    described with that record when the index doesn't know them."""
    with _lock:
        index = _load()
    by_sealed = {}
    for record in history or []:
        sealed = record.get("quarantined")
        if isinstance(sealed, str):
            by_sealed[Path(sealed).name] = record
    items = []
    if VAULT_DIR.is_dir():
        for file in VAULT_DIR.glob("*.csq"):
            info = index.get(file.name)
            record = by_sealed.get(file.name)
            try:
                stat = file.stat()
            except OSError:
                continue
            if info is None:
                # name.<32 hex>.csq: the original name is the part before the random tag
                original_name = file.name.rsplit(".", 2)[0] if file.name.count(".") >= 2 else file.stem
                info = {"original": record["target"] if record else original_name,
                        "reason": record.get("classification", "") if record else "",
                        "threat": "", "source": "history" if record else "manual", "at": stat.st_mtime,
                        "size": None, "sha256": record.get("sha256", "") if record else ""}
            items.append({"id": file.name, **info, "sealed_size": stat.st_size,
                          "record_id": record.get("id") if record else None})
    items.sort(key=lambda i: -float(i.get("at") or 0))
    return items


def _sealed_path(item_id: str) -> Path:
    if "/" in item_id or "\\" in item_id or not item_id.endswith(".csq"):
        raise ValueError("bad quarantine item")
    path = VAULT_DIR / item_id
    if not path.is_file():
        raise FileNotFoundError(item_id)
    return path


def restore(item_id: str, original: str, to_folder: str | None = None) -> str:
    from ui import vault  # noqa: PLC0415

    sealed = _sealed_path(item_id)
    target = Path(original)
    if to_folder:
        target = Path(to_folder) / target.name
    if not target.is_absolute():
        raise ValueError("Choose a folder to restore to.")
    if target.exists():
        stem, suffix = target.stem, target.suffix
        n = 1
        while target.exists():
            target = target.with_name(f"{stem} (restored {n}){suffix}")
            n += 1
    target.parent.mkdir(parents=True, exist_ok=True)
    restored = vault.restore(sealed, target, Path(DATA_DIR))
    sealed.unlink(missing_ok=True)
    with _lock:
        index = _load()
        index.pop(item_id, None)
        _save(index)
    return str(restored)


def delete(item_id: str) -> None:
    sealed = _sealed_path(item_id)
    sealed.unlink()
    with _lock:
        index = _load()
        index.pop(item_id, None)
        _save(index)


def stats() -> dict[str, Any]:
    files = list(VAULT_DIR.glob("*.csq")) if VAULT_DIR.is_dir() else []
    return {"count": len(files), "bytes": sum(f.stat().st_size for f in files if f.is_file())}
