from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any


class LocalUiStore:
    def __init__(self, settings_path: str | Path, history_path: str | Path) -> None:
        self.settings_path = Path(settings_path)
        self.history_path = Path(history_path)

    @staticmethod
    def _read_json(path: Path, expected_type: type, default: Any) -> Any:
        if not path.exists():
            return default
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"Unable to read local UI data from {path}: {exc}") from exc
        if not isinstance(value, expected_type):
            raise ValueError(f"Local UI data in {path} has an invalid format.")
        return value

    @staticmethod
    def _write_json(path: Path, value: Any) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=path.parent,
                prefix=f".{path.name}.",
                suffix=".tmp",
                delete=False,
            ) as temporary:
                temporary_path = Path(temporary.name)
                json.dump(value, temporary, indent=2, ensure_ascii=False)
                temporary.flush()
                os.fsync(temporary.fileno())
            os.replace(temporary_path, path)
        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)

    def load_settings(self, defaults: dict[str, Any]) -> dict[str, Any]:
        persisted = self._read_json(self.settings_path, dict, {})
        compatible = {
            key: value
            for key, value in persisted.items()
            if key in defaults and type(value) is type(defaults[key])
        }
        return {**defaults, **compatible}

    def save_settings(self, settings: dict[str, Any]) -> None:
        self._write_json(self.settings_path, settings)

    def load_history(self) -> list[dict[str, Any]]:
        history = self._read_json(self.history_path, list, [])
        if not all(
            isinstance(item, dict)
            and bool(item.get("id"))
            and isinstance(item.get("id"), str)
            and isinstance(item.get("timestamp"), str)
            and isinstance(item.get("target"), str)
            and isinstance(item.get("classification"), str)
            and isinstance(item.get("score"), (int, float))
            and not isinstance(item.get("score"), bool)
            and isinstance(item.get("sha256", ""), str)
            and isinstance(item.get("report_path"), str)
            for item in history
        ):
            raise ValueError(f"Local scan history in {self.history_path} has an invalid record.")
        return history[-200:]

    def save_history(self, history: list[dict[str, Any]]) -> None:
        self._write_json(self.history_path, history)
