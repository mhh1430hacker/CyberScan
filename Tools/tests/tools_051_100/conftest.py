"""Shared fixtures: every tool test runs through the real ToolRegistry (discovery, hash approval,
schema validation of input and output), with approvals computed in-memory so registry.json is untouched."""
from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from Tools.registry import ToolRegistry

TOOLS_ROOT = Path(__file__).resolve().parents[2]
CATEGORIES = ["network_security", "system_security", "privacy_data_protection", "code_dependency_security",
              "cloud_infrastructure"]


def _registry() -> ToolRegistry:
    base = ToolRegistry(TOOLS_ROOT, approved_directories=CATEGORIES, trusted_tools={})
    records = base.discover()
    trusted = {r.tool_id: r.sha256 for r in records if r.tool_id and r.status != "invalid"}
    return ToolRegistry(TOOLS_ROOT, approved_directories=CATEGORIES, trusted_tools=trusted)


@pytest.fixture(scope="session")
def registry() -> ToolRegistry:
    return _registry()


def check_unified(result: dict, tool_id: str) -> None:
    """Contract checks the schema language cannot express."""
    assert result["tool_id"] == tool_id
    assert 0 <= result["risk_score"] <= 100
    if result["status"] not in ("success", "partial"):
        assert result["classification"] == "unknown" and result["risk_score"] == 0
    elif result["risk_score"] >= 50:
        assert result["classification"] == "suspicious"
    elif result["risk_score"] > 0:
        assert result["classification"] == "review"
    for finding in result["findings"]:
        assert 0 <= finding["weight"] <= 100
        if finding["severity"] == "info" or finding["assurance"] == "informational":
            assert finding["weight"] == 0
    assert result["metadata"]["execution_time_ms"] >= 0
    json.dumps(result, allow_nan=False)


@pytest.fixture(scope="session")
def run(registry):
    def _run(tool_id: str, data: dict, options: dict | None = None) -> dict:
        outcome = registry.execute(tool_id, data, options)
        assert outcome.status == "ok", outcome.error
        check_unified(outcome.result, tool_id)
        return outcome.result
    return _run


def ids(result: dict) -> set[str]:
    return {f["id"] for f in result["findings"]}


def b64(data: bytes | str) -> str:
    return base64.b64encode(data.encode() if isinstance(data, str) else data).decode()


def no_secret_leak(result: dict, *secrets: str) -> None:
    text = json.dumps(result)
    for secret in secrets:
        assert secret not in text, "a secret value leaked into the result"
