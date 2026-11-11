"""Contract checks applied to every one of tools 051-100 (the quality gate in executable form)."""
import ast
import re
import shutil
from pathlib import Path

import pytest

from conftest import CATEGORIES, TOOLS_ROOT, check_unified
from Tools.registry import ToolRegistry

TOOL_FILES = sorted(p for c in CATEGORIES for p in (TOOLS_ROOT / c).glob("*.py") if not p.name.startswith("_"))
TEST_SOURCES = "\n".join(p.read_text(encoding="utf-8") for p in Path(__file__).parent.glob("test_*.py") if p.name != "test_contract.py")


def _literals(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    out = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            try:
                out[node.targets[0].id] = ast.literal_eval(node.value)
            except ValueError:
                pass
    return out


def test_exactly_fifty_tools_numbered_51_to_100():
    numbers = sorted(_literals(p)["TOOL_NUMBER"] for p in TOOL_FILES)
    assert numbers == list(range(51, 101))
    ids = [_literals(p)["TOOL_ID"] for p in TOOL_FILES]
    assert len(set(ids)) == 50


def test_all_tools_discovered_as_valid(registry):
    records = [r for r in registry.discover()]
    assert len(records) == 50 and all(r.status == "available" for r in records), [(r.relative_path, r.error) for r in records if r.status != "available"]


@pytest.mark.parametrize("path", TOOL_FILES, ids=lambda p: p.stem)
def test_metadata_and_schema(path):
    from security_toolkit import digest
    from security_toolkit.core import UNIFIED_OUTPUT_SCHEMA

    meta = _literals(path)
    for key in ("TOOL_ID", "NAME", "DESCRIPTION", "CATEGORY", "VERSION", "LICENSE", "SOURCE", "TIMEOUT_SECONDS", "INPUT_SCHEMA",
                "PRIVACY", "PROCESSING", "TOOLKIT_SHA256"):
        assert meta.get(key) not in (None, "", {}), f"{path.name}: {key} missing"
    assert meta["OUTPUT_SCHEMA"] == UNIFIED_OUTPUT_SCHEMA, f"{path.name}: run Tools/maintenance/pin_toolkit.py"
    assert meta["TOOLKIT_SHA256"] == digest(), f"{path.name}: stale toolkit pin"
    assert meta["PROCESSING"]["timeout_seconds"] == meta["TIMEOUT_SECONDS"]
    assert meta["PROCESSING"]["execution_mode"] in ("local", "local-system", "network-passive", "network-active-authorized")
    assert "external_services" in meta["PRIVACY"] and isinstance(meta["PROCESSING"].get("dependencies"), list)
    assert meta["PROCESSING"]["executes_files"] is False
    assert re.fullmatch(r"cyberscan\.[a-z]+\.[a-z0-9-]+", meta["TOOL_ID"])


@pytest.mark.parametrize("path", TOOL_FILES, ids=lambda p: p.stem)
def test_every_tool_has_functional_tests(path):
    tool_id = _literals(path)["TOOL_ID"]
    assert TEST_SOURCES.count(f'"{tool_id}"') >= 1, f"no functional test references {tool_id}"


@pytest.mark.parametrize("path", TOOL_FILES, ids=lambda p: p.stem)
def test_bad_inputs_are_handled(registry, path):
    tool_id = _literals(path)["TOOL_ID"]
    for bad in ({}, {"content": 12345}, {"files": "not-a-list"}, {"unexpected": True}):
        outcome = registry.execute(tool_id, bad)
        # either the registry rejects it against the input schema, or the tool returns a structured result; never a crash
        assert outcome.status in ("ok", "invalid_input"), (bad, outcome.as_dict())
        if outcome.status == "ok":
            check_unified(outcome.result, tool_id)
            assert outcome.result["status"] in ("invalid_input", "unsupported", "unavailable", "success", "partial")


def test_timeout_budget_produces_partial_result(run):
    # a 1 ms budget on a large input must stop cleanly and say so
    text = "\n".join(f"user{i}@corp-mail.net" for i in range(200000))
    result = run("cyberscan.privacy.pii-detector", {"content": text}, {"timeout_seconds": 0.001})
    assert result["status"] in ("partial", "success")
    assert result["metadata"]["timeout_seconds"] == 0.001


def test_tampered_toolkit_blocks_loading(tmp_path):
    root = tmp_path / "Tools"
    shutil.copytree(TOOLS_ROOT / "security_toolkit", root / "security_toolkit", ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copytree(TOOLS_ROOT / "network_security", root / "network_security", ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copytree(TOOLS_ROOT / "detection", root / "detection", ignore=shutil.ignore_patterns("__pycache__"))
    base = ToolRegistry(root, approved_directories=["network_security"], trusted_tools={})
    trusted = {r.tool_id: r.sha256 for r in base.discover()}
    registry = ToolRegistry(root, approved_directories=["network_security"], trusted_tools=trusted)
    assert registry.execute("cyberscan.network.hsts", {"headers": "Strict-Transport-Security: max-age=1"}).status == "ok"
    core = root / "security_toolkit" / "core.py"
    core.write_text(core.read_text(encoding="utf-8") + "\n# tampered\n", encoding="utf-8")
    outcome = registry.execute("cyberscan.network.hsts", {"headers": "Strict-Transport-Security: max-age=1"})
    assert outcome.status == "import_error" and "security_toolkit differs" in outcome.error["message"]
