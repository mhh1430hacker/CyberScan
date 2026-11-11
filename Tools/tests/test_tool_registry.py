from __future__ import annotations

import json
from pathlib import Path

from Tools.registry import ToolRegistry


_TOOL = '''\
TOOL_ID = "test.echo"
NAME = "Echo"
DESCRIPTION = "Returns a validated value."
CATEGORY = "testing"
VERSION = "1.0.0"
INPUT_SCHEMA = {"type": "object", "required": ["value"], "properties": {"value": {"type": "string"}}, "additionalProperties": False}
OUTPUT_SCHEMA = {"type": "object", "required": ["value"], "properties": {"value": {"type": "string"}}, "additionalProperties": False}
PRIVACY = {"data_handling": "In memory.", "external_services": "None."}
PROCESSING = {"network": False, "filesystem": False, "executes_files": False}

def run(input_data, options=None):
    return {"value": input_data["value"]}
'''


def _registry(tmp_path: Path, source: str = _TOOL, trusted: dict[str, str] | None = None) -> ToolRegistry:
    category = tmp_path / "testing"
    category.mkdir(exist_ok=True)
    tool_path = category / "echo.py"
    tool_path.write_text(source, encoding="utf-8")
    return ToolRegistry(tmp_path, approved_directories=["testing"], trusted_tools=trusted or {})


def _approved_registry(tmp_path: Path, source: str = _TOOL) -> ToolRegistry:
    registry = _registry(tmp_path, source)
    digest = registry.discover()[0].sha256
    return ToolRegistry(
        tmp_path,
        approved_directories=["testing"],
        trusted_tools={"test.echo": digest},
    )


def test_discovery_does_not_import_or_execute_module(tmp_path):
    marker = tmp_path / "side-effect.txt"
    source = _TOOL + f"\nPath({str(marker)!r}).write_text('executed')\n"
    registry = _registry(tmp_path, source)

    records = registry.discover()

    assert len(records) == 1
    assert records[0].status == "disabled"
    assert not marker.exists()


def test_approved_tool_executes_with_structured_validated_output(tmp_path):
    registry = _approved_registry(tmp_path)

    result = registry.execute("test.echo", {"value": "safe"})

    assert result.as_dict() == {
        "tool_id": "test.echo",
        "status": "ok",
        "result": {"value": "safe"},
        "error": None,
    }


def test_unapproved_or_modified_tool_cannot_execute(tmp_path):
    registry = _registry(tmp_path, trusted={"test.echo": "0" * 64})

    result = registry.execute("test.echo", {"value": "safe"})

    assert result.status == "disabled"
    assert result.error["code"] == "approval_hash_mismatch"


def test_invalid_input_is_rejected_before_import(tmp_path):
    registry = _approved_registry(tmp_path)

    result = registry.execute("test.echo", {"unexpected": True})

    assert result.status == "invalid_input"
    assert result.error["code"] == "invalid_input"


def test_duplicate_ids_invalidate_every_match(tmp_path):
    category = tmp_path / "testing"
    category.mkdir()
    (category / "one.py").write_text(_TOOL, encoding="utf-8")
    (category / "two.py").write_text(_TOOL.replace('NAME = "Echo"', 'NAME = "Other"'), encoding="utf-8")
    registry = ToolRegistry(tmp_path, approved_directories=["testing"], trusted_tools={})

    records = registry.discover()

    assert len(records) == 2
    assert {record.status for record in records} == {"invalid"}
    assert {record.error for record in records} == {"duplicate_tool_id"}


def test_import_error_is_reported_without_crashing_registry(tmp_path):
    source = _TOOL + "\nimport module_that_does_not_exist_for_tool_test\n"
    registry = _approved_registry(tmp_path, source)

    result = registry.execute("test.echo", {"value": "safe"})

    assert result.status == "import_error"
    assert result.error["code"] == "import_error"
    assert registry.discover()[0].status == "available"


def test_tool_output_must_match_declared_schema(tmp_path):
    source = _TOOL.replace('return {"value": input_data["value"]}', 'return {"value": 7}')
    registry = _approved_registry(tmp_path, source)

    result = registry.execute("test.echo", {"value": "safe"})

    assert result.status == "invalid_output"
    assert result.error["code"] == "invalid_output"


def test_approval_is_written_only_for_exact_discovered_hash(tmp_path):
    registry = _registry(tmp_path)
    digest = registry.discover()[0].sha256
    (tmp_path / "registry.json").write_text(
        json.dumps({"approved_directories": ["testing"], "trusted_tools": {}}),
        encoding="utf-8",
    )
    registry = ToolRegistry(tmp_path)

    registry.approve("test.echo", digest)

    approved = json.loads((tmp_path / "registry.json").read_text(encoding="utf-8"))
    assert approved["trusted_tools"] == {"test.echo": digest}
    assert registry.discover()[0].status == "available"
