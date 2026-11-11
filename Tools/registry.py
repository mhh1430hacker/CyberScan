"""Static tool discovery and explicit, hash-bound execution approval."""
from __future__ import annotations

import ast
import hashlib
import json
import re
import sys
import types
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable


_TOOL_ID = re.compile(r"^[a-z][a-z0-9._-]{1,95}$")
_DIRECTORY = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_METADATA_FIELDS = (
    "TOOL_ID",
    "NAME",
    "DESCRIPTION",
    "CATEGORY",
    "VERSION",
    "INPUT_SCHEMA",
    "OUTPUT_SCHEMA",
    "PRIVACY",
    "PROCESSING",
)
_SCHEMA_TYPES = {"array", "boolean", "integer", "null", "number", "object", "string"}


class RegistryConfigurationError(ValueError):
    """The central tool approval configuration is invalid."""


@dataclass(frozen=True)
class ToolMetadata:
    tool_id: str
    name: str
    description: str
    category: str
    version: str
    input_schema: dict[str, Any]
    output_schema: dict[str, Any]
    privacy: dict[str, Any]
    processing: dict[str, Any]


@dataclass(frozen=True)
class ToolRecord:
    tool_id: str | None
    status: str
    metadata: ToolMetadata | None
    sha256: str
    relative_path: str
    error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "tool_id": self.tool_id,
            "status": self.status,
            "metadata": asdict(self.metadata) if self.metadata else None,
            "sha256": self.sha256,
            "relative_path": self.relative_path,
            "error": self.error,
        }


@dataclass(frozen=True)
class ToolExecutionResult:
    tool_id: str
    status: str
    result: dict[str, Any] | None = None
    error: dict[str, str] | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _literal_assignments(tree: ast.Module) -> dict[str, Any]:
    values: dict[str, Any] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
            if name in _METADATA_FIELDS:
                if name in values:
                    raise ValueError(f"metadata field {name} is assigned more than once")
                values[name] = ast.literal_eval(node.value)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            name = node.target.id
            if name in _METADATA_FIELDS and node.value is not None:
                if name in values:
                    raise ValueError(f"metadata field {name} is assigned more than once")
                values[name] = ast.literal_eval(node.value)
    return values


def _valid_schema(schema: Any, depth: int = 0) -> bool:
    if depth > 20 or not isinstance(schema, dict):
        return False
    allowed_keys = {
        "type", "enum", "properties", "required", "additionalProperties",
        "items", "minLength", "maxLength", "maxItems",
    }
    if any(key not in allowed_keys for key in schema):
        return False
    schema_type = schema.get("type")
    if isinstance(schema_type, list):
        if not schema_type or any(item not in _SCHEMA_TYPES for item in schema_type):
            return False
    elif schema_type not in _SCHEMA_TYPES:
        return False
    schema_types = set(schema_type) if isinstance(schema_type, list) else {schema_type}
    if "enum" in schema and not isinstance(schema["enum"], list):
        return False
    if "object" in schema_types:
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        if not isinstance(properties, dict) or not isinstance(required, list):
            return False
        if any(not isinstance(key, str) or not _valid_schema(value, depth + 1) for key, value in properties.items()):
            return False
        if any(not isinstance(item, str) or item not in properties for item in required):
            return False
        if "additionalProperties" in schema and not isinstance(schema["additionalProperties"], bool):
            return False
    if "array" in schema_types:
        if "items" in schema and not _valid_schema(schema["items"], depth + 1):
            return False
    for bound in ("minLength", "maxLength", "maxItems"):
        if bound in schema and (not isinstance(schema[bound], int) or schema[bound] < 0):
            return False
    if "minLength" in schema and "maxLength" in schema and schema["minLength"] > schema["maxLength"]:
        return False
    return True


def _schema_errors(value: Any, schema: dict[str, Any], location: str = "$", depth: int = 0) -> list[str]:
    if depth > 20:
        return [f"{location}: maximum schema depth exceeded"]
    expected = schema.get("type")
    accepted = set(expected) if isinstance(expected, list) else {expected}
    actual_matches = {
        "array": isinstance(value, list),
        "boolean": isinstance(value, bool),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "null": value is None,
        "number": isinstance(value, (int, float)) and not isinstance(value, bool),
        "object": isinstance(value, dict),
        "string": isinstance(value, str),
    }
    if not any(actual_matches.get(kind, False) for kind in accepted):
        return [f"{location}: expected {' or '.join(sorted(accepted))}"]
    if "enum" in schema and value not in schema["enum"]:
        return [f"{location}: value is not one of the allowed values"]

    errors: list[str] = []
    if isinstance(value, str):
        if "minLength" in schema and len(value) < schema["minLength"]:
            errors.append(f"{location}: string is shorter than minLength")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            errors.append(f"{location}: string is longer than maxLength")
    elif isinstance(value, dict):
        properties = schema.get("properties", {})
        for key in schema.get("required", []):
            if key not in value:
                errors.append(f"{location}.{key}: required property is missing")
        for key, item in value.items():
            if key in properties:
                errors.extend(_schema_errors(item, properties[key], f"{location}.{key}", depth + 1))
            elif schema.get("additionalProperties") is False:
                errors.append(f"{location}.{key}: additional property is not allowed")
    elif isinstance(value, list):
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            errors.append(f"{location}: array exceeds maxItems")
        if "items" in schema:
            for index, item in enumerate(value):
                errors.extend(_schema_errors(item, schema["items"], f"{location}[{index}]", depth + 1))
    return errors


class ToolRegistry:
    """Discover tools without importing them; execute only hash-approved modules."""

    def __init__(
        self,
        root: str | Path | None = None,
        *,
        approved_directories: Iterable[str] | None = None,
        trusted_tools: dict[str, str] | None = None,
    ) -> None:
        self.root = Path(root).resolve() if root is not None else Path(__file__).resolve().parent
        self.config_path = self.root / "registry.json"
        self._directory_override = tuple(approved_directories) if approved_directories is not None else None
        self._trusted_override = dict(trusted_tools) if trusted_tools is not None else None

    def _configuration(self) -> tuple[tuple[str, ...], dict[str, str]]:
        if self.config_path.exists():
            if self.config_path.is_symlink() or not self.config_path.is_file():
                raise RegistryConfigurationError("registry.json must be a regular file.")
            try:
                config = json.loads(self.config_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise RegistryConfigurationError(f"registry.json could not be read: {type(exc).__name__}.") from exc
            if not isinstance(config, dict):
                raise RegistryConfigurationError("registry.json must contain a JSON object.")
            directories = config.get("approved_directories", [])
            trusted = config.get("trusted_tools", {})
            if not isinstance(directories, list) or not isinstance(trusted, dict):
                raise RegistryConfigurationError("registry.json has invalid approved_directories or trusted_tools.")
        else:
            directories, trusted = (), {}
        if self._directory_override is not None:
            directories = self._directory_override
        if self._trusted_override is not None:
            trusted = self._trusted_override
        if any(not isinstance(item, str) or not _DIRECTORY.fullmatch(item) for item in directories):
            raise RegistryConfigurationError("Approved directories must be simple lower-case directory names.")
        if any(
            not isinstance(tool_id, str)
            or not _TOOL_ID.fullmatch(tool_id)
            or not isinstance(digest, str)
            or not re.fullmatch(r"[a-f0-9]{64}", digest)
            for tool_id, digest in trusted.items()
        ):
            raise RegistryConfigurationError("Trusted tool approvals must map valid IDs to SHA-256 hashes.")
        return tuple(directories), dict(trusted)

    def discover(self) -> list[ToolRecord]:
        """Parse metadata using AST only; module top-level code is never run here."""
        directories, trusted = self._configuration()
        records: list[ToolRecord] = []
        for directory in directories:
            category_root = self.root / directory
            if category_root.is_symlink() or not category_root.is_dir():
                continue
            for path in sorted(category_root.glob("*.py")):
                if path.name.startswith("_") or path.is_symlink() or not path.is_file():
                    continue
                records.append(self._inspect(path, trusted))

        by_id: dict[str, list[int]] = {}
        for index, record in enumerate(records):
            if record.tool_id:
                by_id.setdefault(record.tool_id, []).append(index)
        for tool_id, indices in by_id.items():
            if len(indices) > 1:
                for index in indices:
                    records[index] = ToolRecord(
                        tool_id=tool_id,
                        status="invalid",
                        metadata=records[index].metadata,
                        sha256=records[index].sha256,
                        relative_path=records[index].relative_path,
                        error="duplicate_tool_id",
                    )
        return records

    def _inspect(self, path: Path, trusted: dict[str, str]) -> ToolRecord:
        relative = path.relative_to(self.root).as_posix()
        try:
            source = path.read_bytes()
            digest = hashlib.sha256(source).hexdigest()
            tree = ast.parse(source, filename=str(path))
            values = _literal_assignments(tree)
            missing = [field for field in _METADATA_FIELDS if field not in values]
            if missing:
                raise ValueError(f"missing metadata: {', '.join(missing)}")
            metadata = self._metadata(values, path.parent.name.replace("_", "-"))
            self._validate_run_function(tree)
        except (OSError, SyntaxError, ValueError, TypeError) as exc:
            try:
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
            except OSError:
                digest = ""
            return ToolRecord(None, "invalid", None, digest, relative, f"{type(exc).__name__}: {exc}")

        approved_digest = trusted.get(metadata.tool_id)
        status = "available" if approved_digest == digest else "disabled"
        reason = None if status == "available" else (
            "approval_hash_mismatch" if approved_digest else "explicit_approval_required"
        )
        return ToolRecord(metadata.tool_id, status, metadata, digest, relative, reason)

    @staticmethod
    def _metadata(values: dict[str, Any], directory_category: str) -> ToolMetadata:
        if not isinstance(values["TOOL_ID"], str) or not _TOOL_ID.fullmatch(values["TOOL_ID"]):
            raise ValueError("TOOL_ID is invalid")
        for key in ("NAME", "DESCRIPTION", "CATEGORY", "VERSION"):
            if not isinstance(values[key], str) or not values[key].strip():
                raise ValueError(f"{key} must be a non-empty string")
        if values["CATEGORY"].lower().replace("_", "-") != directory_category:
            raise ValueError("CATEGORY must match the approved directory name")
        if not _valid_schema(values["INPUT_SCHEMA"]) or not _valid_schema(values["OUTPUT_SCHEMA"]):
            raise ValueError("input or output schema is invalid or unsupported")
        if not isinstance(values["PRIVACY"], dict) or not isinstance(values["PRIVACY"].get("data_handling"), str):
            raise ValueError("PRIVACY must document data_handling")
        processing = values["PROCESSING"]
        if not isinstance(processing, dict) or any(
            not isinstance(processing.get(key), bool)
            for key in ("network", "filesystem", "executes_files")
        ):
            raise ValueError("PROCESSING must declare network, filesystem and executes_files booleans")
        return ToolMetadata(
            values["TOOL_ID"],
            values["NAME"].strip(),
            values["DESCRIPTION"].strip(),
            values["CATEGORY"].strip(),
            values["VERSION"].strip(),
            values["INPUT_SCHEMA"],
            values["OUTPUT_SCHEMA"],
            values["PRIVACY"],
            processing,
        )

    @staticmethod
    def _validate_run_function(tree: ast.Module) -> None:
        functions = [node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "run"]
        if len(functions) != 1 or isinstance(functions[0], ast.AsyncFunctionDef):
            raise ValueError("exactly one synchronous run(input_data, options=None) entry point is required")
        function = functions[0]
        args = function.args.args
        if (
            len(args) != 2
            or args[0].arg != "input_data"
            or args[1].arg != "options"
            or len(function.args.defaults) != 1
            or not isinstance(function.args.defaults[0], ast.Constant)
            or function.args.defaults[0].value is not None
        ):
            raise ValueError("run options must be optional")
        if function.args.posonlyargs or function.args.vararg or function.args.kwarg or function.args.kwonlyargs:
            raise ValueError("run must use the standard two-parameter contract")

    def approve(self, tool_id: str, expected_sha256: str) -> None:
        """Explicitly trust the current source hash for one valid, unique tool."""
        if not re.fullmatch(r"[a-f0-9]{64}", expected_sha256):
            raise ValueError("expected_sha256 must be a lowercase SHA-256 digest")
        record = next((item for item in self.discover() if item.tool_id == tool_id), None)
        if record is None or record.status == "invalid" or record.sha256 != expected_sha256:
            raise ValueError("tool must be valid and its current hash must match expected_sha256")
        directories, trusted = self._configuration()
        trusted[tool_id] = expected_sha256
        payload = json.dumps(
            {"approved_directories": list(directories), "trusted_tools": trusted},
            indent=2,
            sort_keys=True,
        ) + "\n"
        temporary = self.config_path.with_name(self.config_path.name + ".tmp")
        temporary.write_text(payload, encoding="utf-8")
        temporary.replace(self.config_path)

    def execute(
        self,
        tool_id: str,
        input_data: Any,
        options: dict[str, Any] | None = None,
    ) -> ToolExecutionResult:
        """Run one explicitly approved tool and validate both sides of its contract."""
        matches = [record for record in self.discover() if record.tool_id == tool_id]
        if not matches:
            return ToolExecutionResult(tool_id, "invalid", error={"code": "unknown_tool", "message": "No valid tool with this ID was discovered."})
        record = matches[0]
        if record.status != "available" or record.metadata is None:
            return ToolExecutionResult(
                tool_id,
                record.status,
                error={"code": record.error or "tool_not_approved", "message": "Tool is not approved for execution."},
            )
        try:
            json.dumps(input_data, allow_nan=False)
        except (TypeError, ValueError):
            return ToolExecutionResult(tool_id, "invalid_input", error={"code": "invalid_input", "message": "Input must be JSON-compatible."})
        input_errors = _schema_errors(input_data, record.metadata.input_schema)
        if input_errors:
            return ToolExecutionResult(tool_id, "invalid_input", error={"code": "invalid_input", "message": "; ".join(input_errors[:10])})
        if options is not None:
            if not isinstance(options, dict):
                return ToolExecutionResult(tool_id, "invalid_input", error={"code": "invalid_options", "message": "Options must be an object."})
            try:
                json.dumps(options, allow_nan=False)
            except (TypeError, ValueError):
                return ToolExecutionResult(tool_id, "invalid_input", error={"code": "invalid_options", "message": "Options must be JSON-compatible."})

        source_path = self.root / record.relative_path
        try:
            source = source_path.read_bytes()
        except OSError as exc:
            return ToolExecutionResult(tool_id, "import_error", error={"code": "source_unavailable", "message": type(exc).__name__})
        if hashlib.sha256(source).hexdigest() != record.sha256:
            return ToolExecutionResult(tool_id, "disabled", error={"code": "source_changed", "message": "The approved source changed after discovery."})

        module = types.ModuleType(f"_cyberscan_tool_{record.sha256[:16]}")
        module.__file__ = str(source_path)
        sys.modules[module.__name__] = module
        try:
            exec(compile(source, str(source_path), "exec"), module.__dict__)
        except ImportError as exc:
            sys.modules.pop(module.__name__, None)
            return ToolExecutionResult(tool_id, "import_error", error={"code": "import_error", "message": f"{type(exc).__name__}: {exc}"})
        except Exception as exc:
            sys.modules.pop(module.__name__, None)
            return ToolExecutionResult(tool_id, "import_error", error={"code": "module_initialization_failed", "message": f"{type(exc).__name__}: {exc}"})

        run = getattr(module, "run", None)
        if not callable(run):
            return ToolExecutionResult(tool_id, "invalid", error={"code": "missing_entry_point", "message": "The approved module has no callable run entry point."})
        try:
            output = run(input_data, options=options)
        except Exception as exc:
            return ToolExecutionResult(tool_id, "execution_error", error={"code": "execution_error", "message": f"{type(exc).__name__}: {exc}"})
        if not isinstance(output, dict):
            return ToolExecutionResult(tool_id, "invalid_output", error={"code": "invalid_output", "message": "Tool output must be an object."})
        output_errors = _schema_errors(output, record.metadata.output_schema)
        if output_errors:
            return ToolExecutionResult(tool_id, "invalid_output", error={"code": "invalid_output", "message": "; ".join(output_errors[:10])})
        try:
            json.dumps(output, allow_nan=False)
        except (TypeError, ValueError):
            return ToolExecutionResult(tool_id, "invalid_output", error={"code": "invalid_output", "message": "Output must be JSON-compatible."})
        return ToolExecutionResult(tool_id, "ok", result=output)
