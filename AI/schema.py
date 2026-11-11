"""Small strict subset of the JSON Schema features accepted by Tools.registry."""
from __future__ import annotations

import json
from typing import Any


_TYPES = {"array", "boolean", "integer", "null", "number", "object", "string"}
_ALLOWED_KEYS = {
    "type",
    "enum",
    "properties",
    "required",
    "additionalProperties",
    "items",
    "minLength",
    "maxLength",
    "maxItems",
}


def validate_schema(schema: Any, *, max_depth: int = 20) -> list[str]:
    errors: list[str] = []

    def check(value: Any, location: str, depth: int) -> None:
        if depth > max_depth or not isinstance(value, dict):
            errors.append(f"{location}: invalid or over-deep schema")
            return
        if set(value) - _ALLOWED_KEYS:
            errors.append(f"{location}: unsupported schema keywords")
        kind = value.get("type")
        kinds = set(kind) if isinstance(kind, list) else {kind}
        if not kinds or not kinds <= _TYPES:
            errors.append(f"{location}: invalid schema type")
            return
        if "enum" in value and (not isinstance(value["enum"], list) or not value["enum"]):
            errors.append(f"{location}.enum: expected a non-empty array")
        if "object" in kinds:
            properties = value.get("properties", {})
            required = value.get("required", [])
            if not isinstance(properties, dict) or not isinstance(required, list):
                errors.append(f"{location}: invalid object properties/required")
                return
            if any(not isinstance(item, str) or item not in properties for item in required):
                errors.append(f"{location}.required: every item must name a property")
            if "additionalProperties" in value and not isinstance(value["additionalProperties"], bool):
                errors.append(f"{location}.additionalProperties: expected boolean")
            for name, child in properties.items():
                if not isinstance(name, str):
                    errors.append(f"{location}.properties: property names must be strings")
                check(child, f"{location}.{name}", depth + 1)
        if "array" in kinds and "items" in value:
            check(value["items"], f"{location}.items", depth + 1)
        for bound in ("minLength", "maxLength", "maxItems"):
            if bound in value and (
                not isinstance(value[bound], int) or isinstance(value[bound], bool) or value[bound] < 0
            ):
                errors.append(f"{location}.{bound}: expected a non-negative integer")
        if value.get("minLength", 0) > value.get("maxLength", float("inf")):
            errors.append(f"{location}: minLength exceeds maxLength")

    check(schema, "$schema", 0)
    return errors


def validate_value(value: Any, schema: dict[str, Any], *, max_depth: int = 20) -> list[str]:
    try:
        json.dumps(value, allow_nan=False)
    except (TypeError, ValueError):
        return ["$: value is not finite JSON data"]
    errors: list[str] = []

    def visit(item: Any, current: dict[str, Any], location: str, depth: int) -> None:
        if depth > max_depth:
            errors.append(f"{location}: maximum schema depth exceeded")
            return
        expected = current.get("type")
        accepted = set(expected) if isinstance(expected, list) else {expected}
        match = {
            "array": isinstance(item, list),
            "boolean": isinstance(item, bool),
            "integer": isinstance(item, int) and not isinstance(item, bool),
            "null": item is None,
            "number": isinstance(item, (int, float)) and not isinstance(item, bool),
            "object": isinstance(item, dict),
            "string": isinstance(item, str),
        }
        if not any(match.get(kind, False) for kind in accepted):
            errors.append(f"{location}: expected {' or '.join(sorted(str(x) for x in accepted))}")
            return
        if "enum" in current and item not in current["enum"]:
            errors.append(f"{location}: value is not allowed")
        if isinstance(item, str):
            if "minLength" in current and len(item) < current["minLength"]:
                errors.append(f"{location}: string is shorter than minLength")
            if "maxLength" in current and len(item) > current["maxLength"]:
                errors.append(f"{location}: string is longer than maxLength")
        elif isinstance(item, dict):
            properties = current.get("properties", {})
            for required in current.get("required", []):
                if required not in item:
                    errors.append(f"{location}.{required}: required property is missing")
            for key, child in item.items():
                if key in properties:
                    visit(child, properties[key], f"{location}.{key}", depth + 1)
                elif current.get("additionalProperties") is False:
                    errors.append(f"{location}.{key}: additional property is not allowed")
        elif isinstance(item, list):
            if "maxItems" in current and len(item) > current["maxItems"]:
                errors.append(f"{location}: array exceeds maxItems")
            if "items" in current:
                for index, child in enumerate(item):
                    visit(child, current["items"], f"{location}[{index}]", depth + 1)

    visit(value, schema, "$", 0)
    return errors
