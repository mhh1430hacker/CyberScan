"""Explicit, fail-closed authorization for Registry tool invocations."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from AI.registry_adapter import CatalogTool
from AI.schema import validate_schema, validate_value
from AI.contracts import ToolInvocation


@dataclass(frozen=True)
class Authorization:
    allowed: bool
    reason: str
    requires_user_confirmation: bool


class PermissionManager:
    """Require a user-confirmed call to a currently hash-approved local tool."""

    def authorize(
        self,
        invocation: ToolInvocation,
        tool: CatalogTool | None,
        *,
        confirmed: bool,
        principal: str,
    ) -> Authorization:
        if not principal or len(principal) > 256:
            return Authorization(False, "invalid_principal", True)
        if tool is None or tool.tool_id != invocation.tool_id:
            return Authorization(False, "tool_not_available_or_approved", True)
        if tool.status != "available":
            return Authorization(False, "tool_not_available_or_approved", True)
        if any(tool.processing.get(key) is True for key in ("network", "filesystem", "executes_files")):
            return Authorization(False, "declared_side_effect_requires_separate_review", True)
        schema_errors = validate_schema(tool.input_schema)
        if schema_errors:
            return Authorization(False, "tool_input_schema_invalid", True)
        input_errors = validate_value(invocation.input_data, tool.input_schema)
        if input_errors:
            return Authorization(False, "tool_input_invalid: " + "; ".join(input_errors[:5]), True)
        if not confirmed:
            return Authorization(False, "explicit_user_confirmation_required", True)
        return Authorization(True, "explicitly_confirmed_registry_approved_tool", False)
