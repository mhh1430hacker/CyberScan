"""Typed extension points; deliberately contains no model or agent implementation."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass(frozen=True)
class ToolInvocation:
    tool_id: str
    input_data: dict[str, Any]
    options: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ExecutionPlan:
    plan_id: str
    invocations: tuple[ToolInvocation, ...]
    rationale: str


@dataclass(frozen=True)
class Conversation:
    conversation_id: str
    messages: tuple[dict[str, Any], ...]


@dataclass(frozen=True)
class ContextItem:
    key: str
    value: Any
    sensitivity: str
    source: str


@dataclass(frozen=True)
class PermissionDecision:
    allowed: bool
    reason: str
    requires_user_confirmation: bool = False


class ToolCatalog(Protocol):
    def discover(self) -> list[Any]:
        """Return metadata and availability states without executing tools."""


class ToolExecutor(Protocol):
    def execute(
        self,
        tool_id: str,
        input_data: Any,
        options: dict[str, Any] | None = None,
    ) -> Any:
        """Execute only tools approved by the shared Tools registry."""


class Planner(Protocol):
    def plan(self, request: str, context: tuple[ContextItem, ...]) -> ExecutionPlan:
        """Propose a plan; planning itself must not execute tools."""


class PermissionManager(Protocol):
    def authorize(
        self,
        invocation: ToolInvocation,
        *,
        principal: str,
        context: tuple[ContextItem, ...],
    ) -> PermissionDecision:
        """Authorize a specific invocation before the executor is called."""


class ConversationStore(Protocol):
    def get(self, conversation_id: str) -> Conversation | None:
        """Load a conversation subject to retention and access policy."""

    def save(self, conversation: Conversation) -> None:
        """Persist a conversation using an implementation-defined secure store."""


class ContextProvider(Protocol):
    def collect(self, conversation: Conversation) -> tuple[ContextItem, ...]:
        """Provide bounded, labeled context for planning and authorization."""


class ResponseGenerator(Protocol):
    def render(
        self,
        request: str,
        plan: ExecutionPlan,
        results: tuple[Any, ...],
        context: tuple[ContextItem, ...],
    ) -> str:
        """Explain verified tool outputs without inventing evidence."""


class AgentOrchestrator(Protocol):
    def handle(self, request: str, conversation_id: str) -> str:
        """Future workflow coordinating planning, permission, tools and response."""
