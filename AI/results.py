"""Provenance-preserving report aggregation; never changes tool outputs."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class UnifiedReport:
    status: str
    tool_results: tuple[dict[str, Any], ...]
    finding_references: tuple[dict[str, Any], ...]
    explanation_kind: str = "deterministic_index"

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "tool_results": list(self.tool_results),
            "finding_references": list(self.finding_references),
            "explanation_kind": self.explanation_kind,
            "risk_aggregation": "none; individual tool results are preserved",
        }


def build_report(tool_results: list[dict[str, Any]], *, cancelled: bool = False) -> UnifiedReport:
    references: list[dict[str, Any]] = []
    for execution in tool_results:
        result = execution.get("result")
        if not isinstance(result, dict):
            continue
        findings = result.get("findings")
        if not isinstance(findings, list):
            continue
        tool_id = execution.get("tool_id")
        for index, finding in enumerate(findings):
            references.append({"tool_id": tool_id, "finding_index": index, "finding": finding})
    statuses = [item.get("status") for item in tool_results]
    if cancelled:
        status = "cancelled"
    elif any(value != "ok" for value in statuses):
        status = "partial"
    elif any(
        isinstance(item.get("result"), dict) and item["result"].get("status") in {"partial", "error"}
        for item in tool_results
    ):
        status = "partial"
    else:
        status = "complete"
    return UnifiedReport(status, tuple(tool_results), tuple(references))
