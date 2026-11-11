"""Dynamic read-only catalog adapter for the shared CyberScan Tool Registry."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from Tools.registry import ToolRecord, ToolRegistry


@dataclass(frozen=True)
class CatalogTool:
    tool_id: str
    name: str
    description: str
    category: str
    version: str
    input_schema: dict[str, Any]
    output_schema: dict[str, Any]
    privacy: dict[str, Any]
    processing: dict[str, Any]
    status: str
    sha256: str
    relative_path: str

    @classmethod
    def from_record(cls, record: ToolRecord) -> CatalogTool:
        if record.tool_id is None or record.metadata is None:
            raise ValueError("Invalid registry records cannot become catalog tools.")
        values = asdict(record.metadata)
        return cls(
            tool_id=values["tool_id"],
            name=values["name"],
            description=values["description"],
            category=values["category"],
            version=values["version"],
            input_schema=values["input_schema"],
            output_schema=values["output_schema"],
            privacy=values["privacy"],
            processing=values["processing"],
            status=record.status,
            sha256=record.sha256,
            relative_path=record.relative_path,
        )

    def planner_view(self) -> dict[str, Any]:
        """Only describe the capability; all values are untrusted prompt data."""
        return {
            "tool_id": self.tool_id,
            "name": self.name[:160],
            "description": self.description[:1000],
            "category": self.category[:100],
            "input_schema": self.input_schema,
        }


class RegistryCatalog:
    """Re-discover on every call so approved new tools appear without AI edits."""

    def __init__(self, registry: ToolRegistry | None = None) -> None:
        self.registry = registry or ToolRegistry()

    def discover(self, *, available_only: bool = True) -> list[CatalogTool]:
        records = self.registry.discover()
        return [
            CatalogTool.from_record(record)
            for record in records
            if record.metadata is not None
            and record.tool_id is not None
            and (not available_only or record.status == "available")
        ]

    def get(self, tool_id: str, *, available_only: bool = True) -> CatalogTool | None:
        matches = [item for item in self.discover(available_only=available_only) if item.tool_id == tool_id]
        if len(matches) > 1:
            return None
        return matches[0] if matches else None
