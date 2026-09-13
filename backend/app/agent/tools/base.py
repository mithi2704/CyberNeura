"""
Base abstract class for CyberNeura Agent Tools.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, Type
from pydantic import BaseModel
from app.agent.tool_result import ToolResult


class AgentTool(ABC):
    """Abstract base for all defensive CyberNeura agent tools."""

    tool_name: str
    description: str
    input_schema: Type[BaseModel]
    timeout_seconds: float = 10.0
    requires_auth: bool = True

    @abstractmethod
    async def execute(self, arguments: Dict[str, Any]) -> ToolResult:
        """Execute the tool with validated arguments."""
        pass

    def get_metadata(self) -> Dict[str, Any]:
        """Return safe, non-sensitive metadata for tool discovery."""
        schema_props = {}
        if hasattr(self.input_schema, "model_json_schema"):
            schema_props = self.input_schema.model_json_schema()
        elif hasattr(self.input_schema, "schema"):
            schema_props = self.input_schema.schema()

        return {
            "name": self.tool_name,
            "description": self.description,
            "input_schema": schema_props,
            "timeout_seconds": self.timeout_seconds,
            "requires_auth": self.requires_auth,
        }
