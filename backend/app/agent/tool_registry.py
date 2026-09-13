"""
Centralized Tool Registry for CyberNeura Agent Tools.
Enforces registration, validation, timeouts, error boundary isolation, and auditability.
"""
from __future__ import annotations

import asyncio
import time
from typing import Any, Dict, List, Optional
from pydantic import ValidationError
from app.agent.tool_result import ToolResult, ToolStatus
from app.agent.tools.base import AgentTool
from app.utils.logger import get_logger

logger = get_logger(__name__)


class ToolRegistry:
    """Central registry controlling tool discovery and safe execution."""

    def __init__(self):
        self._tools: Dict[str, AgentTool] = {}

    def register(self, tool: AgentTool) -> None:
        """Register an authorized agent tool."""
        self._tools[tool.tool_name] = tool
        logger.debug(f"Registered agent tool: {tool.tool_name}")

    def get(self, tool_name: str) -> Optional[AgentTool]:
        """Get registered tool by name."""
        return self._tools.get(tool_name)

    def list_tools(self) -> List[Dict[str, Any]]:
        """Return metadata for all registered tools."""
        return [tool.get_metadata() for tool in self._tools.values()]

    def list_tool_names(self) -> List[str]:
        """Return list of registered tool names."""
        return list(self._tools.keys())

    async def execute(self, tool_name: str, arguments: Dict[str, Any]) -> ToolResult:
        """
        Safely execute a tool with input schema validation and timeout protection.
        Never allows arbitrary code or unregistered tools.
        """
        tool = self.get(tool_name)
        if not tool:
            return ToolResult(
                tool_name=tool_name,
                status=ToolStatus.BLOCKED,
                summary=f"Tool '{tool_name}' is not in the approved tool registry.",
                error="UNAPPROVED_TOOL",
            )

        # Validate input arguments against Pydantic schema
        try:
            validated_args = tool.input_schema(**arguments).model_dump()
        except ValidationError as val_err:
            logger.warning(f"Argument validation failed for tool '{tool_name}': {val_err}")
            return ToolResult(
                tool_name=tool_name,
                status=ToolStatus.ERROR,
                summary=f"Invalid arguments supplied for tool '{tool_name}'.",
                error=str(val_err),
            )
        except Exception as e:
            return ToolResult(
                tool_name=tool_name,
                status=ToolStatus.ERROR,
                summary=f"Argument parsing error for tool '{tool_name}'.",
                error=str(e),
            )

        # Execute with timeout enforcement
        start_time = time.time()
        timeout = tool.timeout_seconds

        try:
            result = await asyncio.wait_for(tool.execute(validated_args), timeout=timeout)
            duration_ms = round((time.time() - start_time) * 1000, 2)
            if result:
                result.duration_ms = duration_ms
            return result or ToolResult(tool_name=tool_name, status=ToolStatus.SUCCESS, duration_ms=duration_ms)
        except (asyncio.TimeoutError, TimeoutError):
            duration_ms = round((time.time() - start_time) * 1000, 2)
            logger.warning(f"Tool execution timed out for '{tool_name}' after {timeout}s")
            return ToolResult(
                tool_name=tool_name,
                status=ToolStatus.TIMEOUT,
                summary=f"Tool '{tool_name}' timed out after {timeout} seconds.",
                duration_ms=duration_ms,
                error="EXECUTION_TIMEOUT",
            )
        except Exception as exc:
            duration_ms = round((time.time() - start_time) * 1000, 2)
            logger.error(f"Tool execution error for '{tool_name}': {exc}", exc_info=True)
            return ToolResult(
                tool_name=tool_name,
                status=ToolStatus.ERROR,
                summary=f"Tool '{tool_name}' encountered an execution error.",
                duration_ms=duration_ms,
                error=str(exc),
            )
