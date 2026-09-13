"""
Agent Executor.
Safely executes planned tools against the ToolRegistry, updates session state,
records execution metrics, and handles exceptions cleanly.
"""
from __future__ import annotations

import uuid
from typing import Any, Dict, Optional, Tuple
from app.agent.guardrails import AgentGuardrails
from app.agent.memory import InvestigationMemory
from app.agent.models import ToolCallRecord
from app.agent.state import AgentState
from app.agent.tool_registry import ToolRegistry
from app.agent.tool_result import ToolResult, ToolStatus
from app.utils.logger import get_logger

logger = get_logger(__name__)


class AgentExecutor:
    """Executes validated tool requests within safety boundaries."""

    def __init__(self, registry: ToolRegistry, memory: InvestigationMemory):
        self.registry = registry
        self.memory = memory

    async def execute_tool(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        state: AgentState,
    ) -> Tuple[ToolResult, ToolCallRecord]:
        """
        Execute a tool, check memory cache, update state, and return result + audit record.
        """
        # 1. Sanitize string arguments against prompt injection
        sanitized_args: Dict[str, Any] = {}
        for k, v in arguments.items():
            if isinstance(v, str):
                sanitized_args[k] = AgentGuardrails.sanitize_untrusted_input(v)
            else:
                sanitized_args[k] = v

        # 2. Check memory cache for identical call
        cached_result = self.memory.get_cached_tool_result(tool_name, sanitized_args)
        if cached_result:
            logger.info(f"[{state.session_id}] Reusing cached result for tool '{tool_name}'")
            tc_record = ToolCallRecord(
                id=f"tc-{uuid.uuid4().hex[:8]}",
                session_id=state.session_id,
                tool_name=tool_name,
                arguments=sanitized_args,
                status=cached_result.status.value,
                result_summary=f"(Cached) {cached_result.summary}",
                duration_ms=0.0,
            )
            return cached_result, tc_record

        # 3. Execute through ToolRegistry with timeout and validation
        result = await self.registry.execute(tool_name, sanitized_args)

        # 4. Cache in investigation memory
        self.memory.cache_tool_result(tool_name, sanitized_args, result)

        # 5. Create ToolCallRecord
        tc_record = ToolCallRecord(
            id=f"tc-{uuid.uuid4().hex[:8]}",
            session_id=state.session_id,
            tool_name=tool_name,
            arguments=sanitized_args,
            status=result.status.value,
            result_summary=result.summary,
            duration_ms=result.duration_ms,
        )

        # 6. Absorb data into state
        if result.is_success and result.data:
            if tool_name == "get_risk_assessment":
                state.risk_assessment = result.data
            elif tool_name == "get_evidence":
                state.evidence.extend(result.data.get("evidence", []))
            elif tool_name == "lookup_threat_intelligence":
                for p in result.data.get("providers", []):
                    if p.get("status") == "UNAVAILABLE":
                        state.uncertainties.append(f"Provider {p.get('provider')} was unavailable.")

        return result, tc_record
