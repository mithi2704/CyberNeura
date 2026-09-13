"""
Agent Planner.
Determines necessary investigation steps and tools using the configured ReasoningProvider.
Adheres to the principle: Existing Evidence > Existing Assessment > Cached Intel > Fresh Tool Calls.
"""
from __future__ import annotations

from typing import Any, Dict, List
from app.agent.providers.base import ReasoningProvider
from app.agent.state import AgentState
from app.utils.logger import get_logger

logger = get_logger(__name__)


class AgentPlanner:
    """Plans tool calls dynamically based on current investigation state."""

    def __init__(self, provider: ReasoningProvider):
        self.provider = provider

    async def get_next_steps(self, state: AgentState) -> List[Dict[str, Any]]:
        """
        Query reasoning provider for the next step(s).
        Filters out any tools that were already executed with identical arguments.
        """
        proposed_steps = await self.provider.plan(state)

        valid_steps = []
        executed_tool_names = {tc.tool_name for tc in state.tool_calls}

        for step in proposed_steps:
            t_name = step.get("tool_name")
            if not t_name:
                continue

            # Don't re-execute already completed tools unless explicitly requested
            if t_name in executed_tool_names:
                continue

            valid_steps.append(step)

        return valid_steps
