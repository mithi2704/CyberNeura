"""
Reasoning layer for CyberNeura AI Security Agent.
Structures reasoning steps, correlates evidence citations, evaluates facts vs inferences,
and isolates contradictions without exposing private chain-of-thought.
"""
from __future__ import annotations

from typing import Any, Dict, List
from app.agent.models import AgentFinding, ReasoningStep
from app.agent.providers.base import ReasoningProvider
from app.agent.state import AgentState
from app.agent.tool_result import ToolResult


class AgentReasoningEngine:
    """Coordinates reasoning operations over collected evidence."""

    def __init__(self, provider: ReasoningProvider):
        self.provider = provider

    async def evaluate_step(self, state: AgentState, tool_result: ToolResult) -> ReasoningStep:
        """Analyze a tool result and produce a structured reasoning step."""
        return await self.provider.analyze_step(state, tool_result)

    async def synthesize_findings(self, state: AgentState) -> List[AgentFinding]:
        """Synthesize key findings citing explicit evidence IDs."""
        return await self.provider.generate_findings(state)

    async def synthesize_explanation(self, state: AgentState) -> Dict[str, Any]:
        """Produce direct answer, reasoning summary, uncertainty, and recommendations."""
        return await self.provider.generate_explanation(state)
