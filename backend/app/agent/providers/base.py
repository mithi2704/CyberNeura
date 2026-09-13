"""
Reasoning Provider abstract interface for CyberNeura AI Security Agent.
Enables pluggable reasoning backends (Deterministic, OpenAI, Anthropic)
without altering the core agent orchestrator.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from app.agent.models import AgentFinding, ReasoningStep
from app.agent.state import AgentState
from app.agent.tool_result import ToolResult


class ReasoningProvider(ABC):
    """Abstract interface for agent planning, analysis, and explanation generation."""

    @abstractmethod
    async def plan(self, state: AgentState) -> List[Dict[str, Any]]:
        """
        Determine the next tool calls needed based on current state and objective.
        Returns a list of dicts specifying: {"tool_name": str, "arguments": dict, "rationale": str}.
        """
        pass

    @abstractmethod
    async def analyze_step(self, state: AgentState, tool_result: ToolResult) -> ReasoningStep:
        """
        Generate an auditable, non-private reasoning step from a tool execution result.
        Must distinguish fact from inference.
        """
        pass

    @abstractmethod
    async def generate_findings(self, state: AgentState) -> List[AgentFinding]:
        """
        Generate structured key findings citing specific evidence IDs.
        """
        pass

    @abstractmethod
    async def generate_explanation(self, state: AgentState) -> Dict[str, Any]:
        """
        Synthesize the final answer, direct answer, reasoning summary,
        uncertainty statement, and recommendations.
        """
        pass
