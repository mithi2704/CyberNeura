"""
CyberNeura Agent state definition.
Maintains state throughout an individual investigation session.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from app.agent.models import (
    AgentFinding,
    AgentObjective,
    AgentStatus,
    ReasoningStep,
    ToolCallRecord,
)


class AgentState(BaseModel):
    session_id: str
    user_id: Optional[str] = None
    scan_id: Optional[str] = None
    url: str
    question: Optional[str] = None
    objective: AgentObjective = AgentObjective.URL_SAFETY_ASSESSMENT

    steps: List[str] = Field(default_factory=list)
    tool_calls: List[ToolCallRecord] = Field(default_factory=list)
    evidence: List[Dict[str, Any]] = Field(default_factory=list)
    findings: List[AgentFinding] = Field(default_factory=list)
    risk_assessment: Dict[str, Any] = Field(default_factory=dict)
    reasoning: List[ReasoningStep] = Field(default_factory=list)
    uncertainties: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    final_answer: Optional[str] = None

    status: AgentStatus = AgentStatus.RUNNING
    step_count: int = 0
    total_tool_calls: int = 0
