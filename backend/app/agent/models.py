"""
CyberNeura AI Security Agent models.
Defines enums, findings, reasoning steps, tool calls, and investigation report structures.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class AgentObjective(str, Enum):
    URL_SAFETY_ASSESSMENT = "URL_SAFETY_ASSESSMENT"
    THREAT_EXPLANATION = "THREAT_EXPLANATION"
    EVIDENCE_INVESTIGATION = "EVIDENCE_INVESTIGATION"
    DISCREPANCY_ANALYSIS = "DISCREPANCY_ANALYSIS"
    GENERAL_INQUIRY = "GENERAL_INQUIRY"


class AgentStatus(str, Enum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    STOPPED = "STOPPED"


class AgentEventType(str, Enum):
    INVESTIGATION_STARTED = "INVESTIGATION_STARTED"
    PLAN_CREATED = "PLAN_CREATED"
    TOOL_REQUESTED = "TOOL_REQUESTED"
    TOOL_COMPLETED = "TOOL_COMPLETED"
    TOOL_FAILED = "TOOL_FAILED"
    EVIDENCE_ADDED = "EVIDENCE_ADDED"
    REASONING_COMPLETED = "REASONING_COMPLETED"
    ASSESSMENT_CREATED = "ASSESSMENT_CREATED"
    RECOMMENDATION_CREATED = "RECOMMENDATION_CREATED"
    INVESTIGATION_COMPLETED = "INVESTIGATION_COMPLETED"
    INVESTIGATION_FAILED = "INVESTIGATION_FAILED"
    INVESTIGATION_STOPPED = "INVESTIGATION_STOPPED"


class ToolCallRecord(BaseModel):
    id: str
    session_id: str
    tool_name: str
    arguments: Dict[str, Any] = Field(default_factory=dict)
    status: str = "SUCCESS"
    result_summary: str = ""
    duration_ms: float = 0.0
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class ReasoningStep(BaseModel):
    step: int
    observation: str
    evidence_ids: List[str] = Field(default_factory=list)
    inference: str
    confidence: float = 1.0


class AgentFinding(BaseModel):
    id: str
    session_id: str
    finding_type: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
    statement: str
    evidence_ids: List[str] = Field(default_factory=list)
    confidence: float = 1.0
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class AgentEvent(BaseModel):
    id: str
    session_id: str
    user_id: Optional[str] = None
    event_type: AgentEventType
    tool_name: Optional[str] = None
    input_summary: Optional[str] = None
    output_summary: Optional[str] = None
    status: str = "SUCCESS"
    duration_ms: float = 0.0
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class AgentInvestigationReport(BaseModel):
    session_id: str
    user_id: Optional[str] = None
    scan_id: Optional[str] = None
    url: str
    objective: str

    status: AgentStatus = AgentStatus.COMPLETED
    started_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    completed_at: Optional[str] = None

    final_assessment: Dict[str, Any] = Field(default_factory=dict)
    final_answer: Optional[str] = None
    key_findings: List[AgentFinding] = Field(default_factory=list)
    evidence_summary: List[Dict[str, Any]] = Field(default_factory=list)
    reasoning_summary: List[ReasoningStep] = Field(default_factory=list)
    uncertainties: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    tools_used: List[str] = Field(default_factory=list)

    total_steps: int = 0
    total_tool_calls: int = 0
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
