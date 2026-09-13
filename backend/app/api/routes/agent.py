"""
CyberNeura AI Security Agent REST API routes.
Endpoints:
- POST /investigate
- GET /investigations/{session_id}
- GET /investigations/{session_id}/events
- POST /investigations/{session_id}/continue
- POST /investigations/{session_id}/stop
- GET /tools
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.agent.agent import cyberneura_agent
from app.agent.guardrails import agent_rate_limiter, AgentGuardrails
from app.agent.models import AgentInvestigationReport, AgentObjective, AgentStatus
from app.config import settings
from app.dependencies import AuthUser, get_current_user_optional
from app.services.scan_store import scan_store
from app.utils.logger import get_logger

logger = get_logger(__name__)
router = APIRouter(prefix="/agent", tags=["AI Security Agent"])


class InvestigateRequest(BaseModel):
    url: str = Field(..., description="Target URL to investigate")
    question: Optional[str] = Field("Is this URL safe?", description="User query or analysis objective")
    scan_id: Optional[str] = Field(None, description="Optional existing scan identifier")
    objective: Optional[AgentObjective] = Field(AgentObjective.URL_SAFETY_ASSESSMENT, description="Agent investigation objective")


class ContinueRequest(BaseModel):
    additional_input: str = Field(..., description="Additional context or follow-up question")


@router.post("/investigate", response_model=AgentInvestigationReport, summary="Initiate or run a defensive cybersecurity investigation")
async def run_investigation(
    body: InvestigateRequest,
    user: Optional[AuthUser] = Depends(get_current_user_optional),
):
    """
    Execute the CyberNeura AI Security Agent against a target URL.
    Coordinates tool selection, evidence correlation, deterministic risk score contextualization,
    and structured defensive recommendations.
    """
    if not getattr(settings, "agent_enabled", True):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="CyberNeura AI Security Agent is currently disabled.",
        )

    user_id = user.uid if user else "anonymous-user"

    # Rate limiting enforcement
    if not agent_rate_limiter.is_allowed(user_id):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded for agent investigations. Please wait before submitting another request.",
        )

    # Sanitize inputs against prompt injection
    sanitized_url = AgentGuardrails.sanitize_untrusted_input(body.url)
    sanitized_question = AgentGuardrails.sanitize_untrusted_input(body.question or "")

    report = await cyberneura_agent.investigate(
        url=sanitized_url,
        question=sanitized_question,
        user_id=user_id,
        scan_id=body.scan_id,
        objective=body.objective or AgentObjective.URL_SAFETY_ASSESSMENT,
    )

    return report


@router.get("/investigations/{session_id}", response_model=AgentInvestigationReport, summary="Get investigation report by session ID")
async def get_investigation(
    session_id: str,
    user: Optional[AuthUser] = Depends(get_current_user_optional),
):
    """Retrieve full structured report for a previous agent investigation."""
    session = scan_store.get_agent_session(session_id)
    if not session:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigation session not found.")

    # Optional user check for security
    user_id = user.uid if user else None
    if user_id and session.get("user_id") and session.get("user_id") not in (user_id, "anonymous-user"):
        # Allow admin bypass if needed; otherwise check ownership
        role = getattr(user, "role", "user")
        if role != "admin":
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied to this investigation session.")

    return session


@router.get("/investigations/{session_id}/events", summary="Get audit events for an investigation session")
async def get_investigation_events(
    session_id: str,
    user: Optional[AuthUser] = Depends(get_current_user_optional),
):
    """Retrieve chronologically ordered audit events logged during an investigation."""
    session = scan_store.get_agent_session(session_id)
    if not session:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigation session not found.")

    events = scan_store.get_agent_events(session_id)
    return events


@router.post("/investigations/{session_id}/continue", response_model=AgentInvestigationReport, summary="Continue an investigation with follow-up inquiry")
async def continue_investigation(
    session_id: str,
    body: ContinueRequest,
    user: Optional[AuthUser] = Depends(get_current_user_optional),
):
    """Provide additional guidance or continue reasoning on an existing session."""
    session = scan_store.get_agent_session(session_id)
    if not session:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigation session not found.")

    url = session.get("url", "")
    scan_id = session.get("scan_id")
    user_id = user.uid if user else session.get("user_id")

    sanitized_question = AgentGuardrails.sanitize_untrusted_input(body.additional_input)

    report = await cyberneura_agent.investigate(
        url=url,
        question=sanitized_question,
        user_id=user_id,
        scan_id=scan_id,
        session_id=session_id,
        objective=AgentObjective.EVIDENCE_INVESTIGATION,
    )

    return report


@router.post("/investigations/{session_id}/stop", summary="Safely stop an active investigation session")
async def stop_investigation(
    session_id: str,
    user: Optional[AuthUser] = Depends(get_current_user_optional),
):
    """Signal the agent orchestrator to terminate execution of an in-flight investigation."""
    stopped = cyberneura_agent.stop(session_id)
    return {"session_id": session_id, "stopped": stopped, "status": AgentStatus.STOPPED}


@router.get("/tools", summary="List registered defensive tools")
async def list_tools():
    """Return public metadata and schemas for all approved defensive agent tools (zero secrets exposed)."""
    return cyberneura_agent.list_available_tools()
