"""
FastAPI Routes for CyberNeura Chrome Browser Extension (Phase 6).
Provides secure endpoints for live URL inspection, status, policy querying,
user override logging, false-positive reporting, and dashboard telemetry.
"""
from __future__ import annotations

import time
from collections import defaultdict
from typing import Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from app.config import settings
from app.dependencies import OptionalAuthUser, AuthUser
from app.extension.models import (
    ExtensionAnalyzeRequest,
    ExtensionAnalyzeResponse,
    ExtensionOverrideRequest,
    ExtensionReportRequest,
    ExtensionStatusResponse,
    ExtensionPolicyResponse,
    ExtensionChatRequest,
    ExtensionChatResponse,
)
from app.extension.service import extension_service
from app.extension.policy import policy_engine
from app.services.scan_store import scan_store
from app.utils.logger import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/extension", tags=["Extension"])

# Lightweight in-memory rate limiter per installation_id / client IP
_rate_limits: Dict[str, List[float]] = defaultdict(list)


def _check_rate_limit(key: str) -> None:
    now = time.time()
    cutoff = now - 60.0
    timestamps = [t for t in _rate_limits[key] if t > cutoff]
    if len(timestamps) >= settings.extension_rate_limit_per_minute:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Extension rate limit exceeded ({settings.extension_rate_limit_per_minute} requests/minute).",
        )
    timestamps.append(now)
    _rate_limits[key] = timestamps


@router.post("/analyze", response_model=ExtensionAnalyzeResponse, summary="Analyze candidate URL from browser navigation")
async def analyze_url(
    payload: ExtensionAnalyzeRequest,
    request: Request,
    user: OptionalAuthUser = None,
):
    """
    Analyzes a candidate browsing URL:
    - Runs multi-source Phase 3 Risk Engine
    - Employs selective Phase 4 AI Agent if signals are ambiguous
    - Renders an authoritative ALLOW, WARN, or BLOCK decision
    - Persists event and streams real-time signals to the dashboard
    """
    if not settings.extension_enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="CyberNeura Browser Extension protection is currently disabled on this server.",
        )

    # Rate limiting key: installation_id or client IP
    client_ip = request.client.host if request.client else "unknown"
    rate_key = payload.installation_id if payload.installation_id != "default-install" else client_ip
    _check_rate_limit(rate_key)

    user_id = user.uid if user else None
    return await extension_service.analyze_url(payload, user_id=user_id)


@router.get("/status", response_model=ExtensionStatusResponse, summary="Extension service health & configuration status")
async def get_status():
    """Returns extension subsystem health, current policy version, and retry limits."""
    return ExtensionStatusResponse(
        service="CyberNeura Extension API",
        status="ONLINE" if settings.extension_enabled else "DISABLED",
        policy_version=settings.extension_policy_version,
        strict_mode=settings.extension_strict_mode,
        fallback_policy="ALLOW" if not settings.extension_strict_mode else "WARN",
        timeout_seconds=settings.extension_analysis_timeout_seconds,
        rate_limit_per_minute=settings.extension_rate_limit_per_minute,
        cache_ttl_seconds=settings.extension_cache_ttl_seconds,
    )


@router.get("/policy", response_model=ExtensionPolicyResponse, summary="Retrieve active extension policy rules")
async def get_policy():
    """Returns active policy rules, risk thresholds, and override permissions."""
    return ExtensionPolicyResponse(
        policy_version=settings.extension_policy_version,
        risk_threshold_safe=settings.risk_threshold_safe,
        risk_threshold_suspicious=settings.risk_threshold_suspicious,
        strict_mode=settings.extension_strict_mode,
        allow_override_warn=True,
        allow_override_block=settings.extension_strict_mode is False and settings.extension_allow_override,
        rules=policy_engine.get_rules_description(),
    )


@router.post("/override", summary="Record user override (Continue Anyway)")
async def record_override(
    payload: ExtensionOverrideRequest,
    user: OptionalAuthUser = None,
):
    """
    Records when a user deliberately chose to proceed past a warning interstitial.
    The underlying risk score remains unaffected.
    """
    user_id = user.uid if user else None
    return await extension_service.record_override(payload, user_id=user_id)


@router.post("/report", summary="Submit false-positive or false-negative report")
async def report_result(
    payload: ExtensionReportRequest,
    user: OptionalAuthUser = None,
):
    """Submits user feedback for false positive/negative tuning."""
    user_id = user.uid if user else None
    return await extension_service.record_report(payload, user_id=user_id)


@router.get("/events", summary="Query extension activity history for dashboard")
async def get_events(
    user: OptionalAuthUser = None,
    installation_id: Optional[str] = Query(None),
    decision: Optional[str] = Query(None),
    since: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=100),
):
    """Retrieves recent browser protection events for the dashboard."""
    user_id = user.uid if user else None
    events = scan_store.get_extension_events(
        user_id=user_id,
        installation_id=installation_id,
        decision=decision,
        since=since,
        limit=limit,
    )
    return {"events": events, "total": len(events)}


@router.get("/stats", summary="Query browser protection aggregate metrics")
async def get_stats(user: OptionalAuthUser = None):
    """Retrieves telemetry summary (inspected, blocked, warned, overrides) for dashboard."""
    user_id = user.uid if user else None
    return scan_store.get_extension_stats(user_id=user_id)


@router.post("/chat", response_model=ExtensionChatResponse, summary="Interactive AI Security Agent chat for active browsing page")
async def chat_with_agent(
    payload: ExtensionChatRequest,
    user: OptionalAuthUser = None,
):
    """
    Handles in-page AI Security Agent conversations:
    - Answers user questions about the active website's safety, risks, and legitimacy
    - Explains credential submission safety, certificate details, and threat indicators
    - Employs LLM reasoning (Groq/OpenAI) or deterministic security analysis
    """
    user_id = user.uid if user else None
    return await extension_service.chat(payload, user_id=user_id)

