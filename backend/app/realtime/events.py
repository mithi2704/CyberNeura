"""
Real-time Event Factory Functions.
Generates typed RealtimeEvent instances for system-wide security actions.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.realtime.models import EntityType, RealtimeEvent, RealtimeEventType
from app.realtime.serializer import sanitize_payload


def create_scan_event(
    event_type: RealtimeEventType,
    scan_id: str,
    url: str,
    user_id: Optional[str] = None,
    payload: Optional[Dict[str, Any]] = None,
) -> RealtimeEvent:
    data = payload or {}
    data["url"] = url
    data["scan_id"] = scan_id
    return RealtimeEvent(
        event_id=str(uuid.uuid4()),
        event_type=event_type,
        entity_type=EntityType.URL_SCAN,
        entity_id=scan_id,
        user_id=user_id,
        payload=sanitize_payload(data),
    )


def create_risk_assessment_event(
    assessment_id: str,
    scan_id: str,
    risk_score: int,
    prediction: str,
    confidence: float,
    user_id: Optional[str] = None,
    threat_category: Optional[str] = None,
    summary: Optional[str] = None,
    recommendations: Optional[List[str]] = None,
) -> RealtimeEvent:
    return RealtimeEvent(
        event_id=str(uuid.uuid4()),
        event_type=RealtimeEventType.RISK_ASSESSMENT_COMPLETED,
        entity_type=EntityType.RISK_ASSESSMENT,
        entity_id=assessment_id,
        user_id=user_id,
        payload=sanitize_payload({
            "assessment_id": assessment_id,
            "scan_id": scan_id,
            "risk_score": risk_score,
            "prediction": prediction,
            "confidence": confidence,
            "threat_category": threat_category,
            "summary": summary,
            "recommendations": recommendations or [],
        }),
    )


def create_threat_detected_event(
    scan_id: str,
    url: str,
    provider: str,
    threat_category: str,
    severity: str,
    user_id: Optional[str] = None,
) -> RealtimeEvent:
    return RealtimeEvent(
        event_id=str(uuid.uuid4()),
        event_type=RealtimeEventType.THREAT_DETECTED,
        entity_type=EntityType.THREAT_INTELLIGENCE,
        entity_id=scan_id,
        user_id=user_id,
        payload=sanitize_payload({
            "scan_id": scan_id,
            "url": url,
            "provider": provider,
            "threat_category": threat_category,
            "severity": severity,
        }),
    )


def create_agent_event(
    event_type: RealtimeEventType,
    session_id: str,
    user_id: Optional[str] = None,
    tool_name: Optional[str] = None,
    summary: Optional[str] = None,
    status: str = "SUCCESS",
    duration_ms: float = 0.0,
    evidence_count: int = 0,
) -> RealtimeEvent:
    return RealtimeEvent(
        event_id=str(uuid.uuid4()),
        event_type=event_type,
        entity_type=EntityType.AGENT_SESSION,
        entity_id=session_id,
        user_id=user_id,
        payload=sanitize_payload({
            "session_id": session_id,
            "tool_name": tool_name,
            "summary": summary,
            "status": status,
            "duration_ms": duration_ms,
            "evidence_count": evidence_count,
        }),
    )


def create_notification_event(
    notification_id: str,
    title: str,
    message: str,
    severity: str = "INFO",
    scan_id: Optional[str] = None,
    user_id: Optional[str] = None,
) -> RealtimeEvent:
    return RealtimeEvent(
        event_id=str(uuid.uuid4()),
        event_type=RealtimeEventType.NOTIFICATION_CREATED,
        entity_type=EntityType.NOTIFICATION,
        entity_id=notification_id,
        user_id=user_id,
        payload=sanitize_payload({
            "notification_id": notification_id,
            "title": title,
            "message": message,
            "severity": severity,
            "scan_id": scan_id,
            "read": False,
        }),
    )
