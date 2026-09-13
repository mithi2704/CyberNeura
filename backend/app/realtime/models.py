"""
Real-time Event Data Models for CyberNeura.
Standardized schemas for events, entity types, and connection tracking.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field, ConfigDict


class RealtimeEventType(str, Enum):
    # Scan lifecycle
    SCAN_CREATED = "SCAN_CREATED"
    SCAN_STARTED = "SCAN_STARTED"
    SCAN_COMPLETED = "SCAN_COMPLETED"
    SCAN_FAILED = "SCAN_FAILED"

    # Risk & Evidence
    RISK_ASSESSMENT_STARTED = "RISK_ASSESSMENT_STARTED"
    RISK_ASSESSMENT_COMPLETED = "RISK_ASSESSMENT_COMPLETED"
    RISK_SCORE_CHANGED = "RISK_SCORE_CHANGED"

    # Threat Intelligence
    THREAT_INTEL_STARTED = "THREAT_INTEL_STARTED"
    THREAT_INTEL_UPDATED = "THREAT_INTEL_UPDATED"
    THREAT_DETECTED = "THREAT_DETECTED"

    # Evidence & Findings
    EVIDENCE_CREATED = "EVIDENCE_CREATED"
    EVIDENCE_UPDATED = "EVIDENCE_UPDATED"
    FINDING_CREATED = "FINDING_CREATED"

    # AI Agent
    AGENT_STARTED = "AGENT_STARTED"
    AGENT_TOOL_STARTED = "AGENT_TOOL_STARTED"
    AGENT_TOOL_COMPLETED = "AGENT_TOOL_COMPLETED"
    AGENT_COMPLETED = "AGENT_COMPLETED"
    AGENT_FAILED = "AGENT_FAILED"

    # Alerts & Notifications
    SECURITY_ALERT_CREATED = "SECURITY_ALERT_CREATED"
    NOTIFICATION_CREATED = "NOTIFICATION_CREATED"

    # System Status
    SYSTEM_STATUS_CHANGED = "SYSTEM_STATUS_CHANGED"

    # Browser Extension (Phase 6)
    EXTENSION_SCAN_STARTED = "EXTENSION_SCAN_STARTED"
    EXTENSION_SCAN_COMPLETED = "EXTENSION_SCAN_COMPLETED"
    EXTENSION_WARNING_SHOWN = "EXTENSION_WARNING_SHOWN"
    EXTENSION_BLOCKED = "EXTENSION_BLOCKED"
    EXTENSION_OVERRIDE = "EXTENSION_OVERRIDE"
    EXTENSION_REPORT_SUBMITTED = "EXTENSION_REPORT_SUBMITTED"

    # AI Media Security (Phase 7)
    MEDIA_UPLOAD_STARTED = "MEDIA_UPLOAD_STARTED"
    MEDIA_ANALYSIS_STARTED = "MEDIA_ANALYSIS_STARTED"
    MEDIA_FRAME_ANALYSIS_STARTED = "MEDIA_FRAME_ANALYSIS_STARTED"
    MEDIA_ANALYSIS_COMPLETED = "MEDIA_ANALYSIS_COMPLETED"
    MEDIA_ANALYSIS_FAILED = "MEDIA_ANALYSIS_FAILED"
    MEDIA_PROVENANCE_FOUND = "MEDIA_PROVENANCE_FOUND"
    MEDIA_THREAT_DETECTED = "MEDIA_THREAT_DETECTED"


class EntityType(str, Enum):
    URL_SCAN = "url_scan"
    RISK_ASSESSMENT = "risk_assessment"
    THREAT_INTELLIGENCE = "threat_intelligence"
    EVIDENCE = "evidence"
    CORRELATED_FINDING = "correlated_finding"
    AGENT_SESSION = "agent_session"
    AGENT_EVENT = "agent_event"
    NOTIFICATION = "notification"
    SECURITY_ALERT = "security_alert"
    EXTENSION_EVENT = "extension_event"
    MEDIA_ASSET = "media_asset"
    MEDIA_ASSESSMENT = "media_assessment"
    MEDIA_JOB = "media_job"
    SYSTEM = "system"


class RealtimeEvent(BaseModel):
    """
    Standardized, auditable real-time event envelope.
    Ensures idempotency, typed entities, and tamper-resistant timestamps.
    """
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_type: RealtimeEventType
    entity_type: EntityType
    entity_id: str
    user_id: Optional[str] = None
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    version: int = Field(default=1, description="Entity or event schema version")
    payload: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(use_enum_values=True)


class RealtimeHealthStatus(BaseModel):
    status: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    database: str
    realtime: str
    active_subscriptions: int = 0
    total_events_published: int = 0
