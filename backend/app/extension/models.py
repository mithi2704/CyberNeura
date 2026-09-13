"""
Data models and schemas for CyberNeura Chrome Browser Extension (Phase 6).
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, ConfigDict


class ExtensionDecision(str, Enum):
    ALLOW = "ALLOW"
    WARN = "WARN"
    BLOCK = "BLOCK"


class ReportType(str, Enum):
    FALSE_POSITIVE = "false_positive"
    FALSE_NEGATIVE = "false_negative"
    OTHER = "other"


class ExtensionAnalyzeRequest(BaseModel):
    url: str = Field(..., description="Target URL to inspect and analyze")
    tab_id: Optional[int] = Field(None, description="Chrome tab identifier for telemetry")
    navigation_id: Optional[str] = Field(None, description="Chrome navigation identifier")
    timestamp: Optional[str] = Field(None, description="Client ISO timestamp")
    extension_version: str = Field("1.0.0", description="Installed extension version")
    browser: str = Field("chrome", description="Client browser identifier")
    installation_id: str = Field("default-install", description="Anonymous device/install identifier")

    model_config = ConfigDict(extra="ignore")


class ExtensionAnalyzeResponse(BaseModel):
    request_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    url: str
    decision: ExtensionDecision
    risk_score: int = Field(..., ge=0, le=100)
    prediction: str
    confidence: float = Field(..., ge=0.0, le=100.0)
    threat_category: Optional[str] = None
    severity: Optional[str] = None
    summary: str
    reasons: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    cached: bool = False
    analysis_timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    policy_version: str = "1.0.0"
    risk_engine_version: str = "1.0.0"
    allow_override: bool = True
    scan_id: Optional[str] = None

    model_config = ConfigDict(use_enum_values=True)


class ExtensionOverrideRequest(BaseModel):
    scan_id: str = Field(..., description="Identifier of the scan or event being overridden")
    url: str = Field(..., description="Target URL the user chose to continue to")
    installation_id: str = Field(..., description="Anonymous device/install identifier")
    original_decision: ExtensionDecision = Field(..., description="Original decision rendered by policy engine")
    override_action: str = Field("CONTINUE_ANYWAY", description="Action taken by user")
    timestamp: Optional[str] = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    model_config = ConfigDict(use_enum_values=True)


class ExtensionReportRequest(BaseModel):
    scan_id: str = Field(..., description="Scan identifier for feedback correlation")
    url: str = Field(..., description="Target URL of the reported result")
    installation_id: str = Field(..., description="Anonymous installation ID")
    report_type: ReportType = Field(ReportType.FALSE_POSITIVE, description="Nature of the report")
    feedback: str = Field(..., max_length=1000, description="User explanation or observation")
    timestamp: Optional[str] = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    model_config = ConfigDict(use_enum_values=True)


class ExtensionStatusResponse(BaseModel):
    service: str = "CyberNeura Extension API"
    status: str = "ONLINE"
    policy_version: str = "1.0.0"
    strict_mode: bool = False
    fallback_policy: str = "ALLOW"
    timeout_seconds: float = 8.0
    rate_limit_per_minute: int = 120
    cache_ttl_seconds: int = 300
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class ExtensionPolicyResponse(BaseModel):
    policy_version: str = "1.0.0"
    risk_threshold_safe: int = 30
    risk_threshold_suspicious: int = 70
    strict_mode: bool = False
    allow_override_warn: bool = True
    allow_override_block: bool = False
    rules: Dict[str, str] = Field(default_factory=dict)


class ExtensionChatRequest(BaseModel):
    url: str = Field(..., description="Target URL user is browsing")
    question: str = Field(..., description="User question about the website")
    risk_score: Optional[int] = Field(None, description="Current risk score if available")
    decision: Optional[str] = Field(None, description="Current decision: ALLOW, WARN, or BLOCK")
    threat_category: Optional[str] = Field(None, description="Detected threat category")
    page_title: Optional[str] = Field(None, description="Active page title")
    has_password_inputs: Optional[bool] = Field(None, description="Whether page contains password fields")
    has_card_inputs: Optional[bool] = Field(None, description="Whether page contains credit card/payment fields")
    history: Optional[List[Dict[str, str]]] = Field(default_factory=list, description="Recent conversation turns")

    model_config = ConfigDict(extra="ignore")


class ExtensionChatResponse(BaseModel):
    reply: str
    verdict: str = "SAFE"  # SAFE, SUSPICIOUS, THREAT
    risk_score: int = 0
    key_findings: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    model_config = ConfigDict(extra="ignore")

