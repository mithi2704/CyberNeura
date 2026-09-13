"""
Risk Subsystem Models for CyberNeura Phase 3.
Defines risk factors, risk bands, assessments, recommendations, and configuration schemas.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from app.evidence.models import Evidence, CorrelatedFinding, EvidenceSeverity


class RiskBand(str, Enum):
    SAFE = "SAFE"
    LOW = "LOW"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RiskFactor(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scan_id: Optional[str] = None
    factor_type: str  # e.g. "ML_PREDICTION", "THREAT_INTELLIGENCE", "DNS", "WHOIS", "URL_FEATURES", "HISTORY"
    factor_name: str
    raw_value: Any = None
    normalized_value: float = Field(default=0.0, ge=0.0, le=1.0)
    weight: float = Field(default=0.1, ge=0.0)
    contribution: float = Field(default=0.0)  # points added/subtracted (e.g. +27.0 out of 30)
    max_contribution: float = Field(default=10.0)  # maximum points this factor could contribute (e.g. 30.0)
    direction: str = "RISK_INCREASING"  # "RISK_INCREASING", "RISK_DECREASING", "NEUTRAL"
    description: str
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class DetailedRecommendation(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    description: str
    severity: EvidenceSeverity = EvidenceSeverity.MEDIUM
    reason: str
    action: str


class SecurityAssessment(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scan_id: str
    url: str
    risk_score: int = Field(ge=0, le=100)
    prediction: str  # "safe", "suspicious", "malicious" (for UI compatibility)
    confidence: float = Field(ge=0.0, le=100.0)
    threat_category: str = "Safe"
    severity: EvidenceSeverity = EvidenceSeverity.INFO
    summary: str
    evidence_count: int = 0
    critical_evidence_count: int = 0
    supporting_evidence_count: int = 0
    contradicting_evidence_count: int = 0
    evidence: List[Evidence] = Field(default_factory=list)
    correlated_findings: List[CorrelatedFinding] = Field(default_factory=list)
    risk_factors: List[RiskFactor] = Field(default_factory=list)
    recommendations: List[DetailedRecommendation] = Field(default_factory=list)
    explanation: str = ""
    risk_engine_version: str = "1.0.0"
    config_version: str = "2026.09.1"
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: Optional[str] = None


class RiskConfig(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = "default"
    version: str = "2026.09.1"
    weights: Dict[str, float] = Field(default_factory=lambda: {
        "ml": 0.30,
        "threat_intel": 0.30,
        "dns": 0.10,
        "whois": 0.10,
        "url_features": 0.10,
        "history": 0.10,
    })
    thresholds: Dict[str, int] = Field(default_factory=lambda: {
        "safe": 20,
        "suspicious": 40,
        "high": 60,
        "malicious": 80,
    })
    enabled: bool = True
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: Optional[str] = None
