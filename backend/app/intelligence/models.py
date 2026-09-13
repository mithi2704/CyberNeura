"""Data models for Threat Intelligence providers, evidence, and results."""
from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ProviderVerdict(str, Enum):
    MATCH = "MATCH"
    NO_MATCH = "NO_MATCH"
    UNAVAILABLE = "UNAVAILABLE"
    ERROR = "ERROR"
    RATE_LIMITED = "RATE_LIMITED"


class ProviderStatus(str, Enum):
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    NOT_CONFIGURED = "NOT_CONFIGURED"


class ThreatCategory(str, Enum):
    SAFE = "SAFE"
    PHISHING = "PHISHING"
    MALWARE = "MALWARE"
    UNWANTED_SOFTWARE = "UNWANTED_SOFTWARE"
    SOCIAL_ENGINEERING = "SOCIAL_ENGINEERING"
    MALWARE_DISTRIBUTION = "MALWARE_DISTRIBUTION"
    SUSPICIOUS = "SUSPICIOUS"
    UNKNOWN = "UNKNOWN"


class ThreatIntelResult(BaseModel):
    """
    Normalized result structure returned by all threat intelligence providers.
    Never exposes raw API keys, secrets, or proprietary underlying lists.
    """
    provider: str
    indicator: str
    indicator_type: str = "url"
    available: bool = True
    matched: bool = False
    verdict: ProviderVerdict = ProviderVerdict.NO_MATCH
    categories: List[str] = Field(default_factory=list)
    confidence: Optional[float] = None
    checked_at: str
    expires_at: Optional[str] = None
    error: Optional[str] = None
    latency_ms: int = 0
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ProviderStatusInfo(BaseModel):
    name: str
    enabled: bool
    configured: bool
    status: ProviderStatus
    lastSuccessfulCheck: Optional[str] = None
    lastError: Optional[str] = None


class ProviderStatusListResponse(BaseModel):
    providers: List[ProviderStatusInfo]


class IntelligenceLookupRequest(BaseModel):
    url: str


class ScanIntelligenceResponse(BaseModel):
    scanId: str
    providers: List[ThreatIntelResult]
    independentConfirmations: int = 0
    checkedAt: str
