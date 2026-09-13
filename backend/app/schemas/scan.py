"""Scan request/response schemas — match frontend TypeScript interfaces exactly."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, field_validator


class ScanRequest(BaseModel):
    url: str

    @field_validator("url")
    @classmethod
    def url_must_not_be_empty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("URL cannot be empty")
        return v


class DNSInfo(BaseModel):
    a: List[str] = []
    aaaa: List[str] = []
    mx: List[str] = []
    ns: List[str] = []
    txt: List[str] = []
    cname: Optional[str] = None
    status: str = "ok"


class WHOISInfo(BaseModel):
    registrar: Optional[str] = None
    creation_date: Optional[str] = None
    expiration_date: Optional[str] = None
    updated_date: Optional[str] = None
    name_servers: List[str] = []
    country: Optional[str] = None
    status: str = "ok"


class ScanResponse(BaseModel):
    """
    Matches the ScanResponse interface in frontend/src/lib/api/aiService.ts
    Field names use camelCase to match the frontend TypeScript interface.
    """
    id: str
    url: str
    prediction: str                        # safe | suspicious | malicious
    riskScore: int                         # 0–100
    confidence: float                      # 0–100
    probability: float                     # 0.0–1.0
    threatCategory: Optional[str]          # Phishing | Malware | Suspicious | Safe | None
    isMalicious: bool
    explanation: str
    featureImportance: Dict[str, float] = {}
    # Domain metadata
    domainAge: Optional[str] = None
    hostingProvider: Optional[str] = None
    ipAddress: Optional[str] = None
    country: Optional[str] = None
    sslStatus: Optional[str] = None       # valid | invalid | expired | none
    whoisRecord: Optional[str] = None     # raw text for frontend display
    dnsRecords: Optional[str] = None      # raw text for frontend display
    recommendations: List[str] = []
    modelVersion: str = "1.0.0"
    scannedAt: str
    # Phase 2: Multi-source Threat Intelligence & Evidence
    threatIntelligence: Dict[str, Any] = {}
    evidence: List[Dict[str, Any]] = []
    independentConfirmations: int = 0
    # Phase 3: Risk + Evidence Engine Assessment
    riskAssessment: Optional[Dict[str, Any]] = None
    riskFactors: List[Dict[str, Any]] = []
    correlatedFindings: List[Dict[str, Any]] = []
    evidenceCount: int = 0
    severity: Optional[str] = None
    summary: Optional[str] = None


class ScanSummary(BaseModel):
    """Lightweight scan for list views (URL Logs page)."""
    id: str
    url: str
    prediction: str
    riskScore: int
    confidence: float
    threatCategory: Optional[str]
    ipAddress: Optional[str]
    sslStatus: Optional[str]
    scannedAt: str
    threatIntelligence: Optional[Dict[str, Any]] = None
    # Phase 3 additions
    evidenceCount: Optional[int] = 0
    summary: Optional[str] = None
    primaryThreatSource: Optional[str] = None


class ScanListResponse(BaseModel):
    items: List[ScanSummary]
    page: int
    pageSize: int
    total: int
    totalPages: int


class ScanUpdateRequest(BaseModel):
    prediction: Optional[str] = None
    riskScore: Optional[int] = None
    threatCategory: Optional[str] = None

