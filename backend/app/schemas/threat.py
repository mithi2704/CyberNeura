"""Threat log schemas."""
from __future__ import annotations
from typing import List, Optional
from pydantic import BaseModel


class ThreatLog(BaseModel):
    id: str
    url: str
    severity: str          # critical | high | medium | low
    category: str          # Phishing | Malware | Suspicious
    sourceIp: str
    country: str
    timestamp: str
    status: str            # active | blocked | flagged | resolved


class ThreatListResponse(BaseModel):
    items: List[ThreatLog]
    page: int
    pageSize: int
    total: int
    totalPages: int
