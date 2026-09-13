"""
Evidence Data Models for CyberNeura Phase 3 Risk + Evidence Engine.
Normalized representations of security facts across ML, Threat Intel, DNS, WHOIS,
URL Features, and Scan History.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class EvidenceSource(str, Enum):
    ML = "ML"
    GOOGLE_WEB_RISK = "GOOGLE_WEB_RISK"
    PHISHTANK = "PHISHTANK"
    URLHAUS = "URLHAUS"
    DNS = "DNS"
    WHOIS = "WHOIS"
    URL_FEATURES = "URL_FEATURES"
    HISTORY = "HISTORY"
    # Phase 7 Media Sources
    IMAGE_MODEL = "IMAGE_MODEL"
    DEEPFAKE_MODEL = "DEEPFAKE_MODEL"
    PROVENANCE = "PROVENANCE"
    FORENSICS = "FORENSICS"
    FRAME_ANALYSIS = "FRAME_ANALYSIS"
    FACE_ANALYSIS = "FACE_ANALYSIS"
    TEMPORAL_ANALYSIS = "TEMPORAL_ANALYSIS"
    MEDIA_METADATA = "MEDIA_METADATA"


class EvidenceType(str, Enum):
    ML_PREDICTION = "ml_prediction"
    THREAT_INTEL_MATCH = "threat_intel_match"
    PHISHING_DATABASE_MATCH = "phishing_database_match"
    MALWARE_DATABASE_MATCH = "malware_database_match"
    DNS_RESOLUTION = "dns_resolution"
    DNS_ANOMALY = "dns_anomaly"
    DOMAIN_AGE = "domain_age"
    REGISTRATION_STATUS = "registration_status"
    REGISTRAR = "registrar"
    NAMESERVER = "nameserver"
    IP_REPUTATION = "ip_reputation"
    HOSTNAME_ANOMALY = "hostname_anomaly"
    URL_LENGTH = "url_length"
    URL_ENTROPY = "url_entropy"
    SUSPICIOUS_TLD = "suspicious_tld"
    SUSPICIOUS_PATH = "suspicious_path"
    REDIRECT = "redirect"
    HISTORICAL_DETECTION = "historical_detection"
    HISTORICAL_ALLOW = "historical_allow"
    REPEATED_SCAN = "repeated_scan"
    PROVIDER_UNAVAILABLE = "provider_unavailable"
    # Phase 7 Media Evidence Types
    AI_GENERATION_PROBABILITY = "ai_generation_probability"
    DEEPFAKE_PROBABILITY = "deepfake_probability"
    C2PA_VERIFIED = "c2pa_verified"
    C2PA_PRESENT = "c2pa_present"
    PROVENANCE_ABSENT = "provenance_absent"
    COMPRESSION_ANOMALY = "compression_anomaly"
    NOISE_INCONSISTENCY = "noise_inconsistency"
    METADATA_INCONSISTENCY = "metadata_inconsistency"
    RESAMPLING_ARTIFACT = "resampling_artifact"
    FACE_MANIPULATION_DETECTED = "face_manipulation_detected"
    TEMPORAL_INCONSISTENCY = "temporal_inconsistency"
    FRAME_ANOMALY = "frame_anomaly"
    HIGH_CONFIDENCE_FRAMES = "high_confidence_frames"


class EvidenceSeverity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class EvidenceState(str, Enum):
    CONFIRMED = "CONFIRMED"
    SUPPORTING = "SUPPORTING"
    CONTRADICTING = "CONTRADICTING"
    UNKNOWN = "UNKNOWN"
    UNAVAILABLE = "UNAVAILABLE"


class Evidence(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scan_id: Optional[str] = None
    media_id: Optional[str] = None
    source: EvidenceSource
    evidence_type: EvidenceType
    category: Optional[str] = None
    severity: EvidenceSeverity = EvidenceSeverity.INFO
    state: EvidenceState = EvidenceState.SUPPORTING
    value: Any = None
    score: float = Field(default=0.0, ge=0.0, le=1.0)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    weight: float = Field(default=1.0, ge=0.0)
    supports_risk: bool = True
    description: str
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class CorrelatedFinding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scan_id: Optional[str] = None
    media_id: Optional[str] = None
    finding_type: str
    severity: EvidenceSeverity
    confidence: float = Field(default=0.9, ge=0.0, le=1.0)
    description: str
    sources: List[str] = Field(default_factory=list)
    evidence_ids: List[str] = Field(default_factory=list)
    rule_id: Optional[str] = None
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

