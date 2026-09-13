"""
Core Data Models and Enums for CyberNeura Phase 7 AI Media Security.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class MediaType(str, Enum):
    IMAGE = "IMAGE"
    VIDEO = "VIDEO"


class MediaClassification(str, Enum):
    LIKELY_AUTHENTIC = "LIKELY_AUTHENTIC"
    SUSPICIOUS = "SUSPICIOUS"
    LIKELY_AI_GENERATED = "LIKELY_AI_GENERATED"
    LIKELY_DEEPFAKE = "LIKELY_DEEPFAKE"
    INCONCLUSIVE = "INCONCLUSIVE"


class ProvenanceStatus(str, Enum):
    PROVENANCE_CONFIRMED = "PROVENANCE_CONFIRMED"
    PROVENANCE_PRESENT = "PROVENANCE_PRESENT"
    PROVENANCE_ABSENT = "PROVENANCE_ABSENT"
    PROVENANCE_INVALID = "PROVENANCE_INVALID"
    PROVENANCE_UNAVAILABLE = "PROVENANCE_UNAVAILABLE"


class JobStatus(str, Enum):
    QUEUED = "QUEUED"
    PROCESSING = "PROCESSING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class MediaAsset(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: Optional[str] = None
    media_type: MediaType
    storage_path: str
    original_filename: str
    mime_type: str
    file_size: int
    sha256: str
    width: Optional[int] = None
    height: Optional[int] = None
    duration: Optional[float] = None
    frame_count: Optional[int] = None
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    expires_at: Optional[str] = None


class ProvenanceClaim(BaseModel):
    label: str
    value: str
    verified: bool = False
    details: Dict[str, Any] = Field(default_factory=dict)


class ProvenanceRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    media_id: str
    status: ProvenanceStatus
    format: Optional[str] = None  # e.g., "C2PA", "EXIF_SIGNATURE", "NONE"
    verified: bool = False
    issuer: Optional[str] = None
    claims: List[ProvenanceClaim] = Field(default_factory=list)
    raw_metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class ForensicResult(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    media_id: str
    signal_type: str  # e.g. "error_level_analysis", "frequency_spectral", "noise_variance", "lighting_consistency"
    severity: str = "INFO"  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    confidence: float = Field(ge=0.0, le=1.0)
    value: Any = None
    description: str
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class FaceResult(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    frame_result_id: str
    face_index: int = 0
    bounding_box: Dict[str, int]  # { "x": int, "y": int, "w": int, "h": int }
    quality_score: float = Field(ge=0.0, le=1.0)
    manipulation_probability: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    anomalies: List[str] = Field(default_factory=list)
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class FrameResult(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    media_id: str
    frame_number: int
    timestamp: float
    model_probability: float = Field(ge=0.0, le=1.0)
    model_confidence: float = Field(ge=0.0, le=1.0)
    face_count: int = 0
    face_quality: float = 1.0
    classification: str = "LIKELY_REAL"  # LIKELY_REAL, LIKELY_MANIPULATED, INCONCLUSIVE
    faces: List[FaceResult] = Field(default_factory=list)
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class MediaAssessment(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    media_id: str
    user_id: Optional[str] = None
    media_type: MediaType
    classification: MediaClassification
    risk_score: int = Field(ge=0, le=100)
    confidence: float = Field(ge=0.0, le=100.0)
    severity: str = "INFO"
    summary: str
    model: Dict[str, Any] = Field(default_factory=dict)
    provenance: Optional[Dict[str, Any]] = None
    forensics: List[Dict[str, Any]] = Field(default_factory=list)
    evidence: List[Dict[str, Any]] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    model_version: str = "1.0.0"
    analysis_version: str = "1.0.0"
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class MediaJob(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    media_id: Optional[str] = None
    user_id: Optional[str] = None
    media_type: MediaType
    status: JobStatus = JobStatus.QUEUED
    progress: int = Field(default=0, ge=0, le=100)
    current_stage: str = "INITIALIZING"
    error_message: Optional[str] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
