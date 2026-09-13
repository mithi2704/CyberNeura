"""
Pydantic API Schemas for CyberNeura Phase 7 AI Media Security Endpoints.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from app.media.models import MediaType, MediaClassification, ProvenanceStatus, JobStatus


class ImageAnalyzeOptions(BaseModel):
    analysis_mode: str = "standard"
    include_provenance: bool = True
    include_forensics: bool = True


class VideoAnalyzeOptions(BaseModel):
    analysis_mode: str = "standard"
    frame_sampling_rate: int = 2
    max_frames: int = 300
    face_analysis: bool = True
    include_provenance: bool = True


class MediaJobStatusResponse(BaseModel):
    job_id: str
    media_id: Optional[str] = None
    media_type: MediaType
    status: JobStatus
    progress: int
    current_stage: str
    error_message: Optional[str] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    created_at: str
    assessment: Optional[Dict[str, Any]] = None


class ImageAnalyzeResponse(BaseModel):
    media_id: str
    media_type: MediaType = MediaType.IMAGE
    filename: str
    sha256: str
    classification: MediaClassification
    probability_ai_generated: float
    confidence: float
    risk_score: int
    severity: str
    summary: str
    explanation: str = ""
    model_score: float = 0.0
    independent_confirmations: int = 1
    model: Dict[str, Any]
    provenance: Optional[Dict[str, Any]] = None
    forensics: List[Dict[str, Any]] = Field(default_factory=list)
    evidence: List[Dict[str, Any]] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    created_at: str


class VideoAnalyzeSubmitResponse(BaseModel):
    job_id: str
    media_id: str
    media_type: MediaType = MediaType.VIDEO
    status: JobStatus = JobStatus.QUEUED
    progress: int = 0
    message: str = "Video analysis job queued successfully."


class MediaAssetResponse(BaseModel):
    id: str
    media_type: MediaType
    original_filename: str
    mime_type: str
    file_size: int
    sha256: str
    width: Optional[int] = None
    height: Optional[int] = None
    duration: Optional[float] = None
    frame_count: Optional[int] = None
    created_at: str


class MediaStatsResponse(BaseModel):
    total_analyzed: int
    ai_generated_images: int
    suspicious_images: int
    deepfake_videos: int
    suspicious_videos: int
    inconclusive_results: int
    average_confidence: float
