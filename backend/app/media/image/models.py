"""
Data schemas specific to Image Analysis.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ImageAnalysisContext(BaseModel):
    media_id: str
    filename: str
    file_bytes: bytes
    sha256: str
    width: int
    height: int
    format: str
    color_mode: str
    metadata: Dict[str, Any] = Field(default_factory=dict)
    options: Dict[str, Any] = Field(default_factory=dict)


class ImageModelOutput(BaseModel):
    classification: str  # LIKELY_AUTHENTIC, LIKELY_AI_GENERATED, SUSPICIOUS, INCONCLUSIVE
    probability_ai_generated: float
    confidence: float
    model_id: str
    model_version: str
    framework: str
    device: str
    timestamp: str
    feature_metrics: Dict[str, Any] = Field(default_factory=dict)
