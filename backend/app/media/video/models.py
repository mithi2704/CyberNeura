"""
Video analysis schema definitions.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class SampledFrame(BaseModel):
    frame_number: int
    timestamp: float
    is_keyframe: bool = False
    rgb_data: Optional[Any] = None  # numpy array held in memory during processing


class DetectedFace(BaseModel):
    face_index: int
    bounding_box: Dict[str, int]  # { "x": int, "y": int, "w": int, "h": int }
    quality_score: float = Field(ge=0.0, le=1.0)
    blur_score: float = 0.0
    illumination_score: float = 1.0


class TrackedFace(BaseModel):
    track_id: int
    frames: List[int] = Field(default_factory=list)
    faces: List[DetectedFace] = Field(default_factory=list)
    temporal_variance: float = 0.0
