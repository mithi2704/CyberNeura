"""Schemas for ML prediction inputs and responses."""
from __future__ import annotations
from pydantic import BaseModel, Field


class URLScanRequest(BaseModel):
    url: str = Field(..., description="Target URL to inspect", example="https://example.com")


class URLScanResult(BaseModel):
    prediction: str
    phishing_probability: float
    legitimate_probability: float
    model_version: str


class URLScanResponse(BaseModel):
    success: bool = True
    module: str = "URL_DETECTION"
    data: URLScanResult


class ImageDetectResult(BaseModel):
    prediction: str
    ai_probability: float
    real_probability: float
    model_version: str


class ImageDetectResponse(BaseModel):
    success: bool = True
    module: str = "AI_IMAGE_DETECTION"
    data: ImageDetectResult

