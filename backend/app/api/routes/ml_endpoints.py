"""
CyberNeura ML Microservice Endpoints.
Implements standardized prediction endpoints:
- GET /health (and root health)
- GET /api/v1/models/info
- POST /api/v1/scan/url
- POST /api/v1/detect/image
"""
from __future__ import annotations

import io
import logging
from typing import Any, Dict, Optional
from fastapi import APIRouter, File, HTTPException, UploadFile, status
from pydantic import BaseModel, Field
from PIL import Image

from app.ml.predictor import predict, get_model_metadata, get_model_version
from app.services.feature_extractor import extract_features
from app.media.model_registry import model_registry
from app.media.validators import validate_image_file

logger = logging.getLogger(__name__)

router = APIRouter(tags=["ML Microservice"])


# --- Schemas ---
class URLScanInput(BaseModel):
    url: str = Field(..., description="Target URL to inspect for phishing/threats", example="https://example.com")


class URLScanData(BaseModel):
    prediction: str = Field(..., description="LEGITIMATE or PHISHING")
    phishing_probability: float
    legitimate_probability: float
    model_version: str


class URLScanOutput(BaseModel):
    success: bool = True
    module: str = "URL_DETECTION"
    data: URLScanData


class ImageDetectData(BaseModel):
    prediction: str = Field(..., description="AI_GENERATED or REAL")
    ai_probability: float
    real_probability: float
    model_version: str


class ImageDetectOutput(BaseModel):
    success: bool = True
    module: str = "AI_IMAGE_DETECTION"
    data: ImageDetectData


# --- Routes ---
@router.get("/models/info", summary="Retrieve active ML models metadata and performance metrics")
async def get_models_info():
    """Returns metadata, architectures, versions, and metrics for URL and Image models."""
    url_meta = get_model_metadata()
    media_models = model_registry.list_models()
    
    return {
        "status": "ok",
        "url_model": {
            "model_name": "CyberNeura URL Threat Classifier",
            "version": url_meta.get("version", get_model_version()),
            "algorithm": url_meta.get("algorithm", "RandomForestClassifier"),
            "accuracy": url_meta.get("accuracy", 0.9829),
            "precision": url_meta.get("precision", 0.9828),
            "recall": url_meta.get("recall", 0.9829),
            "f1_score": url_meta.get("f1_score", 0.9827),
            "preferred_transformer": "CrabInHoney/urlbert-tiny-v6",
        },
        "image_model": {
            "model_name": "CyberNeura Synthetic Detector CNN",
            "version": "1.1.0",
            "framework": "PyTorch",
            "accuracy": 0.9473,
            "roc_auc": 0.9864,
            "preferred_hf_model": "aaronkantrowitz/ai-image-detection",
            "registered_models": media_models,
        },
    }


@router.post("/scan/url", response_model=URLScanOutput, summary="Fast URL Threat Prediction")
async def scan_url_prediction(body: URLScanInput):
    """
    Evaluates target URL using the trained ML model.
    Returns standardized normalized classification (LEGITIMATE / PHISHING) and probabilities.
    """
    raw_url = body.url.strip()
    if not raw_url:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="URL cannot be empty")

    try:
        features = extract_features(raw_url)
        prediction, probability, confidence, fi = predict(features)
        
        phishing_prob = float(probability)
        legit_prob = float(round(1.0 - phishing_prob, 4))
        
        norm_prediction = "PHISHING" if prediction.lower() in ("malicious", "phishing") or phishing_prob >= 0.50 else "LEGITIMATE"
        
        return URLScanOutput(
            success=True,
            module="URL_DETECTION",
            data=URLScanData(
                prediction=norm_prediction,
                phishing_probability=round(phishing_prob, 4),
                legitimate_probability=round(legit_prob, 4),
                model_version=f"url-v{get_model_version()}",
            )
        )
    except Exception as exc:
        logger.error(f"Prediction failed for {raw_url}: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"URL prediction error: {exc}",
        )


@router.post("/detect/image", response_model=ImageDetectOutput, summary="Detect AI-Generated vs Real Image")
async def detect_image_prediction(file: UploadFile = File(...)):
    """
    Accepts multipart image upload, validates image format and dimensions,
    and runs inference through the AI Image Detection neural pipeline.
    """
    file_bytes = await file.read()
    filename = file.filename or "upload.jpg"
    
    # 1. Validation & Safety Checks
    try:
        detected_format, detected_mime, width, height = validate_image_file(file_bytes, filename)
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(val_err))

    # 2. Maximum image dimension and size boundary
    if len(file_bytes) > 25 * 1024 * 1024:
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="Image size exceeds 25MB limit")
        
    try:
        # Load active model from registry
        model = model_registry.get_active_model("image_ai_detection")
        if not model:
            from app.media.image.inference import ImageDetectionModel
            model = ImageDetectionModel()
            model.load()
            model_registry.register_model(model, is_active=True)

        from app.media.image.preprocessing import preprocess_image_for_model
        tensor, np_img, _ = preprocess_image_for_model(file_bytes)
        
        result = model.predict((tensor, np_img))
        ai_prob = float(result.get("probability_ai_generated", 0.5))
        real_prob = float(round(1.0 - ai_prob, 4))
        
        pred_label = "AI_GENERATED" if ai_prob >= 0.50 else "REAL"
        
        return ImageDetectOutput(
            success=True,
            module="AI_IMAGE_DETECTION",
            data=ImageDetectData(
                prediction=pred_label,
                ai_probability=round(ai_prob, 4),
                real_probability=round(real_prob, 4),
                model_version=f"image-v{model.version}",
            )
        )
    except Exception as exc:
        logger.error(f"Image detection failed: {exc}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Image detection error: {exc}",
        )

