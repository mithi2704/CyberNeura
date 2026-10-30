"""Prediction routes for ML Microservice."""
from __future__ import annotations

from pathlib import Path
import sys
from fastapi import APIRouter, File, HTTPException, UploadFile, status

# Import engines from training modules
URL_TRAIN_DIR = Path(__file__).resolve().parent.parent.parent / "training" / "url"
IMG_TRAIN_DIR = Path(__file__).resolve().parent.parent.parent / "training" / "image"
if str(URL_TRAIN_DIR) not in sys.path:
    sys.path.insert(0, str(URL_TRAIN_DIR))
if str(IMG_TRAIN_DIR) not in sys.path:
    sys.path.insert(0, str(IMG_TRAIN_DIR))

from inference import url_engine
from inference import image_engine

from ml_service.app.schemas.predictions import (
    URLScanRequest,
    URLScanResponse,
    URLScanResult,
    ImageDetectResponse,
    ImageDetectResult,
)

router = APIRouter(tags=["Predictions"])


@router.get("/models/info")
async def get_models_info():
    return {
        "status": "ok",
        "url_model": {
            "model_name": "CyberNeura URL Threat Classifier",
            "version": "url-v2.1.0",
            "architecture": "RandomForestClassifier",
            "preferred_transformer": "CrabInHoney/urlbert-tiny-v6",
        },
        "image_model": {
            "model_name": "CyberNeura Synthetic Detector CNN",
            "version": "image-v1.1.0",
            "architecture": "CyberNeuraSyntheticDetectorCNN",
            "preferred_vit": "aaronkantrowitz/ai-image-detection",
        },
    }


@router.post("/scan/url", response_model=URLScanResponse)
async def scan_url_endpoint(req: URLScanRequest):
    res = url_engine.predict(req.url)
    return URLScanResponse(
        success=True,
        module="URL_DETECTION",
        data=URLScanResult(
            prediction=res["prediction"],
            phishing_probability=res["phishing_probability"],
            legitimate_probability=res["legitimate_probability"],
            model_version=res["model_version"],
        ),
    )


@router.post("/detect/image", response_model=ImageDetectResponse)
async def detect_image_endpoint(file: UploadFile = File(...)):
    file_bytes = await file.read()
    if len(file_bytes) == 0:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Uploaded file is empty.")
    if len(file_bytes) > 25 * 1024 * 1024:
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="File exceeds 25MB limit.")

    try:
        res = image_engine.predict_image_bytes(file_bytes)
        return ImageDetectResponse(
            success=True,
            module="AI_IMAGE_DETECTION",
            data=ImageDetectResult(
                prediction=res["prediction"],
                ai_probability=res["ai_probability"],
                real_probability=res["real_probability"],
                model_version=res["model_version"],
            ),
        )
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Image processing error: {exc}")

