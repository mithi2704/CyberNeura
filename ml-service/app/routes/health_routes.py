"""Health check routes for ML Microservice."""
from fastapi import APIRouter

router = APIRouter(tags=["Health"])


@router.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "cyberneura-ml-microservice",
        "version": "2.1.0",
        "active_models": {
            "url_model": "RandomForest-28feat (URLBERT Ready)",
            "image_model": "CyberNeuraSyntheticDetectorCNN (CapCheck ViT Ready)",
        },
    }

