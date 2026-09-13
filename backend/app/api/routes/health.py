"""Health check routes."""
from fastapi import APIRouter
from app.database import check_db_health
from app.ml.predictor import get_model_version
from app.intelligence.manager import threat_intel_manager

router = APIRouter(tags=["Health"])


@router.get("/health", summary="Basic health check")
async def health():
    return {
        "status": "ok",
        "service": "CyberNeura Backend",
        "version": "1.0.0",
    }


@router.get("/health/detailed", summary="Detailed health check")
@router.get("/health/detail", summary="Detailed health check alias")
async def health_detailed():
    db_status = await check_db_health()
    model_version = get_model_version()
    provider_statuses = {
        p.name: p.status.value
        for p in threat_intel_manager.get_providers_status()
    }
    return {
        "status": "ok",
        "service": "CyberNeura Backend",
        "version": "1.0.0",
        "checks": {
            "database": db_status,
            "ml_model": {
                "status": "ok" if model_version != "heuristic-dev-fallback" else "fallback",
                "version": model_version,
            },
            "threat_intelligence": provider_statuses,
        },
    }

