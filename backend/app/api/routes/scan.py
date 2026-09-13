"""
POST /scan — Primary URL scanning endpoint.
Also available as POST /api/v1/scan for versioned access.
"""
from fastapi import APIRouter, HTTPException, status, Request
from app.schemas.scan import ScanRequest, ScanResponse
from app.services.scan_service import execute_scan
from app.utils.validators import validate_url
from app.dependencies import AuthUser
from app.utils.logger import get_logger

logger = get_logger(__name__)
router = APIRouter(tags=["Scanning"])


@router.post(
    "/scan",
    response_model=ScanResponse,
    summary="Scan a URL for threats",
    description="Analyze a URL using ML-powered threat detection. Returns risk score, prediction, and domain intelligence.",
)
async def scan_url(
    body: ScanRequest,
    user: AuthUser,
):
    url = body.url.strip()

    # Validate URL
    is_valid, error_msg = validate_url(url)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error_msg,
        )

    try:
        result = await execute_scan(url=url, user_id=user.uid)
        return result
    except Exception as exc:
        logger.error(f"Scan failed for {url}: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "SCAN_FAILED", "message": "The scan encountered an unexpected error"},
        )
