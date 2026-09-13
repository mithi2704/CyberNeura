"""
Risk API Routes for CyberNeura Phase 3.
Exposes endpoints for full assessment retrieval, risk factor breakdown,
correlated findings, recalculation against active configs, and config management.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Depends, status
from pydantic import BaseModel, Field

from app.services.risk_service import risk_service
from app.services.scan_store import scan_store
from app.dependencies import get_current_user_optional, require_admin
from app.utils.logger import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/risk", tags=["Risk Engine"])


class RiskConfigUpdateRequest(BaseModel):
    name: Optional[str] = None
    weights: Optional[Dict[str, float]] = None
    thresholds: Optional[Dict[str, int]] = None
    enabled: Optional[bool] = None


@router.get("/config", summary="Get active risk engine configuration")
async def get_risk_config():
    """Retrieve the active RiskConfig with factor weights and score thresholds."""
    return risk_service.get_config()


@router.put("/config", summary="Update risk engine configuration (Admin only)")
async def update_risk_config(
    payload: RiskConfigUpdateRequest,
    current_user=Depends(require_admin),
):
    """Update risk weights and threshold parameters. Requires admin authorization."""
    update_data = {k: v for k, v in payload.model_dump().items() if v is not None}
    if not update_data:
        raise HTTPException(status_code=400, detail="No configuration fields provided for update")

    # Validate weights sum to approximately 1.0 if provided
    if "weights" in update_data:
        total_w = sum(update_data["weights"].values())
        if not (0.95 <= total_w <= 1.05):
            raise HTTPException(status_code=400, detail=f"Weights must sum to 1.0 (got {total_w:.2f})")

    updated = risk_service.update_config(update_data)
    logger.info(f"Risk configuration updated by admin: {current_user.get('email')}")
    return updated


@router.get("/assess/{scan_id}", summary="Get complete security assessment for a scan")
async def get_assessment(scan_id: str):
    """Return the complete SecurityAssessment including score, confidence, factors, findings, and explanations."""
    assessment = risk_service.get_assessment(scan_id)
    if not assessment:
        raise HTTPException(status_code=404, detail=f"No assessment found for scan_id: {scan_id}")
    return assessment


@router.post("/assess/{scan_id}", summary="Rebuild or generate risk assessment for a scan")
async def rebuild_assessment(scan_id: str):
    """Rebuild or retrieve the risk assessment for a scan."""
    assessment = risk_service.get_assessment(scan_id)
    if not assessment:
        raise HTTPException(status_code=404, detail=f"No scan record found for scan_id: {scan_id}")
    return assessment


@router.get("/assess/{scan_id}/evidence", summary="Get normalized evidence for a scan")
async def get_assessment_evidence(scan_id: str):
    """Return the list of normalized Evidence objects supporting this scan's assessment."""
    evidence = risk_service.get_evidence(scan_id)
    return {"scan_id": scan_id, "evidence": evidence, "total": len(evidence)}


@router.get("/assess/{scan_id}/factors", summary="Get risk factor contributions breakdown")
async def get_assessment_factors(scan_id: str):
    """Return the breakdown of individual RiskFactor contributions (ML, Intel, DNS, WHOIS, Features, History)."""
    factors = risk_service.get_factors(scan_id)
    assessment = risk_service.get_assessment(scan_id) or {}
    return {
        "scan_id": scan_id,
        "risk_score": assessment.get("risk_score", 0),
        "prediction": assessment.get("prediction", "safe"),
        "factors": factors,
        "total_factors": len(factors),
    }


@router.get("/assess/{scan_id}/findings", summary="Get correlated findings for a scan")
async def get_assessment_findings(scan_id: str):
    """Return the list of multi-source CorrelatedFinding records."""
    findings = risk_service.get_findings(scan_id)
    return {"scan_id": scan_id, "findings": findings, "total": len(findings)}


@router.post("/assess/{scan_id}/recalculate", summary="Recalculate assessment with current risk configuration")
async def recalculate_assessment(scan_id: str):
    """
    Recalculate an existing assessment using the current active weights and thresholds.
    Updates risk scores and factor contributions without re-executing network queries.
    """
    recalculated = risk_service.recalculate_assessment(scan_id)
    if not recalculated:
        raise HTTPException(status_code=404, detail=f"No cached evidence found to recalculate assessment for scan_id: {scan_id}")
    return recalculated
