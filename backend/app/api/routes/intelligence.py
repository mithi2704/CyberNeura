"""Threat Intelligence API endpoints."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List
from fastapi import APIRouter, HTTPException, status
from app.dependencies import AuthUser
from app.database import get_db
from app.services.scan_store import scan_store
from app.intelligence.manager import threat_intel_manager
from app.intelligence.models import (
    IntelligenceLookupRequest,
    ProviderStatusListResponse,
    ScanIntelligenceResponse,
    ThreatIntelResult,
)
from app.utils.validators import validate_url, normalize_url
from app.utils.logger import get_logger

logger = get_logger(__name__)
router = APIRouter(tags=["Threat Intelligence API"], prefix="/intelligence")


@router.post("/lookup", summary="On-demand external threat intelligence lookup")
async def manual_lookup(
    body: IntelligenceLookupRequest,
    user: AuthUser,
):
    """
    Query all enabled threat intelligence providers for a given URL without
    creating a full scan record. Returns normalized provider verdicts.
    """
    is_valid, err_msg = validate_url(body.url)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "INVALID_URL", "message": err_msg},
        )

    norm_url = normalize_url(body.url)
    results = await threat_intel_manager.lookup_all(norm_url)

    confirmations = sum(1 for r in results.values() if r.matched)

    return {
        "url": norm_url,
        "providers": [r.model_dump() for r in results.values()],
        "independentConfirmations": confirmations,
        "checkedAt": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/scan/{scan_id}", summary="Get threat intelligence results for a scan")
async def get_scan_intelligence(
    scan_id: str,
    user: AuthUser,
):
    """Return all normalized provider intelligence results stored for a scan."""
    db = get_db()
    if db is not None:
        try:
            res = db.table("threat_intelligence").select("*").eq("scan_id", scan_id).execute()
            if res.data:
                confirmations = sum(1 for r in res.data if r.get("matched"))
                return {
                    "scanId": scan_id,
                    "providers": res.data,
                    "independentConfirmations": confirmations,
                    "checkedAt": res.data[0].get("checked_at") if res.data else datetime.now(timezone.utc).isoformat(),
                }
        except Exception as exc:
            logger.warning(f"Failed to fetch scan intelligence from Supabase: {exc}")

    # Fallback to scan_store
    intel_items = scan_store.get_scan_intelligence(scan_id)
    confirmations = sum(1 for r in intel_items if r.get("matched"))
    return {
        "scanId": scan_id,
        "providers": intel_items,
        "independentConfirmations": confirmations,
        "checkedAt": datetime.now(timezone.utc).isoformat(),
    }


@router.post("/scan/{scan_id}/refresh", summary="Refresh intelligence for an existing scan")
async def refresh_scan_intelligence(
    scan_id: str,
    user: AuthUser,
):
    """
    Re-check external threat intelligence providers for a scan's URL.
    Updates the existing scan's threat intelligence without creating a duplicate scan.
    """
    # 1. Fetch scan URL
    scan = scan_store.get_scan_by_id(scan_id)
    scan_url = scan.get("url") if scan else None

    if not scan_url:
        db = get_db()
        if db is not None:
            try:
                res = db.table("url_scans").select("url").eq("id", scan_id).single().execute()
                if res.data:
                    scan_url = res.data.get("url")
            except Exception:
                pass

    if not scan_url:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "NOT_FOUND", "message": f"Scan {scan_id} not found"},
        )

    # 2. Query fresh results bypassing cache
    results = await threat_intel_manager.lookup_all(scan_url, skip_cache=True)
    items = [r.model_dump() for r in results.values()]
    now = datetime.now(timezone.utc).isoformat()

    # 3. Update scan_store
    scan_store.add_scan_intelligence(scan_id, items)
    confirmations = sum(1 for r in results.values() if r.matched)

    # Update threatIntelligence in scan object
    scan_store.update_scan(scan_id, {
        "threatIntelligence": {name: res.model_dump() for name, res in results.items()}
    })

    # 4. Update Supabase if available
    db = get_db()
    if db is not None:
        try:
            # Delete old intelligence rows for this scan
            db.table("threat_intelligence").delete().eq("scan_id", scan_id).execute()
            records = []
            for p_name, res in results.items():
                records.append({
                    "scan_id": scan_id,
                    "provider": p_name,
                    "indicator": res.indicator,
                    "indicator_type": res.indicator_type,
                    "status": res.verdict.value,
                    "matched": res.matched,
                    "verdict": res.verdict.value,
                    "threat_type": ", ".join(res.categories) if res.categories else None,
                    "confidence": res.confidence,
                    "metadata": res.metadata,
                    "checked_at": res.checked_at,
                    "expires_at": res.expires_at,
                    "latency_ms": res.latency_ms,
                    "error_code": res.error,
                    "created_at": now,
                })
            if records:
                db.table("threat_intelligence").insert(records).execute()
        except Exception as exc:
            logger.warning(f"Could not refresh threat intelligence in Supabase: {exc}")

    return {
        "scanId": scan_id,
        "providers": items,
        "independentConfirmations": confirmations,
        "checkedAt": now,
    }


@router.get("/providers/status", response_model=ProviderStatusListResponse, summary="Get status of all intelligence providers")
async def get_providers_status(user: AuthUser):
    """
    Returns the real-time operational and configuration health of each provider.
    Never exposes API keys, tokens, or private secrets.
    """
    statuses = threat_intel_manager.get_providers_status()
    return ProviderStatusListResponse(providers=statuses)
