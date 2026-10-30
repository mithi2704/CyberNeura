"""Threat Intelligence routes."""
from __future__ import annotations

import math
from typing import Optional
from fastapi import APIRouter, HTTPException, Query
from app.database import get_db
from app.dependencies import AuthUser, AnalystUser
from app.services.scan_store import scan_store
from app.utils.logger import get_logger

logger = get_logger(__name__)
router = APIRouter(tags=["Threat Intelligence"], prefix="/threats")


def _row_to_threat(row: dict) -> dict:
    return {
        "id": str(row.get("id", "")),
        "url": row.get("url", ""),
        "severity": row.get("severity", "medium"),
        "category": row.get("category", "Suspicious"),
        "sourceIp": row.get("sourceIp", row.get("source_ip", "Unknown")),
        "country": row.get("country", "Unknown"),
        "timestamp": str(row.get("timestamp", "")),
        "status": row.get("status", "blocked"),
    }


@router.get("", summary="Get threat intelligence feed")
async def list_threats(
    user: AuthUser,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=500),
    severity: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
):
    # Unified operational store (guarantees complete threat history from the beginning)
    result = scan_store.get_threats(
        page=page,
        page_size=page_size,
        severity=severity,
        category=category,
        search=search,
    )
    if result["total"] > 0:
        return result

    db = get_db()
    if db is None:
        return result

    try:
        q = db.table("threat_logs").select("*").order("timestamp", desc=True)
        if severity:
            q = q.eq("severity", severity)
        if category:
            q = q.eq("category", category)
        if status:
            q = q.eq("status", status)
        if search:
            q = q.ilike("url", f"%{search}%")

        count_q = db.table("threat_logs").select("id", count="exact")
        total_res = count_q.execute()
        total = total_res.count or 0

        start = (page - 1) * page_size
        result = q.range(start, start + page_size - 1).execute()
        items = [_row_to_threat(r) for r in (result.data or [])]

        return {"items": items, "page": page, "pageSize": page_size,
                "total": total, "totalPages": max(1, math.ceil(total / page_size))}
    except Exception as exc:
        logger.warning(f"Threats DB fetch error, using scan_store fallback: {exc}")
        return scan_store.get_threats(
            page=page,
            page_size=page_size,
            severity=severity,
            category=category,
            search=search,
        )


@router.get("/trends", summary="Threat trends grouped by date and provider")
async def get_threat_trends(
    user: AuthUser,
    days: int = Query(7, ge=1, le=30),
):
    """
    Returns threat intelligence trends grouped by date and provider.
    Uses real database threat intelligence and scan records.
    """
    return {"data": scan_store.get_threat_trends_by_provider(days=days)}


@router.get("/breakdown", summary="Threat intelligence detection breakdown")
async def get_threat_breakdown(user: AuthUser):
    """
    Returns detection breakdown across ML, Google Web Risk, PhishTank, URLhaus, and multi-source detections.
    Never counts provider errors or unavailable lookups as detections.
    """
    return scan_store.get_threat_breakdown()


@router.get("/{threat_id}", summary="Get a specific threat")
async def get_threat(threat_id: str, user: AuthUser):
    db = get_db()
    if db is None:
        for t in scan_store._threats:
            if t["id"] == threat_id:
                return _row_to_threat(t)
        raise HTTPException(status_code=404, detail={"error": "NOT_FOUND", "message": "Threat not found"})
    try:
        result = db.table("threat_logs").select("*").eq("id", threat_id).single().execute()
        if not result.data:
            raise HTTPException(status_code=404, detail={"error": "NOT_FOUND", "message": "Threat not found"})
        return _row_to_threat(result.data)
    except HTTPException:
        raise
    except Exception as exc:
        for t in scan_store._threats:
            if t["id"] == threat_id:
                return _row_to_threat(t)
        raise HTTPException(status_code=404, detail={"error": "NOT_FOUND", "message": "Threat not found"})


@router.delete("/{threat_id}", summary="Delete a threat log")
async def delete_threat(threat_id: str, user: AnalystUser):
    scan_store.delete_threat(threat_id)
    db = get_db()
    if db is None:
        return {"success": True, "message": "Threat deleted from memory"}
    try:
        db.table("threat_logs").delete().eq("id", threat_id).execute()
        return {"success": True}
    except Exception as exc:
        return {"success": True, "message": f"Deleted with warning: {exc}"}


