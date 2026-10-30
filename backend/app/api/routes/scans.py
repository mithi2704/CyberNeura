"""
GET /scans, GET /scans/{id}, DELETE /scans/{id}
Scan history management.
"""
from __future__ import annotations

from typing import Optional
from fastapi import APIRouter, HTTPException, Query, status
from app.schemas.scan import ScanListResponse, ScanSummary, ScanResponse, ScanUpdateRequest
from app.database import get_db
from app.dependencies import AuthUser
from app.auth.rbac import can_delete_scans
from app.services.scan_store import scan_store
from app.utils.logger import get_logger
import math

logger = get_logger(__name__)
router = APIRouter(tags=["Scans"], prefix="/scans")


def _db_to_summary(row: dict) -> dict:
    return {
        "id": str(row.get("id", "")),
        "url": row.get("url", ""),
        "prediction": row.get("prediction", "safe"),
        "riskScore": row.get("riskScore", row.get("risk_score", 0)),
        "confidence": row.get("confidence", 0),
        "threatCategory": row.get("threatCategory", row.get("threat_category")),
        "ipAddress": row.get("ipAddress", row.get("ip_address")),
        "sslStatus": row.get("sslStatus", row.get("ssl_status")),
        "scannedAt": str(row.get("scannedAt", row.get("scanned_at", ""))),
        "threatIntelligence": row.get("threatIntelligence", row.get("threat_intelligence")),
    }



@router.get("", response_model=ScanListResponse, summary="Get scan history")
async def list_scans(
    user: AuthUser,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=500),
    search: Optional[str] = Query(None),
    prediction: Optional[str] = Query(None),
):
    # Unified operational store (guarantees complete scan history from the beginning)
    result = scan_store.get_scans(page=page, page_size=page_size, search=search, prediction=prediction)
    if result["total"] > 0:
        items = [_db_to_summary(r) for r in result["items"]]
        return ScanListResponse(
            items=items,
            page=result["page"],
            pageSize=result["pageSize"],
            total=result["total"],
            totalPages=result["totalPages"],
        )

    db = get_db()
    if db is None:
        items = [_db_to_summary(r) for r in result["items"]]
        return ScanListResponse(
            items=items,
            page=result["page"],
            pageSize=result["pageSize"],
            total=result["total"],
            totalPages=result["totalPages"],
        )

    try:
        q = db.table("url_scans").select("*").order("scanned_at", desc=True)
        if search:
            q = q.ilike("url", f"%{search}%")
        if prediction:
            q = q.eq("prediction", prediction)

        count_q = db.table("url_scans").select("id", count="exact")
        if search:
            count_q = count_q.ilike("url", f"%{search}%")
        if prediction:
            count_q = count_q.eq("prediction", prediction)

        total_result = count_q.execute()
        total = total_result.count or 0

        start = (page - 1) * page_size
        result = q.range(start, start + page_size - 1).execute()
        items = [_db_to_summary(r) for r in (result.data or [])]

        return ScanListResponse(
            items=items,
            page=page, pageSize=page_size, total=total,
            totalPages=max(1, math.ceil(total / page_size)),
        )
    except Exception as exc:
        logger.warning(f"DB fetch failed, falling back to in-memory scan_store: {exc}")
        result = scan_store.get_scans(page=page, page_size=page_size, search=search, prediction=prediction)
        items = [_db_to_summary(r) for r in result["items"]]
        return ScanListResponse(
            items=items,
            page=result["page"],
            pageSize=result["pageSize"],
            total=result["total"],
            totalPages=result["totalPages"],
        )


@router.get("/{scan_id}", summary="Get a specific scan")
async def get_scan(scan_id: str, user: AuthUser):
    db = get_db()
    if db is None:
        scan = scan_store.get_scan_by_id(scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail={"error": "NOT_FOUND", "message": "Scan not found"})
        return scan
    try:
        result = db.table("url_scans").select("*").eq("id", scan_id).single().execute()
        if not result.data:
            raise HTTPException(status_code=404, detail={"error": "NOT_FOUND", "message": "Scan not found"})
        return result.data
    except HTTPException:
        raise
    except Exception as exc:
        logger.error(f"Failed to fetch scan {scan_id}: {exc}")
        raise HTTPException(status_code=500, detail={"error": "DB_ERROR", "message": str(exc)})


@router.delete("/{scan_id}", summary="Delete a scan")
async def delete_scan(scan_id: str, user: AuthUser):
    if not can_delete_scans(user.role):
        # Users can delete their own scans
        db = get_db()
        if db:
            try:
                res = db.table("url_scans").select("scanned_by").eq("id", scan_id).single().execute()
                if res.data and res.data.get("scanned_by") != user.uid:
                    raise HTTPException(status_code=403, detail={"error": "FORBIDDEN", "message": "Cannot delete others' scans"})
            except HTTPException:
                raise
            except Exception:
                pass

    # Always delete from scan_store
    scan_store.delete_scan(scan_id)

    db = get_db()
    if db is None:
        return {"success": True}
    try:
        db.table("url_scans").delete().eq("id", scan_id).execute()
        return {"success": True, "message": "Scan deleted"}
    except Exception as exc:
        raise HTTPException(status_code=500, detail={"error": "DB_ERROR", "message": str(exc)})


@router.delete("", summary="Clear all scans")
async def clear_all_scans(user: AuthUser):
    scan_store.clear_scans()
    db = get_db()
    if db is not None:
        try:
            db.table("url_scans").delete().neq("id", "00000000-0000-0000-0000-000000000000").execute()
        except Exception:
            pass
    return {"success": True, "message": "All scans cleared"}



@router.patch("/{scan_id}", summary="Update a scan's status or prediction")
async def update_scan(scan_id: str, body: ScanUpdateRequest, user: AuthUser):
    updates = {}
    if body.prediction is not None:
        updates["prediction"] = body.prediction
    if body.riskScore is not None:
        updates["riskScore"] = body.riskScore
        updates["risk_score"] = body.riskScore
    if body.threatCategory is not None:
        updates["threatCategory"] = body.threatCategory
        updates["threat_category"] = body.threatCategory

    updated = scan_store.update_scan(scan_id, updates)

    db = get_db()
    if db is not None:
        try:
            db_updates = {}
            if body.prediction is not None:
                db_updates["prediction"] = body.prediction
            if body.riskScore is not None:
                db_updates["risk_score"] = body.riskScore
            if body.threatCategory is not None:
                db_updates["threat_category"] = body.threatCategory
            if db_updates:
                db.table("url_scans").update(db_updates).eq("id", scan_id).execute()
        except Exception as exc:
            logger.warning(f"Failed to update scan {scan_id} in DB: {exc}")

    return {"success": True, "scan": updated}

