"""Notifications routes — matches frontend notificationService.ts."""
from __future__ import annotations

from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException
from app.database import get_db
from app.dependencies import AuthUser
from app.utils.logger import get_logger

logger = get_logger(__name__)
router = APIRouter(tags=["Notifications"], prefix="/notifications")


def _row_to_notif(row: dict) -> dict:
    return {
        "id": str(row.get("id", "")),
        "title": row.get("title", ""),
        "body": row.get("body", ""),
        "type": row.get("type", "system_update"),
        "isRead": row.get("is_read", False),
        "userId": row.get("user_id"),
        "createdAt": str(row.get("created_at", "")),
    }


@router.get("", summary="Get user notifications")
async def get_notifications(user: AuthUser):
    db = get_db()
    if db is None:
        return []
    try:
        result = (
            db.table("notifications")
            .select("*")
            .eq("user_id", user.uid)
            .order("created_at", desc=True)
            .limit(50)
            .execute()
        )
        return [_row_to_notif(r) for r in (result.data or [])]
    except Exception as exc:
        logger.error(f"Notifications fetch error: {exc}")
        return []


@router.post("/{notif_id}/read", summary="Mark notification as read")
async def mark_read(notif_id: str, user: AuthUser):
    db = get_db()
    if db is None:
        return {"success": True}
    try:
        db.table("notifications").update({"is_read": True}).eq("id", notif_id).eq("user_id", user.uid).execute()
        return {"success": True}
    except Exception as exc:
        raise HTTPException(status_code=500, detail={"error": "DB_ERROR", "message": str(exc)})


@router.post("/read-all", summary="Mark all notifications as read")
async def mark_all_read(user: AuthUser):
    db = get_db()
    if db is None:
        return {"success": True}
    try:
        db.table("notifications").update({"is_read": True}).eq("user_id", user.uid).eq("is_read", False).execute()
        return {"success": True}
    except Exception as exc:
        raise HTTPException(status_code=500, detail={"error": "DB_ERROR", "message": str(exc)})


@router.delete("/{notif_id}", summary="Delete a notification")
async def delete_notification(notif_id: str, user: AuthUser):
    db = get_db()
    if db is None:
        return {"success": True}
    try:
        db.table("notifications").delete().eq("id", notif_id).eq("user_id", user.uid).execute()
        return {"success": True}
    except Exception as exc:
        raise HTTPException(status_code=500, detail={"error": "DB_ERROR", "message": str(exc)})
