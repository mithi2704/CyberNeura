"""Settings routes — matches frontend ThemeContext/SettingsPage."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from app.database import get_db
from app.dependencies import AuthUser
from app.utils.logger import get_logger

logger = get_logger(__name__)
router = APIRouter(tags=["Settings"], prefix="/settings")


class SettingsUpdate(BaseModel):
    realTimeProtection: Optional[bool] = None
    autoBlock: Optional[bool] = None
    emailScanning: Optional[bool] = None
    browserProtection: Optional[bool] = None
    apiAccess: Optional[bool] = None
    notificationPreferences: Optional[Dict[str, Any]] = None


def _default_settings(user_id: str) -> dict:
    return {
        "id": f"settings-{user_id}",
        "userId": user_id,
        "realTimeProtection": True,
        "autoBlock": True,
        "emailScanning": False,
        "browserProtection": True,
        "apiAccess": False,
        "notificationPreferences": {
            "criticalAlerts": True,
            "dailyReports": True,
            "weeklyAnalytics": True,
            "systemUpdates": False,
            "newFeatures": False,
        },
        "licenseKey": "CNEU-2024-XXXX-XXXX",
        "licenseValidUntil": "2026-12-31",
        "apiUsageLimit": 50000,
        "apiUsageCount": 0,
        "updatedAt": datetime.now(timezone.utc).isoformat(),
    }


def _row_to_settings(row: dict, user_id: str) -> dict:
    return {
        "id": str(row.get("id", f"settings-{user_id}")),
        "userId": user_id,
        "realTimeProtection": row.get("real_time_protection", True),
        "autoBlock": row.get("auto_block", True),
        "emailScanning": row.get("email_scanning", False),
        "browserProtection": row.get("browser_protection", True),
        "apiAccess": row.get("api_access", False),
        "notificationPreferences": row.get("notification_preferences", {}),
        "licenseKey": row.get("license_key", "CNEU-2024-XXXX-XXXX"),
        "licenseValidUntil": str(row.get("license_valid_until", "2026-12-31")),
        "apiUsageLimit": row.get("api_usage_limit", 50000),
        "apiUsageCount": row.get("api_usage_count", 0),
        "updatedAt": str(row.get("updated_at", "")),
    }


@router.get("", summary="Get user settings")
async def get_settings(user: AuthUser):
    db = get_db()
    if db is None:
        return _default_settings(user.uid)
    try:
        result = db.table("system_settings").select("*").eq("user_id", user.uid).execute()
        if result.data:
            return _row_to_settings(result.data[0], user.uid)
        # Auto-create default settings
        defaults = {
            "user_id": user.uid,
            "real_time_protection": True,
            "auto_block": True,
            "email_scanning": False,
            "browser_protection": True,
            "api_access": False,
        }
        db.table("system_settings").insert(defaults).execute()
        return _default_settings(user.uid)
    except Exception as exc:
        logger.error(f"Settings fetch error: {exc}")
        return _default_settings(user.uid)


@router.put("", summary="Update user settings")
async def update_settings(body: SettingsUpdate, user: AuthUser):
    db = get_db()
    if db is None:
        return {"success": True}
    update_data: Dict[str, Any] = {}
    if body.realTimeProtection is not None:
        update_data["real_time_protection"] = body.realTimeProtection
    if body.autoBlock is not None:
        update_data["auto_block"] = body.autoBlock
    if body.emailScanning is not None:
        update_data["email_scanning"] = body.emailScanning
    if body.browserProtection is not None:
        update_data["browser_protection"] = body.browserProtection
    if body.apiAccess is not None:
        update_data["api_access"] = body.apiAccess
    if body.notificationPreferences is not None:
        update_data["notification_preferences"] = body.notificationPreferences
    update_data["updated_at"] = datetime.now(timezone.utc).isoformat()
    try:
        db.table("system_settings").update(update_data).eq("user_id", user.uid).execute()
        return {"success": True}
    except Exception as exc:
        raise HTTPException(status_code=500, detail={"error": "DB_ERROR", "message": str(exc)})


@router.post("/reset", summary="Reset settings to defaults")
async def reset_settings(user: AuthUser):
    db = get_db()
    if db is None:
        return {"success": True}
    try:
        defaults = {
            "real_time_protection": True, "auto_block": True,
            "email_scanning": False, "browser_protection": True,
            "api_access": False,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        db.table("system_settings").update(defaults).eq("user_id", user.uid).execute()
        return {"success": True, "message": "Settings reset to defaults"}
    except Exception as exc:
        raise HTTPException(status_code=500, detail={"error": "DB_ERROR", "message": str(exc)})


@router.post("/clear-logs", summary="Clear all scan logs for user")
async def clear_logs(user: AuthUser):
    from app.services.scan_store import scan_store
    scan_store.clear_scans()
    db = get_db()
    if db is None:
        return {"success": True, "message": "All scan logs cleared"}
    try:
        db.table("url_scans").delete().eq("scanned_by", user.uid).execute()
        return {"success": True, "message": "All scan logs cleared"}
    except Exception as exc:
        raise HTTPException(status_code=500, detail={"error": "DB_ERROR", "message": str(exc)})


@router.post("/deactivate", summary="Deactivate user account")
async def deactivate_account(user: AuthUser):
    # Soft deactivation — just clear their data for now
    # A full implementation would disable the Firebase account via Admin SDK
    db = get_db()
    if db is None:
        return {"success": True}
    try:
        db.table("url_scans").delete().eq("scanned_by", user.uid).execute()
        db.table("chat_history").delete().eq("user_id", user.uid).execute()
        db.table("notifications").delete().eq("user_id", user.uid).execute()
        return {"success": True, "message": "Account deactivated. Contact support for full deletion."}
    except Exception as exc:
        raise HTTPException(status_code=500, detail={"error": "DB_ERROR", "message": str(exc)})
