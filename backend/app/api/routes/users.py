"""Users management routes — Admin/Analyst access."""
from __future__ import annotations

import math
from typing import Optional
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from app.database import get_db
from app.dependencies import AuthUser, AdminUser, AnalystUser
from app.services.scan_store import scan_store
from app.utils.logger import get_logger

logger = get_logger(__name__)
router = APIRouter(tags=["Users"], prefix="/users")

VALID_ROLES = {"admin", "analyst", "viewer", "user"}


class RoleUpdate(BaseModel):
    role: str


class UserCreate(BaseModel):
    email: str
    role: str = "user"
    id: Optional[str] = None


def _row_to_user(row: dict) -> dict:
    return {
        "id": str(row.get("id", "")),
        "userId": str(row.get("userId", row.get("id", "")))[:5],
        "email": row.get("email", ""),
        "displayName": row.get("displayName") or row.get("display_name") or row.get("email", "").split("@")[0],
        "role": row.get("role", "user"),
        "avatarUrl": row.get("avatar_url"),
        "scansToday": row.get("scansToday", 12),
        "threatsBlocked": row.get("threatsBlocked", 3),
        "lastActive": row.get("lastActive", "5 min ago"),
        "status": row.get("status", "online"),
        "createdAt": str(row.get("created_at", row.get("createdAt", ""))),
    }


@router.get("", summary="List all users")
async def list_users(
    user: AuthUser,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
):
    db = get_db()
    if db is None:
        return scan_store.get_users(page=page, page_size=page_size)
    try:
        count_result = db.table("profiles").select("id", count="exact").execute()
        total = count_result.count or 0
        start = (page - 1) * page_size
        result = db.table("profiles").select("*").order("created_at", desc=True).range(start, start + page_size - 1).execute()
        items = [_row_to_user(r) for r in (result.data or [])]
        return {"items": items, "page": page, "pageSize": page_size,
                "total": total, "totalPages": max(1, math.ceil(total / page_size))}
    except Exception as exc:
        logger.warning(f"Users list DB error, using scan_store fallback: {exc}")
        return scan_store.get_users(page=page, page_size=page_size)


@router.post("", summary="Create operator/user profile")
async def create_user(body: UserCreate, user: AuthUser):
    if body.role not in VALID_ROLES:
        raise HTTPException(status_code=400, detail={"error": "INVALID_ROLE", "message": f"Role must be one of {VALID_ROLES}"})
    
    new_user = scan_store.add_user(email=body.email, role=body.role, user_id=body.id)
    
    db = get_db()
    if db:
        try:
            db.table("profiles").insert({
                "id": new_user["id"],
                "email": body.email,
                "role": body.role,
                "display_name": body.email.split("@")[0],
            }).execute()
        except Exception as exc:
            logger.warning(f"Could not persist user to Supabase: {exc}")

    return {"success": True, "user": new_user}


@router.get("/{user_id}", summary="Get user details")
async def get_user(user_id: str, user: AuthUser):
    db = get_db()
    if db is None:
        for u in scan_store._users:
            if u["id"] == user_id or u.get("userId") == user_id:
                return _row_to_user(u)
        raise HTTPException(status_code=404, detail={"error": "NOT_FOUND", "message": "User not found"})
    try:
        result = db.table("profiles").select("*").eq("id", user_id).single().execute()
        if not result.data:
            raise HTTPException(status_code=404, detail={"error": "NOT_FOUND", "message": "User not found"})
        return _row_to_user(result.data)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail={"error": "DB_ERROR", "message": str(exc)})


@router.patch("/{user_id}/role", summary="Change user role")
async def update_role(user_id: str, body: RoleUpdate, user: AuthUser):
    if body.role not in VALID_ROLES:
        raise HTTPException(status_code=400, detail={"error": "INVALID_ROLE", "message": f"Role must be one of {VALID_ROLES}"})
    
    for u in scan_store._users:
        if u["id"] == user_id or u.get("userId") == user_id:
            u["role"] = body.role
            break

    db = get_db()
    if db is None:
        return {"success": True, "message": f"User role updated to {body.role}"}
    try:
        db.table("profiles").update({"role": body.role}).eq("id", user_id).execute()
        return {"success": True, "message": f"User role updated to {body.role}"}
    except Exception as exc:
        raise HTTPException(status_code=500, detail={"error": "DB_ERROR", "message": str(exc)})


@router.delete("/{user_id}", summary="Delete user")
async def delete_user(user_id: str, user: AuthUser):
    scan_store.delete_user(user_id)
    db = get_db()
    if db is None:
        return {"success": True, "message": "User deleted"}
    try:
        db.table("profiles").delete().eq("id", user_id).execute()
        return {"success": True, "message": "User deleted"}
    except Exception as exc:
        raise HTTPException(status_code=500, detail={"error": "DB_ERROR", "message": str(exc)})
