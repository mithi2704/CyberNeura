"""
FastAPI dependency injection for auth, database, and current-user resolution.
"""
from __future__ import annotations

from typing import Annotated, Optional
from fastapi import Depends, HTTPException, Header, status
from app.auth.firebase import verify_firebase_token, is_demo_token
from app.database import get_db
from app.config import settings
from app.utils.logger import get_logger

logger = get_logger(__name__)


class CurrentUser:
    def __init__(
        self,
        uid: str,
        email: str,
        role: str = "user",
        is_demo: bool = False,
    ):
        self.uid = uid
        self.email = email
        self.role = role
        self.is_demo = is_demo

    def __repr__(self):
        return f"<User uid={self.uid} role={self.role}>"


async def _resolve_user_profile(uid: str, email: str) -> tuple[str, str]:
    """Fetch or auto-create user profile in Supabase. Returns (uid, role)."""
    db = get_db()
    if db is None:
        return uid, "user"

    try:
        result = db.table("profiles").select("id,role").eq("id", uid).execute()
        if result.data:
            return uid, result.data[0].get("role", "user")

        # Auto-create profile on first login
        default_role = "admin" if email == "admin@cyberneura.ai" else "user"
        db.table("profiles").insert({
            "id": uid,
            "email": email,
            "display_name": email.split("@")[0],
            "role": default_role,
        }).execute()
        return uid, default_role
    except Exception as exc:
        logger.warning(f"Could not resolve user profile for {uid}: {exc}")
        return uid, "user"


async def get_current_user(
    authorization: Annotated[Optional[str], Header()] = None
) -> CurrentUser:
    """
    Extract and verify the Bearer token from the Authorization header.
    Returns a CurrentUser or raises 401.
    """
    if not authorization or not authorization.startswith("Bearer "):
        if settings.allow_demo_auth and not settings.is_production:
            return CurrentUser(
                uid="dev-admin-user",
                email="admin@cyberneura.ai",
                role="admin",
                is_demo=True,
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "MISSING_TOKEN", "message": "Authorization header required"},
        )

    token = authorization.removeprefix("Bearer ").strip()

    # ── Demo mode ──────────────────────────────────────────────
    if is_demo_token(token):
        if not settings.allow_demo_auth and settings.is_production:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"error": "DEMO_AUTH_DISABLED", "message": "Demo auth is disabled in production"},
            )
        email = "demo@cyberneura.ai"
        role = "admin" if "admin" in token else "user"
        return CurrentUser(uid="demo-uid-12345", email=email, role=role, is_demo=True)

    # ── Firebase verification ───────────────────────────────────
    decoded = await verify_firebase_token(token)
    if decoded is None:
        if settings.allow_demo_auth and not settings.is_production:
            # Dev fallback: accept any token if Firebase is not configured
            logger.warning("Firebase not configured — accepting token in dev mode")
            uid = f"dev-{hash(token) % 100000}"
            return CurrentUser(uid=uid, email="dev@cyberneura.local", role="admin", is_demo=True)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "INVALID_TOKEN", "message": "Firebase token verification failed"},
        )

    uid = decoded.get("uid", "")
    email = decoded.get("email", "")
    _, role = await _resolve_user_profile(uid, email)
    return CurrentUser(uid=uid, email=email, role=role)


async def get_current_user_optional(
    authorization: Annotated[Optional[str], Header()] = None
) -> Optional[CurrentUser]:
    """Optional user resolution — returns CurrentUser or None if unauthenticated."""
    if not authorization or not authorization.startswith("Bearer "):
        return None
    try:
        return await get_current_user(authorization)
    except HTTPException:
        return None


# ── Convenience typed dependencies ──────────────────────────
AuthUser = Annotated[CurrentUser, Depends(get_current_user)]
OptionalAuthUser = Annotated[Optional[CurrentUser], Depends(get_current_user_optional)]


async def require_admin(user: AuthUser) -> CurrentUser:
    from app.auth.rbac import require_admin as _require_admin
    _require_admin(user.role)
    return user


async def require_analyst(user: AuthUser) -> CurrentUser:
    from app.auth.rbac import require_analyst as _require_analyst
    _require_analyst(user.role)
    return user


AdminUser = Annotated[CurrentUser, Depends(require_admin)]
AnalystUser = Annotated[CurrentUser, Depends(require_analyst)]
