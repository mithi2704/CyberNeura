"""
Supabase database client using the service role key for backend operations.
The service role key bypasses RLS — authorization is enforced in route handlers / RBAC.
"""
from __future__ import annotations

from functools import lru_cache
from typing import Optional

from supabase import create_client, Client
from app.config import settings
from app.utils.logger import get_logger

logger = get_logger(__name__)

_supabase_client: Optional[Client] = None


def get_db() -> Optional[Client]:
    """Return a configured Supabase service-role client, or None if not configured."""
    global _supabase_client
    if _supabase_client is not None:
        return _supabase_client

    if not settings.supabase_configured:
        logger.warning(
            "Supabase not configured — running with in-memory fallback. "
            "Set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY in .env"
        )
        return None

    try:
        _supabase_client = create_client(
            settings.supabase_url,
            settings.supabase_service_role_key,
        )
        logger.info("Supabase client initialized successfully")
        return _supabase_client
    except Exception as exc:
        logger.error(f"Failed to initialize Supabase client: {exc}")
        return None


async def check_db_health() -> dict:
    """Ping the database and return health status."""
    db = get_db()
    if db is None:
        return {"status": "not_configured"}
    try:
        result = db.table("profiles").select("id").limit(1).execute()
        return {"status": "ok"}
    except Exception as exc:
        logger.error(f"DB health check failed: {exc}")
        return {"status": "error", "detail": str(exc)}
