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
_db_checked: bool = False
_db_available: bool = False


def get_db() -> Optional[Client]:
    """Return a configured Supabase service-role client, or None if not configured or unmigrated."""
    global _supabase_client, _db_checked, _db_available
    if _db_checked:
        return _supabase_client if _db_available else None

    if not settings.supabase_configured:
        logger.info("Supabase not configured — running with fast in-memory scan_store.")
        _db_checked = True
        _db_available = False
        return None

    try:
        from supabase import ClientOptions
        client = create_client(
            settings.supabase_url,
            settings.supabase_service_role_key,
            options=ClientOptions(postgrest_client_timeout=5),
        )
        # Verify schema cache has CyberNeura tables
        client.table("url_scans").select("id").limit(1).execute()
        _supabase_client = client
        _db_available = True
        logger.info("Supabase client initialized and schema verified successfully")
    except Exception as exc:
        _supabase_client = None
        _db_available = False
        logger.warning(
            f"Supabase schema not initialized in project ({exc}). "
            "Running with in-memory scan_store fallback. "
            "To enable Supabase persistence, execute frontend/supabase/migrations/001_initial_schema.sql in your Supabase SQL editor."
        )
    finally:
        _db_checked = True

    return _supabase_client if _db_available else None


async def check_db_health() -> dict:
    """Ping the database and return health status."""
    db = get_db()
    if db is None:
        return {"status": "in_memory_fallback", "schema_initialized": False}
    try:
        db.table("url_scans").select("id").limit(1).execute()
        return {"status": "ok", "schema_initialized": True}
    except Exception as exc:
        return {"status": "error", "detail": str(exc)}

