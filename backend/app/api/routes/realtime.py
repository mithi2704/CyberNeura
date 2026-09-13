"""
Real-time Management & Health API Endpoints.
Provides health telemetry, missed-event recovery synchronization, and connection metadata.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, Query, status

from app.config import settings
from app.database import get_db
from app.dependencies import AuthUser, get_current_user
from app.realtime.models import RealtimeHealthStatus
from app.realtime.publisher import event_publisher
from app.services.scan_store import scan_store
from app.utils.logger import get_logger

logger = get_logger(__name__)

router = APIRouter(tags=["Realtime"], prefix="/realtime")


@router.get("/health", response_model=RealtimeHealthStatus, summary="Check real-time subsystem health")
async def get_realtime_health():
    """
    Evaluates database connectivity and real-time publication status.
    Truthfully reports AVAILABLE or DEGRADED/MOCK.
    """
    db = get_db()
    db_status = "CONNECTED" if db is not None else "MOCK_OR_DISCONNECTED"

    realtime_status = "UNAVAILABLE"
    if getattr(settings, "realtime_enabled", True):
        realtime_status = "AVAILABLE" if db is not None else "FALLBACK_IN_MEMORY"

    metrics = event_publisher.metrics

    return RealtimeHealthStatus(
        status="HEALTHY" if realtime_status != "UNAVAILABLE" else "DEGRADED",
        timestamp=datetime.now(timezone.utc).isoformat(),
        database=db_status,
        realtime=realtime_status,
        total_events_published=metrics.get("events_published", 0),
    )


@router.get("/events", summary="Query historical or missed real-time events")
async def get_events(
    user: AuthUser,
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    entity_type: Optional[str] = Query(None, description="Filter by entity type"),
    entity_id: Optional[str] = Query(None, description="Filter by entity ID"),
    since: Optional[str] = Query(None, description="ISO timestamp for missed-event catchup"),
    limit: int = Query(50, ge=1, le=100),
):
    """
    Allows reconnected clients to perform lightweight synchronization of events missed while disconnected.
    Enforces user isolation: regular users only retrieve their own private events or system alerts.
    """
    db = get_db()
    user_id = user.uid

    # 1. Attempt database query if Supabase is connected
    if db is not None:
        try:
            q = db.table("realtime_events").select("*").order("created_at", desc=True)
            if user_id:
                # User can read their own events or system events (user_id IS NULL)
                q = q.or_(f"user_id.eq.{user_id},user_id.is.null")
            if event_type:
                q = q.eq("event_type", event_type)
            if entity_type:
                q = q.eq("entity_type", entity_type)
            if entity_id:
                q = q.eq("entity_id", entity_id)
            if since:
                q = q.gt("created_at", since)

            res = q.limit(limit).execute()
            if res.data is not None:
                return {
                    "events": res.data,
                    "count": len(res.data),
                    "since": since,
                    "source": "database",
                }
        except Exception as exc:
            logger.warning(f"Database event query failed, falling back to in-memory store: {exc}")

    # 2. Fallback to in-memory event buffer
    mem_events = scan_store.get_realtime_events(
        user_id=user_id,
        event_type=event_type,
        entity_type=entity_type,
        entity_id=entity_id,
        since=since,
        limit=limit,
    )
    return {
        "events": mem_events,
        "count": len(mem_events),
        "since": since,
        "source": "in_memory",
    }


@router.get("/status", summary="Get connection parameters for the authenticated user")
async def get_realtime_status(user: AuthUser):
    """
    Provides channel names and configuration parameters for client-side subscription setup.
    """
    return {
        "user_id": user.uid,
        "user_channel": f"user:{user.uid}:events",
        "system_channel": "public:system_status",
        "realtime_enabled": getattr(settings, "realtime_enabled", True),
        "fallback_polling_interval_seconds": getattr(settings, "realtime_fallback_interval_seconds", 30),
        "max_reconnect_attempts": getattr(settings, "realtime_reconnect_max_attempts", 10),
    }
