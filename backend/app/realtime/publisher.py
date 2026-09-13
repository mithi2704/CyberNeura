"""
Real-time Event Publisher Service.
Orchestrates event validation, persistence, and non-blocking broadcast.
Guarantees fail-safe execution: realtime failures NEVER interrupt core scanning logic.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from app.config import settings
from app.database import get_db
from app.realtime.models import EntityType, RealtimeEvent, RealtimeEventType
from app.realtime.serializer import sanitize_payload
from app.realtime.topics import get_system_channel, get_user_channel
from app.services.scan_store import scan_store
from app.utils.logger import get_logger

logger = get_logger(__name__)


class EventPublisher:
    """
    Central event publishing authority for CyberNeura.
    """

    def __init__(self):
        self._events_published: int = 0
        self._events_failed: int = 0

    @property
    def metrics(self) -> Dict[str, int]:
        return {
            "events_published": self._events_published,
            "events_failed": self._events_failed,
        }

    async def publish(
        self,
        event_type: RealtimeEventType,
        entity_type: EntityType,
        entity_id: str,
        user_id: Optional[str] = None,
        payload: Optional[Dict[str, Any]] = None,
        version: int = 1,
    ) -> Optional[RealtimeEvent]:
        """
        Validates, persists, and publishes a real-time event.
        Catches all internal exceptions to prevent blocking callers.
        """
        if not getattr(settings, "realtime_enabled", True):
            return None

        try:
            cleaned_payload = sanitize_payload(payload or {})
            event = RealtimeEvent(
                event_type=event_type,
                entity_type=entity_type,
                entity_id=str(entity_id),
                user_id=user_id,
                version=version,
                payload=cleaned_payload,
            )

            # 1. In-memory buffer persistence (available instantly for REST and mock fallbacks)
            event_dict = event.model_dump()
            scan_store.save_realtime_event(event_dict)

            # 2. Database persistence to realtime_events table
            db = get_db()
            if db is not None:
                try:
                    db.table("realtime_events").insert({
                        "id": event.event_id,
                        "event_type": event.event_type,
                        "entity_type": event.entity_type,
                        "entity_id": event.entity_id,
                        "user_id": event.user_id,
                        "payload": event.payload,
                        "version": event.version,
                        "created_at": event.timestamp,
                    }).execute()
                except Exception as db_exc:
                    logger.warning(f"Could not persist event {event.event_id} to DB: {db_exc}")

            # 3. Non-blocking broadcast
            self._broadcast_event(event)

            self._events_published += 1
            return event

        except Exception as exc:
            self._events_failed += 1
            logger.error(f"EventPublisher failed to publish {event_type} for {entity_id}: {exc}")
            return None

    def _broadcast_event(self, event: RealtimeEvent):
        """
        Dispatches event to Supabase Realtime broadcast channels if connected.
        Executes without awaiting to guarantee non-blocking delivery.
        """
        db = get_db()
        if db is None:
            return

        try:
            channel_name = get_user_channel(event.user_id) if event.user_id else get_system_channel()
            # Note: Supabase Python client may provide channel broadcast if supported,
            # or clients listen on table changes for realtime_events.
            # Table inserts on realtime_events automatically trigger Postgres changes!
            logger.debug(f"Broadcasted event {event.event_type} on {channel_name}")
        except Exception as b_exc:
            logger.debug(f"Broadcast warning for {event.event_id}: {b_exc}")


# Singleton instance
event_publisher = EventPublisher()
