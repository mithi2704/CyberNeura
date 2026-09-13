"""
Unit tests for CyberNeura EventPublisher service, persistence, and error boundaries.
"""
import asyncio
import pytest
from unittest.mock import patch

from app.realtime.models import RealtimeEventType, EntityType
from app.realtime.publisher import EventPublisher, event_publisher
from app.services.scan_store import scan_store


def test_publisher_publishes_and_persists_event():
    publisher = EventPublisher()

    event = asyncio.run(
        publisher.publish(
            event_type=RealtimeEventType.SCAN_COMPLETED,
            entity_type=EntityType.URL_SCAN,
            entity_id="scan-pub-001",
            user_id="user-pub",
            payload={"url": "https://test-publish.org", "risk_score": 15},
        )
    )

    assert event is not None
    assert event.entity_id == "scan-pub-001"
    assert event.event_type == RealtimeEventType.SCAN_COMPLETED

    # Verify persisted in scan_store
    events = scan_store.get_realtime_events(entity_id="scan-pub-001")
    assert len(events) >= 1
    assert events[0]["entity_id"] == "scan-pub-001"
    assert events[0]["payload"]["risk_score"] == 15


def test_publisher_strips_sensitive_keys_before_publishing():
    publisher = EventPublisher()

    event = asyncio.run(
        publisher.publish(
            event_type=RealtimeEventType.SECURITY_ALERT_CREATED,
            entity_type=EntityType.SECURITY_ALERT,
            entity_id="alert-pub-002",
            user_id="user-pub",
            payload={
                "alert": "Malware detected",
                "api_key": "super_secret_leak",
                "nested": {"token": "secret_token", "safe_val": 100},
            },
        )
    )

    assert event is not None
    assert "api_key" not in event.payload
    assert "token" not in event.payload.get("nested", {})
    assert event.payload.get("nested", {}).get("safe_val") == 100


def test_publisher_failsafe_never_crashes():
    publisher = EventPublisher()

    # Simulate an error in payload handling or serialization
    class UnserializableObject:
        pass

    with patch.object(scan_store, "save_realtime_event", side_effect=Exception("Database down")):
        # Must not raise an exception; returns None and logs warning
        event = asyncio.run(
            publisher.publish(
                event_type=RealtimeEventType.SCAN_FAILED,
                entity_type=EntityType.URL_SCAN,
                entity_id="scan-fail-001",
                payload={"error": "Scan failed"},
            )
        )
        assert event is None
        assert publisher.metrics["events_failed"] >= 1
