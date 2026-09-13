"""
Integration tests for CyberNeura Real-Time API routes.
"""
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.realtime.models import RealtimeEventType, EntityType
from app.realtime.publisher import event_publisher
from app.services.scan_store import scan_store


@pytest.fixture
def client():
    return TestClient(app)


def test_realtime_health_endpoint(client):
    res = client.get("/api/v1/realtime/health")
    assert res.status_code == 200
    data = res.json()
    assert "status" in data
    assert "database" in data
    assert "realtime" in data
    assert "timestamp" in data


def test_realtime_events_query_and_sync(client):
    # Save a test event first
    scan_store.save_realtime_event({
        "event_id": "evt-sync-test-01",
        "event_type": RealtimeEventType.SCAN_COMPLETED.value,
        "entity_type": EntityType.URL_SCAN.value,
        "entity_id": "scan-sync-01",
        "user_id": "demo-user",
        "timestamp": "2026-09-13T12:00:00Z",
        "version": 1,
        "payload": {"url": "https://sync-test.com", "riskScore": 10},
    })

    # Query with authentication header (demo auth enabled in development)
    headers = {"Authorization": "Bearer demo-token-for-tests"}
    res = client.get("/api/v1/realtime/events?limit=10", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert "events" in data
    assert "count" in data
    assert isinstance(data["events"], list)


def test_realtime_status_endpoint(client):
    headers = {"Authorization": "Bearer demo-token-for-tests"}
    res = client.get("/api/v1/realtime/status", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert "user_channel" in data
    assert "system_channel" in data
    assert "realtime_enabled" in data
    assert "fallback_polling_interval_seconds" in data
