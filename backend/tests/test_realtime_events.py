"""
Unit tests for CyberNeura Real-Time Event models, serialization, and secret sanitization.
"""
import pytest
from app.realtime.models import RealtimeEvent, RealtimeEventType, EntityType
from app.realtime.serializer import sanitize_payload, SENSITIVE_KEYS
from app.realtime.events import (
    create_scan_event,
    create_risk_assessment_event,
    create_threat_detected_event,
    create_agent_event,
    create_notification_event,
)


def test_realtime_event_model_defaults():
    event = RealtimeEvent(
        event_type=RealtimeEventType.SCAN_CREATED,
        entity_type=EntityType.URL_SCAN,
        entity_id="scan-12345",
        user_id="usr-abc",
        payload={"url": "https://example.com"},
    )
    assert event.event_id is not None
    assert len(event.event_id) > 10
    assert event.timestamp is not None
    assert event.version == 1
    assert event.payload["url"] == "https://example.com"


def test_secret_sanitization_strips_api_keys():
    raw_payload = {
        "url": "https://suspicious-link.xyz",
        "api_key": "secret_key_12345",
        "google_web_risk_api_key": "AIzaSy...",
        "supabase_service_role_key": "eyJhbGciOi...",
        "nested": {
            "token": "bearer_secret",
            "safe_field": "public_data",
            "password": "super_secret_pwd",
        },
        "score": 95,
    }

    sanitized = sanitize_payload(raw_payload)

    assert "url" in sanitized
    assert "score" in sanitized
    assert "api_key" not in sanitized
    assert "google_web_risk_api_key" not in sanitized
    assert "supabase_service_role_key" not in sanitized
    assert "token" not in sanitized["nested"]
    assert "password" not in sanitized["nested"]
    assert sanitized["nested"]["safe_field"] == "public_data"


def test_event_factories_create_valid_events():
    scan_ev = create_scan_event(
        event_type=RealtimeEventType.SCAN_COMPLETED,
        scan_id="s-999",
        url="https://paypal-verify.com",
        user_id="user-1",
        payload={"risk_score": 92},
    )
    assert scan_ev.event_type == RealtimeEventType.SCAN_COMPLETED
    assert scan_ev.entity_type == EntityType.URL_SCAN
    assert scan_ev.entity_id == "s-999"
    assert scan_ev.payload["risk_score"] == 92

    risk_ev = create_risk_assessment_event(
        assessment_id="as-111",
        scan_id="s-999",
        risk_score=94,
        prediction="MALICIOUS",
        confidence=96.0,
        user_id="user-1",
        threat_category="Phishing",
    )
    assert risk_ev.event_type == RealtimeEventType.RISK_ASSESSMENT_COMPLETED
    assert risk_ev.payload["risk_score"] == 94
    assert risk_ev.payload["prediction"] == "MALICIOUS"

    threat_ev = create_threat_detected_event(
        scan_id="s-999",
        url="https://paypal-verify.com",
        provider="phishtank",
        threat_category="Phishing",
        severity="CRITICAL",
    )
    assert threat_ev.event_type == RealtimeEventType.THREAT_DETECTED
    assert threat_ev.payload["provider"] == "phishtank"

    agent_ev = create_agent_event(
        event_type=RealtimeEventType.AGENT_TOOL_COMPLETED,
        session_id="sess-xyz",
        tool_name="analyze_ml_prediction",
        summary="Model predicted malicious",
        status="SUCCESS",
        duration_ms=45.2,
    )
    assert agent_ev.event_type == RealtimeEventType.AGENT_TOOL_COMPLETED
    assert agent_ev.payload["tool_name"] == "analyze_ml_prediction"

    notif_ev = create_notification_event(
        notification_id="n-001",
        title="High Risk Threat",
        message="Critical threat detected",
        severity="CRITICAL",
        scan_id="s-999",
    )
    assert notif_ev.event_type == RealtimeEventType.NOTIFICATION_CREATED
    assert notif_ev.payload["severity"] == "CRITICAL"
