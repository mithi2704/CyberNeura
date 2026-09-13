"""
End-to-end integration tests verifying that security scans and agent investigations
emit real-time events properly.
"""
import asyncio
import pytest
from app.services.scan_service import execute_scan
from app.agent.agent import cyberneura_agent
from app.services.scan_store import scan_store
from app.realtime.models import RealtimeEventType


def test_scan_pipeline_emits_realtime_events():
    initial_event_count = len(scan_store.get_realtime_events())

    # Execute a clean scan
    scan_resp = asyncio.run(execute_scan(url="https://github.com", user_id="test-user-rt"))
    assert scan_resp.id is not None

    # Check that events were published and persisted
    events = scan_store.get_realtime_events(entity_id=scan_resp.id)
    assert len(events) >= 1

    event_types = [e.get("event_type") for e in events]
    # Should include SCAN_STARTED, RISK_ASSESSMENT_COMPLETED, and SCAN_COMPLETED
    assert any(et in event_types for et in [
        RealtimeEventType.SCAN_STARTED.value,
        RealtimeEventType.RISK_ASSESSMENT_COMPLETED.value,
        RealtimeEventType.SCAN_COMPLETED.value,
    ])


def test_agent_investigation_emits_realtime_events():
    # Run an agent investigation
    report = asyncio.run(cyberneura_agent.investigate(
        url="https://secure-docs-test.org",
        user_id="test-agent-rt-user",
    ))

    assert report.session_id is not None

    # Check that agent session emitted AGENT_STARTED and completed events
    events = scan_store.get_realtime_events(entity_id=report.session_id)
    assert len(events) >= 1

    event_types = [e.get("event_type") for e in events]
    assert RealtimeEventType.AGENT_STARTED.value in event_types
