"""
Unit tests for CyberNeura Agent Orchestrator end-to-end execution, events, and persistence.
"""
import asyncio
import pytest
from app.agent.agent import cyberneura_agent
from app.agent.models import AgentStatus, AgentObjective
from app.services.scan_store import scan_store


def test_agent_investigate_safe_url():
    report = asyncio.run(cyberneura_agent.investigate(
        url="https://google.com",
        question="Is google.com safe to visit?",
    ))
    assert report.status == AgentStatus.COMPLETED
    assert report.url == "https://google.com"
    assert len(report.tools_used) >= 1
    assert "get_risk_assessment" in report.tools_used
    assert len(report.recommendations) >= 1

    # Check persistence in scan_store
    saved = scan_store.get_agent_session(report.session_id)
    assert saved is not None
    assert saved["session_id"] == report.session_id


def test_agent_investigate_malicious_seed_url():
    report = asyncio.run(cyberneura_agent.investigate(
        url="https://malicious-bank-verify.ru",
        question="Why is this URL malicious?",
        scan_id="s-seed-1",
    ))
    assert report.status == AgentStatus.COMPLETED
    assert len(report.key_findings) >= 1
    # Authoritative Phase 3 score should be preserved (>= 85)
    assessment = report.final_assessment
    assert assessment.get("risk_score", 0) >= 85

    # Check audit events
    events = scan_store.get_agent_events(report.session_id)
    assert len(events) >= 3
    event_types = [e.get("event_type") for e in events]
    assert "INVESTIGATION_STARTED" in event_types
    assert "INVESTIGATION_COMPLETED" in event_types


def test_agent_stop_active_session():
    stopped = cyberneura_agent.stop("non-existent-session")
    assert stopped is False
