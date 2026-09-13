"""
Integration tests for Agent API endpoints and Chat route delegation using TestClient.
"""
import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_agent_investigate_endpoint():
    resp = client.post(
        "/api/v1/agent/investigate",
        json={"url": "https://secure-payment.com", "question": "Is this safe?"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "session_id" in data
    assert data["status"] == "COMPLETED"
    assert len(data["tools_used"]) >= 1

    session_id = data["session_id"]
    # Fetch investigation by session_id
    get_resp = client.get(f"/api/v1/agent/investigations/{session_id}")
    assert get_resp.status_code == 200

    # Fetch investigation events
    evt_resp = client.get(f"/api/v1/agent/investigations/{session_id}/events")
    assert evt_resp.status_code == 200
    assert len(evt_resp.json()) >= 2


def test_agent_tools_endpoint():
    resp = client.get("/api/v1/agent/tools")
    assert resp.status_code == 200
    tools = resp.json()
    assert len(tools) >= 8
    tool_names = [t["name"] for t in tools]
    assert "analyze_ml_prediction" in tool_names
    assert "lookup_threat_intelligence" in tool_names


def test_chat_delegation_with_url():
    resp = client.post(
        "/chat",
        json={"message": "Analyze https://phishing-amazon.tk and tell me why it's malicious"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "message" in data
    assert "recommendations" in data
    assert "timeline" in data
    assert len(data["timeline"]) >= 1


def test_chat_delegation_with_scan_id():
    resp = client.post(
        "/chat",
        json={"message": "Why did CyberNeura classify this URL as malicious?", "scanId": "s-seed-1"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "message" in data
    assert data.get("risk") is not None
    assert data["risk"] >= 85
