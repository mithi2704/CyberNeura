"""
API tests for CyberNeura Browser Extension endpoints (Phase 6).
Verifies analyze, status, policy, override, report, events, and rate limiting.
"""
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.extension.models import ExtensionDecision
from app.services.scan_store import scan_store


@pytest.fixture
def client():
    return TestClient(app)


def test_extension_status_endpoint(client):
    res = client.get("/api/v1/extension/status")
    assert res.status_code == 200
    data = res.json()
    assert data["service"] == "CyberNeura Extension API"
    assert data["status"] in ("ONLINE", "DISABLED")
    assert "policy_version" in data
    assert "timeout_seconds" in data


def test_extension_policy_endpoint(client):
    res = client.get("/api/v1/extension/policy")
    assert res.status_code == 200
    data = res.json()
    assert "rules" in data
    assert data["risk_threshold_safe"] > 0
    assert data["risk_threshold_suspicious"] > data["risk_threshold_safe"]


def test_extension_override_endpoint(client):
    payload = {
        "scan_id": "test-override-scan",
        "url": "https://suspicious-test.xyz",
        "installation_id": "inst-test-01",
        "original_decision": "WARN",
        "override_action": "CONTINUE_ANYWAY",
    }
    res = client.post("/api/v1/extension/override", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "OVERRIDE_RECORDED"
    assert data["user_override"] is True


def test_extension_report_endpoint(client):
    payload = {
        "scan_id": "test-report-scan",
        "url": "https://legitimate-blog.com",
        "installation_id": "inst-test-01",
        "report_type": "false_positive",
        "feedback": "This is a legitimate developer documentation website.",
    }
    res = client.post("/api/v1/extension/report", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "REPORT_RECORDED"
    assert "report_id" in data


def test_extension_events_and_stats(client):
    res_events = client.get("/api/v1/extension/events")
    assert res_events.status_code == 200
    assert "events" in res_events.json()

    res_stats = client.get("/api/v1/extension/stats")
    assert res_stats.status_code == 200
    stats = res_stats.json()
    assert "total_events" in stats
    assert "blocked" in stats
    assert "warned" in stats
    assert "allowed" in stats


def test_extension_analyze_precheck_invalid_scheme(client):
    payload = {
        "url": "chrome://settings",
        "installation_id": "inst-test-02",
    }
    res = client.post("/api/v1/extension/analyze", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["decision"] == "ALLOW"
    assert "Skipped inspection" in data["summary"]


def test_extension_chat_endpoint(client):
    # Test safe inquiry
    payload = {
        "url": "https://example.com/login",
        "question": "Is this website safe to enter my password?",
        "risk_score": 10,
        "decision": "ALLOW",
        "page_title": "Example Login",
        "has_password_inputs": True,
    }
    res = client.post("/api/v1/extension/chat", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert "reply" in data
    assert len(data["reply"]) > 0
    assert data["verdict"] == "SAFE"
    assert data["risk_score"] == 10
    assert len(data["key_findings"]) > 0
    assert len(data["recommendations"]) > 0

    # Test threat inquiry
    payload_threat = {
        "url": "http://paypal-security-update.xyz/verify",
        "question": "Can I enter my credit card here?",
        "risk_score": 90,
        "decision": "BLOCK",
        "threat_category": "PHISHING",
        "has_card_inputs": True,
    }
    res_threat = client.post("/api/v1/extension/chat", json=payload_threat)
    assert res_threat.status_code == 200
    data_threat = res_threat.json()
    assert data_threat["verdict"] == "THREAT"
    assert "DO NOT" in data_threat["reply"].upper() or "DANGER" in data_threat["reply"].upper() or "WARNING" in data_threat["reply"].upper()

