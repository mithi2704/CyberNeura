"""
Phase 2 End-to-End Integration Tests.
Verifies the complete flow:
URL -> ML -> Threat Intelligence Manager -> Evidence Engine -> Risk Engine -> Database / API.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.config import settings

client = TestClient(app)


def test_full_scan_pipeline_with_threat_intelligence():
    # Perform full scan
    resp = client.post("/api/v1/scan", json={"url": "https://www.google.com"})
    assert resp.status_code == 200
    data = resp.json()

    # Core Phase 1 properties preserved
    assert "id" in data
    assert "prediction" in data
    assert "riskScore" in data
    assert "confidence" in data
    assert data["prediction"] in ("safe", "suspicious", "malicious")

    # Phase 2 properties present
    assert "threatIntelligence" in data
    assert isinstance(data["threatIntelligence"], dict)
    assert "evidence" in data
    assert isinstance(data["evidence"], list)
    assert "independentConfirmations" in data

    scan_id = data["id"]

    # Verify GET /intelligence/scan/{scan_id}
    intel_resp = client.get(f"/api/v1/intelligence/scan/{scan_id}")
    assert intel_resp.status_code == 200
    intel_data = intel_resp.json()
    assert intel_data["scanId"] == scan_id
    assert "providers" in intel_data

    # Verify POST /intelligence/scan/{scan_id}/refresh
    refresh_resp = client.post(f"/api/v1/intelligence/scan/{scan_id}/refresh")
    assert refresh_resp.status_code == 200
    assert refresh_resp.json()["scanId"] == scan_id


def test_manual_intelligence_lookup():
    resp = client.post("/api/v1/intelligence/lookup", json={"url": "https://chatgpt.com"})
    assert resp.status_code == 200
    data = resp.json()
    assert "url" in data
    assert "providers" in data
    assert "independentConfirmations" in data
    assert len(data["providers"]) > 0


def test_provider_status_endpoint():
    resp = client.get("/api/v1/intelligence/providers/status")
    assert resp.status_code == 200
    data = resp.json()
    assert "providers" in data
    names = [p["name"] for p in data["providers"]]
    assert "google_webrisk" in names
    assert "phishtank" in names
    assert "urlhaus" in names
    for p in data["providers"]:
        assert p["status"] in ("HEALTHY", "DEGRADED", "NOT_CONFIGURED")
        # Ensure credentials are NEVER leaked
        assert "key" not in p
        assert "token" not in p
        assert "auth" not in p


def test_threat_trends_endpoint():
    resp = client.get("/api/v1/threats/trends?days=7")
    assert resp.status_code == 200
    data = resp.json()
    assert "data" in data
    assert len(data["data"]) == 7
    first_item = data["data"][0]
    assert "date" in first_item
    assert "google" in first_item
    assert "phishtank" in first_item
    assert "urlhaus" in first_item


def test_threat_breakdown_endpoint():
    resp = client.get("/api/v1/threats/breakdown")
    assert resp.status_code == 200
    data = resp.json()
    assert "mlDetections" in data
    assert "googleConfirmations" in data
    assert "phishtankConfirmations" in data
    assert "urlhausConfirmations" in data
    assert "multiSourceDetections" in data


def test_health_detail_includes_threat_intelligence():
    resp = client.get("/health/detail")
    assert resp.status_code == 200
    data = resp.json()
    assert "checks" in data
    assert "threat_intelligence" in data["checks"]
    intel_checks = data["checks"]["threat_intelligence"]
    assert "google_webrisk" in intel_checks
    assert "phishtank" in intel_checks
    assert "urlhaus" in intel_checks
