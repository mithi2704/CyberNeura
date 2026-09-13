"""
Integration tests for CyberNeura FastAPI endpoints.
"""
import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "version" in data


def test_health_detail():
    response = client.get("/health/detail")
    assert response.status_code == 200
    data = response.json()
    assert "checks" in data
    assert "database" in data["checks"]
    assert "ml_model" in data["checks"]


def test_scan_endpoint_safe_url():
    response = client.post("/scan", json={"url": "https://www.google.com"})
    assert response.status_code == 200
    data = response.json()
    assert "prediction" in data
    assert "riskScore" in data
    assert "confidence" in data
    assert "probability" in data
    assert "featureImportance" in data
    assert data["prediction"] in ("safe", "suspicious", "malicious")
    assert 0 <= data["riskScore"] <= 100
    assert 0 <= data["confidence"] <= 100
    assert 0.0 <= data["probability"] <= 1.0


def test_scan_endpoint_ssrf_blocked():
    response = client.post("/scan", json={"url": "http://127.0.0.1:8080/admin"})
    assert response.status_code == 400
    assert "private" in response.json()["detail"].lower() or "localhost" in response.json()["detail"].lower()


def test_scan_endpoint_empty_url():
    response = client.post("/scan", json={"url": ""})
    assert response.status_code == 422  # validation error


def test_versioned_scan_endpoint():
    response = client.post("/api/v1/scan", json={"url": "https://github.com"})
    assert response.status_code == 200
    assert response.json()["prediction"] in ("safe", "suspicious", "malicious")


def test_model_insights():
    response = client.get("/insights/model")
    assert response.status_code == 200
    data = response.json()
    assert "modelVersion" in data
    assert "algorithm" in data
    assert data["accuracy"] is not None
    assert data["accuracy"] > 0.85


def test_dashboard_stats():
    response = client.get("/dashboard/stats")
    assert response.status_code == 200
    data = response.json()
    assert "totalScans" in data
    assert "threatsBlocked" in data


def test_threat_logs():
    response = client.get("/threats")
    assert response.status_code == 200
    data = response.json()
    assert "items" in data
    assert "total" in data


def test_list_and_patch_scans():
    # Test GET /scans
    response = client.get("/api/v1/scans")
    assert response.status_code == 200
    data = response.json()
    assert "items" in data
    assert len(data["items"]) > 0
    scan_id = data["items"][0]["id"]

    # Test PATCH /scans/{scan_id}
    patch_resp = client.patch(
        f"/api/v1/scans/{scan_id}",
        json={"prediction": "safe", "riskScore": 5, "threatCategory": "Safe"}
    )
    assert patch_resp.status_code == 200
    assert patch_resp.json()["success"] is True

