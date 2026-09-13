"""
Integration tests for CyberNeura Phase 3 Risk + Evidence Engine API routes and scan pipeline.
"""
import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_get_risk_config():
    response = client.get("/api/v1/risk/config")
    assert response.status_code == 200
    data = response.json()
    assert "weights" in data
    assert "thresholds" in data
    assert "version" in data
    assert data["weights"]["ml"] == 0.30
    assert data["weights"]["threat_intel"] == 0.30


def test_get_evidence_types():
    response = client.get("/api/v1/evidence/types")
    assert response.status_code == 200
    data = response.json()
    assert "sources" in data
    assert "types" in data
    assert "ML" in data["sources"]
    assert "GOOGLE_WEB_RISK" in data["sources"]
    assert "ml_prediction" in data["types"]


def test_get_evidence_stats():
    response = client.get("/api/v1/evidence/stats")
    assert response.status_code == 200
    data = response.json()
    assert "total_assessments" in data
    assert "source_breakdown" in data


def test_full_scan_pipeline_phase3():
    """Verify POST /api/v1/scan returns both Phase 1/2 fields and Phase 3 assessment fields."""
    response = client.post("/api/v1/scan", json={"url": "https://example.com"})
    assert response.status_code == 200
    data = response.json()

    # Phase 1/2 fields preserved
    assert "id" in data
    assert "url" in data
    assert "prediction" in data
    assert "riskScore" in data
    assert "confidence" in data
    assert "threatIntelligence" in data
    assert "evidence" in data
    assert "independentConfirmations" in data

    # Phase 3 additions
    assert "riskAssessment" in data
    assert "riskFactors" in data
    assert "correlatedFindings" in data
    assert "evidenceCount" in data
    assert "severity" in data
    assert "summary" in data

    scan_id = data["id"]

    # Verify /api/v1/risk/assess/{scan_id}
    assess_res = client.get(f"/api/v1/risk/assess/{scan_id}")
    assert assess_res.status_code == 200
    assess_data = assess_res.json()
    assert assess_data["scan_id"] == scan_id
    assert "risk_score" in assess_data

    # Verify /api/v1/risk/assess/{scan_id}/evidence
    ev_res = client.get(f"/api/v1/risk/assess/{scan_id}/evidence")
    assert ev_res.status_code == 200
    assert "evidence" in ev_res.json()

    # Verify /api/v1/risk/assess/{scan_id}/factors
    factors_res = client.get(f"/api/v1/risk/assess/{scan_id}/factors")
    assert factors_res.status_code == 200
    factors_data = factors_res.json()
    assert len(factors_data["factors"]) >= 6

    # Verify /api/v1/risk/assess/{scan_id}/recalculate
    recalc_res = client.post(f"/api/v1/risk/assess/{scan_id}/recalculate")
    assert recalc_res.status_code == 200
    assert "risk_score" in recalc_res.json()
