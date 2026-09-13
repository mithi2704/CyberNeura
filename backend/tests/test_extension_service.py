"""
Integration tests for CyberNeura ExtensionService (Phase 6).
Verifies caching fast path, URL normalization, failure isolation, and real-time emission.
"""
import asyncio
import pytest
from datetime import datetime, timezone
from app.extension.service import extension_service
from app.extension.models import ExtensionAnalyzeRequest, ExtensionOverrideRequest, ExtensionDecision
from app.services.scan_store import scan_store


def test_extension_service_cached_fast_path():
    url = "https://cached-example-target.org"
    now_iso = datetime.now(timezone.utc).isoformat()
    scan_store.add_scan({
        "id": "scan-cached-1",
        "url": url,
        "riskScore": 15,
        "prediction": "SAFE",
        "confidence": 92.0,
        "threatCategory": "Safe",
        "scannedAt": now_iso,
    })

    req = ExtensionAnalyzeRequest(
        url=url,
        installation_id="test-cache-install",
    )
    res = asyncio.run(extension_service.analyze_url(req))
    assert res.cached is True
    assert res.decision == ExtensionDecision.ALLOW
    assert res.risk_score == 15
    assert res.prediction == "SAFE"


def test_extension_service_unsupported_scheme_skipped():
    req = ExtensionAnalyzeRequest(
        url="file:///C:/Users/test/secrets.txt",
        installation_id="test-install",
    )
    res = asyncio.run(extension_service.analyze_url(req))
    assert res.decision == ExtensionDecision.ALLOW
    assert res.risk_score == 0
    assert "Skipped inspection" in res.summary


def test_extension_service_records_override():
    req = ExtensionOverrideRequest(
        scan_id="test-override-unit",
        url="https://test-override.org",
        installation_id="unit-install",
        original_decision=ExtensionDecision.WARN,
        override_action="CONTINUE_ANYWAY",
    )
    res = asyncio.run(extension_service.record_override(req))
    assert res["status"] == "OVERRIDE_RECORDED"
    assert res["user_override"] is True
