"""
Unit tests for Threat Intelligence providers (Google Web Risk, PhishTank, URLhaus).
Uses mocked HTTP responses to test all state transitions deterministically without external calls.
"""
from __future__ import annotations

import pytest
import httpx
from unittest.mock import AsyncMock, patch

from app.intelligence.providers.google_webrisk import GoogleWebRiskProvider
from app.intelligence.providers.phishtank import PhishTankProvider
from app.intelligence.providers.urlhaus import URLhausProvider
from app.intelligence.models import ProviderVerdict


# ── Google Web Risk Tests ────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_google_webrisk_match():
    provider = GoogleWebRiskProvider(api_key="test-api-key-123", enabled=True)
    mock_resp = httpx.Response(
        status_code=200,
        json={
            "threat": {
                "threatTypes": ["SOCIAL_ENGINEERING"],
                "expireTime": "2026-09-13T15:00:00Z",
            }
        },
        request=httpx.Request("GET", "https://webrisk.googleapis.com"),
    )

    with patch.object(httpx.AsyncClient, "get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp
        res = await provider.lookup("https://malicious-bank.com")

        assert res.matched is True
        assert res.verdict == ProviderVerdict.MATCH
        assert "SOCIAL_ENGINEERING" in res.categories
        assert res.available is True
        assert res.expires_at == "2026-09-13T15:00:00Z"


@pytest.mark.anyio
async def test_google_webrisk_no_match():
    provider = GoogleWebRiskProvider(api_key="test-api-key-123", enabled=True)
    mock_resp = httpx.Response(
        status_code=200,
        json={},  # Google returns empty object when safe
        request=httpx.Request("GET", "https://webrisk.googleapis.com"),
    )

    with patch.object(httpx.AsyncClient, "get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp
        res = await provider.lookup("https://safe-domain.com")

        assert res.matched is False
        assert res.verdict == ProviderVerdict.NO_MATCH
        assert res.available is True


@pytest.mark.anyio
async def test_google_webrisk_api_error():
    provider = GoogleWebRiskProvider(api_key="invalid-key", enabled=True)
    mock_resp = httpx.Response(
        status_code=403,
        text="Permission denied: API key not valid",
        request=httpx.Request("GET", "https://webrisk.googleapis.com"),
    )

    with patch.object(httpx.AsyncClient, "get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp
        res = await provider.lookup("https://some-url.com")

        assert res.available is False
        assert res.verdict == ProviderVerdict.UNAVAILABLE
        assert "403" in (res.error or "")


@pytest.mark.anyio
async def test_google_webrisk_timeout():
    provider = GoogleWebRiskProvider(api_key="test-api-key", enabled=True)

    with patch.object(httpx.AsyncClient, "get", side_effect=httpx.ReadTimeout("Timeout")):
        res = await provider.lookup("https://timeout-url.com")

        assert res.available is False
        assert res.verdict == ProviderVerdict.UNAVAILABLE


# ── PhishTank Tests ──────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_phishtank_verified_match():
    provider = PhishTankProvider(enabled=True)
    mock_resp = httpx.Response(
        status_code=200,
        json={
            "results": {
                "in_database": True,
                "verified": True,
                "valid": True,
                "phish_id": "123456",
                "target": "PayPal",
            }
        },
        request=httpx.Request("POST", "https://checkurl.phishtank.com"),
    )

    with patch.object(httpx.AsyncClient, "post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_resp
        res = await provider.lookup("https://fake-paypal-verify.com")

        assert res.matched is True
        assert res.verdict == ProviderVerdict.MATCH
        assert "PHISHING" in res.categories
        assert res.metadata.get("verified") is True
        assert res.metadata.get("target") == "PayPal"


@pytest.mark.anyio
async def test_phishtank_not_in_database():
    provider = PhishTankProvider(enabled=True)
    mock_resp = httpx.Response(
        status_code=200,
        json={"results": {"in_database": False}},
        request=httpx.Request("POST", "https://checkurl.phishtank.com"),
    )

    with patch.object(httpx.AsyncClient, "post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_resp
        res = await provider.lookup("https://legitimate-service.org")

        assert res.matched is False
        assert res.verdict == ProviderVerdict.NO_MATCH
        assert res.available is True


@pytest.mark.anyio
async def test_phishtank_rate_limited():
    provider = PhishTankProvider(enabled=True)
    mock_resp = httpx.Response(
        status_code=509,
        text="Bandwidth Limit Exceeded",
        request=httpx.Request("POST", "https://checkurl.phishtank.com"),
    )

    with patch.object(httpx.AsyncClient, "post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_resp
        res = await provider.lookup("https://rate-limited-test.com")

        assert res.verdict == ProviderVerdict.RATE_LIMITED
        assert res.available is False


# ── URLhaus Tests ────────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_urlhaus_malware_match():
    provider = URLhausProvider(enabled=True)
    mock_resp = httpx.Response(
        status_code=200,
        json={
            "query_status": "ok",
            "url_status": "online",
            "threat": "malware_download",
            "tags": ["mozi", "elf"],
            "date_added": "2026-09-13 10:00:00 UTC",
        },
        request=httpx.Request("POST", "https://urlhaus-api.abuse.ch"),
    )

    with patch.object(httpx.AsyncClient, "post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_resp
        res = await provider.lookup("http://malware-server.com/payload.exe")

        assert res.matched is True
        assert res.verdict == ProviderVerdict.MATCH
        assert "MALWARE" in res.categories
        assert "mozi" in res.metadata.get("tags", [])


@pytest.mark.anyio
async def test_urlhaus_no_results():
    provider = URLhausProvider(enabled=True)
    mock_resp = httpx.Response(
        status_code=200,
        json={"query_status": "no_results"},
        request=httpx.Request("POST", "https://urlhaus-api.abuse.ch"),
    )

    with patch.object(httpx.AsyncClient, "post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_resp
        res = await provider.lookup("https://clean-domain.org")

        assert res.matched is False
        assert res.verdict == ProviderVerdict.NO_MATCH
        assert res.available is True


@pytest.mark.anyio
async def test_urlhaus_server_error():
    provider = URLhausProvider(enabled=True)

    with patch.object(httpx.AsyncClient, "post", side_effect=httpx.ConnectError("Connection refused")):
        res = await provider.lookup("https://broken-server.com")

        assert res.available is False
        assert res.verdict == ProviderVerdict.UNAVAILABLE
