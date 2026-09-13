"""
Unit and functional tests for the Threat Intelligence Pipeline:
Cache, Concurrency, Evidence Engine, and Risk Engine Correlation.
"""
from __future__ import annotations

import pytest
from app.intelligence.cache import ThreatIntelCache
from app.intelligence.models import ThreatIntelResult, ProviderVerdict
from app.intelligence.providers.generic import GenericMockProvider
from app.intelligence.manager import ThreatIntelligenceManager
from app.services.evidence_service import compile_evidence, count_independent_confirmations
from app.services.risk_engine import calculate_risk_score, classify, calculate_confidence


def test_threat_intel_cache():
    cache = ThreatIntelCache(default_ttl_seconds=10)
    url = "https://example-test.com"

    # Initially empty
    assert cache.get("google_webrisk", url) is None

    result = ThreatIntelResult(
        provider="google_webrisk",
        indicator=url,
        available=True,
        matched=False,
        verdict=ProviderVerdict.NO_MATCH,
        checked_at="2026-09-13T10:00:00Z",
    )
    cache.set("google_webrisk", url, result)

    # Cache hit
    cached = cache.get("google_webrisk", url)
    assert cached is not None
    assert cached.indicator == url

    # Provider specific: different provider misses
    assert cache.get("phishtank", url) is None


@pytest.mark.anyio
async def test_manager_parallel_lookups_and_isolation():
    manager = ThreatIntelligenceManager()
    manager.providers = {
        "p1": GenericMockProvider(name="google_webrisk"),
        "p2": GenericMockProvider(name="phishtank"),
        "p3": GenericMockProvider(name="urlhaus"),
    }

    # Query a phishing test URL
    results = await manager.lookup_all("https://malicious-bank-verify.ru/login")

    assert "google_webrisk" in results
    assert "phishtank" in results
    assert "urlhaus" in results

    # Verify both google and phishtank matched
    assert results["google_webrisk"].matched is True
    assert results["phishtank"].matched is True


@pytest.mark.anyio
async def test_manager_timeout_isolation():
    manager = ThreatIntelligenceManager()
    
    class FailingTimeoutProvider(GenericMockProvider):
        async def lookup(self, url: str) -> ThreatIntelResult:
            import asyncio
            raise asyncio.TimeoutError("Simulated timeout")

    manager.providers = {
        "timeout_provider": FailingTimeoutProvider(name="timeout_provider"),
        "google_webrisk": GenericMockProvider(name="google_webrisk"),
    }

    results = await manager.lookup_all("https://normal-check.com")

    # One provider timed out, but overall lookup completed
    assert results["timeout_provider"].available is False
    assert results["timeout_provider"].verdict == ProviderVerdict.UNAVAILABLE
    assert results["google_webrisk"].available is True



def test_evidence_engine_compilation():
    intel_results = {
        "google_webrisk": ThreatIntelResult(
            provider="google_webrisk",
            indicator="https://phish.com",
            available=True,
            matched=True,
            verdict=ProviderVerdict.MATCH,
            categories=["SOCIAL_ENGINEERING"],
            checked_at="2026-09-13T10:00:00Z",
        ),
        "phishtank": ThreatIntelResult(
            provider="phishtank",
            indicator="https://phish.com",
            available=True,
            matched=True,
            verdict=ProviderVerdict.MATCH,
            categories=["PHISHING"],
            checked_at="2026-09-13T10:00:00Z",
        ),
    }

    features = {"has_phishing_keyword": 1, "uses_https": 0}
    evidence = compile_evidence(
        ml_prediction="malicious",
        probability=0.92,
        features=features,
        whois_data={"status": "ok"},
        dns_data={"status": "ok", "a": ["1.2.3.4"]},
        intel_results=intel_results,
    )

    sources = [e["source"] for e in evidence]
    assert "google_webrisk" in sources
    assert "phishtank" in sources
    assert "ml_model" in sources
    assert count_independent_confirmations(intel_results) == 2


def test_risk_correlation_distinguishes_ml_from_confirmed():
    # Case A: Only ML thinks suspicious (no external provider match)
    no_match_intel = {
        "google_webrisk": ThreatIntelResult(
            provider="google_webrisk", indicator="https://test.com", available=True, matched=False, verdict=ProviderVerdict.NO_MATCH, checked_at=""
        ),
        "phishtank": ThreatIntelResult(
            provider="phishtank", indicator="https://test.com", available=True, matched=False, verdict=ProviderVerdict.NO_MATCH, checked_at=""
        ),
    }
    score_a = calculate_risk_score(
        probability=0.65,
        features={"uses_https": 1},
        whois_data={"status": "ok", "creation_date": "2020-01-01"},
        dns_data={"status": "ok", "a": ["1.1.1.1"]},
        intel_results=no_match_intel,
    )
    pred_a = classify(score_a, independent_confirmations=0)
    assert pred_a == "suspicious"

    # Case B: External intelligence confirms threat -> Escalates to malicious with high risk
    confirmed_intel = {
        "google_webrisk": ThreatIntelResult(
            provider="google_webrisk", indicator="https://test.com", available=True, matched=True, verdict=ProviderVerdict.MATCH, categories=["SOCIAL_ENGINEERING"], checked_at=""
        ),
        "phishtank": ThreatIntelResult(
            provider="phishtank", indicator="https://test.com", available=True, matched=True, verdict=ProviderVerdict.MATCH, categories=["PHISHING"], checked_at=""
        ),
    }
    score_b = calculate_risk_score(
        probability=0.65,
        features={"uses_https": 1},
        whois_data={"status": "ok", "creation_date": "2020-01-01"},
        dns_data={"status": "ok", "a": ["1.1.1.1"]},
        intel_results=confirmed_intel,
    )
    pred_b = classify(score_b, independent_confirmations=2)
    assert pred_b == "malicious"
    assert score_b >= 85


def test_unavailable_provider_never_safe():
    # Provider unavailable must NOT reduce risk score or force a SAFE verdict
    unavailable_intel = {
        "google_webrisk": ThreatIntelResult(
            provider="google_webrisk", indicator="https://test.com", available=False, matched=False, verdict=ProviderVerdict.UNAVAILABLE, error="Network error", checked_at=""
        ),
    }
    score = calculate_risk_score(
        probability=0.92,
        features={"has_phishing_keyword": 1, "uses_https": 0},
        whois_data={},
        dns_data={},
        intel_results=unavailable_intel,
    )
    # ML probability is 0.92 with phishing keyword and missing HTTPS -> must remain malicious
    assert score >= 75
    assert classify(score) == "malicious"
