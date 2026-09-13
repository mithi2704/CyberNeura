"""
Unit tests for CyberNeura Phase 3 Evidence Engine and Normalizers.
"""
import pytest
from app.evidence.models import (
    EvidenceSource,
    EvidenceType,
    EvidenceSeverity,
    EvidenceState,
    Evidence,
)
from app.evidence.builder import EvidenceBuilder
from app.evidence.normalizer import EvidenceNormalizer
from app.intelligence.models import ThreatIntelResult, ProviderVerdict


@pytest.fixture
def normalizer():
    return EvidenceNormalizer()


def test_evidence_builder():
    ev = (
        EvidenceBuilder(EvidenceSource.ML, EvidenceType.ML_PREDICTION)
        .with_scan_id("test-scan-1")
        .with_category("PHISHING")
        .with_severity(EvidenceSeverity.HIGH)
        .with_state(EvidenceState.SUPPORTING)
        .with_score(0.92)
        .with_confidence(0.95)
        .supports_risk(True)
        .with_description("Test description")
        .build()
    )
    assert ev.scan_id == "test-scan-1"
    assert ev.source == EvidenceSource.ML
    assert ev.score == 0.92
    assert ev.confidence == 0.95
    assert ev.supports_risk is True


def test_normalize_ml_high_probability(normalizer):
    items = normalizer.normalize_ml(
        scan_id="s1",
        prediction="malicious",
        probability=0.96,
        features={},
    )
    assert len(items) == 1
    ev = items[0]
    assert ev.source == EvidenceSource.ML
    assert ev.severity == EvidenceSeverity.CRITICAL
    assert ev.state == EvidenceState.CONFIRMED
    assert ev.supports_risk is True
    assert ev.score == 0.96


def test_normalize_ml_safe_probability(normalizer):
    items = normalizer.normalize_ml(
        scan_id="s1",
        prediction="safe",
        probability=0.08,
        features={},
    )
    assert len(items) == 1
    ev = items[0]
    assert ev.source == EvidenceSource.ML
    assert ev.severity == EvidenceSeverity.INFO
    assert ev.state == EvidenceState.CONTRADICTING
    assert ev.supports_risk is False


def test_normalize_threat_intel_match(normalizer):
    pt_res = ThreatIntelResult(
        provider="phishtank",
        indicator="https://phish.example.com",
        available=True,
        matched=True,
        verdict=ProviderVerdict.MATCH,
        categories=["PHISHING"],
        confidence=0.96,
        checked_at="2026-09-13T12:00:00Z",
    )
    items = normalizer.normalize_threat_intel(
        scan_id="s1",
        intel_results={"phishtank": pt_res},
    )
    assert len(items) == 1
    ev = items[0]
    assert ev.source == EvidenceSource.PHISHTANK
    assert ev.evidence_type == EvidenceType.PHISHING_DATABASE_MATCH
    assert ev.state == EvidenceState.CONFIRMED
    assert ev.severity == EvidenceSeverity.CRITICAL
    assert ev.supports_risk is True


def test_normalize_threat_intel_unavailable_invariant(normalizer):
    """INVARIANT: UNAVAILABLE != SAFE. Provider failure must never be marked safe."""
    g_res = ThreatIntelResult(
        provider="google_webrisk",
        indicator="https://example.com",
        available=False,
        matched=False,
        verdict=ProviderVerdict.UNAVAILABLE,
        error="Gateway timeout (504)",
        checked_at="2026-09-13T12:00:00Z",
    )
    items = normalizer.normalize_threat_intel(
        scan_id="s1",
        intel_results={"google_webrisk": g_res},
    )
    assert len(items) == 1
    ev = items[0]
    assert ev.source == EvidenceSource.GOOGLE_WEB_RISK
    assert ev.state == EvidenceState.UNAVAILABLE
    assert ev.supports_risk is False
    assert "not treated as safe" in ev.description.lower()


def test_normalize_dns_resolution(normalizer):
    dns_ok = {"status": "ok", "a": ["93.184.216.34"], "ns": ["a.iana-servers.net"]}
    items = normalizer.normalize_dns(scan_id="s1", dns_data=dns_ok, domain="example.com")
    assert any(e.evidence_type == EvidenceType.DNS_RESOLUTION and not e.supports_risk for e in items)

    dns_err = {"status": "error"}
    items_err = normalizer.normalize_dns(scan_id="s1", dns_data=dns_err, domain="failed.com")
    assert any(e.evidence_type == EvidenceType.DNS_ANOMALY and e.supports_risk for e in items_err)


def test_normalize_whois_domain_age(normalizer):
    # Young domain (3 days old)
    whois_young = {"status": "ok", "creation_date": "2026-09-10T00:00:00Z", "registrar": "NameCheap"}
    items = normalizer.normalize_whois(scan_id="s1", whois_data=whois_young, domain="young.xyz")
    age_ev = next((e for e in items if e.evidence_type == EvidenceType.DOMAIN_AGE), None)
    assert age_ev is not None
    assert age_ev.supports_risk is True
    assert age_ev.severity == EvidenceSeverity.MEDIUM

    # Mature domain (10 years old)
    whois_mature = {"status": "ok", "creation_date": "2015-01-01T00:00:00Z", "registrar": "MarkMonitor"}
    items_mature = normalizer.normalize_whois(scan_id="s1", whois_data=whois_mature, domain="mature.com")
    age_mature_ev = next((e for e in items_mature if e.evidence_type == EvidenceType.DOMAIN_AGE), None)
    assert age_mature_ev is not None
    assert age_mature_ev.supports_risk is False


def test_normalize_url_features(normalizer):
    features = {
        "is_ip": True,
        "hostname": "192.168.1.1",
        "suspicious_tld": True,
        "tld": "tk",
        "entropy": 4.8,
        "url_length": 140,
    }
    items = normalizer.normalize_url_features(
        scan_id="s1",
        features=features,
        url="http://192.168.1.1/login-banking-verify-secure.tk",
    )
    types = {e.evidence_type for e in items}
    assert EvidenceType.IP_REPUTATION in types
    assert EvidenceType.SUSPICIOUS_TLD in types
    assert EvidenceType.URL_ENTROPY in types
    assert EvidenceType.URL_LENGTH in types
    assert EvidenceType.SUSPICIOUS_PATH in types
