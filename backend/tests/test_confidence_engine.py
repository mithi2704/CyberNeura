"""
Unit tests for CyberNeura Phase 3 Confidence Engine.
"""
from app.evidence.models import (
    EvidenceSource,
    EvidenceType,
    EvidenceState,
)
from app.evidence.builder import EvidenceBuilder
from app.risk.confidence import confidence_engine


def test_confidence_multi_source_corroboration():
    """Confidence exceeds 90% when multiple external sources corroborate."""
    ev_google = (
        EvidenceBuilder(EvidenceSource.GOOGLE_WEB_RISK, EvidenceType.THREAT_INTEL_MATCH)
        .with_state(EvidenceState.CONFIRMED)
        .build()
    )
    ev_pt = (
        EvidenceBuilder(EvidenceSource.PHISHTANK, EvidenceType.PHISHING_DATABASE_MATCH)
        .with_state(EvidenceState.CONFIRMED)
        .build()
    )

    conf = confidence_engine.calculate_confidence(
        evidence_list=[ev_google, ev_pt],
        probability=0.92,
        risk_score=95,
    )
    assert conf >= 90.0


def test_confidence_contradictory_evidence():
    """Confidence is reduced when ML is high but external databases report clean & domain is mature."""
    ev_google = (
        EvidenceBuilder(EvidenceSource.GOOGLE_WEB_RISK, EvidenceType.THREAT_INTEL_MATCH)
        .with_state(EvidenceState.CONTRADICTING)
        .supports_risk(False)
        .build()
    )
    ev_pt = (
        EvidenceBuilder(EvidenceSource.PHISHTANK, EvidenceType.PHISHING_DATABASE_MATCH)
        .with_state(EvidenceState.CONTRADICTING)
        .supports_risk(False)
        .build()
    )
    ev_whois = (
        EvidenceBuilder(EvidenceSource.WHOIS, EvidenceType.DOMAIN_AGE)
        .with_state(EvidenceState.CONTRADICTING)
        .supports_risk(False)
        .build()
    )

    conf = confidence_engine.calculate_confidence(
        evidence_list=[ev_google, ev_pt, ev_whois],
        probability=0.85,
        risk_score=55,
    )
    # Contradictory evidence should bring confidence down significantly
    assert conf <= 65.0


def test_confidence_provider_unavailability_penalty():
    """Unavailable providers reduce confidence without marking URL safe."""
    ev_unavail1 = (
        EvidenceBuilder(EvidenceSource.GOOGLE_WEB_RISK, EvidenceType.PROVIDER_UNAVAILABLE)
        .with_state(EvidenceState.UNAVAILABLE)
        .build()
    )
    ev_unavail2 = (
        EvidenceBuilder(EvidenceSource.PHISHTANK, EvidenceType.PROVIDER_UNAVAILABLE)
        .with_state(EvidenceState.UNAVAILABLE)
        .build()
    )

    conf = confidence_engine.calculate_confidence(
        evidence_list=[ev_unavail1, ev_unavail2],
        probability=0.60,
        risk_score=50,
    )
    assert conf <= 60.0
