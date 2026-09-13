"""
Unit tests for CyberNeura Phase 3 Risk Scoring Engine.
"""
from app.evidence.models import (
    EvidenceSource,
    EvidenceType,
    EvidenceState,
    EvidenceSeverity,
)
from app.evidence.builder import EvidenceBuilder
from app.risk.scoring import RiskScoringEngine, VERIFIED_MATCH_FLOOR


def test_verified_match_floor_enforcement():
    """Any verified match from threat intel guarantees risk score >= 85."""
    engine = RiskScoringEngine()

    # Low ML probability (0.10) but confirmed PhishTank match
    ev_ml = EvidenceBuilder(EvidenceSource.ML, EvidenceType.ML_PREDICTION).with_score(0.10).build()
    ev_pt = (
        EvidenceBuilder(EvidenceSource.PHISHTANK, EvidenceType.PHISHING_DATABASE_MATCH)
        .with_state(EvidenceState.CONFIRMED)
        .build()
    )

    score, factors = engine.compute_risk(
        scan_id="s1",
        evidence_list=[ev_ml, ev_pt],
        correlated_findings=[],
    )
    assert score >= VERIFIED_MATCH_FLOOR
    assert score >= 85


def test_multi_source_consensus_boost():
    """Multiple confirmed threat intel feeds elevate score to >= 94."""
    engine = RiskScoringEngine()

    ev_ml = EvidenceBuilder(EvidenceSource.ML, EvidenceType.ML_PREDICTION).with_score(0.90).build()
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

    score, factors = engine.compute_risk(
        scan_id="s1",
        evidence_list=[ev_ml, ev_google, ev_pt],
        correlated_findings=[],
    )
    assert score >= 94


def test_safe_url_scoring():
    """Clean signals produce low risk score (< 20)."""
    engine = RiskScoringEngine()

    ev_ml = (
        EvidenceBuilder(EvidenceSource.ML, EvidenceType.ML_PREDICTION)
        .with_score(0.04)
        .supports_risk(False)
        .build()
    )
    ev_dns = (
        EvidenceBuilder(EvidenceSource.DNS, EvidenceType.DNS_RESOLUTION)
        .supports_risk(False)
        .build()
    )
    ev_whois = (
        EvidenceBuilder(EvidenceSource.WHOIS, EvidenceType.DOMAIN_AGE)
        .supports_risk(False)
        .with_value("10 years")
        .build()
    )

    score, factors = engine.compute_risk(
        scan_id="s1",
        evidence_list=[ev_ml, ev_dns, ev_whois],
        correlated_findings=[],
    )
    assert score < 20
    assert len(factors) == 6  # ML, Intel, DNS, WHOIS, Features, History


def test_factor_directionality_and_breakdown():
    engine = RiskScoringEngine()
    ev_ml = EvidenceBuilder(EvidenceSource.ML, EvidenceType.ML_PREDICTION).with_score(0.85).build()
    score, factors = engine.compute_risk(scan_id="s1", evidence_list=[ev_ml], correlated_findings=[])

    ml_factor = next(f for f in factors if f.factor_type == "ML_PREDICTION")
    assert ml_factor.direction == "RISK_INCREASING"
    assert ml_factor.contribution > 20.0
    assert ml_factor.max_contribution == 30.0
