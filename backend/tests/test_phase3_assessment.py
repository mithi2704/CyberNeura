"""
Unit tests for CyberNeura Phase 3 full SecurityAssessment generation, explanations, and recommendations.
"""
from app.evidence.models import (
    EvidenceSource,
    EvidenceType,
    EvidenceSeverity,
    EvidenceState,
)
from app.evidence.builder import EvidenceBuilder
from app.risk.engine import RiskEngine
from app.risk.models import SecurityAssessment


def test_full_phishing_assessment():
    engine = RiskEngine()

    ev_ml = (
        EvidenceBuilder(EvidenceSource.ML, EvidenceType.ML_PREDICTION)
        .with_score(0.95)
        .with_category("PHISHING")
        .with_severity(EvidenceSeverity.CRITICAL)
        .build()
    )
    ev_pt = (
        EvidenceBuilder(EvidenceSource.PHISHTANK, EvidenceType.PHISHING_DATABASE_MATCH)
        .with_state(EvidenceState.CONFIRMED)
        .with_category("PHISHING")
        .with_severity(EvidenceSeverity.CRITICAL)
        .build()
    )

    assessment: SecurityAssessment = engine.assess(
        scan_id="test-scan-phish",
        url="https://secure-bank-login.xyz",
        probability=0.95,
        evidence_list=[ev_ml, ev_pt],
        correlated_findings=[],
    )

    assert assessment.prediction == "malicious"
    assert assessment.risk_score >= 85
    assert assessment.threat_category == "Phishing"
    assert assessment.severity == EvidenceSeverity.CRITICAL
    assert len(assessment.recommendations) >= 2
    assert any(r.action == "BLOCK_PERIMETER" for r in assessment.recommendations)
    assert any(r.action == "ISOLATE_CREDENTIALS" for r in assessment.recommendations)
    assert "CyberNeura classified this URL as malicious" in assessment.explanation


def test_safe_assessment():
    engine = RiskEngine()

    ev_ml = (
        EvidenceBuilder(EvidenceSource.ML, EvidenceType.ML_PREDICTION)
        .with_score(0.02)
        .supports_risk(False)
        .build()
    )
    ev_whois = (
        EvidenceBuilder(EvidenceSource.WHOIS, EvidenceType.DOMAIN_AGE)
        .with_value("12 years")
        .supports_risk(False)
        .build()
    )

    assessment: SecurityAssessment = engine.assess(
        scan_id="test-scan-safe",
        url="https://github.com",
        probability=0.02,
        evidence_list=[ev_ml, ev_whois],
        correlated_findings=[],
    )

    assert assessment.prediction == "safe"
    assert assessment.risk_score < 20
    assert assessment.threat_category == "Safe"
    assert any(r.action == "ALLOW_STANDARD" for r in assessment.recommendations)
    assert "legitimate" in assessment.explanation.lower()
