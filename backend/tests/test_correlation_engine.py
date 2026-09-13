"""
Unit tests for CyberNeura Phase 3 Evidence Correlation Engine and Rules.
"""
from app.evidence.models import (
    EvidenceSource,
    EvidenceType,
    EvidenceSeverity,
    EvidenceState,
    Evidence,
)
from app.evidence.builder import EvidenceBuilder
from app.evidence.correlator import EvidenceCorrelator


def test_rule1_high_confidence_phishing():
    correlator = EvidenceCorrelator()
    ev_ml = (
        EvidenceBuilder(EvidenceSource.ML, EvidenceType.ML_PREDICTION)
        .with_score(0.92)
        .build()
    )
    ev_google = (
        EvidenceBuilder(EvidenceSource.GOOGLE_WEB_RISK, EvidenceType.THREAT_INTEL_MATCH)
        .with_state(EvidenceState.CONFIRMED)
        .with_category("SOCIAL_ENGINEERING")
        .build()
    )
    findings = correlator.correlate([ev_ml, ev_google])
    assert any(f.finding_type == "HIGH_CONFIDENCE_PHISHING" for f in findings)
    assert any(f.severity == EvidenceSeverity.CRITICAL for f in findings)


def test_rule2_phishtank_confirmed():
    correlator = EvidenceCorrelator()
    ev_pt = (
        EvidenceBuilder(EvidenceSource.PHISHTANK, EvidenceType.PHISHING_DATABASE_MATCH)
        .with_state(EvidenceState.CONFIRMED)
        .with_confidence(0.98)
        .build()
    )
    findings = correlator.correlate([ev_pt])
    assert any(f.finding_type == "CONFIRMED_PHISHING" for f in findings)


def test_rule3_urlhaus_confirmed_malware():
    correlator = EvidenceCorrelator()
    ev_uh = (
        EvidenceBuilder(EvidenceSource.URLHAUS, EvidenceType.MALWARE_DATABASE_MATCH)
        .with_state(EvidenceState.CONFIRMED)
        .with_confidence(0.95)
        .build()
    )
    findings = correlator.correlate([ev_uh])
    assert any(f.finding_type == "CONFIRMED_MALWARE" for f in findings)


def test_rule4_ml_database_confirmation():
    correlator = EvidenceCorrelator()
    ev_ml = (
        EvidenceBuilder(EvidenceSource.ML, EvidenceType.ML_PREDICTION)
        .with_score(0.88)
        .build()
    )
    ev_pt = (
        EvidenceBuilder(EvidenceSource.PHISHTANK, EvidenceType.PHISHING_DATABASE_MATCH)
        .with_state(EvidenceState.CONFIRMED)
        .build()
    )
    findings = correlator.correlate([ev_ml, ev_pt])
    assert any(f.finding_type == "ML_DATABASE_CONFIRMATION" for f in findings)


def test_rule5_multi_source_corroboration():
    correlator = EvidenceCorrelator()
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
    findings = correlator.correlate([ev_google, ev_pt])
    assert any(f.finding_type == "MULTI_SOURCE_CONFIRMATION" for f in findings)
    assert correlator.get_independent_confirmation_count([ev_google, ev_pt]) == 2


def test_rule6_provider_unavailable_isolation():
    correlator = EvidenceCorrelator()
    ev_unavail = (
        EvidenceBuilder(EvidenceSource.GOOGLE_WEB_RISK, EvidenceType.PROVIDER_UNAVAILABLE)
        .with_state(EvidenceState.UNAVAILABLE)
        .build()
    )
    findings = correlator.correlate([ev_unavail])
    assert any(f.finding_type == "PROVIDER_UNAVAILABLE_ISOLATION" for f in findings)


def test_rule8_young_domain_suspicious_features():
    correlator = EvidenceCorrelator()
    ev_whois = (
        EvidenceBuilder(EvidenceSource.WHOIS, EvidenceType.DOMAIN_AGE)
        .supports_risk(True)
        .build()
    )
    ev_feat = (
        EvidenceBuilder(EvidenceSource.URL_FEATURES, EvidenceType.SUSPICIOUS_TLD)
        .supports_risk(True)
        .build()
    )
    ev_ml = (
        EvidenceBuilder(EvidenceSource.ML, EvidenceType.ML_PREDICTION)
        .with_score(0.75)
        .build()
    )
    findings = correlator.correlate([ev_whois, ev_feat, ev_ml])
    assert any(f.finding_type == "YOUNG_DOMAIN_SUSPICIOUS_CHARACTERISTICS" for f in findings)
