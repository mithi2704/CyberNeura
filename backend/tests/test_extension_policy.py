"""
Unit tests for CyberNeura Extension PolicyEngine (Phase 6).
Verifies deterministic translation of risk signals into ALLOW, WARN, and BLOCK decisions.
"""
import pytest
from app.extension.models import ExtensionDecision
from app.extension.policy import PolicyEngine


def test_policy_allow_benign():
    engine = PolicyEngine(safe_threshold=30, suspicious_threshold=70)
    decision, can_override, reasons, recs = engine.evaluate(
        risk_score=10,
        prediction="SAFE",
        confidence=95.0,
        severity="INFO",
    )
    assert decision == ExtensionDecision.ALLOW
    assert can_override is False
    assert any("safe" in r.lower() for r in reasons)


def test_policy_warn_suspicious():
    engine = PolicyEngine(safe_threshold=30, suspicious_threshold=70)
    decision, can_override, reasons, recs = engine.evaluate(
        risk_score=55,
        prediction="SUSPICIOUS",
        confidence=80.0,
        threat_category="Typosquatting",
        severity="MEDIUM",
    )
    assert decision == ExtensionDecision.WARN
    assert can_override is True
    assert any("suspicious" in r.lower() for r in reasons)
    assert any("personal" in r.lower() or "financial" in r.lower() or "credentials" in r.lower() for r in recs)


def test_policy_block_malicious_high_confidence():
    engine = PolicyEngine(safe_threshold=30, suspicious_threshold=70)
    decision, can_override, reasons, recs = engine.evaluate(
        risk_score=92,
        prediction="MALICIOUS",
        confidence=90.0,
        threat_category="Phishing",
        severity="HIGH",
    )
    assert decision == ExtensionDecision.BLOCK
    assert any("threat" in r.lower() or "malicious" in r.lower() for r in reasons)
    assert any("do not proceed" in r.lower() for r in recs)


def test_policy_block_threat_intel_match():
    engine = PolicyEngine(safe_threshold=30, suspicious_threshold=70)
    intel = {
        "urlhaus": {"matched": True, "categories": ["MALWARE"]},
    }
    decision, can_override, reasons, recs = engine.evaluate(
        risk_score=40,
        prediction="SUSPICIOUS",
        confidence=60.0,
        threat_intel=intel,
    )
    assert decision == ExtensionDecision.BLOCK
    assert any("threat intelligence provider" in r.lower() for r in reasons)


def test_policy_warn_malicious_low_confidence():
    engine = PolicyEngine(safe_threshold=30, suspicious_threshold=70, strict_mode=False)
    decision, can_override, reasons, recs = engine.evaluate(
        risk_score=75,
        prediction="MALICIOUS",
        confidence=50.0,
        severity="LOW",
    )
    # Without strict mode or intel match, low-confidence malicious defaults to WARN
    assert decision == ExtensionDecision.WARN
    assert can_override is True


def test_policy_strict_mode_blocks_low_confidence():
    engine = PolicyEngine(safe_threshold=30, suspicious_threshold=70, strict_mode=True)
    decision, can_override, reasons, recs = engine.evaluate(
        risk_score=75,
        prediction="MALICIOUS",
        confidence=50.0,
        severity="LOW",
    )
    assert decision == ExtensionDecision.BLOCK


def test_policy_rules_metadata():
    engine = PolicyEngine()
    rules = engine.get_rules_description()
    assert "RULE_ALLOW_SAFE" in rules
    assert "RULE_WARN_SUSPICIOUS" in rules
    assert "RULE_BLOCK_MALICIOUS_HIGH_CONF" in rules
    assert "RULE_BLOCK_THREAT_INTEL" in rules
