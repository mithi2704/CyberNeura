"""
Correlation Rules for CyberNeura Phase 3 Risk + Evidence Engine.
Defines deterministic, auditable rule evaluations across normalized Evidence objects.
"""
from __future__ import annotations

from typing import List, Optional, Tuple, Dict, Any
from app.evidence.models import (
    Evidence,
    EvidenceSeverity,
    EvidenceSource,
    EvidenceState,
    EvidenceType,
    CorrelatedFinding,
)
from app.evidence.builder import CorrelatedFindingBuilder


class CorrelationRule:
    """Base interface for deterministic correlation rules."""
    rule_id: str
    name: str

    def evaluate(self, evidence_list: List[Evidence], scan_id: Optional[str] = None) -> Optional[CorrelatedFinding]:
        raise NotImplementedError


# ── RULE 1: ML >= 0.85 + Google Web Risk (Social Engineering) ────────────
class HighConfidencePhishingRule(CorrelationRule):
    rule_id = "RULE-1"
    name = "HIGH_CONFIDENCE_PHISHING"

    def evaluate(self, evidence_list: List[Evidence], scan_id: Optional[str] = None) -> Optional[CorrelatedFinding]:
        ml_ev = next((e for e in evidence_list if e.source == EvidenceSource.ML and e.evidence_type == EvidenceType.ML_PREDICTION and e.score >= 0.85), None)
        g_ev = next((e for e in evidence_list if e.source == EvidenceSource.GOOGLE_WEB_RISK and e.state == EvidenceState.CONFIRMED and "SOCIAL_ENGINEERING" in str(e.category or "")), None)

        if ml_ev and g_ev:
            return (
                CorrelatedFindingBuilder("HIGH_CONFIDENCE_PHISHING", EvidenceSeverity.CRITICAL)
                .with_scan_id(scan_id)
                .with_confidence(0.98)
                .with_description(
                    "High-confidence phishing threat: Machine-learning model detection confirmed by Google Web Risk social engineering telemetry."
                )
                .with_sources([EvidenceSource.ML.value, EvidenceSource.GOOGLE_WEB_RISK.value])
                .with_evidence_ids([ml_ev.id, g_ev.id])
                .with_rule_id(self.rule_id)
                .build()
            )
        return None


# ── RULE 2: PhishTank Verified Match ─────────────────────────────────────
class PhishTankVerifiedRule(CorrelationRule):
    rule_id = "RULE-2"
    name = "CONFIRMED_PHISHING"

    def evaluate(self, evidence_list: List[Evidence], scan_id: Optional[str] = None) -> Optional[CorrelatedFinding]:
        pt_ev = next((e for e in evidence_list if e.source == EvidenceSource.PHISHTANK and e.state == EvidenceState.CONFIRMED), None)
        if pt_ev:
            return (
                CorrelatedFindingBuilder("CONFIRMED_PHISHING", EvidenceSeverity.CRITICAL)
                .with_scan_id(scan_id)
                .with_confidence(pt_ev.confidence)
                .with_description("Authoritative verification: URL is listed as an active, confirmed phish in PhishTank community database.")
                .with_sources([EvidenceSource.PHISHTANK.value])
                .with_evidence_ids([pt_ev.id])
                .with_rule_id(self.rule_id)
                .build()
            )
        return None


# ── RULE 3: URLhaus Malware Match ────────────────────────────────────────
class URLhausConfirmedMalwareRule(CorrelationRule):
    rule_id = "RULE-3"
    name = "CONFIRMED_MALWARE"

    def evaluate(self, evidence_list: List[Evidence], scan_id: Optional[str] = None) -> Optional[CorrelatedFinding]:
        uh_ev = next((e for e in evidence_list if e.source == EvidenceSource.URLHAUS and e.state == EvidenceState.CONFIRMED), None)
        if uh_ev:
            return (
                CorrelatedFindingBuilder("CONFIRMED_MALWARE", EvidenceSeverity.CRITICAL)
                .with_scan_id(scan_id)
                .with_confidence(uh_ev.confidence)
                .with_description("Malware distribution verified: Active payload/malware host identified by abuse.ch URLhaus threat telemetry.")
                .with_sources([EvidenceSource.URLHAUS.value])
                .with_evidence_ids([uh_ev.id])
                .with_rule_id(self.rule_id)
                .build()
            )
        return None


# ── RULE 4: ML >= 0.85 + PhishTank Verified ──────────────────────────────
class MLDatabaseConfirmationRule(CorrelationRule):
    rule_id = "RULE-4"
    name = "ML_DATABASE_CONFIRMATION"

    def evaluate(self, evidence_list: List[Evidence], scan_id: Optional[str] = None) -> Optional[CorrelatedFinding]:
        ml_ev = next((e for e in evidence_list if e.source == EvidenceSource.ML and e.score >= 0.85), None)
        pt_ev = next((e for e in evidence_list if e.source == EvidenceSource.PHISHTANK and e.state == EvidenceState.CONFIRMED), None)

        if ml_ev and pt_ev:
            return (
                CorrelatedFindingBuilder("ML_DATABASE_CONFIRMATION", EvidenceSeverity.CRITICAL)
                .with_scan_id(scan_id)
                .with_confidence(0.99)
                .with_description("ML and human-verified phishing database corroborate: Neural pattern extraction aligns with known operational phishing campaign.")
                .with_sources([EvidenceSource.ML.value, EvidenceSource.PHISHTANK.value])
                .with_evidence_ids([ml_ev.id, pt_ev.id])
                .with_rule_id(self.rule_id)
                .build()
            )
        return None


# ── RULE 5: Multi-Source Independent Corroboration ───────────────────────
class MultiSourceCorroborationRule(CorrelationRule):
    rule_id = "RULE-5"
    name = "MULTI_SOURCE_CONFIRMATION"

    def evaluate(self, evidence_list: List[Evidence], scan_id: Optional[str] = None) -> Optional[CorrelatedFinding]:
        confirmed_intel = [
            e for e in evidence_list
            if e.source in {EvidenceSource.GOOGLE_WEB_RISK, EvidenceSource.PHISHTANK, EvidenceSource.URLHAUS}
            and e.state == EvidenceState.CONFIRMED
        ]
        if len(confirmed_intel) >= 2:
            sources = [e.source.value for e in confirmed_intel]
            return (
                CorrelatedFindingBuilder("MULTI_SOURCE_CONFIRMATION", EvidenceSeverity.CRITICAL)
                .with_scan_id(scan_id)
                .with_confidence(0.99)
                .with_description(
                    f"Consensus threat identification: {len(confirmed_intel)} independent external security feeds independently identified this target."
                )
                .with_sources(sources)
                .with_evidence_ids([e.id for e in confirmed_intel])
                .with_rule_id(self.rule_id)
                .build()
            )
        return None


# ── RULE 6: Provider Unavailable Fail-Safe ────────────────────────────────
class ProviderUnavailableRule(CorrelationRule):
    rule_id = "RULE-6"
    name = "PROVIDER_UNAVAILABLE_ISOLATION"

    def evaluate(self, evidence_list: List[Evidence], scan_id: Optional[str] = None) -> Optional[CorrelatedFinding]:
        unavail = [e for e in evidence_list if e.state == EvidenceState.UNAVAILABLE]
        if unavail:
            sources = [e.source.value for e in unavail]
            return (
                CorrelatedFindingBuilder("PROVIDER_UNAVAILABLE_ISOLATION", EvidenceSeverity.INFO)
                .with_scan_id(scan_id)
                .with_confidence(0.7)
                .with_description(
                    f"External telemetry degraded: {', '.join(sources)} was unavailable. Invariant enforced: UNAVAILABLE is never treated as safe."
                )
                .with_sources(sources)
                .with_evidence_ids([e.id for e in unavail])
                .with_rule_id(self.rule_id)
                .build()
            )
        return None


# ── RULE 7: DNS Anomaly (Supporting Only) ────────────────────────────────
class DNSAnomalyRule(CorrelationRule):
    rule_id = "RULE-7"
    name = "DNS_ANOMALY_SUPPORTING"

    def evaluate(self, evidence_list: List[Evidence], scan_id: Optional[str] = None) -> Optional[CorrelatedFinding]:
        dns_ev = next((e for e in evidence_list if e.source == EvidenceSource.DNS and e.evidence_type == EvidenceType.DNS_ANOMALY), None)
        if dns_ev:
            return (
                CorrelatedFindingBuilder("DNS_ANOMALY_SUPPORTING", EvidenceSeverity.LOW)
                .with_scan_id(scan_id)
                .with_confidence(0.65)
                .with_description("DNS infrastructure anomaly noted. Used solely as supporting contextual evidence, not independent malicious proof.")
                .with_sources([EvidenceSource.DNS.value])
                .with_evidence_ids([dns_ev.id])
                .with_rule_id(self.rule_id)
                .build()
            )
        return None


# ── RULE 8: Young Domain + Suspicious URL Characteristics + Elevated ML ──
class YoungDomainSuspiciousRule(CorrelationRule):
    rule_id = "RULE-8"
    name = "YOUNG_DOMAIN_SUSPICIOUS_CHARACTERISTICS"

    def evaluate(self, evidence_list: List[Evidence], scan_id: Optional[str] = None) -> Optional[CorrelatedFinding]:
        young_ev = next((e for e in evidence_list if e.source == EvidenceSource.WHOIS and e.evidence_type == EvidenceType.DOMAIN_AGE and e.supports_risk), None)
        feat_ev = next((e for e in evidence_list if e.source == EvidenceSource.URL_FEATURES and e.supports_risk), None)
        ml_ev = next((e for e in evidence_list if e.source == EvidenceSource.ML and e.score >= 0.5), None)

        if young_ev and feat_ev and ml_ev:
            sources = [EvidenceSource.WHOIS.value, EvidenceSource.URL_FEATURES.value, EvidenceSource.ML.value]
            ev_ids = [young_ev.id, feat_ev.id, ml_ev.id]
            return (
                CorrelatedFindingBuilder("YOUNG_DOMAIN_SUSPICIOUS_CHARACTERISTICS", EvidenceSeverity.HIGH)
                .with_scan_id(scan_id)
                .with_confidence(0.85)
                .with_description(
                    "High-risk domain footprint: Newly registered domain combined with obfuscated lexical URL patterns and elevated ML risk."
                )
                .with_sources(sources)
                .with_evidence_ids(ev_ids)
                .with_rule_id(self.rule_id)
                .build()
            )
        return None


# ── RULE 9: Persistent Historical Threat ─────────────────────────────────
class PersistentHistoricalThreatRule(CorrelationRule):
    rule_id = "RULE-9"
    name = "PERSISTENT_HISTORICAL_THREAT"

    def evaluate(self, evidence_list: List[Evidence], scan_id: Optional[str] = None) -> Optional[CorrelatedFinding]:
        hist_ev = next((e for e in evidence_list if e.source == EvidenceSource.HISTORY and e.evidence_type == EvidenceType.HISTORICAL_DETECTION), None)
        if hist_ev:
            decay = hist_ev.metadata.get("decay_factor", 1.0)
            if decay >= 0.5:
                return (
                    CorrelatedFindingBuilder("PERSISTENT_HISTORICAL_THREAT", EvidenceSeverity.HIGH)
                    .with_scan_id(scan_id)
                    .with_confidence(0.9 * decay)
                    .with_description("Historical telemetry recurrence: Target URL or domain has repeat confirmed malicious incidents in CyberNeura history.")
                    .with_sources([EvidenceSource.HISTORY.value])
                    .with_evidence_ids([hist_ev.id])
                    .with_rule_id(self.rule_id)
                    .build()
                )
        return None


# Default ruleset
ALL_CORRELATION_RULES: List[CorrelationRule] = [
    HighConfidencePhishingRule(),
    PhishTankVerifiedRule(),
    URLhausConfirmedMalwareRule(),
    MLDatabaseConfirmationRule(),
    MultiSourceCorroborationRule(),
    YoungDomainSuspiciousRule(),
    PersistentHistoricalThreatRule(),
    DNSAnomalyRule(),
    ProviderUnavailableRule(),
]
