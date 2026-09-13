"""
Deterministic Explanation Engine for CyberNeura Phase 3.
Generates human-readable, auditable analysis narratives derived exclusively
from verified evidence facts, without hallucination or LLM dependency.
"""
from __future__ import annotations

from typing import List, Optional
from app.evidence.models import Evidence, EvidenceSeverity, EvidenceSource, EvidenceState, CorrelatedFinding
from app.risk.models import RiskFactor


class ExplanationEngine:
    def generate_explanation(
        self,
        *,
        prediction: str,
        risk_score: int,
        confidence: float,
        evidence_list: List[Evidence],
        correlated_findings: List[CorrelatedFinding],
        risk_factors: List[RiskFactor],
    ) -> str:
        """
        Synthesize a deterministic explanation paragraph from verified evidence.
        """
        # 1. Multi-source confirmed threat
        confirmed_intel = [
            e for e in evidence_list
            if e.source in {EvidenceSource.GOOGLE_WEB_RISK, EvidenceSource.PHISHTANK, EvidenceSource.URLHAUS}
            and e.state == EvidenceState.CONFIRMED
        ]
        ml_ev = next((e for e in evidence_list if e.source == EvidenceSource.ML), None)
        high_ml = ml_ev is not None and ml_ev.score >= 0.70

        if confirmed_intel:
            providers_str = " and ".join(e.source.value.replace("_", " ").title() for e in confirmed_intel)
            categories = list({e.category for e in confirmed_intel if e.category})
            cat_str = f" ({', '.join(categories)})" if categories else ""
            if high_ml:
                return (
                    f"CyberNeura classified this URL as malicious (Risk Score: {risk_score}/100) because machine-learning pattern inference "
                    f"detected severe anomalies and external security telemetry from {providers_str} independently verified active threat indicators{cat_str}."
                )
            else:
                return (
                    f"CyberNeura classified this URL as malicious (Risk Score: {risk_score}/100) based on authoritative external threat verification "
                    f"from {providers_str}{cat_str}, overriding neutral lexical indicators."
                )

        # 2. Elevated ML risk but no external confirmation (contradicting/unconfirmed)
        clean_intel = [
            e for e in evidence_list
            if e.source in {EvidenceSource.GOOGLE_WEB_RISK, EvidenceSource.PHISHTANK, EvidenceSource.URLHAUS}
            and e.state == EvidenceState.CONTRADICTING
        ]
        unavail_intel = [
            e for e in evidence_list
            if e.state == EvidenceState.UNAVAILABLE
        ]

        if high_ml:
            if clean_intel:
                return (
                    f"CyberNeura classified this URL as {prediction} (Risk Score: {risk_score}/100). The machine-learning model detected "
                    f"elevated threat characteristics, but external threat intelligence feeds did not report existing reputation records. "
                    f"Confidence is moderated ({confidence:.0f}%) due to absence of external corroboration."
                )
            elif unavail_intel:
                return (
                    f"CyberNeura classified this URL as {prediction} (Risk Score: {risk_score}/100). The machine-learning model detected "
                    f"elevated threat characteristics, while external intelligence providers were unavailable. "
                    f"Confidence is capped at {confidence:.0f}% due to degraded external telemetry."
                )

        # 3. Suspicious domain / lexical features
        young_ev = next((e for e in evidence_list if e.source == EvidenceSource.WHOIS and e.supports_risk), None)
        feat_evs = [e for e in evidence_list if e.source == EvidenceSource.URL_FEATURES and e.supports_risk]

        if prediction == "suspicious":
            reasons = []
            if young_ev:
                reasons.append("recent domain registration")
            if feat_evs:
                reasons.append("suspicious lexical URL patterns")
            reason_text = " and ".join(reasons) if reasons else "moderate structural anomalies"
            return (
                f"CyberNeura flagged this URL as suspicious (Risk Score: {risk_score}/100) due to {reason_text}. "
                f"No authoritative blacklist matches were triggered, but defensive precautions are recommended."
            )

        # 4. Safe URL
        mature_ev = next((e for e in evidence_list if e.source == EvidenceSource.WHOIS and not e.supports_risk), None)
        mature_text = f" and an established domain history ({mature_ev.value})" if mature_ev else ""
        return (
            f"No malicious indicators or threat telemetry matches were identified across machine-learning analysis, "
            f"DNS infrastructure checks, or external security databases{mature_text}. This URL matches standard legitimate profiles."
        )

    def generate_summary(
        self,
        *,
        prediction: str,
        risk_score: int,
        correlated_findings: List[CorrelatedFinding],
        evidence_list: List[Evidence],
    ) -> str:
        """Concise one-line summary for card headers and executive reporting."""
        if correlated_findings:
            top_finding = correlated_findings[0]
            return top_finding.description

        if prediction == "malicious":
            return "Critical threat indicators identified across security analysis."
        elif prediction == "suspicious":
            return "Elevated risk signals detected without external confirmation."
        return "Clean security profile. No actionable risk detected."


explanation_engine = ExplanationEngine()
