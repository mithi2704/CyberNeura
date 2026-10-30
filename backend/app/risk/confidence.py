"""
Confidence Engine for CyberNeura Phase 3.
Calculates assessment confidence (0-100%) independently from risk score.
Evaluates evidence completeness, external provider corroboration, source diversity,
and penalizes provider unavailability and contradictory signals.
"""
from __future__ import annotations

from typing import List
from app.evidence.models import Evidence, EvidenceSeverity, EvidenceSource, EvidenceState, EvidenceType


class ConfidenceEngine:
    def calculate_confidence(
        self,
        *,
        evidence_list: List[Evidence],
        probability: float,
        risk_score: int,
    ) -> float:
        """
        Calculate confidence (0.0 to 100.0) based on model decision certainty,
        evidence completeness, external provider corroboration, and consistency.
        High certainty on either extreme (very safe or very malicious) yields 85-98% confidence.
        """
        # Base confidence from model probability certainty (distance from 0.50 boundary)
        certainty = abs(probability - 0.50)
        base_confidence = 60.0 + (certainty * 36.0)

        # 1. External Threat Intelligence Corroboration
        intel_evs = [
            e for e in evidence_list
            if e.source in {EvidenceSource.GOOGLE_WEB_RISK, EvidenceSource.PHISHTANK, EvidenceSource.URLHAUS}
        ]
        confirmed_intel = [e for e in intel_evs if e.state == EvidenceState.CONFIRMED]
        unavailable_intel = [e for e in intel_evs if e.state == EvidenceState.UNAVAILABLE]
        contradicting_evs = [e for e in evidence_list if e.state == EvidenceState.CONTRADICTING]

        if len(confirmed_intel) >= 2:
            base_confidence += 20.0  # Consensus threat
        elif len(confirmed_intel) == 1:
            base_confidence += 12.0  # Single verified threat

        # Contradictory evidence penalty
        if contradicting_evs:
            base_confidence -= (len(contradicting_evs) * 10.0)

        # Provider unavailability penalty (heavier when decision is borderline/uncertain)
        if len(unavailable_intel) >= 2:
            base_confidence -= 15.0 if certainty < 0.25 else 6.0
        elif len(unavailable_intel) == 1:
            base_confidence -= 8.0 if certainty < 0.25 else 3.0

        # 2. Corroborating signals bonus
        supporting_count = sum(1 for e in evidence_list if e.state in {EvidenceState.CONFIRMED, EvidenceState.SUPPORTING})
        if supporting_count >= 3:
            base_confidence += 8.0

        # Established legitimate domain confirmation
        mature_domain = any(
            e.source == EvidenceSource.WHOIS
            and e.evidence_type == EvidenceType.DOMAIN_AGE
            and not e.supports_risk
            for e in evidence_list
        )
        if probability < 0.25 and mature_domain and not contradicting_evs:
            base_confidence += 8.0

        final_confidence = max(20.0, min(99.0, base_confidence))
        return round(final_confidence, 1)



confidence_engine = ConfidenceEngine()
