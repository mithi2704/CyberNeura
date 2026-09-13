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
        Calculate confidence (0.0 to 100.0) based on evidence volume, consistency,
        provider availability, and corroboration.
        """
        base_confidence = 70.0

        # 1. External Threat Intelligence Corroboration
        intel_evs = [
            e for e in evidence_list
            if e.source in {EvidenceSource.GOOGLE_WEB_RISK, EvidenceSource.PHISHTANK, EvidenceSource.URLHAUS}
        ]
        confirmed_intel = [e for e in intel_evs if e.state == EvidenceState.CONFIRMED]
        unavailable_intel = [e for e in intel_evs if e.state == EvidenceState.UNAVAILABLE]
        clean_intel = [e for e in intel_evs if e.state == EvidenceState.CONTRADICTING]

        if len(confirmed_intel) >= 2:
            base_confidence += 25.0  # Consensus threat
        elif len(confirmed_intel) == 1:
            base_confidence += 15.0  # Single verified threat

        # 2. Availability Penalization (UNAVAILABLE != SAFE)
        # If external providers were unavailable, reduce confidence accordingly
        if len(unavailable_intel) >= 3:
            base_confidence -= 30.0
        elif len(unavailable_intel) == 2:
            base_confidence -= 20.0
        elif len(unavailable_intel) == 1:
            base_confidence -= 10.0

        # 3. Contradictory Evidence Analysis
        # E.g. ML predicts high risk (>=0.80) but all available external intel reports clean
        has_high_ml = probability >= 0.80
        has_clean_intel = len(clean_intel) >= 2 and len(confirmed_intel) == 0
        mature_domain = any(
            e.source == EvidenceSource.WHOIS
            and e.evidence_type == EvidenceType.DOMAIN_AGE
            and not e.supports_risk
            for e in evidence_list
        )

        if has_high_ml and has_clean_intel:
            # Conflicting signals: ML says dangerous, external databases say clean
            base_confidence -= 18.0
            if mature_domain:
                base_confidence -= 10.0

        # Conversely, if ML is safe (<=0.15), all external feeds are clean, and domain is mature:
        if probability <= 0.15 and has_clean_intel and mature_domain:
            base_confidence += 20.0

        # 4. Evidence volume bonus
        supporting_count = sum(1 for e in evidence_list if e.state in {EvidenceState.CONFIRMED, EvidenceState.SUPPORTING})
        if supporting_count >= 5:
            base_confidence += 5.0

        # Clamp strictly between 15.0 and 99.0
        final_confidence = max(15.0, min(99.0, base_confidence))
        return round(final_confidence, 1)


confidence_engine = ConfidenceEngine()
