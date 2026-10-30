"""
Unified Risk Engine for CyberNeura Phase 3.
Coordinates scoring, confidence estimation, threshold mapping, explanation synthesis,
and recommendation generation into a finalized SecurityAssessment.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import List, Optional
from app.evidence.models import Evidence, EvidenceSeverity, EvidenceState, CorrelatedFinding
from app.risk.models import SecurityAssessment, RiskConfig, DetailedRecommendation
from app.risk.scoring import RiskScoringEngine
from app.risk.confidence import confidence_engine
from app.risk.thresholds import score_to_prediction, score_to_severity
from app.risk.explanations import explanation_engine
from app.risk.recommendations import recommendation_engine
from app.utils.logger import get_logger

logger = get_logger(__name__)

RISK_ENGINE_VERSION = "1.0.0"


class RiskEngine:
    def __init__(self, config: Optional[RiskConfig] = None):
        self.config = config or RiskConfig()
        self.scoring_engine = RiskScoringEngine(self.config)

    def assess(
        self,
        *,
        scan_id: str,
        url: str,
        probability: float,
        evidence_list: List[Evidence],
        correlated_findings: List[CorrelatedFinding],
    ) -> SecurityAssessment:
        """
        Produce a deterministic, complete SecurityAssessment object.
        """
        # 1. Compute deterministic score and factor breakdown
        risk_score, risk_factors = self.scoring_engine.compute_risk(
            scan_id=scan_id,
            evidence_list=evidence_list,
            correlated_findings=correlated_findings,
            url=url,
        )

        # 2. Count independent external confirmations
        confirmed_intel = [
            e for e in evidence_list
            if e.source.value in {"GOOGLE_WEB_RISK", "PHISHTANK", "URLHAUS"}
            and e.state == EvidenceState.CONFIRMED
        ]
        confirmations = len(confirmed_intel)

        # 3. Classify prediction & severity
        prediction = score_to_prediction(risk_score, independent_confirmations=confirmations)
        severity = score_to_severity(risk_score)

        # 4. Compute independent confidence
        confidence = confidence_engine.calculate_confidence(
            evidence_list=evidence_list,
            probability=probability,
            risk_score=risk_score,
        )

        # 5. Determine threat category
        threat_category = self._determine_threat_category(prediction, evidence_list)

        # 6. Generate deterministic explanations
        explanation = explanation_engine.generate_explanation(
            prediction=prediction,
            risk_score=risk_score,
            confidence=confidence,
            evidence_list=evidence_list,
            correlated_findings=correlated_findings,
            risk_factors=risk_factors,
        )
        summary = explanation_engine.generate_summary(
            prediction=prediction,
            risk_score=risk_score,
            correlated_findings=correlated_findings,
            evidence_list=evidence_list,
        )

        # 7. Generate structured recommendations
        recommendations = recommendation_engine.generate_recommendations(
            prediction=prediction,
            risk_score=risk_score,
            evidence_list=evidence_list,
            correlated_findings=correlated_findings,
        )

        # 8. Evidence counting by state
        critical_count = sum(1 for e in evidence_list if e.severity == EvidenceSeverity.CRITICAL and e.supports_risk)
        supporting_count = sum(1 for e in evidence_list if e.state in {EvidenceState.CONFIRMED, EvidenceState.SUPPORTING})
        contradicting_count = sum(1 for e in evidence_list if e.state == EvidenceState.CONTRADICTING)

        return SecurityAssessment(
            id=str(uuid.uuid4()),
            scan_id=scan_id,
            url=url,
            risk_score=risk_score,
            prediction=prediction,
            confidence=confidence,
            threat_category=threat_category,
            severity=severity,
            summary=summary,
            evidence_count=len(evidence_list),
            critical_evidence_count=critical_count,
            supporting_evidence_count=supporting_count,
            contradicting_evidence_count=contradicting_count,
            evidence=evidence_list,
            correlated_findings=correlated_findings,
            risk_factors=risk_factors,
            recommendations=recommendations,
            explanation=explanation,
            risk_engine_version=RISK_ENGINE_VERSION,
            config_version=self.config.version,
            created_at=datetime.now(timezone.utc).isoformat(),
        )

    def _determine_threat_category(self, prediction: str, evidence_list: List[Evidence]) -> str:
        if prediction == "safe":
            return "Safe"

        # Check confirmed threat intel categories first
        for e in evidence_list:
            if e.state == EvidenceState.CONFIRMED:
                cat = str(e.category or "").upper()
                if "PHISH" in cat or "SOCIAL_ENGINEERING" in cat:
                    return "Phishing"
                if "MALWARE" in cat:
                    return "Malware"

        # Check features
        has_phish_hints = any("phish" in str(e.description).lower() or e.evidence_type.value == "suspicious_path" for e in evidence_list)
        if has_phish_hints:
            return "Phishing"

        return "Suspicious Domain" if prediction == "suspicious" else "Malicious"


risk_engine = RiskEngine()
