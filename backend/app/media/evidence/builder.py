"""
Fluent builder for Media Evidence items conforming to the Phase 3 Evidence subsystem.
"""
from __future__ import annotations

from typing import Any, Dict, Optional
from app.evidence.models import Evidence, EvidenceSource, EvidenceType, EvidenceSeverity, EvidenceState


class MediaEvidenceBuilder:
    def __init__(self, media_id: str):
        self.media_id = media_id

    def build_model_evidence(
        self,
        probability: float,
        confidence: float,
        model_name: str,
        features: Dict[str, Any],
        is_video: bool = False,
    ) -> Evidence:
        prob = 0.5 if (probability is None or not (0.0 <= probability <= 1.0)) else float(probability)
        conf = 0.8 if (confidence is None or not (0.0 <= confidence <= 1.0)) else float(confidence)

        severity = (
            EvidenceSeverity.CRITICAL if prob >= 0.85
            else EvidenceSeverity.HIGH if prob >= 0.70
            else EvidenceSeverity.MEDIUM if prob >= 0.40
            else EvidenceSeverity.LOW
        )
        return Evidence(
            media_id=self.media_id,
            source=EvidenceSource.DEEPFAKE_MODEL if is_video else EvidenceSource.IMAGE_MODEL,
            evidence_type=EvidenceType.DEEPFAKE_PROBABILITY if is_video else EvidenceType.AI_GENERATION_PROBABILITY,
            category="Neural Model Detection",
            severity=severity,
            state=EvidenceState.CONFIRMED if prob >= 0.70 or prob <= 0.30 else EvidenceState.SUPPORTING,
            score=prob,
            confidence=conf,
            weight=1.0,
            supports_risk=bool(prob >= 0.50),
            description=(
                f"{model_name} computed a {prob * 100:.1f}% probability of synthetic/manipulated origin "
                f"(confidence: {conf * 100:.1f}%)."
            ),
            metadata={"model_name": model_name, "features": features},
        )

    def build_provenance_evidence(
        self,
        status: str,
        issuer: Optional[str] = None,
        verified: bool = False,
        claims_count: int = 0,
    ) -> Evidence:
        if status in ("PROVENANCE_CONFIRMED", "PROVENANCE_PRESENT") and verified:
            severity = EvidenceSeverity.INFO
            state = EvidenceState.CONFIRMED
            desc = f"Verified Content Credentials (C2PA) present from trusted issuer: {issuer or 'Standard Authority'}."
            supports_risk = False  # Decreases risk of malicious spoofing unless synthetic tag
            score = 0.1
        elif status == "PROVENANCE_ABSENT":
            severity = EvidenceSeverity.INFO
            state = EvidenceState.UNKNOWN
            desc = "No cryptographic provenance or Content Credentials (C2PA) were detected in the bitstream."
            supports_risk = False
            score = 0.5
        else:
            severity = EvidenceSeverity.MEDIUM
            state = EvidenceState.SUPPORTING
            desc = f"Provenance signature is unverified or invalid ({status})."
            supports_risk = True
            score = 0.6

        return Evidence(
            media_id=self.media_id,
            source=EvidenceSource.PROVENANCE,
            evidence_type=EvidenceType.C2PA_VERIFIED if verified else EvidenceType.PROVENANCE_ABSENT,
            category="Provenance & Authenticity",
            severity=severity,
            state=state,
            score=score,
            confidence=0.95 if verified else 0.80,
            weight=0.8,
            supports_risk=supports_risk,
            description=desc,
            metadata={"issuer": issuer, "claims_count": claims_count, "status": status},
        )

    def build_forensic_evidence(
        self,
        signal_type: str,
        severity: str,
        confidence: float,
        description: str,
        value: Any = None,
    ) -> Evidence:
        sev_map = {
            "CRITICAL": EvidenceSeverity.CRITICAL,
            "HIGH": EvidenceSeverity.HIGH,
            "MEDIUM": EvidenceSeverity.MEDIUM,
            "LOW": EvidenceSeverity.LOW,
            "INFO": EvidenceSeverity.INFO,
        }
        return Evidence(
            media_id=self.media_id,
            source=EvidenceSource.FORENSICS,
            evidence_type=EvidenceType.COMPRESSION_ANOMALY if "error" in signal_type else EvidenceType.NOISE_INCONSISTENCY,
            category="Physical & Digital Forensics",
            severity=sev_map.get(severity, EvidenceSeverity.LOW),
            state=EvidenceState.SUPPORTING,
            score=0.7 if severity in ("HIGH", "CRITICAL") else 0.3,
            confidence=confidence,
            weight=0.6,
            supports_risk=bool(severity in ("MEDIUM", "HIGH", "CRITICAL")),
            description=description,
            metadata={"signal_type": signal_type, "value": value},
        )
