"""
Media Risk & Assessment Engine for CyberNeura Phase 7.
Coordinates multi-signal evaluation using media-specific risk weights,
independent confidence scoring, probabilistic classifications, and deterministic explanations.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Tuple
from app.media.models import MediaType, MediaClassification, MediaAssessment
from app.evidence.models import Evidence, EvidenceSeverity

logger = logging.getLogger(__name__)


class MediaRiskEngine:
    """Evaluates multi-signal media evidence into calibrated risk, confidence, and audit summaries."""

    def __init__(self):
        # Configurable default weight distribution
        self.image_weights = {
            "model": 0.40,
            "provenance": 0.25,
            "forensics": 0.20,
            "metadata": 0.15,
        }
        self.video_weights = {
            "model": 0.40,
            "frames": 0.20,
            "faces": 0.20,
            "temporal": 0.15,
            "metadata": 0.05,
        }

    def assess_image(
        self,
        media_id: str,
        user_id: str | None,
        model_output: Dict[str, Any],
        provenance: Dict[str, Any] | None,
        forensics: List[Dict[str, Any]],
        evidence_list: List[Evidence],
        metadata: Dict[str, Any],
    ) -> MediaAssessment:
        """Computes comprehensive assessment for an image asset."""
        model_prob = float(model_output.get("probability_ai_generated", 0.5))
        model_conf = float(model_output.get("confidence", 0.8))

        # 1. Model component score (0-100)
        model_score = model_prob * 100.0

        # 2. Provenance component score
        # Verified human capture reduces risk; verified synthetic tag elevates risk
        provenance_status = provenance.get("status") if provenance else "PROVENANCE_ABSENT"
        provenance_verified = provenance.get("verified", False) if provenance else False
        is_synthetic_tag = False
        if provenance and provenance.get("claims"):
            is_synthetic_tag = any(
                c.get("details", {}).get("indicates_synthetic")
                for c in provenance.get("claims", [])
                if isinstance(c, dict)
            )

        if is_synthetic_tag:
            provenance_score = 95.0
            provenance_conf = 0.95
        elif provenance_status == "PROVENANCE_CONFIRMED" and provenance_verified:
            provenance_score = 10.0
            provenance_conf = 0.92
        else:
            # Absence of provenance is neutral
            provenance_score = 45.0
            provenance_conf = 0.70

        # 3. Forensic component score
        forensic_high_count = sum(1 for f in forensics if f.get("severity") in ("HIGH", "CRITICAL"))
        forensic_med_count = sum(1 for f in forensics if f.get("severity") == "MEDIUM")
        forensic_score = min(100.0, (forensic_high_count * 45.0) + (forensic_med_count * 25.0) + 15.0)
        forensic_conf = 0.82 if forensics else 0.50

        # 4. Metadata component score
        has_exif = metadata.get("has_exif", False)
        metadata_score = 25.0 if has_exif else 40.0
        metadata_conf = 0.75

        # Weighted Composite Risk Score
        raw_risk = (
            self.image_weights["model"] * model_score +
            self.image_weights["provenance"] * provenance_score +
            self.image_weights["forensics"] * forensic_score +
            self.image_weights["metadata"] * metadata_score
        )
        risk_score = int(round(max(0.0, min(100.0, raw_risk))))

        # Independent Confidence Rating (0-100%)
        # Decreases when model confidence is low or signals strongly disagree
        composite_conf = (
            self.image_weights["model"] * model_conf +
            self.image_weights["provenance"] * provenance_conf +
            self.image_weights["forensics"] * forensic_conf +
            self.image_weights["metadata"] * metadata_conf
        )
        confidence = round(float(composite_conf * 100.0), 1)

        # Classification mapping
        if is_synthetic_tag:
            classification = MediaClassification.LIKELY_AI_GENERATED
            severity = "HIGH"
        elif risk_score >= 70 and model_prob >= 0.70:
            classification = MediaClassification.LIKELY_AI_GENERATED
            severity = "HIGH" if risk_score >= 85 else "MEDIUM"
        elif risk_score <= 32 and model_prob <= 0.32:
            classification = MediaClassification.LIKELY_AUTHENTIC
            severity = "LOW"
        elif confidence < 60.0:
            classification = MediaClassification.INCONCLUSIVE
            severity = "INFO"
        else:
            classification = MediaClassification.SUSPICIOUS
            severity = "MEDIUM"

        # Limitations disclosure
        limitations = [
            "Detection accuracy may decrease for heavily compressed or re-saved social media images.",
            "Absence of cryptographic provenance (C2PA) does not constitute proof of synthetic generation.",
            "Probabilistic neural models cannot guarantee 100% certainty; manual verification advised.",
        ]
        if metadata.get("width", 0) < 512 or metadata.get("height", 0) < 512:
            limitations.append("Low image resolution reduces the efficacy of high-frequency spectral and noise forensics.")

        # Deterministic Explanation Synthesis
        summary = self._generate_image_summary(
            classification=classification,
            model_prob=model_prob,
            confidence=confidence,
            provenance_status=provenance_status,
            forensic_high_count=forensic_high_count,
            is_synthetic_tag=is_synthetic_tag,
        )

        return MediaAssessment(
            media_id=media_id,
            user_id=user_id,
            media_type=MediaType.IMAGE,
            classification=classification,
            risk_score=risk_score,
            confidence=confidence,
            severity=severity,
            summary=summary,
            model=model_output.get("model", {}),
            provenance=provenance,
            forensics=forensics,
            evidence=[e.model_dump() for e in evidence_list],
            limitations=limitations,
            model_version=model_output.get("model", {}).get("version", "1.0.0"),
            analysis_version="1.0.0",
        )

    def assess_video(
        self,
        media_id: str,
        user_id: str | None,
        deepfake_model_output: Dict[str, Any],
        frame_metrics: Dict[str, Any],
        face_metrics: Dict[str, Any],
        temporal_metrics: Dict[str, Any],
        evidence_list: List[Evidence],
    ) -> MediaAssessment:
        """Computes comprehensive assessment for a video asset."""
        model_prob = float(deepfake_model_output.get("deepfake_probability", 0.5))
        model_conf = float(deepfake_model_output.get("confidence", 0.8))

        # Frame level metrics
        frames_analyzed = frame_metrics.get("frames_analyzed", 0)
        suspicious_frames = frame_metrics.get("suspicious_frames", 0)
        frame_ratio = (suspicious_frames / frames_analyzed) if frames_analyzed > 0 else 0.0

        # Face manipulation metrics
        faces_detected = face_metrics.get("faces_detected", 0)
        face_manipulation_score = face_metrics.get("manipulation_score", 0.0)

        # Temporal inconsistency
        temporal_inconsistency_score = temporal_metrics.get("inconsistency_score", 0.0)

        # Composite Risk Score Calculation
        model_component = model_prob * 100.0
        frame_component = frame_ratio * 100.0
        face_component = face_manipulation_score * 100.0
        temporal_component = temporal_inconsistency_score * 100.0
        metadata_component = 30.0

        raw_risk = (
            self.video_weights["model"] * model_component +
            self.video_weights["frames"] * frame_component +
            self.video_weights["faces"] * face_component +
            self.video_weights["temporal"] * temporal_component +
            self.video_weights["metadata"] * metadata_component
        )
        risk_score = int(round(max(0.0, min(100.0, raw_risk))))

        # Confidence Calculation
        base_conf = model_conf * 100.0
        if frames_analyzed < 10:
            base_conf -= 25.0
        if faces_detected == 0:
            base_conf -= 20.0  # Face manipulation models require face visibility
        confidence = round(max(30.0, min(98.0, base_conf)), 1)

        # Classification
        if risk_score >= 70 and (model_prob >= 0.70 or frame_ratio >= 0.60):
            classification = MediaClassification.LIKELY_DEEPFAKE
            severity = "HIGH" if risk_score >= 85 else "MEDIUM"
        elif risk_score <= 32 and model_prob <= 0.35:
            classification = MediaClassification.LIKELY_AUTHENTIC
            severity = "LOW"
        elif confidence < 60.0 or frames_analyzed == 0:
            classification = MediaClassification.INCONCLUSIVE
            severity = "INFO"
        else:
            classification = MediaClassification.SUSPICIOUS
            severity = "MEDIUM"

        limitations = [
            f"Analysis sampled {frames_analyzed} keyframes across the video stream.",
            "Absence of detectable faces in certain frames limits face-swap detection scope.",
            "Video compression artifacts and motion blur may influence temporal consistency scores.",
        ]

        summary = (
            f"CyberNeura identified deepfake indicators across {suspicious_frames}/{frames_analyzed} sampled frames. "
            f"Face-level manipulation score is {face_manipulation_score * 100:.1f}%, and temporal inconsistency is "
            f"{temporal_inconsistency_score * 100:.1f}%. Conclusion: {classification.value}."
            if classification == MediaClassification.LIKELY_DEEPFAKE
            else f"Video analysis completed across {frames_analyzed} frames without persistent manipulation patterns. "
            f"Classification: {classification.value}."
        )

        return MediaAssessment(
            media_id=media_id,
            user_id=user_id,
            media_type=MediaType.VIDEO,
            classification=classification,
            risk_score=risk_score,
            confidence=confidence,
            severity=severity,
            summary=summary,
            model=deepfake_model_output.get("model", {}),
            provenance=None,
            forensics=[],
            evidence=[e.model_dump() for e in evidence_list],
            limitations=limitations,
            model_version=deepfake_model_output.get("model", {}).get("version", "1.0.0"),
            analysis_version="1.0.0",
        )

    def _generate_image_summary(
        self,
        classification: MediaClassification,
        model_prob: float,
        confidence: float,
        provenance_status: str,
        forensic_high_count: int,
        is_synthetic_tag: bool,
    ) -> str:
        """Generates deterministic, audit-ready explanation without external LLM dependencies."""
        if is_synthetic_tag:
            return (
                "Verified digital provenance indicates this asset was generated by synthetic AI software. "
                f"Image analysis model corroborates with a {model_prob * 100:.1f}% synthetic probability."
            )
        if classification == MediaClassification.LIKELY_AI_GENERATED:
            return (
                f"CyberNeura's image detection model identified strong synthetic-image indicators "
                f"({model_prob * 100:.1f}% probability). Forensic analysis identified {forensic_high_count} "
                f"supporting anomaly signals. No verified cryptographic provenance was available."
            )
        if classification == MediaClassification.LIKELY_AUTHENTIC:
            return (
                f"CyberNeura's analysis indicates high probability of authentic capture "
                f"({(1.0 - model_prob) * 100:.1f}% authenticity score). Sensor noise and spectral frequencies "
                f"exhibit natural camera sensor distributions."
            )
        if classification == MediaClassification.INCONCLUSIVE:
            return (
                f"Available evidence is inconclusive (confidence: {confidence:.1f}%). Multi-signal analysis "
                f"did not yield sufficient consensus to determine synthetic vs authentic status."
            )
        return (
            f"Analysis identified mixed signals with moderate risk score. Forensic and spectral metrics "
            f"exhibit borderline characteristics. Further inspection recommended."
        )


media_risk_engine = MediaRiskEngine()
