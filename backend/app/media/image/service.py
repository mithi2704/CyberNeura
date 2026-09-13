"""
Image Analysis Orchestration Service for CyberNeura.
Coordinates validation, preprocessing, neural model inference, C2PA provenance,
physical forensics, evidence normalization, risk scoring, and real-time broadcasting.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional
from app.media.models import MediaType, MediaClassification, MediaAssessment
from app.media.validators import validate_image_file
from app.media.storage.service import media_storage_service
from app.media.image.preprocessing import preprocess_image_for_model
from app.media.image.provenance import analyze_provenance
from app.media.image.forensics import analyze_image_forensics
from app.media.evidence.builder import MediaEvidenceBuilder
from app.media.risk.engine import media_risk_engine
from app.media.model_registry import model_registry
from app.services.scan_store import scan_store
from app.realtime.publisher import event_publisher
from app.realtime.models import RealtimeEventType, EntityType

logger = logging.getLogger(__name__)


class ImageAnalysisService:
    async def analyze_image(
        self,
        file_bytes: bytes,
        filename: str,
        user_id: Optional[str] = None,
        options: Optional[Dict[str, Any]] = None,
    ) -> MediaAssessment:
        options = options or {}
        include_provenance = options.get("include_provenance", True)
        include_forensics = options.get("include_forensics", True)

        # 1. Image Security & Sanity Validation
        detected_format, detected_mime, width, height = validate_image_file(file_bytes, filename)
        sha256 = media_storage_service.calculate_sha256(file_bytes)

        # 2. Check Deduplication Cache
        existing_asset = scan_store.get_media_asset_by_hash(sha256)
        if existing_asset:
            cached_assessment = scan_store.get_media_assessment(existing_asset["id"])
            if cached_assessment:
                logger.info(f"Deduplication cache hit for image SHA256: {sha256[:12]}")
                return MediaAssessment(**cached_assessment)

        # 3. Store Asset
        asset = media_storage_service.store_file(
            file_bytes=file_bytes,
            original_filename=filename,
            media_type=MediaType.IMAGE,
            mime_type=detected_mime,
            user_id=user_id,
            width=width,
            height=height,
        )
        scan_store.save_media_asset(asset.model_dump())

        # 4. Broadcast Realtime: MEDIA_ANALYSIS_STARTED
        await event_publisher.publish(
            event_type=RealtimeEventType.MEDIA_ANALYSIS_STARTED,
            entity_type=EntityType.MEDIA_ASSET,
            entity_id=asset.id,
            user_id=user_id,
            payload={
                "media_id": asset.id,
                "media_type": "IMAGE",
                "filename": filename,
                "file_size": len(file_bytes),
            },
        )

        # 5. Preprocessing
        tensor, np_img, metadata = preprocess_image_for_model(file_bytes)
        metadata["media_id"] = asset.id

        # 6. Active Image Model Inference
        active_model = model_registry.get_active_model("image_ai_detection")
        if not active_model:
            from app.media.image.inference import default_image_model
            active_model = default_image_model

        model_output = active_model.predict((tensor, np_img))

        # 7. Provenance Analysis (C2PA / Content Credentials)
        provenance_record = None
        if include_provenance:
            try:
                provenance_record = analyze_provenance(file_bytes, metadata)
                if provenance_record.verified:
                    await event_publisher.publish(
                        event_type=RealtimeEventType.MEDIA_PROVENANCE_FOUND,
                        entity_type=EntityType.MEDIA_ASSET,
                        entity_id=asset.id,
                        user_id=user_id,
                        payload={
                            "media_id": asset.id,
                            "issuer": provenance_record.issuer,
                            "status": provenance_record.status.value,
                        },
                    )
            except Exception as prov_err:
                logger.warning(f"Provenance parsing error: {prov_err}")

        # 8. Digital & Physical Forensics (ELA & Noise Consistency)
        forensic_results = []
        if include_forensics:
            try:
                forensic_results = analyze_image_forensics(file_bytes, np_img, asset.id)
            except Exception as fore_err:
                logger.warning(f"Forensic analysis error: {fore_err}")

        # 9. Evidence Subsystem Normalization (Phase 3 Integration)
        builder = MediaEvidenceBuilder(media_id=asset.id)
        evidence_list = []

        # Model evidence
        evidence_list.append(
            builder.build_model_evidence(
                probability=model_output["probability_ai_generated"],
                confidence=model_output["confidence"],
                model_name=model_output["model"]["name"],
                features=model_output.get("features", {}),
                is_video=False,
            )
        )

        # Provenance evidence
        if provenance_record:
            evidence_list.append(
                builder.build_provenance_evidence(
                    status=provenance_record.status.value,
                    issuer=provenance_record.issuer,
                    verified=provenance_record.verified,
                    claims_count=len(provenance_record.claims),
                )
            )

        # Forensic evidence
        for f in forensic_results:
            evidence_list.append(
                builder.build_forensic_evidence(
                    signal_type=f.signal_type,
                    severity=f.severity,
                    confidence=f.confidence,
                    description=f.description,
                    value=f.value,
                )
            )

        # 10. Risk Engine Assessment
        provenance_dict = provenance_record.model_dump() if provenance_record else None
        forensics_dicts = [f.model_dump() for f in forensic_results]

        assessment = media_risk_engine.assess_image(
            media_id=asset.id,
            user_id=user_id,
            model_output=model_output,
            provenance=provenance_dict,
            forensics=forensics_dicts,
            evidence_list=evidence_list,
            metadata=metadata,
        )

        # 11. Persistence to ScanStore & Disk
        scan_store.save_media_assessment(
            assessment=assessment.model_dump(),
            evidence=[e.model_dump() for e in evidence_list],
            provenance=provenance_dict,
            forensics=forensics_dicts,
        )

        # 12. Realtime Event Emission: MEDIA_ANALYSIS_COMPLETED
        await event_publisher.publish(
            event_type=RealtimeEventType.MEDIA_ANALYSIS_COMPLETED,
            entity_type=EntityType.MEDIA_ASSESSMENT,
            entity_id=assessment.id,
            user_id=user_id,
            payload={
                "media_id": asset.id,
                "classification": assessment.classification.value,
                "risk_score": assessment.risk_score,
                "confidence": assessment.confidence,
                "severity": assessment.severity,
                "summary": assessment.summary,
            },
        )

        # If threat detected (AI generated / high risk), emit threat event
        if assessment.risk_score >= 70 or assessment.classification == MediaClassification.LIKELY_AI_GENERATED:
            await event_publisher.publish(
                event_type=RealtimeEventType.MEDIA_THREAT_DETECTED,
                entity_type=EntityType.MEDIA_ASSESSMENT,
                entity_id=assessment.id,
                user_id=user_id,
                payload={
                    "media_id": asset.id,
                    "classification": assessment.classification.value,
                    "risk_score": assessment.risk_score,
                    "summary": assessment.summary,
                },
            )

        return assessment


image_service = ImageAnalysisService()
