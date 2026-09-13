"""
FastAPI Route Handlers for CyberNeura Phase 7 AI Media Security.
Supports multipart image and video uploads, asynchronous jobs, evidence queries,
provenance inspections, frame timelines, and telemetry statistics.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile, status
from app.dependencies import OptionalAuthUser
from app.media.models import MediaType, MediaClassification
from app.media.schemas import (
    ImageAnalyzeResponse,
    VideoAnalyzeSubmitResponse,
    MediaJobStatusResponse,
    MediaAssetResponse,
    MediaStatsResponse,
)
from app.media.image.service import image_service
from app.media.video.frame_sampler import extract_video_metadata
from app.media.validators import validate_video_file
from app.media.storage.service import media_storage_service
from app.media.jobs.queue import job_queue
from app.media.jobs.worker import dispatch_video_job
from app.services.scan_store import scan_store

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/media", tags=["AI Media Security"])


@router.post("/images/analyze", response_model=ImageAnalyzeResponse)
async def analyze_image_endpoint(
    file: UploadFile = File(...),
    options: Optional[str] = Form(None),  # JSON-encoded ImageAnalyzeOptions
    current_user: OptionalAuthUser = None,
):
    """
    Analyzes an uploaded image for synthetic AI generation, C2PA provenance, and forensic anomalies.
    """
    file_bytes = await file.read()
    filename = file.filename or "uploaded_image.jpg"

    opts_dict: Dict[str, Any] = {}
    if options:
        try:
            opts_dict = json.loads(options)
        except Exception:
            pass

    user_id = current_user.uid if current_user else None

    try:
        assessment = await image_service.analyze_image(
            file_bytes=file_bytes,
            filename=filename,
            user_id=user_id,
            options=opts_dict,
        )

        asset = scan_store.get_media_asset(assessment.media_id) or {}

        prob = float(assessment.model.get("probability_ai_generated", assessment.risk_score / 100.0))
        return ImageAnalyzeResponse(
            media_id=assessment.media_id,
            media_type=MediaType.IMAGE,
            filename=filename,
            sha256=asset.get("sha256", ""),
            classification=assessment.classification,
            probability_ai_generated=prob,
            model_score=prob,
            confidence=assessment.confidence,
            risk_score=assessment.risk_score,
            severity=assessment.severity,
            summary=assessment.summary,
            explanation=assessment.summary,
            independent_confirmations=len(assessment.evidence),
            model=assessment.model,
            provenance=assessment.provenance,
            forensics=assessment.forensics,
            evidence=assessment.evidence,
            limitations=assessment.limitations,
            created_at=assessment.created_at,
        )
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(val_err))
    except Exception as exc:
        logger.error(f"Image analysis error: {exc}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Analysis failed: {exc}")


@router.post("/videos/analyze", response_model=VideoAnalyzeSubmitResponse)
async def analyze_video_endpoint(
    file: UploadFile = File(...),
    options: Optional[str] = Form(None),
    current_user: OptionalAuthUser = None,
):
    """
    Submits a video for asynchronous deepfake and frame-level manipulation analysis.
    Returns a job_id for status polling.
    """
    file_bytes = await file.read()
    filename = file.filename or "uploaded_video.mp4"

    opts_dict: Dict[str, Any] = {}
    if options:
        try:
            opts_dict = json.loads(options)
        except Exception:
            pass

    user_id = current_user.uid if current_user else None

    try:
        # Validate video format
        detected_format, detected_mime = validate_video_file(file_bytes, filename)

        # Store video asset to private storage
        asset = media_storage_service.store_file(
            file_bytes=file_bytes,
            original_filename=filename,
            media_type=MediaType.VIDEO,
            mime_type=detected_mime,
            user_id=user_id,
        )
        scan_store.save_media_asset(asset.model_dump())

        # Extract metadata (duration, width, height)
        try:
            meta = extract_video_metadata(asset.storage_path)
            asset.duration = meta.get("duration")
            asset.width = meta.get("width")
            asset.height = meta.get("height")
            asset.frame_count = meta.get("total_frames")
            scan_store.save_media_asset(asset.model_dump())
        except Exception as meta_err:
            logger.warning(f"Video metadata read warning: {meta_err}")

        # Dispatch async job
        sampling_rate = int(opts_dict.get("frame_sampling_rate", 2))
        max_frames = int(opts_dict.get("max_frames", 300))

        job_id = await dispatch_video_job(
            media_id=asset.id,
            video_path=asset.storage_path,
            user_id=user_id,
            sampling_rate_fps=sampling_rate,
            max_frames=max_frames,
        )

        return VideoAnalyzeSubmitResponse(
            job_id=job_id,
            media_id=asset.id,
            media_type=MediaType.VIDEO,
            message="Video analysis job queued successfully.",
        )
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(val_err))
    except Exception as exc:
        logger.error(f"Video job submission error: {exc}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Video submission failed: {exc}")


@router.get("/jobs/{job_id}", response_model=MediaJobStatusResponse)
async def get_job_status_endpoint(job_id: str):
    """Queries asynchronous media processing job progress, stage, and result."""
    job_data = scan_store.get_media_job(job_id)
    if not job_data:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Media job not found.")

    assessment_data = None
    if job_data.get("media_id"):
        assessment_data = scan_store.get_media_assessment(job_data["media_id"])

    return MediaJobStatusResponse(
        job_id=job_id,
        media_id=job_data.get("media_id"),
        media_type=job_data.get("media_type", MediaType.VIDEO),
        status=job_data.get("status"),
        progress=job_data.get("progress", 0),
        current_stage=job_data.get("current_stage", "INITIALIZING"),
        error_message=job_data.get("error_message"),
        started_at=job_data.get("started_at"),
        completed_at=job_data.get("completed_at"),
        created_at=job_data.get("created_at"),
        assessment=assessment_data,
    )


@router.post("/jobs/{job_id}/cancel")
async def cancel_job_endpoint(job_id: str):
    """Cancels an active or queued media job."""
    success = await job_queue.cancel_job(job_id)
    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job not found or already completed.")
    return {"message": "Job cancellation requested.", "job_id": job_id}


@router.get("/stats", response_model=MediaStatsResponse)
async def get_media_stats_endpoint():
    """Returns platform-wide media security detection statistics."""
    stats = scan_store.get_media_stats()
    return MediaStatsResponse(**stats)


@router.get("/assessments")
async def list_media_assessments_endpoint(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    media_type: Optional[str] = Query(None),
    classification: Optional[str] = Query(None),
):
    """Lists historical media assessments with pagination."""
    return scan_store.list_media_assessments(
        page=page,
        page_size=page_size,
        media_type=media_type,
        classification=classification,
    )


@router.get("/{media_id}")
async def get_media_asset_endpoint(media_id: str):
    """Fetches media asset metadata."""
    asset = scan_store.get_media_asset(media_id)
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Media asset not found.")
    # Strip internal storage path for privacy/security
    clean = dict(asset)
    clean.pop("storage_path", None)
    return clean


@router.get("/{media_id}/assessment")
async def get_media_assessment_endpoint(media_id: str):
    """Fetches comprehensive assessment report for a media asset."""
    assessment = scan_store.get_media_assessment(media_id)
    if not assessment:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assessment not found for media.")
    data = dict(assessment)
    data["explanation"] = data.get("summary", "")
    model_data = data.get("model", {})
    prob = float(model_data.get("probability_ai_generated", data.get("risk_score", 50) / 100.0))
    data["model_score"] = prob
    data["probability_ai_generated"] = prob
    data["independent_confirmations"] = len(data.get("evidence", []))
    return data


@router.get("/{media_id}/evidence")
async def get_media_evidence_endpoint(media_id: str):
    """Fetches normalized evidence catalog items for a media asset."""
    evidence = scan_store.get_media_evidence(media_id)
    return {"media_id": media_id, "evidence": evidence, "total": len(evidence), "items": evidence}


@router.get("/{media_id}/provenance")
async def get_media_provenance_endpoint(media_id: str):
    """Fetches C2PA / Content Credentials provenance record."""
    provenance = scan_store.get_media_provenance(media_id)
    if not provenance:
        return {
            "media_id": media_id,
            "provenance_status": "provenance_absent",
            "has_c2pa_manifest": False,
            "claim_valid": False,
            "issuer_name": "None identified",
            "has_synthetic_watermark": False,
            "status": "PROVENANCE_ABSENT",
            "verified": False,
            "claims": [],
            "message": "No verified provenance information was available.",
        }
    data = dict(provenance)
    claims = data.get("claims", [])
    has_watermark = any(c.get("details", {}).get("indicates_synthetic") for c in claims if isinstance(c, dict))
    data["provenance_status"] = data.get("status", "provenance_absent")
    data["has_c2pa_manifest"] = data.get("verified", False) or len(claims) > 0
    data["claim_valid"] = data.get("verified", False)
    data["issuer_name"] = data.get("issuer") or "None identified"
    data["has_synthetic_watermark"] = has_watermark
    return data


@router.get("/{media_id}/forensics")
async def get_media_forensics_endpoint(media_id: str):
    """Fetches digital and physical forensic results (ELA, noise)."""
    forensics = scan_store.get_media_forensics(media_id)
    ela_val = 0.0
    noise_val = 0.0
    color_val = 0.0
    comp_inconsist = False

    for f in forensics:
        st = f.get("signal_type")
        val = f.get("value")
        if st == "error_level_analysis":
            ela_val = float(val) if isinstance(val, (int, float)) else float(f.get("confidence", 0.0))
            if f.get("severity") in ("MEDIUM", "HIGH", "CRITICAL"):
                comp_inconsist = True
        elif st in ("noise_variance", "spatial_noise"):
            noise_val = float(val) if isinstance(val, (int, float)) else float(f.get("confidence", 0.0))
        elif st in ("color_covariance", "color_divergence"):
            color_val = float(val) if isinstance(val, (int, float)) else float(f.get("confidence", 0.0))

    return {
        "media_id": media_id,
        "forensics": forensics,
        "ela_anomaly_score": round(ela_val, 4),
        "noise_variance_anomaly": round(noise_val, 4),
        "compression_inconsistency": comp_inconsist,
        "color_space_anomaly": round(color_val, 4),
    }


@router.get("/{media_id}/frames")
async def get_media_frames_endpoint(media_id: str):
    """Fetches sampled video frame results and face manipulation indicators."""
    frames = scan_store.get_media_frames(media_id)
    return {"media_id": media_id, "frames": frames, "total_frames": len(frames)}


@router.delete("/{media_id}")
async def delete_media_endpoint(media_id: str):
    """Permanently deletes a media asset and all associated analysis records."""
    asset = scan_store.get_media_asset(media_id)
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Media not found.")

    from app.media.models import MediaAsset
    media_storage_service.delete_file(MediaAsset(**asset))
    scan_store.delete_media_asset(media_id)
    return {"message": "Media asset deleted successfully.", "media_id": media_id}
