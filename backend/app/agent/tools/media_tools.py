"""
CyberNeura Phase 7 Media Agent Tools.
Provides 6 defensive media analysis tools for the AI Security Agent:
1. analyze_image
2. analyze_video
3. get_media_evidence
4. get_media_provenance
5. get_media_forensics
6. get_frame_analysis
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from app.agent.tools.base import AgentTool
from app.agent.tool_result import ToolResult, ToolStatus
from app.services.scan_store import scan_store


class MediaIdInput(BaseModel):
    media_id: str = Field(..., description="Unique ID of the media asset to inspect")


class ImageAnalyzeInput(BaseModel):
    media_id: Optional[str] = Field(None, description="Existing media ID of the image, if already uploaded")
    image_url: Optional[str] = Field(None, description="Optional public URL of the image to fetch and analyze")


class VideoAnalyzeInput(BaseModel):
    media_id: Optional[str] = Field(None, description="Existing media ID of the video, if already uploaded")
    video_url: Optional[str] = Field(None, description="Optional public URL of the video to fetch and analyze")


class AnalyzeImageTool(AgentTool):
    tool_name = "analyze_image"
    description = (
        "Inspect an image for AI generation or synthetic manipulation using spectral FFT, "
        "spatial edge variance, and neural artifacts. Returns classification, risk score, and confidence."
    )
    input_schema = ImageAnalyzeInput

    async def execute(self, arguments: Dict[str, Any]) -> ToolResult:
        media_id = arguments.get("media_id")
        image_url = arguments.get("image_url")

        if not media_id and not image_url:
            return ToolResult(
                tool_name=self.tool_name,
                status=ToolStatus.ERROR,
                summary="Either media_id or image_url must be provided for image analysis.",
                error="MISSING_INPUT",
            )

        if media_id:
            assessment = scan_store.get_media_assessment(media_id)
            if assessment:
                return ToolResult(
                    tool_name=self.tool_name,
                    status=ToolStatus.SUCCESS,
                    summary=f"Image assessment found for {media_id}: {assessment.classification.value} (Risk {assessment.risk_score:.1f}, Confidence {assessment.confidence:.2f})",
                    data={
                        "media_id": media_id,
                        "classification": assessment.classification.value,
                        "risk_score": assessment.risk_score,
                        "confidence": assessment.confidence,
                        "model_score": assessment.model_score,
                        "explanation": assessment.explanation,
                        "evidence_count": len(assessment.evidence_ids),
                    },
                )

        if image_url:
            # Attempt to download and analyze via ImageAnalysisService
            try:
                import httpx
                from app.media.image.service import image_analysis_service
                async with httpx.AsyncClient(timeout=15.0) as client:
                    resp = await client.get(image_url)
                    resp.raise_for_status()
                    content = resp.content

                filename = image_url.split("/")[-1].split("?")[0] or "image.jpg"
                assessment = await image_analysis_service.analyze_image_bytes(
                    content=content,
                    filename=filename,
                )
                return ToolResult(
                    tool_name=self.tool_name,
                    status=ToolStatus.SUCCESS,
                    summary=f"Image analyzed from URL: {assessment.classification.value} (Risk {assessment.risk_score:.1f}, Confidence {assessment.confidence:.2f})",
                    data={
                        "media_id": assessment.media_id,
                        "classification": assessment.classification.value,
                        "risk_score": assessment.risk_score,
                        "confidence": assessment.confidence,
                        "model_score": assessment.model_score,
                        "explanation": assessment.explanation,
                    },
                )
            except Exception as e:
                return ToolResult(
                    tool_name=self.tool_name,
                    status=ToolStatus.ERROR,
                    summary=f"Failed to fetch and analyze image from URL: {e}",
                    error=str(e),
                )

        return ToolResult(
            tool_name=self.tool_name,
            status=ToolStatus.NO_DATA,
            summary=f"No image assessment found for media_id '{media_id}'.",
        )


class AnalyzeVideoTool(AgentTool):
    tool_name = "analyze_video"
    description = (
        "Inspect a video for deepfake manipulation, facial boundary blending artifacts, "
        "and temporal inconsistencies. Submits or checks an async video processing job."
    )
    input_schema = VideoAnalyzeInput

    async def execute(self, arguments: Dict[str, Any]) -> ToolResult:
        media_id = arguments.get("media_id")
        video_url = arguments.get("video_url")

        if not media_id and not video_url:
            return ToolResult(
                tool_name=self.tool_name,
                status=ToolStatus.ERROR,
                summary="Either media_id or video_url must be provided for video analysis.",
                error="MISSING_INPUT",
            )

        if media_id:
            assessment = scan_store.get_media_assessment(media_id)
            if assessment:
                return ToolResult(
                    tool_name=self.tool_name,
                    status=ToolStatus.SUCCESS,
                    summary=f"Video assessment found for {media_id}: {assessment.classification.value} (Risk {assessment.risk_score:.1f}, Confidence {assessment.confidence:.2f})",
                    data={
                        "media_id": media_id,
                        "classification": assessment.classification.value,
                        "risk_score": assessment.risk_score,
                        "confidence": assessment.confidence,
                        "model_score": assessment.model_score,
                        "explanation": assessment.explanation,
                    },
                )

            # Check if there is an ongoing job
            from app.media.jobs.queue import media_job_queue
            jobs = media_job_queue.get_all_jobs()
            matching = [j for j in jobs if j.media_id == media_id]
            if matching:
                latest = matching[-1]
                return ToolResult(
                    tool_name=self.tool_name,
                    status=ToolStatus.SUCCESS,
                    summary=f"Video analysis job in progress for {media_id}: status={latest.status.value}, progress={latest.progress_percent:.0f}%",
                    data=latest.dict(),
                )

        return ToolResult(
            tool_name=self.tool_name,
            status=ToolStatus.NO_DATA,
            summary=f"No video assessment or active job found for media_id '{media_id}'.",
        )


class MediaEvidenceTool(AgentTool):
    tool_name = "get_media_evidence"
    description = (
        "Retrieve Phase 3 normalized evidence items generated specifically for a media asset, "
        "including confidence scores, observation states, severity, and forensic findings."
    )
    input_schema = MediaIdInput

    async def execute(self, arguments: Dict[str, Any]) -> ToolResult:
        media_id = arguments.get("media_id")
        if not media_id:
            return ToolResult(
                tool_name=self.tool_name,
                status=ToolStatus.ERROR,
                summary="media_id is required to fetch media evidence.",
                error="MISSING_MEDIA_ID",
            )

        evidence_items = scan_store.get_media_evidence(media_id)
        if not evidence_items:
            return ToolResult(
                tool_name=self.tool_name,
                status=ToolStatus.NO_DATA,
                summary=f"No evidence records found for media ID '{media_id}'.",
            )

        return ToolResult(
            tool_name=self.tool_name,
            status=ToolStatus.SUCCESS,
            summary=f"Found {len(evidence_items)} normalized evidence items for media {media_id}.",
            data={
                "media_id": media_id,
                "evidence_count": len(evidence_items),
                "items": [item.dict() for item in evidence_items],
            },
        )


class MediaProvenanceTool(AgentTool):
    tool_name = "get_media_provenance"
    description = (
        "Retrieve C2PA / Content Credentials provenance claims, signing certificates, "
        "and edit action history for a media asset. Note: Absence of C2PA manifest does NOT imply fake."
    )
    input_schema = MediaIdInput

    async def execute(self, arguments: Dict[str, Any]) -> ToolResult:
        media_id = arguments.get("media_id")
        if not media_id:
            return ToolResult(
                tool_name=self.tool_name,
                status=ToolStatus.ERROR,
                summary="media_id is required to fetch media provenance.",
                error="MISSING_MEDIA_ID",
            )

        prov = scan_store.get_media_provenance(media_id)
        if not prov:
            return ToolResult(
                tool_name=self.tool_name,
                status=ToolStatus.NO_DATA,
                summary=f"No provenance record recorded for media ID '{media_id}'.",
            )

        return ToolResult(
            tool_name=self.tool_name,
            status=ToolStatus.SUCCESS,
            summary=f"Provenance status for {media_id}: {prov.status.value} (Verified: {prov.verified})",
            data=prov.dict(),
        )


class MediaForensicsTool(AgentTool):
    tool_name = "get_media_forensics"
    description = (
        "Retrieve forensic analysis results including Error Level Analysis (ELA) compression anomalies, "
        "quadrant noise variance, and codec inconsistencies."
    )
    input_schema = MediaIdInput

    async def execute(self, arguments: Dict[str, Any]) -> ToolResult:
        media_id = arguments.get("media_id")
        if not media_id:
            return ToolResult(
                tool_name=self.tool_name,
                status=ToolStatus.ERROR,
                summary="media_id is required to fetch media forensics.",
                error="MISSING_MEDIA_ID",
            )

        forensic = scan_store.get_media_forensic(media_id)
        if not forensic:
            return ToolResult(
                tool_name=self.tool_name,
                status=ToolStatus.NO_DATA,
                summary=f"No forensic record found for media ID '{media_id}'.",
            )

        return ToolResult(
            tool_name=self.tool_name,
            status=ToolStatus.SUCCESS,
            summary=f"Forensics for {media_id}: signals={len(forensic) if isinstance(forensic, list) else 1}",
            data={"forensics": [f.dict() if hasattr(f, 'dict') else f for f in (forensic if isinstance(forensic, list) else [forensic])]},
        )


class FrameAnalysisTool(AgentTool):
    tool_name = "get_frame_analysis"
    description = (
        "Retrieve keyframe analysis records, temporal anomalies, and face manipulation scores "
        "for a deepfake-assessed video asset."
    )
    input_schema = MediaIdInput

    async def execute(self, arguments: Dict[str, Any]) -> ToolResult:
        media_id = arguments.get("media_id")
        if not media_id:
            return ToolResult(
                tool_name=self.tool_name,
                status=ToolStatus.ERROR,
                summary="media_id is required to fetch frame analysis.",
                error="MISSING_MEDIA_ID",
            )

        frames = scan_store.get_media_frames(media_id)
        faces = scan_store.get_media_faces(media_id)

        if not frames:
            return ToolResult(
                tool_name=self.tool_name,
                status=ToolStatus.NO_DATA,
                summary=f"No frame analysis records found for video ID '{media_id}'.",
            )

        high_risk_frames = [f for f in frames if getattr(f, 'model_probability', 0.0) > 0.6]

        return ToolResult(
            tool_name=self.tool_name,
            status=ToolStatus.SUCCESS,
            summary=f"Video {media_id} has {len(frames)} analyzed keyframes and {len(faces)} tracked face detections. {len(high_risk_frames)} frames show elevated manipulation scores.",
            data={
                "media_id": media_id,
                "total_frames_analyzed": len(frames),
                "total_faces_detected": len(faces),
                "elevated_risk_frames_count": len(high_risk_frames),
                "frames": [f.dict() if hasattr(f, 'dict') else f for f in frames[:20]],
            },
        )
