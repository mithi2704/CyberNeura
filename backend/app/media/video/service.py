"""
Video Deepfake Analysis Orchestration Service for CyberNeura.
Coordinates decoding, frame sampling, face detection, face tracking,
frame-level neural evaluation, temporal consistency, robust aggregation,
evidence normalization, and risk scoring.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
import numpy as np
from app.media.models import MediaType, MediaClassification, MediaAssessment, FrameResult, FaceResult
from app.media.video.frame_sampler import extract_video_metadata, sample_video_frames
from app.media.video.face_detector import detect_faces_in_frame
from app.media.video.face_tracker import track_faces_across_frames
from app.media.video.inference import default_deepfake_model
from app.media.video.temporal_analysis import analyze_temporal_consistency
from app.media.evidence.builder import MediaEvidenceBuilder
from app.media.risk.engine import media_risk_engine
from app.media.model_registry import model_registry
from app.services.scan_store import scan_store
from app.realtime.publisher import event_publisher
from app.realtime.models import RealtimeEventType, EntityType

logger = logging.getLogger(__name__)


class VideoAnalysisService:
    async def analyze_video(
        self,
        video_path: str,
        media_id: str,
        user_id: Optional[str] = None,
        sampling_rate_fps: int = 2,
        max_frames: int = 300,
        progress_callback: Optional[Any] = None,
    ) -> MediaAssessment:
        """
        Executes end-to-end video deepfake analysis pipeline with staged progress reporting.
        """
        # Staged progress updates
        async def report_progress(pct: int, stage: str):
            if progress_callback:
                await progress_callback(pct, stage)

        # Stage 1: Metadata Extraction (10%)
        await report_progress(10, "EXTRACTING_METADATA")
        metadata = extract_video_metadata(video_path)

        # Stage 2: Frame Sampling (25%)
        await report_progress(25, "SAMPLING_FRAMES")
        sampled_frames, frame_arrays = sample_video_frames(
            video_path=video_path,
            sampling_rate_fps=sampling_rate_fps,
            max_frames=max_frames,
        )

        if not sampled_frames:
            raise ValueError("No video frames could be decoded from bitstream.")

        # Stage 3: Face Detection & Tracking (50%)
        await report_progress(50, "DETECTING_AND_TRACKING_FACES")
        active_model = model_registry.get_active_model("video_deepfake_detection") or default_deepfake_model

        frame_results: List[FrameResult] = []
        frame_faces_list = []
        all_detected_faces_count = 0

        for idx, (sf, rgb_arr) in enumerate(zip(sampled_frames, frame_arrays)):
            faces = detect_faces_in_frame(rgb_arr)
            frame_faces_list.append((sf.frame_number, faces))
            all_detected_faces_count += len(faces)

            # Evaluate individual frame using model
            eval_dict = active_model.evaluate_frame(
                rgb_frame=rgb_arr,
                frame_number=sf.frame_number,
                timestamp=sf.timestamp,
                detected_faces=faces,
            )

            # Build FaceResults
            face_results_for_frame = []
            for face in faces:
                face_results_for_frame.append(
                    FaceResult(
                        frame_result_id=f"fr-{media_id}-{sf.frame_number}",
                        face_index=face.face_index,
                        bounding_box=face.bounding_box,
                        quality_score=face.quality_score,
                        manipulation_probability=eval_dict["deepfake_probability"],
                        confidence=eval_dict["confidence"],
                        anomalies=eval_dict.get("anomalies", []),
                    )
                )

            frame_results.append(
                FrameResult(
                    media_id=media_id,
                    frame_number=sf.frame_number,
                    timestamp=sf.timestamp,
                    model_probability=eval_dict["deepfake_probability"],
                    model_confidence=eval_dict["confidence"],
                    face_count=len(faces),
                    face_quality=float(np.mean([f.quality_score for f in faces])) if faces else 1.0,
                    classification=eval_dict["classification"],
                    faces=face_results_for_frame,
                )
            )

        # Track faces across frames
        tracked_faces = track_faces_across_frames(frame_faces_list)

        # Stage 4: Temporal Analysis (75%)
        await report_progress(75, "ANALYZING_TEMPORAL_CONSISTENCY")
        temporal_dict = analyze_temporal_consistency(frame_arrays, tracked_faces)

        # Stage 5: Robust Aggregation (90%)
        await report_progress(90, "AGGREGATING_EVIDENCE")
        frame_probs = [fr.model_probability for fr in frame_results]
        suspicious_frames_count = sum(1 for p in frame_probs if p >= 0.70)
        total_frames = len(frame_results)
        manipulated_ratio = suspicious_frames_count / total_frames if total_frames > 0 else 0.0

        # Robust aggregation: check for isolated vs persistent manipulation
        # If standard deviation of frame probs is extremely high (e.g. 1 frame 0.95, 99 frames 0.08),
        # trigger uncertainty rather than declaring whole video deepfake.
        std_dev = float(np.std(frame_probs)) if frame_probs else 0.0
        median_prob = float(np.median(frame_probs)) if frame_probs else 0.0
        p90_prob = float(np.percentile(frame_probs, 90)) if frame_probs else 0.0

        # Weighted aggregate probability
        if manipulated_ratio >= 0.40:
            aggregated_prob = float(0.60 * np.mean(frame_probs) + 0.40 * p90_prob)
        elif manipulated_ratio > 0.05:
            # Isolated spikes: reduce certainty
            aggregated_prob = float(0.50 * median_prob + 0.50 * np.mean(frame_probs))
        else:
            aggregated_prob = float(np.mean(frame_probs))

        aggregated_prob = round(float(np.clip(aggregated_prob, 0.02, 0.98)), 3)

        # Build Normalized Evidence Items (Phase 3 Integration)
        builder = MediaEvidenceBuilder(media_id=media_id)
        evidence_list = []

        # Model evidence
        evidence_list.append(
            builder.build_model_evidence(
                probability=aggregated_prob,
                confidence=0.91 if total_frames >= 10 else 0.65,
                model_name=active_model.model_name,
                features={
                    "frames_analyzed": total_frames,
                    "suspicious_frames": suspicious_frames_count,
                    "faces_detected": all_detected_faces_count,
                    "temporal_inconsistency": temporal_dict["inconsistency_score"],
                },
                is_video=True,
            )
        )

        # Temporal evidence
        evidence_list.append(
            builder.build_forensic_evidence(
                signal_type="temporal_consistency",
                severity="HIGH" if temporal_dict["inconsistency_score"] > 0.60 else "LOW",
                confidence=0.88,
                description=temporal_dict["description"],
                value=temporal_dict,
            )
        )

        # Stage 6: Risk Engine Assessment (100%)
        await report_progress(100, "FINALIZING_ASSESSMENT")
        deepfake_model_output = {
            "deepfake_probability": aggregated_prob,
            "confidence": 0.92 if total_frames >= 10 and all_detected_faces_count > 0 else 0.65,
            "model": active_model.model_info(),
        }

        frame_metrics = {
            "frames_analyzed": total_frames,
            "suspicious_frames": suspicious_frames_count,
            "manipulated_ratio": manipulated_ratio,
            "std_dev": std_dev,
        }
        face_metrics = {
            "faces_detected": all_detected_faces_count,
            "tracked_face_count": len(tracked_faces),
            "manipulation_score": float(np.mean([fr.model_probability for fr in frame_results if fr.face_count > 0])) if any(fr.face_count > 0 for fr in frame_results) else 0.0,
        }
        temporal_metrics = temporal_dict

        assessment = media_risk_engine.assess_video(
            media_id=media_id,
            user_id=user_id,
            deepfake_model_output=deepfake_model_output,
            frame_metrics=frame_metrics,
            face_metrics=face_metrics,
            temporal_metrics=temporal_metrics,
            evidence_list=evidence_list,
        )

        # Persist to ScanStore & Disk
        scan_store.save_media_assessment(
            assessment=assessment.model_dump(),
            evidence=[e.model_dump() for e in evidence_list],
            frames=[fr.model_dump() for fr in frame_results],
        )

        return assessment


video_service = VideoAnalysisService()
