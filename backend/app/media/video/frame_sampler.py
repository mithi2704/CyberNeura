"""
Intelligent Video Frame Sampler for CyberNeura.
Supports uniform time-based sampling and scene-change detection without loading
entire video streams into memory.
"""
from __future__ import annotations

import logging
from typing import Dict, List, Tuple
import cv2
import numpy as np
from app.media.video.models import SampledFrame

logger = logging.getLogger(__name__)


def extract_video_metadata(video_path: str) -> Dict[str, Any]:
    """Extracts duration, dimensions, FPS, and total frame count from a video file."""
    cap = cv2.VideoCapture(video_path)
    if not cap.isOpened():
        raise ValueError(f"Could not open video bitstream at {video_path}")

    try:
        width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
        height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
        fps = float(cap.get(cv2.CAP_PROP_FPS)) or 24.0
        total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
        duration = float(total_frames / fps) if fps > 0 else 0.0

        return {
            "width": width,
            "height": height,
            "fps": fps,
            "total_frames": total_frames,
            "duration": round(duration, 2),
        }
    finally:
        cap.release()


def sample_video_frames(
    video_path: str,
    sampling_rate_fps: int = 2,
    max_frames: int = 300,
) -> Tuple[List[SampledFrame], List[np.ndarray]]:
    """
    Samples frames uniformly at `sampling_rate_fps` up to `max_frames`.
    Returns list of SampledFrame metadata objects and matching RGB numpy arrays.
    """
    cap = cv2.VideoCapture(video_path)
    if not cap.isOpened():
        raise ValueError(f"Unable to open video at {video_path}")

    sampled_frames: List[SampledFrame] = []
    frame_arrays: List[np.ndarray] = []

    try:
        fps = float(cap.get(cv2.CAP_PROP_FPS)) or 24.0
        total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
        frame_interval = max(1, int(round(fps / max(1, sampling_rate_fps))))

        current_frame_idx = 0
        prev_hist: np.ndarray | None = None

        while True:
            ret, bgr_frame = cap.read()
            if not ret:
                break

            if current_frame_idx % frame_interval == 0:
                # Convert to RGB
                rgb_frame = cv2.cvtColor(bgr_frame, cv2.COLOR_BGR2RGB)
                timestamp = round(float(current_frame_idx / fps), 2)

                # Scene change keyframe detection via color histogram delta
                is_keyframe = False
                hist = cv2.calcHist([bgr_frame], [0, 1, 2], None, [8, 8, 8], [0, 256, 0, 256, 0, 256])
                cv2.normalize(hist, hist)
                if prev_hist is not None:
                    similarity = cv2.compareHist(prev_hist, hist, cv2.HISTCMP_CORREL)
                    if similarity < 0.70:  # Scene cut detected
                        is_keyframe = True
                prev_hist = hist

                sampled_frames.append(
                    SampledFrame(
                        frame_number=current_frame_idx,
                        timestamp=timestamp,
                        is_keyframe=is_keyframe,
                    )
                )
                frame_arrays.append(rgb_frame)

                if len(sampled_frames) >= max_frames:
                    break

            current_frame_idx += 1

        logger.info(f"Sampled {len(sampled_frames)} frames from {video_path} (total: {total_frames})")
        return sampled_frames, frame_arrays
    finally:
        cap.release()
