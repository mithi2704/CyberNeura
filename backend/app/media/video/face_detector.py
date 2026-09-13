"""
Privacy-Preserving Face Detector for Manipulation Analysis.
STRICT INVARIANT:
No facial recognition, biometric indexing, or identity matching is performed or stored.
Faces are detected solely to analyze boundary blending, skin compression, and temporal stability.
"""
from __future__ import annotations

import logging
from typing import List, Tuple
import cv2
import numpy as np
from app.media.video.models import DetectedFace

import os
from pathlib import Path

logger = logging.getLogger(__name__)

# Search candidate locations for cascade XML
_CANDIDATE_PATHS = [
    Path(__file__).resolve().parents[3] / "data" / "haarcascade_frontalface_default.xml",
    Path("data/haarcascade_frontalface_default.xml"),
    Path(getattr(cv2.data, "haarcascades", "")) / "haarcascade_frontalface_default.xml" if hasattr(cv2, "data") else Path(""),
]

face_cascade = cv2.CascadeClassifier()
for p in _CANDIDATE_PATHS:
    if p.exists() and p.is_file():
        face_cascade.load(str(p))
        if not face_cascade.empty():
            logger.debug(f"Loaded face cascade from {p}")
            break


def detect_faces_in_frame(rgb_frame: np.ndarray) -> List[DetectedFace]:
    """
    Detects faces in an RGB frame, assesses quality (blur, size, illumination),
    and returns bounding boxes without biometric identifiers.
    """
    gray = cv2.cvtColor(rgb_frame, cv2.COLOR_RGB2GRAY)
    h, w = gray.shape

    if face_cascade.empty():
        return []

    # Minimum face size: at least 30x30 pixels
    faces_rects = face_cascade.detectMultiScale(
        gray,
        scaleFactor=1.1,
        minNeighbors=4,
        minSize=(32, 32),
    )

    detected_faces: List[DetectedFace] = []

    for idx, (x, y, fw, fh) in enumerate(faces_rects):
        # 1. Bounding box safety clamp
        x_clamped = max(0, int(x))
        y_clamped = max(0, int(y))
        fw_clamped = min(w - x_clamped, int(fw))
        fh_clamped = min(h - y_clamped, int(fh))

        face_crop = gray[y_clamped:y_clamped + fh_clamped, x_clamped:x_clamped + fw_clamped]

        # 2. Quality Estimation
        # Blur estimation: Laplacian variance
        blur_val = float(cv2.Laplacian(face_crop, cv2.CV_64F).var()) if face_crop.size > 0 else 0.0
        # Illumination uniformity: standard deviation of luminance
        illum_val = float(np.std(face_crop)) if face_crop.size > 0 else 0.0

        # Quality score 0.0 to 1.0 based on resolution and sharpness
        res_factor = min(1.0, (fw_clamped * fh_clamped) / (128.0 * 128.0))
        blur_factor = min(1.0, blur_val / 200.0)
        quality_score = round(float(0.6 * blur_factor + 0.4 * res_factor), 3)

        detected_faces.append(
            DetectedFace(
                face_index=idx,
                bounding_box={"x": x_clamped, "y": y_clamped, "w": fw_clamped, "h": fh_clamped},
                quality_score=quality_score,
                blur_score=round(blur_val, 1),
                illumination_score=round(illum_val, 1),
            )
        )

    return detected_faces
