"""
Tests for Media Video Pipeline: sampling, face detection, tracking, temporal analysis.
"""
import pytest
import numpy as np

from app.media.video.face_detector import detect_faces_in_frame
from app.media.video.face_tracker import track_faces_across_frames
from app.media.video.temporal_analysis import analyze_temporal_consistency
from app.media.video.models import SampledFrame, DetectedFace


def test_face_detector_privacy_invariant():
    """Verify face detector returns bounding boxes and quality, NO biometric embeddings."""
    frame = np.ones((100, 100, 3), dtype=np.uint8) * 120
    faces = detect_faces_in_frame(frame)
    for face in faces:
        assert hasattr(face, "bounding_box")
        assert hasattr(face, "quality_score")
        # Ensure no identity attributes exist
        assert not hasattr(face, "embedding")
        assert not hasattr(face, "identity")


def test_face_tracking_iou():
    f1_face = DetectedFace(
        face_index=0,
        bounding_box={"x": 50, "y": 50, "w": 40, "h": 40},
        quality_score=0.9,
    )
    f2_face = DetectedFace(
        face_index=0,
        bounding_box={"x": 52, "y": 51, "w": 40, "h": 40},
        quality_score=0.9,
    )

    tracks = track_faces_across_frames([(0, [f1_face]), (1, [f2_face])])
    assert len(tracks) >= 1
    assert len(tracks[0].faces) == 2


def test_temporal_consistency():
    f1 = np.zeros((64, 64, 3), dtype=np.uint8)
    f2 = np.ones((64, 64, 3), dtype=np.uint8) * 10

    res = analyze_temporal_consistency([f1, f2], [])
    assert "inconsistency_score" in res
    assert 0.0 <= res["inconsistency_score"] <= 1.0
