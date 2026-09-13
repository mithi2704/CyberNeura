"""
Face Tracker for CyberNeura Video Deepfake Detection.
Links bounding boxes across contiguous frames using Intersection-over-Union (IoU)
tracking to measure temporal manipulation consistency across time.
"""
from __future__ import annotations

from typing import Dict, List
from app.media.video.models import DetectedFace, TrackedFace


def calculate_iou(box1: Dict[str, int], box2: Dict[str, int]) -> float:
    """Calculates Intersection over Union between two bounding boxes."""
    x1 = max(box1["x"], box2["x"])
    y1 = max(box1["y"], box2["y"])
    x2 = min(box1["x"] + box1["w"], box2["x"] + box2["w"])
    y2 = min(box1["y"] + box1["h"], box2["y"] + box2["h"])

    intersection_w = max(0, x2 - x1)
    intersection_h = max(0, y2 - y1)
    intersection = intersection_w * intersection_h

    area1 = box1["w"] * box1["h"]
    area2 = box2["w"] * box2["h"]
    union = area1 + area2 - intersection + 1e-6

    return float(intersection / union)


def track_faces_across_frames(
    frame_faces: List[Tuple[int, List[DetectedFace]]],  # List of (frame_idx, faces)
    iou_threshold: float = 0.30,
) -> List[TrackedFace]:
    """
    Groups face instances into continuous TrackedFace paths across time.
    """
    tracks: List[TrackedFace] = []
    next_track_id = 1

    for frame_idx, faces in frame_faces:
        matched_tracks = set()

        for face in faces:
            best_iou = 0.0
            best_track_idx = -1

            for t_idx, track in enumerate(tracks):
                if t_idx in matched_tracks:
                    continue
                # Compare with last detected face in track
                last_face = track.faces[-1]
                iou = calculate_iou(face.bounding_box, last_face.bounding_box)
                if iou > best_iou:
                    best_iou = iou
                    best_track_idx = t_idx

            if best_iou >= iou_threshold and best_track_idx != -1:
                tracks[best_track_idx].frames.append(frame_idx)
                tracks[best_track_idx].faces.append(face)
                matched_tracks.add(best_track_idx)
            else:
                # New face track
                tracks.append(
                    TrackedFace(
                        track_id=next_track_id,
                        frames=[frame_idx],
                        faces=[face],
                    )
                )
                next_track_id += 1

    return tracks
