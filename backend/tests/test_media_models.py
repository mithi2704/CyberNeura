"""
Tests for Media Model Registry & Inference Models (Phase 7).
"""
import pytest
import numpy as np
import torch
from PIL import Image

from app.media.model_registry import model_registry
from app.media.image.inference import ImageDetectionModel, SyntheticFeatureExtractor
from app.media.video.inference import DeepfakeDetectionModel
from app.media.video.models import DetectedFace


@pytest.fixture
def sample_pil_image():
    arr = np.zeros((128, 128, 3), dtype=np.uint8)
    arr[::8, :, :] = 255
    arr[:, ::8, :] = 255
    return arr


def test_model_registry_registration():
    models = model_registry.list_models()
    model_ids = [m["model_id"] for m in models]
    assert "cyberneura-image-detector" in model_ids
    assert "cyberneura-video-detector" in model_ids

    img_model = model_registry.get_model("cyberneura-image-detector")
    assert img_model is not None
    assert img_model.version in ("1.0.0", "1.1.0")

    # When loaded, health reports HEALTHY
    img_model.load()
    assert img_model.health()["status"] == "HEALTHY"


def test_image_detection_model_inference(sample_pil_image):
    model = ImageDetectionModel()
    tensor = torch.from_numpy(sample_pil_image).permute(2, 0, 1).float().unsqueeze(0) / 255.0
    out = model.predict((tensor, sample_pil_image))

    assert "probability_ai_generated" in out
    assert 0.0 <= out["probability_ai_generated"] <= 1.0
    assert 0.0 <= out["confidence"] <= 1.0
    assert out["classification"] in ("LIKELY_AUTHENTIC", "SUSPICIOUS", "LIKELY_AI_GENERATED")
    assert "features" in out


def test_deepfake_detection_model_frame_inference():
    model = DeepfakeDetectionModel()

    # Synthetic RGB frame
    frame_arr = np.random.randint(50, 200, (120, 160, 3), dtype=np.uint8)
    face = DetectedFace(
        face_index=0,
        bounding_box={"x": 20, "y": 20, "w": 40, "h": 40},
        quality_score=0.8,
        blur_score=150.0,
        illumination_score=40.0,
    )

    out = model.evaluate_frame(
        rgb_frame=frame_arr,
        frame_number=1,
        timestamp=0.5,
        detected_faces=[face],
    )

    assert "deepfake_probability" in out
    assert 0.0 <= out["deepfake_probability"] <= 1.0
    assert 0.0 <= out["confidence"] <= 1.0
    assert "anomalies" in out
