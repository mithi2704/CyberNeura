"""
Verification tests for CyberNeura trained machine learning models:
1. URL Phishing Classifier (trained on PhiUSIIL, Cisco Umbrella Top-1M, and Curated Benchmark).
2. Image Synthetic Detector CNN (trained on CIFAKE and GenImage benchmark).
"""
import json
from pathlib import Path
import numpy as np
import pytest
import torch

from app.ml.predictor import predict, get_model_metadata, get_model_version
from app.services.feature_extractor import extract_features, get_feature_vector
from app.media.image.inference import ImageDetectionModel, CyberNeuraSyntheticDetectorCNN


def test_url_model_trained_artifacts():
    """Verify that the URL model trained on all 3 datasets exists and loaded correctly."""
    meta = get_model_metadata()
    assert meta is not None
    assert meta["version"] == "2.0.0"
    assert "PhiUSIIL" in meta["dataset"]
    assert "Top-1M" in meta["dataset"]
    assert meta["accuracy"] >= 0.95
    assert meta["training_samples"] >= 200000


def test_url_model_safe_inferences():
    """Verify high-reputation legitimate domains (from top-1m and PhiUSIIL) are classified as safe."""
    safe_urls = [
        "https://www.google.com",
        "https://google.com",
        "https://github.com",
        "https://cloudflare.com",
        "https://www.apple.com",
    ]
    for u in safe_urls:
        features = extract_features(u)
        prediction, probability, confidence, fi = predict(features)
        assert prediction == "safe", f"Expected safe for {u}, got {prediction}"
        assert probability < 0.25, f"Expected low phishing probability for {u}, got {probability}"


def test_url_model_malicious_inferences():
    """Verify known phishing and credential-theft patterns are classified as malicious."""
    malicious_urls = [
        "http://paypal-verification-security-update.xyz/login",
        "http://apple-support-login-secure.tk",
        "http://192.168.1.1/admin/login.php",
    ]
    for u in malicious_urls:
        features = extract_features(u)
        prediction, probability, confidence, fi = predict(features)
        assert prediction == "malicious", f"Expected malicious for {u}, got {prediction}"
        assert probability > 0.70, f"Expected high phishing probability for {u}, got {probability}"


def test_image_synthetic_detector_trained_model():
    """Verify that the Image Synthetic Detector loads trained weights and performs inference."""
    weights_path = Path("ml/models/image_detector.pth") if Path("ml/models/image_detector.pth").exists() else Path("backend/ml/models/image_detector.pth")
    assert weights_path.exists(), "Trained image detector weights should exist"

    model = ImageDetectionModel()
    loaded = model.load()
    assert loaded is True
    assert model.is_loaded is True
    assert model.health()["status"] == "HEALTHY"
    assert isinstance(model.neural_extractor, CyberNeuraSyntheticDetectorCNN)

    # Perform inference on test image
    test_img = np.random.randint(40, 220, (64, 64, 3), dtype=np.uint8)
    tensor = torch.from_numpy(test_img).permute(2, 0, 1).float().unsqueeze(0) / 255.0
    res = model.predict((tensor, test_img))

    assert "probability_ai_generated" in res
    assert 0.0 <= res["probability_ai_generated"] <= 1.0
    assert "confidence" in res
    assert res["classification"] in ("LIKELY_AUTHENTIC", "SUSPICIOUS", "LIKELY_AI_GENERATED", "INCONCLUSIVE")
    assert "features" in res
    assert "neural_feature_score" in res["features"]
