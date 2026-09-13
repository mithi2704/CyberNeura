"""
ML Model loader and predictor.
Loads a pre-trained joblib model from disk.
Falls back to a heuristic engine if no trained model is available.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Dict, Any, Optional, Tuple

from app.utils.logger import get_logger
from app.services.feature_extractor import FEATURE_ORDER, get_feature_vector

logger = get_logger(__name__)

_model = None
_metadata: Dict[str, Any] = {}
_model_loaded = False


def _load_model(model_path: str, metadata_path: str) -> bool:
    """Load the trained model from disk. Returns True on success."""
    global _model, _metadata, _model_loaded
    try:
        import joblib
        p = Path(model_path)
        if not p.exists():
            logger.warning(f"Model file not found at {model_path}")
            return False

        _model = joblib.load(p)
        logger.info(f"ML model loaded from {model_path}")

        mp = Path(metadata_path)
        if mp.exists():
            with open(mp) as f:
                _metadata = json.load(f)
            logger.info(f"Model metadata loaded: version={_metadata.get('version', 'unknown')}")

        _model_loaded = True
        return True
    except Exception as exc:
        logger.error(f"Failed to load ML model: {exc}")
        return False


def _ensure_model_loaded() -> None:
    """Ensure the model and metadata are loaded into memory."""
    global _model_loaded
    if not _model_loaded:
        from app.config import settings
        _load_model(settings.model_path, settings.model_metadata_path)


def get_model_metadata() -> Dict[str, Any]:
    """Return model metadata dict (accuracy, version, etc.)."""
    _ensure_model_loaded()
    return _metadata


def predict(features: Dict[str, Any]) -> Tuple[str, float, float, Dict[str, float]]:
    """
    Run ML inference on the extracted features.
    Returns (prediction, probability, confidence, feature_importance).

    Falls back to heuristic scoring if no model is loaded.
    """
    _ensure_model_loaded()

    vector = get_feature_vector(features)

    if _model is not None:
        return _predict_with_model(vector, features)
    else:
        return _heuristic_predict(features)


def _predict_with_model(vector: list, features: Dict[str, Any]) -> Tuple[str, float, float, Dict[str, float]]:
    """Run inference with the trained model."""
    import numpy as np
    X = [vector]
    try:
        proba = _model.predict_proba(X)[0]
        n_classes = len(proba)

        if n_classes == 2:
            # Binary classification: 0 = safe, 1 = malicious/phishing
            probability = float(proba[1])
            class_idx = int(proba.argmax())
            confidence = float(proba[class_idx]) * 100
            if probability >= 0.70:
                prediction = "malicious"
            elif probability >= 0.30:
                prediction = "suspicious"
            else:
                prediction = "safe"
        elif n_classes >= 3:
            # Multi-class: 0 = safe, 1 = suspicious, 2 = malicious
            class_idx = int(proba.argmax())
            confidence = float(proba[class_idx]) * 100
            label_map = {0: "safe", 1: "suspicious", 2: "malicious"}
            prediction = label_map.get(class_idx, "suspicious")
            probability = float(proba[2])
        else:
            class_idx = 0
            confidence = 100.0
            prediction = "safe"
            probability = 0.0

        # Feature importance from model
        feature_importance = {}
        if hasattr(_model, "feature_importances_"):
            for name, imp in zip(FEATURE_ORDER, _model.feature_importances_):
                feature_importance[name] = round(float(imp), 4)

        return prediction, probability, confidence, feature_importance
    except Exception as exc:
        logger.error(f"Model inference failed: {exc}")
        return _heuristic_predict(features)


def _heuristic_predict(features: Dict[str, Any]) -> Tuple[str, float, float, Dict[str, float]]:
    """
    Deterministic heuristic fallback when no trained model is available.
    Clearly marked as heuristic in the response.
    """
    score = 0.0

    # Malicious indicators (high weight)
    if features.get("has_phishing_keyword"): score += 35
    if features.get("has_ip_hostname"): score += 30
    if features.get("is_suspicious_tld"): score += 25
    if features.get("has_at_symbol"): score += 20
    if features.get("has_brand_in_subdomain"): score += 25
    if features.get("uses_punycode"): score += 15

    # Suspicious indicators (medium weight)
    if not features.get("uses_https"): score += 15
    if features.get("url_length", 0) > 75: score += 10
    if features.get("num_dots", 0) > 4: score += 8
    if features.get("num_hyphens", 0) > 3: score += 8
    if features.get("has_hex_encoding"): score += 10
    if features.get("is_url_shortener"): score += 5
    if features.get("num_subdomains", 0) > 2: score += 8
    if features.get("has_suspicious_port"): score += 10
    if features.get("url_entropy", 0) > 4.5: score += 8

    score = min(score, 100.0)
    probability = score / 100.0
    confidence = 70.0 + (abs(probability - 0.5) * 60)  # higher when more certain

    if score >= 70:
        prediction = "malicious"
    elif score >= 30:
        prediction = "suspicious"
    else:
        prediction = "safe"

    feature_importance = {
        "phishing_keywords": 0.35,
        "ip_as_hostname": 0.30,
        "suspicious_tld": 0.25,
        "https_usage": 0.15,
        "url_length": 0.10,
        "subdomain_depth": 0.08,
    }

    return prediction, probability, min(confidence, 98.0), feature_importance


def get_model_version() -> str:
    """Return 'version' from metadata, or heuristic-dev-fallback."""
    _ensure_model_loaded()
    if _metadata.get("version"):
        return _metadata["version"]
    return "heuristic-dev-fallback"
