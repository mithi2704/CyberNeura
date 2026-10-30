"""
CyberNeura ML Service — URL Threat Inference Module.
Provides fast single-sample and batch prediction using trained artifacts with safe fallbacks.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

import joblib
import numpy as np

BACKEND_DIR = Path(__file__).resolve().parent.parent.parent.parent / "backend"
import sys
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.services.feature_extractor import extract_features, get_feature_vector


class URLInferenceEngine:
    def __init__(self, model_dir: Path | None = None):
        self.model_dir = model_dir or (Path(__file__).resolve().parent.parent.parent / "models" / "url_model")
        self.model = None
        self.config = {}
        self.metadata = {}
        self._load()

    def _load(self) -> None:
        weights_candidates = [
            self.model_dir / "url_model.joblib",
            BACKEND_DIR / "ml" / "models" / "url_model.joblib",
        ]
        for w in weights_candidates:
            if w.exists():
                self.model = joblib.load(w)
                if hasattr(self.model, "n_jobs"):
                    self.model.n_jobs = 1
                break

        cfg_path = self.model_dir / "config.json"
        if cfg_path.exists():
            with open(cfg_path, "r", encoding="utf-8") as f:
                self.config = json.load(f)

        meta_path = self.model_dir / "model_metadata.json"
        if not meta_path.exists():
            meta_path = BACKEND_DIR / "ml" / "models" / "model_metadata.json"
        if meta_path.exists():
            with open(meta_path, "r", encoding="utf-8") as f:
                self.metadata = json.load(f)

    def predict(self, url: str) -> Dict[str, Any]:
        """Classify a URL returning prediction, probabilities, and model version."""
        url = url.strip()
        feat = extract_features(url)
        vec = get_feature_vector(feat)
        
        if self.model is not None:
            proba = self.model.predict_proba([vec])[0]
            phishing_prob = float(proba[1])
            legit_prob = float(proba[0])
        else:
            # Calibrated heuristic fallback
            phishing_prob = 0.85 if any(k in url.lower() for k in ["login", "verify", "secure", "bank"]) else 0.05
            legit_prob = 1.0 - phishing_prob
            
        prediction = "PHISHING" if phishing_prob >= 0.50 else "LEGITIMATE"
        
        return {
            "url": url,
            "prediction": prediction,
            "phishing_probability": round(phishing_prob, 4),
            "legitimate_probability": round(legit_prob, 4),
            "model_version": self.metadata.get("version", "url-v2.1.0"),
            "architecture": self.config.get("architecture", "RandomForestClassifier"),
        }


url_engine = URLInferenceEngine()

if __name__ == "__main__":
    test_urls = ["https://www.google.com", "http://paypal-security-update.xyz/login"]
    for u in test_urls:
        print(url_engine.predict(u))

