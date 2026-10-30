"""
CyberNeura ML Service — AI Image Detection Inference Module.
Loads trained PyTorch weights and performs inference on images.
"""
from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any, Dict, Tuple

import numpy as np
import torch
import torch.nn as nn
from PIL import Image
from torchvision import transforms

BACKEND_DIR = Path(__file__).resolve().parent.parent.parent.parent / "backend"


class ConvResidualBlock(nn.Module):
    def __init__(self, in_channels: int, out_channels: int, pool: bool = True):
        super().__init__()
        self.conv1 = nn.Conv2d(in_channels, out_channels, kernel_size=3, padding=1, bias=False)
        self.bn1 = nn.BatchNorm2d(out_channels)
        self.conv2 = nn.Conv2d(out_channels, out_channels, kernel_size=3, padding=1, bias=False)
        self.bn2 = nn.BatchNorm2d(out_channels)
        self.act = nn.LeakyReLU(0.1, inplace=True)
        self.pool = nn.MaxPool2d(2) if pool else nn.Identity()
        self.shortcut = (
            nn.Sequential(
                nn.Conv2d(in_channels, out_channels, kernel_size=1, bias=False),
                nn.BatchNorm2d(out_channels),
            )
            if in_channels != out_channels
            else nn.Identity()
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        res = self.shortcut(x)
        out = self.act(self.bn1(self.conv1(x)))
        out = self.bn2(self.conv2(out))
        out = self.act(out + res)
        return self.pool(out)


class CyberNeuraSyntheticDetectorCNN(nn.Module):
    def __init__(self):
        super().__init__()
        self.stem = nn.Sequential(
            nn.Conv2d(3, 32, kernel_size=3, padding=1, bias=False),
            nn.BatchNorm2d(32),
            nn.LeakyReLU(0.1, inplace=True),
        )
        self.stage1 = ConvResidualBlock(32, 64, pool=True)
        self.stage2 = ConvResidualBlock(64, 128, pool=True)
        self.stage3 = ConvResidualBlock(128, 256, pool=True)
        self.stage4 = ConvResidualBlock(256, 256, pool=False)
        self.gap = nn.AdaptiveAvgPool2d((1, 1))
        self.classifier = nn.Sequential(
            nn.Linear(256, 128),
            nn.LeakyReLU(0.1, inplace=True),
            nn.Dropout(0.35),
            nn.Linear(128, 1),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        feat = self.stem(x)
        feat = self.stage1(feat)
        feat = self.stage2(feat)
        feat = self.stage3(feat)
        feat = self.stage4(feat)
        feat = self.gap(feat)
        feat = feat.view(feat.size(0), -1)
        return self.classifier(feat)


class ImageInferenceEngine:
    def __init__(self, model_dir: Path | None = None):
        self.model_dir = model_dir or (Path(__file__).resolve().parent.parent.parent / "models" / "image_model")
        self.device = torch.device("cpu")
        self.model = CyberNeuraSyntheticDetectorCNN().to(self.device)
        self.config = {}
        self.metadata = {}
        self.transform = transforms.Compose([
            transforms.Resize((32, 32)),
            transforms.ToTensor(),
            transforms.Normalize(mean=[0.485, 0.456, 0.406], std=[0.229, 0.224, 0.225]),
        ])
        self._load()

    def _load(self) -> None:
        weights_candidates = [
            self.model_dir / "image_detector.pth",
            BACKEND_DIR / "ml" / "models" / "image_detector.pth",
        ]
        for w in weights_candidates:
            if w.exists():
                try:
                    state_dict = torch.load(w, map_location=self.device)
                    self.model.load_state_dict(state_dict)
                    self.model.eval()
                    break
                except Exception as exc:
                    print(f"[IMAGE_INFERENCE] Warning loading weights: {exc}")

        meta_path = self.model_dir / "image_model_metadata.json"
        if not meta_path.exists():
            meta_path = BACKEND_DIR / "ml" / "models" / "image_model_metadata.json"
        if meta_path.exists():
            with open(meta_path, "r", encoding="utf-8") as f:
                self.metadata = json.load(f)

    @torch.inference_mode()
    def predict_image_bytes(self, image_bytes: bytes) -> Dict[str, Any]:
        """Classify image bytes returning AI vs Real probabilities."""
        img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
        tensor = self.transform(img).unsqueeze(0).to(self.device)
        
        logits = self.model(tensor)
        prob_ai = float(torch.sigmoid(logits).item())
        prob_real = float(1.0 - prob_ai)
        
        prediction = "AI_GENERATED" if prob_ai >= 0.50 else "REAL"
        
        return {
            "prediction": prediction,
            "ai_probability": round(prob_ai, 4),
            "real_probability": round(prob_real, 4),
            "model_version": self.metadata.get("version", "image-v1.1.0"),
            "architecture": "CyberNeuraSyntheticDetectorCNN",
            "dimensions": {"width": img.width, "height": img.height},
        }


image_engine = ImageInferenceEngine()

