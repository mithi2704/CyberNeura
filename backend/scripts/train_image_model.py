"""
CyberNeura Image Synthetic Detector Training Script.
Trains a deep convolutional neural network for AI-generated / synthetic image detection
using CIFAKE / GenImage benchmark datasets (e.g., e:/CyberNeura/archive).

Usage:
    cd backend
    python scripts/train_image_model.py --dataset e:/CyberNeura/archive --samples_per_class 6000 --epochs 5
"""
from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time
from datetime import date, datetime, timezone
from pathlib import Path
from typing import List, Tuple

# Allow imports from parent
sys.path.insert(0, str(Path(__file__).parent.parent))

import numpy as np
from PIL import Image
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, Dataset
from torchvision import transforms
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix

DEFAULT_ARCHIVE_PATH = Path("e:/CyberNeura/archive")
MODEL_OUTPUT_PATH = Path("ml/models/image_detector.pth")
METADATA_OUTPUT_PATH = Path("ml/models/image_model_metadata.json")
MODEL_VERSION = "1.1.0"


class ConvResidualBlock(nn.Module):
    """Residual convolutional block for high-frequency synthetic artifact extraction."""

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
    """
    Multiscale PyTorch Neural Architecture for AI-Generated & Synthetic Image Detection.
    Detects spatial checkerboard artifacts, upsampling frequency grids, and boundary seams.
    """

    def __init__(self):
        super().__init__()
        # Initial high-pass feature extractor
        self.stem = nn.Sequential(
            nn.Conv2d(3, 32, kernel_size=3, padding=1, bias=False),
            nn.BatchNorm2d(32),
            nn.LeakyReLU(0.1, inplace=True),
        )
        self.stage1 = ConvResidualBlock(32, 64, pool=True)    # 32x32 -> 16x16
        self.stage2 = ConvResidualBlock(64, 128, pool=True)   # 16x16 -> 8x8
        self.stage3 = ConvResidualBlock(128, 256, pool=True)  # 8x8 -> 4x4
        self.stage4 = ConvResidualBlock(256, 256, pool=False) # 4x4 -> 4x4
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
        logits = self.classifier(feat)
        return logits


class ImageBinaryDataset(Dataset):
    """Fast indexed image dataset for Real (0) vs Synthetic/Fake (1) classification."""

    def __init__(self, file_tuples: List[Tuple[str, int]], transform=None):
        self.file_tuples = file_tuples
        self.transform = transform

    def __len__(self) -> int:
        return len(self.file_tuples)

    def __getitem__(self, idx: int) -> Tuple[torch.Tensor, int]:
        fpath, label = self.file_tuples[idx]
        try:
            with Image.open(fpath) as img:
                img = img.convert("RGB")
                if self.transform:
                    tensor = self.transform(img)
                else:
                    tensor = transforms.ToTensor()(img)
                return tensor, label
        except Exception:
            # Fallback black image if corrupt
            tensor = torch.zeros((3, 32, 32), dtype=torch.float32)
            return tensor, label


def collect_dataset_samples(
    data_dir: Path,
    samples_per_class: int | None = 6000,
    val_samples_per_class: int | None = 1500,
) -> Tuple[List[Tuple[str, int]], List[Tuple[str, int]]]:
    """Collects and balances real and fake image file paths."""
    print(f"[INFO] Scanning image dataset at: {data_dir.resolve()}")
    train_real_dir = data_dir / "train" / "REAL"
    train_fake_dir = data_dir / "train" / "FAKE"
    test_real_dir = data_dir / "test" / "REAL"
    test_fake_dir = data_dir / "test" / "FAKE"

    if not (train_real_dir.exists() and train_fake_dir.exists()):
        raise FileNotFoundError(f"Missing train REAL or FAKE folders inside {data_dir}")

    # Gather training files
    print("[INFO] Indexing training directory...")
    real_train_files = [str(train_real_dir / f) for f in os.listdir(train_real_dir) if f.lower().endswith(('.jpg', '.jpeg', '.png'))]
    fake_train_files = [str(train_fake_dir / f) for f in os.listdir(train_fake_dir) if f.lower().endswith(('.jpg', '.jpeg', '.png'))]
    print(f"[INFO] Found {len(real_train_files):,} train REAL images and {len(fake_train_files):,} train FAKE images.")

    random.seed(42)
    random.shuffle(real_train_files)
    random.shuffle(fake_train_files)

    if samples_per_class and samples_per_class > 0:
        real_train_files = real_train_files[:samples_per_class]
        fake_train_files = fake_train_files[:samples_per_class]
        print(f"[INFO] Balanced sampling: {len(real_train_files):,} REAL + {len(fake_train_files):,} FAKE = {len(real_train_files) + len(fake_train_files):,} training images.")

    train_tuples = [(p, 0) for p in real_train_files] + [(p, 1) for p in fake_train_files]
    random.shuffle(train_tuples)

    # Gather test/val files
    real_test_files = [str(test_real_dir / f) for f in os.listdir(test_real_dir) if f.lower().endswith(('.jpg', '.jpeg', '.png'))]
    fake_test_files = [str(test_fake_dir / f) for f in os.listdir(test_fake_dir) if f.lower().endswith(('.jpg', '.jpeg', '.png'))]
    print(f"[INFO] Found {len(real_test_files):,} test REAL images and {len(fake_test_files):,} test FAKE images.")

    random.shuffle(real_test_files)
    random.shuffle(fake_test_files)

    if val_samples_per_class and val_samples_per_class > 0:
        real_test_files = real_test_files[:val_samples_per_class]
        fake_test_files = fake_test_files[:val_samples_per_class]

    val_tuples = [(p, 0) for p in real_test_files] + [(p, 1) for p in fake_test_files]
    random.shuffle(val_tuples)
    print(f"[INFO] Validation set: {len(val_tuples):,} images.")

    return train_tuples, val_tuples


def train_image_model(
    data_dir: Path,
    samples_per_class: int = 6000,
    val_samples_per_class: int = 1500,
    epochs: int = 5,
    batch_size: int = 64,
    lr: float = 0.001,
    output_model: Path = MODEL_OUTPUT_PATH,
    output_meta: Path = METADATA_OUTPUT_PATH,
):
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"[INFO] Using device: {device} for image model training")

    train_tuples, val_tuples = collect_dataset_samples(
        data_dir,
        samples_per_class=samples_per_class,
        val_samples_per_class=val_samples_per_class,
    )

    # Transforms: standard normalization + gentle augmentation for train
    train_transform = transforms.Compose([
        transforms.Resize((32, 32)),
        transforms.RandomHorizontalFlip(),
        transforms.ToTensor(),
        transforms.Normalize(mean=[0.485, 0.456, 0.406], std=[0.229, 0.224, 0.225]),
    ])

    val_transform = transforms.Compose([
        transforms.Resize((32, 32)),
        transforms.ToTensor(),
        transforms.Normalize(mean=[0.485, 0.456, 0.406], std=[0.229, 0.224, 0.225]),
    ])

    train_dataset = ImageBinaryDataset(train_tuples, transform=train_transform)
    val_dataset = ImageBinaryDataset(val_tuples, transform=val_transform)

    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True, num_workers=0)
    val_loader = DataLoader(val_dataset, batch_size=batch_size, shuffle=False, num_workers=0)

    model = CyberNeuraSyntheticDetectorCNN().to(device)
    total_params = sum(p.numel() for p in model.parameters() if p.requires_grad)
    print(f"[INFO] Initialized CyberNeuraSyntheticDetectorCNN with {total_params:,} parameters.")

    criterion = nn.BCEWithLogitsLoss()
    optimizer = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=1e-4)
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=epochs)

    best_val_acc = 0.0
    best_metrics = {}

    print(f"\n{'='*65}")
    print(f"  STARTING IMAGE SYNTHETIC DETECTOR TRAINING ({epochs} EPOCHS)")
    print(f"{'='*65}")

    t_start = time.time()
    for epoch in range(1, epochs + 1):
        model.train()
        train_loss = 0.0
        train_correct = 0
        train_total = 0
        ep_start = time.time()

        for batch_idx, (images, labels) in enumerate(train_loader):
            images = images.to(device)
            labels = labels.float().unsqueeze(1).to(device)

            optimizer.zero_grad()
            logits = model(images)
            loss = criterion(logits, labels)
            loss.backward()
            optimizer.step()

            train_loss += loss.item() * images.size(0)
            preds = (torch.sigmoid(logits) >= 0.5).float()
            train_correct += (preds == labels).sum().item()
            train_total += images.size(0)

            if (batch_idx + 1) % 50 == 0 or (batch_idx + 1) == len(train_loader):
                batch_acc = train_correct / train_total
                print(f"  Epoch [{epoch}/{epochs}] Batch [{batch_idx+1}/{len(train_loader)}] Loss: {loss.item():.4f} Acc: {batch_acc:.4f}")

        scheduler.step()
        ep_duration = time.time() - ep_start
        train_acc = train_correct / train_total
        avg_train_loss = train_loss / train_total

        # Validation phase
        model.eval()
        val_loss = 0.0
        all_preds = []
        all_probs = []
        all_targets = []

        with torch.no_grad():
            for images, labels in val_loader:
                images = images.to(device)
                labels = labels.float().unsqueeze(1).to(device)
                logits = model(images)
                loss = criterion(logits, labels)
                val_loss += loss.item() * images.size(0)

                probs = torch.sigmoid(logits).cpu().numpy().flatten()
                preds = (probs >= 0.5).astype(int)

                all_probs.extend(probs.tolist())
                all_preds.extend(preds.tolist())
                all_targets.extend(labels.cpu().numpy().flatten().astype(int).tolist())

        val_total = len(all_targets)
        avg_val_loss = val_loss / val_total
        val_acc = accuracy_score(all_targets, all_preds)
        val_prec = precision_score(all_targets, all_preds, zero_division=0)
        val_rec = recall_score(all_targets, all_preds, zero_division=0)
        val_f1 = f1_score(all_targets, all_preds, zero_division=0)
        val_auc = roc_auc_score(all_targets, all_probs)

        print(f"\n  [Epoch {epoch} Summary] Time: {ep_duration:.1f}s | Train Acc: {train_acc:.4f} | Val Acc: {val_acc:.4f} | Val F1: {val_f1:.4f} | Val AUC: {val_auc:.4f}")

        if val_acc > best_val_acc:
            best_val_acc = val_acc
            output_model.parent.mkdir(parents=True, exist_ok=True)
            torch.save(model.state_dict(), output_model)
            print(f"  [CHECKPOINT] Saved best model to {output_model.resolve()} (Val Acc: {val_acc:.4f})")

            best_metrics = {
                "version": MODEL_VERSION,
                "model_name": "CyberNeura Synthetic Detector CNN",
                "framework": "PyTorch",
                "device": str(device),
                "accuracy": round(float(val_acc), 4),
                "precision": round(float(val_prec), 4),
                "recall": round(float(val_rec), 4),
                "f1_score": round(float(val_f1), 4),
                "roc_auc": round(float(val_auc), 4),
                "training_samples": len(train_tuples),
                "test_samples": len(val_tuples),
                "training_date": date.today().isoformat(),
                "epochs_trained": epochs,
                "best_epoch": epoch,
                "batch_size": batch_size,
                "dataset": "GenImage-CIFAKE Benchmark (Real vs Synthetic)",
                "classes": ["real_authentic", "ai_synthetic"],
            }

    total_time = time.time() - t_start
    print(f"\n{'='*65}")
    print(f"  IMAGE MODEL TRAINING COMPLETE IN {total_time:.1f}s")
    print(f"  Best Validation Accuracy: {best_val_acc:.4f} ({best_val_acc*100:.2f}%)")
    print(f"{'='*65}")

    # Write metadata
    output_meta.parent.mkdir(parents=True, exist_ok=True)
    with open(output_meta, "w", encoding="utf-8") as f:
        json.dump(best_metrics, f, indent=2)
    print(f"[INFO] Metadata saved to {output_meta.resolve()}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train CyberNeura Image Synthetic Detector")
    parser.add_argument("--dataset", type=str, default=str(DEFAULT_ARCHIVE_PATH), help="Path to archive dataset")
    parser.add_argument("--samples_per_class", type=int, default=6000, help="Train samples per class (0 for all)")
    parser.add_argument("--val_samples_per_class", type=int, default=1500, help="Val samples per class")
    parser.add_argument("--epochs", type=int, default=5, help="Number of training epochs")
    parser.add_argument("--batch_size", type=int, default=64, help="Batch size")
    parser.add_argument("--lr", type=float, default=0.001, help="Learning rate")
    args = parser.parse_args()

    train_image_model(
        data_dir=Path(args.dataset),
        samples_per_class=args.samples_per_class,
        val_samples_per_class=args.val_samples_per_class,
        epochs=args.epochs,
        batch_size=args.batch_size,
        lr=args.lr,
    )
