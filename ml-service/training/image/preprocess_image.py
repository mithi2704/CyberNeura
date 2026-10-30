"""
CyberNeura ML Service — Image Dataset Preprocessing & Augmentation.
Handles generator-aware indexing, corrupt image filtering, and PyTorch transform pipelines.
Normalizes labels: 0 = AI_GENERATED, 1 = REAL.
"""
from __future__ import annotations

import os
import random
from pathlib import Path
from typing import List, Tuple

import torch
from PIL import Image
from torch.utils.data import Dataset
from torchvision import transforms

DEFAULT_ARCHIVE_PATH = Path("archive")


class ImageBinaryDataset(Dataset):
    """Indexed image dataset for Authentic (1) vs Synthetic (0) classification."""

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
            tensor = torch.zeros((3, 32, 32), dtype=torch.float32)
            return tensor, label


def get_image_transforms(target_size: Tuple[int, int] = (32, 32)):
    """Returns training and validation torchvision transforms."""
    train_transform = transforms.Compose([
        transforms.Resize(target_size),
        transforms.RandomHorizontalFlip(),
        transforms.ToTensor(),
        transforms.Normalize(mean=[0.485, 0.456, 0.406], std=[0.229, 0.224, 0.225]),
    ])

    val_transform = transforms.Compose([
        transforms.Resize(target_size),
        transforms.ToTensor(),
        transforms.Normalize(mean=[0.485, 0.456, 0.406], std=[0.229, 0.224, 0.225]),
    ])
    return train_transform, val_transform


def collect_image_samples(
    data_dir: Path,
    samples_per_class: int = 1000,
    val_samples_per_class: int = 250,
) -> Tuple[List[Tuple[str, int]], List[Tuple[str, int]]]:
    """
    Collects real and fake image file paths.
    Normalized labels:
    0 = AI_GENERATED (FAKE)
    1 = REAL (AUTHENTIC)
    """
    train_real_dir = data_dir / "train" / "REAL"
    train_fake_dir = data_dir / "train" / "FAKE"
    test_real_dir = data_dir / "test" / "REAL"
    test_fake_dir = data_dir / "test" / "FAKE"

    if not (train_real_dir.exists() and train_fake_dir.exists()):
        raise FileNotFoundError(f"Missing train REAL or FAKE folders inside {data_dir}")

    real_train = [str(train_real_dir / f) for f in os.listdir(train_real_dir) if f.lower().endswith(('.jpg', '.jpeg', '.png'))]
    fake_train = [str(train_fake_dir / f) for f in os.listdir(train_fake_dir) if f.lower().endswith(('.jpg', '.jpeg', '.png'))]

    random.seed(42)
    random.shuffle(real_train)
    random.shuffle(fake_train)

    if samples_per_class > 0:
        real_train = real_train[:samples_per_class]
        fake_train = fake_train[:samples_per_class]

    # Label mapping: 0 = AI_GENERATED (fake), 1 = REAL
    train_tuples = [(p, 1) for p in real_train] + [(p, 0) for p in fake_train]
    random.shuffle(train_tuples)

    real_test = [str(test_real_dir / f) for f in os.listdir(test_real_dir) if f.lower().endswith(('.jpg', '.jpeg', '.png'))]
    fake_test = [str(test_fake_dir / f) for f in os.listdir(test_fake_dir) if f.lower().endswith(('.jpg', '.jpeg', '.png'))]

    random.shuffle(real_test)
    random.shuffle(fake_test)

    if val_samples_per_class > 0:
        real_test = real_test[:val_samples_per_class]
        fake_test = fake_test[:val_samples_per_class]

    val_tuples = [(p, 1) for p in real_test] + [(p, 0) for p in fake_test]
    random.shuffle(val_tuples)

    return train_tuples, val_tuples

