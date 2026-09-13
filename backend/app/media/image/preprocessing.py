"""
Image Preprocessing Pipeline for CyberNeura Media Security.
Decodes images safely, extracts raw metadata, normalizes color spaces,
and generates model input tensors without altering the original bitstream.
"""
from __future__ import annotations

import io
from typing import Any, Dict, Tuple
from PIL import Image, ExifTags
import numpy as np
import torch


def extract_image_metadata(img: Image.Image) -> Dict[str, Any]:
    """Extracts safe metadata and EXIF properties from a PIL image."""
    meta: Dict[str, Any] = {
        "format": img.format,
        "mode": img.mode,
        "width": img.width,
        "height": img.height,
        "has_exif": False,
        "has_icc_profile": "icc_profile" in img.info,
    }

    try:
        exif_raw = img.getexif()
        if exif_raw:
            meta["has_exif"] = True
            exif_dict: Dict[str, Any] = {}
            for tag_id, value in exif_raw.items():
                tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
                # Only keep scalar/text values for audit safety
                if isinstance(value, (str, int, float)):
                    exif_dict[tag_name] = value
                elif isinstance(value, bytes):
                    exif_dict[tag_name] = f"<{len(value)} bytes binary>"
            meta["exif"] = exif_dict
    except Exception:
        meta["exif_error"] = "Failed to parse EXIF tags"

    # Extract other safe info tags (e.g. software, comment)
    info_clean = {}
    for k, v in img.info.items():
        if k in ("software", "comment", "description", "copyright"):
            info_clean[k] = str(v)[:256]
    if info_clean:
        meta["info"] = info_clean

    return meta


def preprocess_image_for_model(
    file_bytes: bytes,
    target_size: Tuple[int, int] = (256, 256),
    device: str = "cpu",
) -> Tuple[torch.Tensor, np.ndarray, Dict[str, Any]]:
    """
    Decodes the image, preserves original metadata, normalizes to RGB,
    generates a normalized numpy array, and converts to a float32 PyTorch tensor (1, C, H, W).
    """
    with Image.open(io.BytesIO(file_bytes)) as img:
        metadata = extract_image_metadata(img)
        # Convert to RGB (handles RGBA, Grayscale, CMYK, Palette)
        rgb_img = img.convert("RGB")
        # High quality bilinear resize for model input
        resized_img = rgb_img.resize(target_size, Image.Resampling.BILINEAR)
        # Full resolution numpy array for forensics (noise, frequency, ELA)
        np_full = np.array(rgb_img, dtype=np.uint8)

    # Convert resized to normalized float tensor: [0, 1] range, (1, 3, H, W)
    np_resized = np.array(resized_img, dtype=np.float32) / 255.0
    tensor = torch.from_numpy(np_resized).permute(2, 0, 1).unsqueeze(0).to(device)

    return tensor, np_full, metadata
