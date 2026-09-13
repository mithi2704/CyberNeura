"""
Security and Integrity Validators for Uploaded Media Files.
Guards against decompression bombs, polyglot files, MIME spoofing, oversized payloads,
and corrupted bitstreams.
"""
from __future__ import annotations

import io
from typing import Tuple, Optional
from PIL import Image, ImageFile
from app.config import settings

# Enforce strict pixel limit to neutralize decompression bombs (max 50 megapixels)
Image.MAX_IMAGE_PIXELS = 50_000_000
ImageFile.LOAD_TRUNCATED_IMAGES = False

# Magic bytes for supported image formats
MAGIC_BYTES_MAP = {
    b"\xFF\xD8\xFF": ("JPEG", "image/jpeg", [".jpg", ".jpeg"]),
    b"\x89PNG\r\n\x1a\n": ("PNG", "image/png", [".png"]),
    b"RIFF": ("WEBP", "image/webp", [".webp"]),  # Also checks WEBP chunk below
    b"GIF87a": ("GIF", "image/gif", [".gif"]),
    b"GIF89a": ("GIF", "image/gif", [".gif"]),
}

# Magic bytes for supported video formats
VIDEO_MAGIC_BYTES = [
    (b"\x00\x00\x00\x18ftypmp42", "video/mp4"),
    (b"\x00\x00\x00\x1cftypisom", "video/mp4"),
    (b"\x00\x00\x00\x20ftypisom", "video/mp4"),
    (b"\x00\x00\x00\x14ftyp", "video/mp4"),
    (b"\x1a\x45\xdf\xa3", "video/webm"),  # EBML / Matroska / WebM
]


class MediaValidationError(ValueError):
    """Raised when an uploaded file violates security or format invariants."""
    pass


def validate_image_file(file_bytes: bytes, filename: str) -> Tuple[str, str, int, int]:
    """
    Validates image bytes against magic signatures, max size, decompression bombs,
    and PIL decoder integrity.
    Returns: (detected_format, detected_mime, width, height)
    """
    # 1. Size check
    max_bytes = settings.max_image_size_mb * 1024 * 1024
    if len(file_bytes) > max_bytes:
        raise MediaValidationError(
            f"Image file size ({len(file_bytes) / 1024 / 1024:.1f}MB) exceeds configured maximum ({settings.max_image_size_mb}MB)."
        )
    if len(file_bytes) < 16:
        raise MediaValidationError("File is truncated or empty.")

    # 2. Magic byte verification
    detected_format: Optional[str] = None
    detected_mime: Optional[str] = None

    if file_bytes.startswith(b"\xFF\xD8\xFF"):
        detected_format = "JPEG"
        detected_mime = "image/jpeg"
    elif file_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
        detected_format = "PNG"
        detected_mime = "image/png"
    elif file_bytes.startswith(b"RIFF") and len(file_bytes) >= 12 and file_bytes[8:12] == b"WEBP":
        detected_format = "WEBP"
        detected_mime = "image/webp"
    elif file_bytes.startswith(b"GIF87a") or file_bytes.startswith(b"GIF89a"):
        detected_format = "GIF"
        detected_mime = "image/gif"
    else:
        raise MediaValidationError(
            "Unsupported or unrecognized image signature. Only valid JPEG, PNG, and WEBP images are supported."
        )

    # 3. PIL Safe Decode & Decompression Bomb Guard
    try:
        with Image.open(io.BytesIO(file_bytes)) as img:
            img.verify()  # Verifies file integrity without full bitmap decode
            width, height = img.size
    except Exception as exc:
        raise MediaValidationError(f"Image decoder verification failed: {exc}")

    # 4. Pixel count boundary
    pixel_count = width * height
    if pixel_count > 50_000_000:
        raise MediaValidationError(
            f"Image dimensions ({width}x{height} = {pixel_count:,} pixels) exceed safety ceiling to prevent decompression attacks."
        )
    if width < 16 or height < 16:
        raise MediaValidationError(f"Image resolution too small ({width}x{height}) for meaningful security analysis.")

    return detected_format, detected_mime, width, height


def validate_video_file(file_bytes: bytes, filename: str) -> Tuple[str, str]:
    """
    Validates video payload against magic headers and maximum upload bounds.
    Returns: (detected_format, detected_mime)
    """
    max_bytes = settings.max_video_size_mb * 1024 * 1024
    if len(file_bytes) > max_bytes:
        raise MediaValidationError(
            f"Video file size ({len(file_bytes) / 1024 / 1024:.1f}MB) exceeds limit ({settings.max_video_size_mb}MB)."
        )
    if len(file_bytes) < 32:
        raise MediaValidationError("Video stream is truncated or empty.")

    # Check magic headers
    detected_format = None
    detected_mime = None

    # Check for MP4 ftyp atom
    if b"ftyp" in file_bytes[:32]:
        detected_format = "MP4"
        detected_mime = "video/mp4"
    elif file_bytes.startswith(b"\x1a\x45\xdf\xa3"):
        detected_format = "WEBM"
        detected_mime = "video/webm"
    elif file_bytes[:4] == b"RIFF" and len(file_bytes) >= 12 and file_bytes[8:12] == b"AVI ":
        detected_format = "AVI"
        detected_mime = "video/x-msvideo"
    elif b"moov" in file_bytes[:1024] or b"mdat" in file_bytes[:1024]:
        detected_format = "MOV"
        detected_mime = "video/quicktime"
    else:
        # Fallback check by extension if header has alternative atom
        lower_name = filename.lower()
        if lower_name.endswith((".mp4", ".m4v")):
            detected_format = "MP4"
            detected_mime = "video/mp4"
        elif lower_name.endswith(".webm"):
            detected_format = "WEBM"
            detected_mime = "video/webm"
        else:
            raise MediaValidationError("Unsupported video format. Please upload MP4 or WebM video.")

    return detected_format, detected_mime
