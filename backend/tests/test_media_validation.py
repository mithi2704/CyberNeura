"""
Tests for Media Validation, Magic Bytes, Decompression Bomb Bounds (Phase 7).
"""
import io
import pytest
from PIL import Image

from app.media.validators import (
    validate_image_file,
    validate_video_file,
    MediaValidationError,
)


def create_test_png(width=100, height=100, color=(255, 0, 0)) -> bytes:
    buf = io.BytesIO()
    img = Image.new("RGB", (width, height), color=color)
    img.save(buf, format="PNG")
    return buf.getvalue()


def create_test_jpeg(width=100, height=100) -> bytes:
    buf = io.BytesIO()
    img = Image.new("RGB", (width, height), color=(0, 255, 0))
    img.save(buf, format="JPEG")
    return buf.getvalue()


def test_validate_valid_image():
    png_bytes = create_test_png(120, 120)
    fmt, mime, w, h = validate_image_file(png_bytes, "sample.png")
    assert fmt == "PNG"
    assert mime == "image/png"
    assert w == 120
    assert h == 120

    jpeg_bytes = create_test_jpeg(80, 80)
    fmt2, mime2, w2, h2 = validate_image_file(jpeg_bytes, "sample.jpg")
    assert fmt2 == "JPEG"
    assert mime2 == "image/jpeg"
    assert w2 == 80


def test_detect_video_magic_bytes():
    # MP4 ftyp box
    mp4_bytes = b"\x00\x00\x00\x18ftypmp42\x00\x00\x00\x00" + b"\x00" * 100
    fmt, mime = validate_video_file(mp4_bytes, "sample.mp4")
    assert fmt == "MP4"
    assert mime == "video/mp4"

    # WebM EBML header
    webm_bytes = b"\x1a\x45\xdf\xa3" + b"\x00" * 100
    fmt, mime = validate_video_file(webm_bytes, "sample.webm")
    assert fmt == "WEBM"
    assert mime == "video/webm"


def test_validate_invalid_magic_bytes():
    fake_png = b"This is not a real image at all"
    with pytest.raises(MediaValidationError) as exc_info:
        validate_image_file(fake_png, "fake.png")
    assert "Unsupported" in str(exc_info.value)


def test_decompression_bomb_bounds():
    # Large pixel bounds
    fake_header = b"\x89PNG\r\n\x1a\n"
    with pytest.raises(MediaValidationError):
        validate_image_file(b"\x00" * 20, "corrupt.png")
