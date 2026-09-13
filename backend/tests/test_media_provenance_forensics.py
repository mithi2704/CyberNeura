"""
Tests for Media Provenance (C2PA/EXIF) and Forensics (ELA/Noise) (Phase 7).
"""
import io
import pytest
import numpy as np
from PIL import Image

from app.media.image.provenance import analyze_provenance
from app.media.image.forensics import analyze_image_forensics, compute_error_level_analysis, analyze_noise_inconsistency
from app.media.models import ProvenanceStatus


def test_provenance_absent_invariant():
    """Verify that absent provenance manifests do NOT mark the image as fake."""
    prov = analyze_provenance(b"\x00" * 50, {"media_id": "test-med-01"})

    assert prov.status == ProvenanceStatus.PROVENANCE_ABSENT
    assert prov.verified is False


def test_c2pa_manifest_detected():
    """Verify C2PA header byte signature recognition."""
    fake_c2pa_bytes = b"\x00" * 20 + b"c2pa" + b"\x00" * 40
    prov = analyze_provenance(fake_c2pa_bytes, {"media_id": "test-med-02"})

    assert prov.status in (ProvenanceStatus.PROVENANCE_CONFIRMED, ProvenanceStatus.PROVENANCE_PRESENT)
    assert len(prov.claims) >= 1


def test_error_level_analysis_and_noise_forensics():
    """Verify ELA and spatial quadrant noise computation."""
    buf = io.BytesIO()
    arr = np.ones((100, 100, 3), dtype=np.uint8) * 128
    arr[0:50, 0:50, :] = np.random.randint(0, 255, (50, 50, 3), dtype=np.uint8)
    img = Image.fromarray(arr)
    img.save(buf, format="JPEG")
    raw_bytes = buf.getvalue()

    ela_res = compute_error_level_analysis(raw_bytes)
    assert "signal_type" in ela_res
    assert ela_res["signal_type"] == "error_level_analysis"

    noise_res = analyze_noise_inconsistency(arr)
    assert "signal_type" in noise_res
    assert noise_res["signal_type"] == "noise_variance"

    results = analyze_image_forensics(raw_bytes, arr, "test-med-03")
    assert len(results) >= 2
