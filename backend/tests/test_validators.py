"""
Tests for URL validation and SSRF protection.
"""
import pytest
from app.utils.validators import validate_url, normalize_url, extract_domain


def test_validate_valid_urls():
    valid, err = validate_url("https://www.google.com")
    assert valid is True
    assert err == ""

    # Normalization of scheme
    normalized = normalize_url("github.com/torvalds/linux")
    assert normalized.startswith("https://")


def test_validate_ssrf_blocking_localhost():
    valid, err = validate_url("http://127.0.0.1:8080")
    assert valid is False
    assert "private" in err.lower() or "localhost" in err.lower()

    valid, err = validate_url("http://localhost:3000")
    assert valid is False
    assert "localhost" in err.lower()


def test_validate_ssrf_blocking_internal_ranges():
    for blocked in ["http://10.0.0.1", "http://192.168.1.1", "http://172.16.0.1", "http://169.254.169.254"]:
        valid, err = validate_url(blocked)
        assert valid is False
        assert "private" in err.lower()


def test_validate_disallowed_schemes():
    for bad_scheme in ["javascript:alert(1)", "file:///etc/passwd", "ftp://example.com"]:
        valid, err = validate_url(bad_scheme)
        assert valid is False
        assert "not allowed" in err.lower()


def test_validate_empty_url():
    valid, err = validate_url("")
    assert valid is False
    assert "empty" in err.lower()


def test_extract_domain():
    assert extract_domain("https://cyberneura.io/scans/123") == "cyberneura.io"
    assert extract_domain("google.com") == "google.com"
