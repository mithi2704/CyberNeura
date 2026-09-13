"""
Tests for URL feature extraction pipeline.
"""
from app.services.feature_extractor import (
    extract_features,
    get_feature_vector,
    _shannon_entropy,
    _is_ip_address,
)


def test_extract_features_safe_url():
    features = extract_features("https://www.google.com/search?q=cybersecurity")
    assert bool(features["uses_https"]) is True
    assert bool(features["has_ip_hostname"]) is False
    assert bool(features["is_suspicious_tld"]) is False
    assert features["url_length"] > 10
    assert features["num_dots"] >= 1
    assert features["url_entropy"] > 0


def test_extract_features_ip_address():
    features = extract_features("http://192.168.1.1:8080/admin/login.php")
    assert bool(features["has_ip_hostname"]) is True
    assert bool(features["uses_https"]) is False
    assert bool(features["has_suspicious_port"]) is True
    assert bool(features["has_phishing_keyword"]) is True


def test_extract_features_suspicious_tld():
    features = extract_features("http://free-crypto-giveaway.xyz")
    assert bool(features["is_suspicious_tld"]) is True
    assert bool(features["uses_https"]) is False


def test_feature_vector_length():
    features = extract_features("https://github.com/torvalds/linux")
    vector = get_feature_vector(features)
    assert len(vector) == 28
    assert all(isinstance(v, (int, float)) for v in vector)


def test_shannon_entropy():
    # Low entropy: repeated characters
    low = _shannon_entropy("aaaaaaa")
    # High entropy: diverse string
    high = _shannon_entropy("a8!9z#q1$Lm")
    assert high > low


def test_is_ip_address():
    assert _is_ip_address("192.168.0.1") is True
    assert _is_ip_address("10.0.0.1") is True
    assert _is_ip_address("google.com") is False
    assert _is_ip_address("192.168.com") is False
