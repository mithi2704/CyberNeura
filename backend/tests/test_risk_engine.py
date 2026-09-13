"""
Tests for Risk Engine and scoring heuristics.
"""
from app.services.risk_engine import (
    calculate_risk_score,
    classify,
    get_threat_category,
    generate_explanation,
    generate_recommendations,
)


def test_safe_risk_score():
    features = {
        "uses_https": True,
        "has_ip_hostname": False,
        "is_suspicious_tld": False,
        "has_phishing_keyword": False,
        "has_at_symbol": False,
        "is_url_shortener": False,
        "url_length": 25,
        "num_subdomains": 0,
        "url_entropy": 3.2,
    }
    dns_data = {"status": "ok", "a": ["142.250.190.46"]}
    whois_data = {"status": "ok", "creation_date": "2015-01-01", "country": "US"}

    score = calculate_risk_score(probability=0.05, features=features, whois_data=whois_data, dns_data=dns_data)
    assert 0 <= score <= 30
    assert classify(score) == "safe"


def test_malicious_risk_score():
    features = {
        "uses_https": False,
        "has_ip_hostname": True,
        "is_suspicious_tld": True,
        "has_phishing_keyword": True,
        "has_at_symbol": True,
        "is_url_shortener": False,
        "url_length": 95,
        "num_subdomains": 3,
        "url_entropy": 4.8,
    }
    dns_data = {"status": "no_records"}
    whois_data = {"status": "lookup_failed"}

    score = calculate_risk_score(probability=0.95, features=features, whois_data=whois_data, dns_data=dns_data)
    assert score >= 70
    assert classify(score) == "malicious"


def test_classify_threat_category():
    features_phish = {"has_phishing_keyword": True, "has_ip_hostname": False}
    assert get_threat_category("malicious", features_phish) == "Phishing"

    features_malware = {"has_phishing_keyword": False, "is_suspicious_tld": True}
    assert get_threat_category("malicious", features_malware) == "Malware"

    features_safe = {"has_phishing_keyword": False, "has_ip_hostname": False}
    assert get_threat_category("safe", features_safe) == "Safe"


def test_generate_recommendations():
    recs_mal = generate_recommendations("malicious", 90, {"uses_https": False, "has_phishing_keyword": True}, {})
    assert len(recs_mal) >= 2
    assert any("block" in r.lower() or "not" in r.lower() for r in recs_mal)

    recs_safe = generate_recommendations("safe", 10, {"uses_https": True}, {})
    assert len(recs_safe) >= 1
