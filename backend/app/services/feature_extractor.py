"""
URL Feature Extraction Pipeline.
Extracts a numeric feature vector from a URL for ML inference.
"""
from __future__ import annotations

import re
import math
from urllib.parse import urlparse, parse_qs
from typing import Dict, Any

import tldextract

# Suspicious TLDs commonly associated with abuse
SUSPICIOUS_TLDS = {
    "ru", "tk", "ml", "ga", "cf", "gq", "xyz", "top",
    "club", "online", "site", "info", "biz", "pw",
    "cn", "cc", "ws", "in", "vn", "br",
}

PHISHING_KEYWORDS = {
    "verify", "login", "signin", "account", "secure", "banking", "update",
    "confirm", "password", "paypal", "amazon", "apple", "microsoft",
    "google", "facebook", "netflix", "bank", "wallet", "crypto",
    "invoice", "support", "alert", "suspended", "unusual",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly",
    "is.gd", "buff.ly", "adf.ly", "short.io",
}


def extract_features(url: str) -> Dict[str, Any]:
    """
    Extract a rich feature set from a URL.
    Returns a dict of named features.
    """
    # Normalize
    raw_url = url.strip()
    if not raw_url.startswith(("http://", "https://")):
        raw_url = f"https://{raw_url}"

    try:
        parsed = urlparse(raw_url)
    except Exception:
        return _empty_features(url)

    # Normalize root trailing slash: https://example.com/ -> https://example.com
    if parsed.path == "/" and not parsed.query and not parsed.fragment:
        raw_url = raw_url.rstrip("/")
        parsed = urlparse(raw_url)

    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""
    fragment = parsed.fragment or ""
    ext = tldextract.extract(raw_url)

    domain = ext.domain or hostname
    suffix = ext.suffix or ""
    subdomain = ext.subdomain or ""

    clean_path = path.strip("/")
    path_segments = [p for p in clean_path.split("/") if p]

    # ── Structural features ───────────────────────────────────
    url_length = len(raw_url)
    hostname_length = len(hostname)
    path_length = len(clean_path)
    query_length = len(query)
    num_params = len(parse_qs(query))
    num_dots = raw_url.count(".")
    num_hyphens = hostname.count("-")
    num_underscores = raw_url.count("_")
    num_digits = sum(c.isdigit() for c in hostname)
    num_special = sum(not c.isalnum() and c not in ".-" for c in hostname)
    num_subdomains = len(subdomain.split(".")) if subdomain else 0
    path_depth = len(path_segments)
    num_slashes = len(path_segments)

    # ── Security indicators ────────────────────────────────────
    uses_https = parsed.scheme == "https"
    has_ip_hostname = _is_ip_address(hostname)
    is_suspicious_tld = suffix.split(".")[-1].lower() in SUSPICIOUS_TLDS if suffix else False
    has_phishing_keyword = any(kw in raw_url.lower() for kw in PHISHING_KEYWORDS)
    has_at_symbol = "@" in raw_url
    has_double_slash = "//" in path
    has_hex_encoding = bool(re.search(r"%[0-9a-fA-F]{2}", raw_url))
    is_url_shortener = hostname.lower() in URL_SHORTENERS
    uses_punycode = "xn--" in hostname.lower()
    has_suspicious_port = parsed.port is not None and parsed.port not in (80, 443)
    domain_has_numbers = bool(re.search(r"\d", domain))
    subdomain_depth = num_subdomains
    has_brand_in_subdomain = any(kw in subdomain.lower() for kw in PHISHING_KEYWORDS) if subdomain else False

    # ── Entropy ───────────────────────────────────────────────
    url_entropy = _shannon_entropy(raw_url)
    domain_entropy = _shannon_entropy(domain)

    features = {
        # Structural
        "url_length": url_length,
        "hostname_length": hostname_length,
        "path_length": path_length,
        "query_length": query_length,
        "num_params": num_params,
        "num_dots": num_dots,
        "num_hyphens": num_hyphens,
        "num_underscores": num_underscores,
        "num_digits_in_hostname": num_digits,
        "num_special_chars": num_special,
        "num_subdomains": num_subdomains,
        "path_depth": path_depth,
        "num_slashes": num_slashes,
        # Security
        "uses_https": int(uses_https),
        "has_ip_hostname": int(has_ip_hostname),
        "is_suspicious_tld": int(is_suspicious_tld),
        "has_phishing_keyword": int(has_phishing_keyword),
        "has_at_symbol": int(has_at_symbol),
        "has_double_slash": int(has_double_slash),
        "has_hex_encoding": int(has_hex_encoding),
        "is_url_shortener": int(is_url_shortener),
        "uses_punycode": int(uses_punycode),
        "has_suspicious_port": int(has_suspicious_port),
        "domain_has_numbers": int(domain_has_numbers),
        "subdomain_depth": subdomain_depth,
        "has_brand_in_subdomain": int(has_brand_in_subdomain),
        # Entropy
        "url_entropy": round(url_entropy, 4),
        "domain_entropy": round(domain_entropy, 4),
    }

    return features


FEATURE_ORDER = [
    "url_length", "hostname_length", "path_length", "query_length",
    "num_params", "num_dots", "num_hyphens", "num_underscores",
    "num_digits_in_hostname", "num_special_chars", "num_subdomains",
    "path_depth", "num_slashes",
    "uses_https", "has_ip_hostname", "is_suspicious_tld",
    "has_phishing_keyword", "has_at_symbol", "has_double_slash",
    "has_hex_encoding", "is_url_shortener", "uses_punycode",
    "has_suspicious_port", "domain_has_numbers", "subdomain_depth",
    "has_brand_in_subdomain", "url_entropy", "domain_entropy",
]


def get_feature_vector(features: Dict[str, Any]) -> list:
    """Convert feature dict to ordered numeric list for ML inference."""
    return [features.get(k, 0) for k in FEATURE_ORDER]


def _is_ip_address(hostname: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


calculate_shannon_entropy = _shannon_entropy



def _empty_features(url: str) -> Dict[str, Any]:
    return {k: 0 for k in [
        "url_length", "hostname_length", "path_length", "query_length",
        "num_params", "num_dots", "num_hyphens", "num_underscores",
        "num_digits_in_hostname", "num_special_chars", "num_subdomains",
        "path_depth", "num_slashes", "uses_https", "has_ip_hostname",
        "is_suspicious_tld", "has_phishing_keyword", "has_at_symbol",
        "has_double_slash", "has_hex_encoding", "is_url_shortener",
        "uses_punycode", "has_suspicious_port", "domain_has_numbers",
        "subdomain_depth", "has_brand_in_subdomain", "url_entropy", "domain_entropy",
    ]}
