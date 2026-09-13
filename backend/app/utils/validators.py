"""URL validation helpers with SSRF protection."""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

import validators

BLOCKED_PRIVATE_RANGES = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]

ALLOWED_SCHEMES = {"http", "https"}
BLOCKED_SCHEMES = {"javascript", "file", "data", "vbscript", "ftp", "blob"}
MAX_URL_LENGTH = 2048


def validate_url(url: str) -> tuple[bool, str]:
    """
    Validate a URL for scanning.
    Returns (is_valid, error_message).
    """
    if not url or not url.strip():
        return False, "URL cannot be empty"

    url = url.strip()

    if len(url) > MAX_URL_LENGTH:
        return False, f"URL exceeds maximum length of {MAX_URL_LENGTH} characters"

    # Check raw scheme if present
    raw_parsed = urlparse(url)
    if raw_parsed.scheme:
        scheme = raw_parsed.scheme.lower()
        if scheme in BLOCKED_SCHEMES:
            return False, f"URL scheme '{scheme}' is not allowed"
        if scheme not in ALLOWED_SCHEMES:
            return False, "Only http and https URLs are allowed"
    else:
        # Auto-prepend https:// if no scheme present
        url = f"https://{url}"

    try:
        parsed = urlparse(url)
    except Exception:
        return False, "Malformed URL"

    scheme = parsed.scheme.lower()
    if scheme in BLOCKED_SCHEMES:
        return False, f"URL scheme '{scheme}' is not allowed"
    if scheme not in ALLOWED_SCHEMES:
        return False, "Only http and https URLs are allowed"

    hostname = parsed.hostname or ""
    if not hostname:
        return False, "URL has no valid hostname"

    # Block localhost variants
    if hostname.lower() in ("localhost", "0.0.0.0", "::1"):
        return False, "Scanning localhost is not permitted"

    # Block raw IP in private ranges (SSRF protection)
    try:
        ip = ipaddress.ip_address(hostname)
        for net in BLOCKED_PRIVATE_RANGES:
            if ip in net:
                return False, "Scanning private network addresses is not permitted"
    except ValueError:
        pass  # hostname is a domain, not a raw IP — OK

    return True, ""


def normalize_url(url: str) -> str:
    """Normalize URL — add https:// if missing and strip root trailing slashes."""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    try:
        parsed = urlparse(url)
        if parsed.path == "/" and not parsed.query and not parsed.fragment:
            url = url.rstrip("/")
    except Exception:
        pass
    return url


def extract_domain(url: str) -> str:
    """Extract the hostname from a URL."""
    try:
        parsed = urlparse(normalize_url(url))
        return parsed.hostname or url
    except Exception:
        return url


def normalize_domain(url_or_domain: str) -> str:
    """Normalize domain/hostname from a domain string or URL."""
    d = extract_domain(url_or_domain)
    if d.startswith("www."):
        d = d[4:]
    return d.lower().strip()

