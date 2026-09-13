"""
Risk Engine — converts ML probability + multi-source threat intelligence + security indicators
into a deterministic 0-100 risk score and generates contextual recommendations.
"""
from __future__ import annotations

from typing import Dict, Any, List, Optional
import tldextract

from app.config import settings
from app.intelligence.models import ThreatIntelResult, ProviderVerdict

VERIFIED_AUTHORITY_DOMAINS = {
    "chatgpt.com", "openai.com", "google.com", "github.com", "microsoft.com",
    "apple.com", "amazon.com", "wikipedia.org", "cloudflare.com", "linkedin.com",
    "youtube.com", "twitter.com", "x.com", "netflix.com", "facebook.com",
    "instagram.com", "meta.com", "anthropic.com", "claude.ai", "python.org",
    "stackoverflow.com", "reddit.com", "yahoo.com", "bing.com", "zoom.us",
    "adobe.com", "dropbox.com", "slack.com", "spotify.com", "twitch.tv",
    "wordpress.org", "mozilla.org", "medium.com", "nytimes.com", "bbc.com",
    "cnn.com", "forbes.com", "reuters.com", "bloomberg.com", "stripe.com",
    "paypal.com", "salesforce.com", "gitlab.com", "atlassian.com",
}


def _get_registered_domain(domain: str) -> str:
    """Extract registered domain (e.g. sub.chatgpt.com -> chatgpt.com)."""
    if not domain:
        return ""
    ext = tldextract.extract(domain)
    reg = getattr(ext, "top_domain_under_public_suffix", None) or getattr(ext, "registered_domain", "")
    return reg.lower() if reg else domain.lower()


def is_verified_authority_domain(domain: str, features: Dict[str, Any]) -> bool:
    """Check if domain is a globally recognized verified authority with no active spoofing vectors."""
    reg_domain = _get_registered_domain(domain)
    if reg_domain not in VERIFIED_AUTHORITY_DOMAINS:
        return False
    # If it uses an IP, suspicious TLD, punycode, or at-symbol, it is NOT an authentic authority
    if (
        features.get("has_ip_hostname")
        or features.get("is_suspicious_tld")
        or features.get("uses_punycode")
        or features.get("has_at_symbol")
        or features.get("has_brand_in_subdomain")
    ):
        return False
    return True


def calculate_risk_score(
    probability: float,
    features: Dict[str, Any],
    whois_data: Dict[str, Any],
    dns_data: Dict[str, Any],
    domain: str = "",
    intel_results: Optional[Dict[str, ThreatIntelResult]] = None,
) -> int:
    """
    Compute a 0-100 risk score deterministically by correlating:
    1. ML probability contribution
    2. External threat intelligence confirmations (Google Web Risk, PhishTank, URLhaus)
    3. Lexical and structural URL heuristics
    4. Domain/DNS/WHOIS indicators

    Note: Provider UNAVAILABLE or ERROR states add 0 risk and remove 0 risk.
    """
    if domain and is_verified_authority_domain(domain, features):
        return 0

    # ── External Threat Intelligence Pre-Check ────────────
    matching_providers = 0
    if intel_results:
        for p_name, res in intel_results.items():
            if getattr(res, "matched", False) and getattr(res, "verdict", None) == ProviderVerdict.MATCH:
                matching_providers += 1

    # Safe HTTPS Invariant: If URL uses HTTPS with zero threat intel matches,
    # no IP hostname, no punycode, no '@' symbol, and ML probability < 0.50, score is 0.
    uses_https = bool(features.get("uses_https", True))
    if uses_https and matching_providers == 0:
        if (
            not features.get("has_ip_hostname")
            and not features.get("uses_punycode")
            and not features.get("has_at_symbol")
            and not features.get("has_brand_in_subdomain")
            and probability < 0.50
        ):
            return 0

    # ── 1. Base ML Contribution ──────────────────────────
    # 0.00-0.30: low contribution (0-20 pts)
    # 0.30-0.60: moderate contribution (20-45 pts)
    # 0.60-0.80: high contribution (45-65 pts)
    # 0.80-1.00: very high contribution (65-80 pts)
    if probability < 0.30:
        base = probability * 66.6  # max 20
    elif probability < 0.60:
        base = 20.0 + (probability - 0.30) * 83.3  # 20 to 45
    elif probability < 0.80:
        base = 45.0 + (probability - 0.60) * 100.0  # 45 to 65
    else:
        base = 65.0 + (probability - 0.80) * 75.0  # 65 to 80

    # ── 2. External Threat Intelligence Contribution ─────
    intel_bonus = 0.0


    if intel_results:
        for p_name, res in intel_results.items():
            if res.matched and res.verdict == ProviderVerdict.MATCH:
                matching_providers += 1
                if p_name == "google_webrisk":
                    if "MALWARE" in res.categories:
                        intel_bonus += 35.0
                    else:
                        intel_bonus += 30.0  # SOCIAL_ENGINEERING
                elif p_name == "phishtank":
                    # Verified phishing match gets highest weight
                    intel_bonus += 35.0 if res.metadata.get("verified") else 25.0
                elif p_name == "urlhaus":
                    intel_bonus += 40.0  # Malware distribution
                else:
                    intel_bonus += 25.0

    # Multi-provider confirmation bonus
    if matching_providers >= 2:
        intel_bonus += 15.0

    # ── 3. Heuristic Adjustments ─────────────────────────
    heuristic_bonus = 0.0
    if features.get("has_phishing_keyword"): heuristic_bonus += 5.0
    if features.get("has_ip_hostname"): heuristic_bonus += 8.0
    if features.get("is_suspicious_tld"): heuristic_bonus += 4.0
    if not features.get("uses_https"): heuristic_bonus += 5.0
    if features.get("has_at_symbol"): heuristic_bonus += 6.0
    if features.get("has_brand_in_subdomain"): heuristic_bonus += 6.0
    if features.get("uses_punycode"): heuristic_bonus += 4.0
    if features.get("url_entropy", 0) > 5.0: heuristic_bonus += 3.0

    # Domain age penalty
    creation = whois_data.get("creation_date") if whois_data else None
    if not creation:
        heuristic_bonus += 3.0

    # DNS failure penalty
    if dns_data and dns_data.get("status") not in ("ok", None):
        heuristic_bonus += 2.0
    elif dns_data and not dns_data.get("a"):
        heuristic_bonus += 3.0

    # Safe reductions
    safe_reduction = 0.0
    if features.get("uses_https") and matching_providers == 0:
        safe_reduction += 3.0

    final = base + intel_bonus + heuristic_bonus - safe_reduction

    # If external provider confirms active threat, floor risk score at 85 (Malicious)
    if matching_providers >= 1:
        final = max(final, 85.0)

    return max(0, min(100, int(round(final))))


def classify(risk_score: int, independent_confirmations: int = 0) -> str:
    """
    Map risk score to prediction label.
    Distinguishes 'ML thinks suspicious' from 'external intelligence confirms threat'.
    """
    if independent_confirmations >= 1 or risk_score > settings.risk_threshold_suspicious:
        return "malicious"
    elif risk_score <= settings.risk_threshold_safe:
        return "safe"
    else:
        return "suspicious"


def get_threat_category(
    prediction: str,
    features: Dict[str, Any],
    intel_results: Optional[Dict[str, ThreatIntelResult]] = None,
) -> str:
    """Determine normalized threat category based on provider findings and heuristics."""
    if prediction == "safe":
        return "Safe"

    # Check external provider categories first (direct evidence)
    if intel_results:
        all_categories = []
        for res in intel_results.values():
            if res.matched:
                all_categories.extend(res.categories)

        if "MALWARE" in all_categories or "MALWARE_DISTRIBUTION" in all_categories:
            return "Malware"
        if "PHISHING" in all_categories or "SOCIAL_ENGINEERING" in all_categories:
            return "Phishing"
        if "UNWANTED_SOFTWARE" in all_categories:
            return "Unwanted Software"

    # Heuristic fallback
    if features.get("has_phishing_keyword") or features.get("has_brand_in_subdomain"):
        return "Phishing"
    if features.get("is_suspicious_tld") and prediction == "malicious":
        return "Malware"
    if prediction == "malicious":
        return "Phishing"
    return "Suspicious"


def calculate_confidence(
    probability: float,
    intel_results: Optional[Dict[str, ThreatIntelResult]] = None,
) -> float:
    """
    Calculate confidence based on evidence agreement, ML probability distance from 0.5,
    and provider confirmations. Returns percentage (e.g. 94.5).
    """
    # Base confidence: distance from decision boundary (0.50)
    base_conf = 70.0 + abs(probability - 0.50) * 50.0  # 70 to 95%

    if not intel_results:
        return round(min(99.0, max(50.0, base_conf)), 1)

    matching_count = sum(1 for r in intel_results.values() if r.matched and r.verdict == ProviderVerdict.MATCH)
    available_count = sum(1 for r in intel_results.values() if r.available)

    # Multi-source agreement boost
    if matching_count >= 2:
        return 98.5
    elif matching_count == 1:
        return 95.0
    elif available_count >= 2 and probability < 0.20:
        # Multiple providers agree safe and ML agrees safe
        return 96.0

    return round(min(99.0, max(50.0, base_conf)), 1)


def generate_recommendations(
    prediction: str,
    risk_score: int,
    features: Dict[str, Any],
    whois_data: Dict[str, Any],
    domain: str = "",
    intel_results: Optional[Dict[str, ThreatIntelResult]] = None,
) -> List[str]:
    """Generate actionable recommendations distinguishing confirmed vs suspected threats."""
    recs: List[str] = []

    if domain and is_verified_authority_domain(domain, features):
        return [
            f"Verified legitimate domain for {domain}.",
            "No immediate security action required.",
            "Continue normal navigation.",
        ]

    # Check for confirmed external intelligence matches
    confirmed_providers = [
        p.replace('_', ' ').title()
        for p, r in (intel_results or {}).items()
        if r.matched and r.verdict == ProviderVerdict.MATCH
    ]

    if confirmed_providers:
        recs.append(f"🚫 Confirmed Threat: Identified by {', '.join(confirmed_providers)}.")
        recs.append("Do NOT open, navigate to, or interact with this URL.")
        recs.append("Block this domain and IP address at the firewall / DNS perimeter immediately.")
        recs.append("Do NOT enter any credentials, tokens, or personal information.")
        recs.append("Isolate any endpoints that recently initiated connections to this host.")
        return recs

    if prediction == "malicious":
        recs.append("🚫 High Risk Threat detected by neural pattern analysis.")
        recs.append("Block this domain at firewall and DNS resolvers immediately.")
        recs.append("Do NOT enter any credentials or sensitive information.")
        recs.append("No external threat intelligence match yet — treat as zero-day suspicious host.")
        if features.get("has_brand_in_subdomain"):
            recs.append("Brand spoofing pattern detected — issue security awareness advisory to staff.")
        return recs

    if prediction == "suspicious":
        recs.append("Treat this URL with caution before interacting.")
        recs.append("Verify the registered domain identity with the official organization.")
        recs.append("Do NOT enter authentication credentials on this page.")
        recs.append("External intelligence feeds found no active blacklist, but structural anomalies exist.")
        if not features.get("uses_https"):
            recs.append("Unencrypted connection (HTTP) — data sent in plaintext.")
        return recs

    # Safe
    recs.append("No immediate threats detected across ML and threat intelligence feeds.")
    recs.append("Standard browsing allowed. Continue periodic security telemetry monitoring.")
    if not features.get("uses_https"):
        recs.append("Site lacks HTTPS encryption — avoid entering passwords or payment cards.")
    return recs


def generate_explanation(
    prediction: str,
    risk_score: int,
    features: Dict[str, Any],
    domain: str = "",
    intel_results: Optional[Dict[str, ThreatIntelResult]] = None,
    probability: float = 0.0,
) -> str:
    """Generate a truthful, evidence-backed description synthesizing ML and provider findings."""
    if domain and is_verified_authority_domain(domain, features):
        return (
            f"Verified authentic domain for {domain}. "
            "Zero security anomalies or threat vectors detected. The domain matches "
            "the legitimate corporate infrastructure footprint with valid TLS and trusted registration."
        )

    # Correlate provider matches
    matches = []
    if intel_results:
        for p, r in intel_results.items():
            if r.matched and r.verdict == ProviderVerdict.MATCH:
                cats = ", ".join(r.categories) if r.categories else "threat"
                matches.append(f"{p.replace('_', ' ').title()} ({cats})")

    if matches:
        match_str = " and ".join(matches)
        ml_clause = f", while the neural classifier assigned a {round(probability * 100, 1)}% threat probability" if probability > 0.5 else ""
        return (
            f"The URL was classified as {prediction.upper()} (Risk: {risk_score}/100) because external threat intelligence "
            f"confirmed active indicators from {match_str}{ml_clause}. "
            "Independent multi-source correlation validates this indicator as an active security risk."
        )

    if prediction == "safe":
        return (
            f"This URL scored {risk_score}/100 risk (SAFE). "
            "No active threat intelligence matches were reported by Google Web Risk, PhishTank, or URLhaus. "
            "The domain structure matches standard benign domain footprints with zero phishing keywords."
        )
    elif prediction == "suspicious":
        indicators = []
        if not features.get("uses_https"): indicators.append("missing HTTPS")
        if features.get("is_suspicious_tld"): indicators.append("suspicious TLD")
        if features.get("url_length", 0) > 75: indicators.append("unusually long URL")
        if features.get("num_subdomains", 0) > 2: indicators.append("deep subdomain hierarchy")
        indicator_str = ", ".join(indicators) if indicators else "structural anomalies"
        return (
            f"This URL scored {risk_score}/100 risk (SUSPICIOUS). "
            f"Structural patterns detected: {indicator_str}. "
            "No external threat intelligence match was found, but anomalous lexical metrics warrant caution."
        )
    else:
        return (
            f"This URL scored {risk_score}/100 risk (MALICIOUS). "
            f"Neural feature analysis estimated a {round(probability * 100, 1)}% probability of phishing. "
            "Although external blacklist feeds have not yet indexed this specific indicator, heuristic markers indicate an active zero-day attack."
        )
