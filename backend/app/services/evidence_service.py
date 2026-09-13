"""Evidence Engine — compiles and correlates evidence across ML, threat intel, and domain indicators."""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from app.intelligence.models import ThreatIntelResult, ProviderVerdict


class EvidenceItem:
    def __init__(
        self,
        source: str,
        type: str,
        severity: str,
        description: str,
        matched: bool,
        value: Any = None,
    ):
        self.source = source
        self.type = type
        self.severity = severity
        self.description = description
        self.matched = matched
        self.value = value

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "type": self.type,
            "severity": self.severity,
            "description": self.description,
            "matched": self.matched,
            "value": self.value,
        }


def compile_evidence(
    ml_prediction: str,
    probability: float,
    features: Dict[str, Any],
    whois_data: Dict[str, Any],
    dns_data: Dict[str, Any],
    intel_results: Dict[str, ThreatIntelResult],
    domain: str = "",
) -> List[Dict[str, Any]]:
    """
    Synthesize all security signals into a correlated, auditable list of evidence items.
    """
    evidence: List[EvidenceItem] = []

    # ── 1. External Threat Intelligence Evidence ─────────────────────────
    for provider_name, res in intel_results.items():
        if res.matched and res.verdict == ProviderVerdict.MATCH:
            categories_str = ", ".join(res.categories) if res.categories else "Uncategorized Threat"
            severity = "CRITICAL" if any(c in categories_str for c in ("MALWARE", "MALWARE_DISTRIBUTION")) else "HIGH"
            evidence.append(
                EvidenceItem(
                    source=provider_name,
                    type="threat_intel_match",
                    severity=severity,
                    description=f"{provider_name.replace('_', ' ').title()} identified this indicator as {categories_str}.",
                    matched=True,
                    value=res.categories,
                )
            )
        elif res.verdict == ProviderVerdict.UNAVAILABLE:
            evidence.append(
                EvidenceItem(
                    source=provider_name,
                    type="provider_unavailable",
                    severity="INFO",
                    description=f"{provider_name.replace('_', ' ').title()} was unavailable during lookup ({res.error or 'timeout'}).",
                    matched=False,
                    value=res.error,
                )
            )

    # ── 2. Machine Learning Model Evidence ──────────────────────────────
    if probability >= 0.80:
        evidence.append(
            EvidenceItem(
                source="ml_model",
                type="phishing_probability",
                severity="HIGH",
                description=f"Neural pattern engine detected high-confidence malicious structure ({round(probability * 100, 1)}% probability).",
                matched=True,
                value=round(probability, 4),
            )
        )
    elif probability >= 0.50:
        evidence.append(
            EvidenceItem(
                source="ml_model",
                type="suspicious_probability",
                severity="MEDIUM",
                description=f"Neural pattern engine detected moderate anomaly score ({round(probability * 100, 1)}% probability).",
                matched=True,
                value=round(probability, 4),
            )
        )

    # ── 3. URL Lexical & Heuristic Evidence ──────────────────────────────
    if features.get("has_phishing_keyword"):
        evidence.append(
            EvidenceItem(
                source="url_features",
                type="phishing_keyword",
                severity="HIGH",
                description="URL path contains deceptive credential-harvesting keywords.",
                matched=True,
                value=True,
            )
        )

    if features.get("has_brand_in_subdomain"):
        evidence.append(
            EvidenceItem(
                source="url_features",
                type="brand_spoofing",
                severity="HIGH",
                description="Well-known corporate brand keyword detected in subdomain hierarchy (spoofing indicator).",
                matched=True,
                value=True,
            )
        )

    if features.get("has_ip_hostname"):
        evidence.append(
            EvidenceItem(
                source="url_features",
                type="ip_hostname",
                severity="HIGH",
                description="Host address is a raw numerical IP rather than a registered DNS domain name.",
                matched=True,
                value=True,
            )
        )

    if features.get("is_suspicious_tld"):
        evidence.append(
            EvidenceItem(
                source="url_features",
                type="suspicious_tld",
                severity="MEDIUM",
                description="Top-level domain (TLD) has statistically elevated prevalence in malicious campaigns.",
                matched=True,
                value=True,
            )
        )

    if features.get("uses_punycode"):
        evidence.append(
            EvidenceItem(
                source="url_features",
                type="punycode_homograph",
                severity="MEDIUM",
                description="URL uses punycode/IDN encoding, commonly associated with homograph lookalike attacks.",
                matched=True,
                value=True,
            )
        )

    # ── 4. Domain & Infrastructure Evidence ─────────────────────────────
    if not features.get("uses_https"):
        evidence.append(
            EvidenceItem(
                source="transport_security",
                type="missing_tls",
                severity="LOW",
                description="Transport layer is unencrypted (HTTP).",
                matched=True,
                value=False,
            )
        )

    if whois_data and whois_data.get("status") == "error":
        evidence.append(
            EvidenceItem(
                source="whois",
                type="whois_unavailable",
                severity="LOW",
                description="Domain WHOIS registration record could not be verified or is concealed.",
                matched=True,
                value=False,
            )
        )

    return [e.to_dict() for e in evidence]


def count_independent_confirmations(intel_results: Dict[str, ThreatIntelResult]) -> int:
    """Return the count of distinct external providers that confirmed a threat match."""
    return sum(
        1 for res in intel_results.values()
        if res.matched and res.verdict == ProviderVerdict.MATCH
    )
