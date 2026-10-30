"""
Deterministic Risk Scoring Engine for CyberNeura Phase 3.
Calculates weighted risk factor contributions, applies verified threat floors,
and produces auditable RiskFactor breakdowns.
"""
from __future__ import annotations

import math
from typing import Any, Dict, List, Optional, Tuple
from app.evidence.models import Evidence, EvidenceSource, EvidenceState, EvidenceType, CorrelatedFinding
from app.risk.models import RiskFactor, RiskConfig
from app.utils.logger import get_logger

logger = get_logger(__name__)

VERIFIED_MATCH_FLOOR = 85


class RiskScoringEngine:
    def __init__(self, config: Optional[RiskConfig] = None):
        self.config = config or RiskConfig()

    def compute_risk(
        self,
        *,
        scan_id: Optional[str] = None,
        evidence_list: List[Evidence],
        correlated_findings: List[CorrelatedFinding],
        url: Optional[str] = None,
        domain: Optional[str] = None,
    ) -> Tuple[int, List[RiskFactor]]:
        """
        Compute deterministic risk score and return breakdown of risk factors.
        Returns (risk_score, risk_factors).
        """
        weights = self.config.weights
        factors: List[RiskFactor] = []

        # ── 1. ML Factor (30%) ───────────────────────────────────────────────
        ml_weight = weights.get("ml", 0.30)
        ml_max = ml_weight * 100.0
        ml_ev = next((e for e in evidence_list if e.source == EvidenceSource.ML), None)
        ml_norm = ml_ev.score if ml_ev else 0.0
        # Non-linear curve: low probs (<0.2) contribute negligible risk, high probs (>0.8) contribute full weight
        if ml_norm <= 0.2:
            ml_scaled = ml_norm * 0.5
        elif ml_norm >= 0.8:
            ml_scaled = 0.8 + (ml_norm - 0.8) * 1.0
        else:
            ml_scaled = ml_norm

        ml_contrib = round(ml_scaled * ml_max, 1)
        factors.append(
            RiskFactor(
                scan_id=scan_id,
                factor_type="ML_PREDICTION",
                factor_name="Machine Learning Model Probability",
                raw_value=f"{ml_norm:.1%}" if ml_ev else "N/A",
                normalized_value=round(ml_norm, 3),
                weight=ml_weight,
                contribution=ml_contrib,
                max_contribution=ml_max,
                direction="RISK_INCREASING" if ml_norm >= 0.5 else "RISK_DECREASING",
                description=f"Neural pattern inference contributed {ml_contrib:.1f} of {ml_max:.1f} maximum points.",
            )
        )

        # ── 2. Threat Intelligence Factor (30%) ──────────────────────────────
        intel_weight = weights.get("threat_intel", 0.30)
        intel_max = intel_weight * 100.0
        intel_evs = [
            e for e in evidence_list
            if e.source in {EvidenceSource.GOOGLE_WEB_RISK, EvidenceSource.PHISHTANK, EvidenceSource.URLHAUS}
        ]
        confirmed_intel = [e for e in intel_evs if e.state == EvidenceState.CONFIRMED]
        has_verified_match = len(confirmed_intel) > 0

        if len(confirmed_intel) >= 2:
            intel_norm = 1.0
        elif len(confirmed_intel) == 1:
            intel_norm = 0.95
        else:
            # Check if any provider gave suspicious hints
            supporting_intel = [e for e in intel_evs if e.supports_risk and e.state != EvidenceState.UNAVAILABLE]
            intel_norm = 0.3 if supporting_intel else 0.0

        intel_contrib = round(intel_norm * intel_max, 1)
        factors.append(
            RiskFactor(
                scan_id=scan_id,
                factor_type="THREAT_INTELLIGENCE",
                factor_name="External Threat Intelligence",
                raw_value=f"{len(confirmed_intel)} confirmed match(es)",
                normalized_value=round(intel_norm, 3),
                weight=intel_weight,
                contribution=intel_contrib,
                max_contribution=intel_max,
                direction="RISK_INCREASING" if intel_norm > 0 else "NEUTRAL",
                description=f"Multi-feed external telemetry contributed {intel_contrib:.1f} of {intel_max:.1f} maximum points.",
            )
        )

        # ── 3. DNS Infrastructure Factor (10%) ───────────────────────────────
        dns_weight = weights.get("dns", 0.10)
        dns_max = dns_weight * 100.0
        dns_evs = [e for e in evidence_list if e.source == EvidenceSource.DNS]
        dns_anomaly = any(e.evidence_type == EvidenceType.DNS_ANOMALY for e in dns_evs)
        dns_resolution = any(e.evidence_type == EvidenceType.DNS_RESOLUTION for e in dns_evs)

        if dns_anomaly:
            dns_norm = 0.6  # Supporting anomaly, not sole malice
            dns_dir = "RISK_INCREASING"
        elif dns_resolution:
            dns_norm = 0.0
            dns_dir = "RISK_DECREASING"
        else:
            dns_norm = 0.2
            dns_dir = "NEUTRAL"

        dns_contrib = round(dns_norm * dns_max, 1)
        factors.append(
            RiskFactor(
                scan_id=scan_id,
                factor_type="DNS_INFRASTRUCTURE",
                factor_name="DNS & Network Resolution",
                raw_value="Anomaly Detected" if dns_anomaly else "Normal Resolution",
                normalized_value=round(dns_norm, 3),
                weight=dns_weight,
                contribution=dns_contrib,
                max_contribution=dns_max,
                direction=dns_dir,
                description=f"DNS infrastructure checks contributed {dns_contrib:.1f} of {dns_max:.1f} points.",
            )
        )

        # ── 4. WHOIS / Domain Factor (10%) ───────────────────────────────────
        whois_weight = weights.get("whois", 0.10)
        whois_max = whois_weight * 100.0
        whois_ev = next((e for e in evidence_list if e.source == EvidenceSource.WHOIS and e.evidence_type == EvidenceType.DOMAIN_AGE), None)

        if whois_ev and whois_ev.supports_risk:
            whois_norm = whois_ev.score  # 0.7 (<7 days) or 0.4 (<30 days)
            whois_dir = "RISK_INCREASING"
            whois_val = whois_ev.value
        elif whois_ev and not whois_ev.supports_risk:
            whois_norm = 0.0  # Mature domain
            whois_dir = "RISK_DECREASING"
            whois_val = whois_ev.value
        else:
            whois_norm = 0.2
            whois_dir = "NEUTRAL"
            whois_val = "Unknown / Unresolved"

        whois_contrib = round(whois_norm * whois_max, 1)
        factors.append(
            RiskFactor(
                scan_id=scan_id,
                factor_type="WHOIS_DOMAIN",
                factor_name="Domain Registration Age",
                raw_value=str(whois_val),
                normalized_value=round(whois_norm, 3),
                weight=whois_weight,
                contribution=whois_contrib,
                max_contribution=whois_max,
                direction=whois_dir,
                description=f"Registration telemetry contributed {whois_contrib:.1f} of {whois_max:.1f} points.",
            )
        )

        # ── 5. URL Features Factor (10%) ─────────────────────────────────────
        url_feat_weight = weights.get("url_features", 0.10)
        url_feat_max = url_feat_weight * 100.0
        feat_evs = [e for e in evidence_list if e.source == EvidenceSource.URL_FEATURES and e.supports_risk]

        if feat_evs:
            # Average scores of triggered lexical risk features
            feat_norm = min(1.0, sum(e.score for e in feat_evs) / max(1, len(feat_evs)) * 1.2)
            feat_dir = "RISK_INCREASING"
        else:
            feat_norm = 0.0
            feat_dir = "RISK_DECREASING"

        feat_contrib = round(feat_norm * url_feat_max, 1)
        factors.append(
            RiskFactor(
                scan_id=scan_id,
                factor_type="URL_FEATURES",
                factor_name="Lexical & Structural URL Characteristics",
                raw_value=f"{len(feat_evs)} anomalies",
                normalized_value=round(feat_norm, 3),
                weight=url_feat_weight,
                contribution=feat_contrib,
                max_contribution=url_feat_max,
                direction=feat_dir,
                description=f"Structural syntax and obfuscation indicators contributed {feat_contrib:.1f} of {url_feat_max:.1f} points.",
            )
        )

        # ── 6. Historical Scan Factor (10%) ──────────────────────────────────
        hist_weight = weights.get("history", 0.10)
        hist_max = hist_weight * 100.0
        hist_det = next((e for e in evidence_list if e.source == EvidenceSource.HISTORY and e.evidence_type == EvidenceType.HISTORICAL_DETECTION), None)
        hist_allow = next((e for e in evidence_list if e.source == EvidenceSource.HISTORY and e.evidence_type == EvidenceType.HISTORICAL_ALLOW), None)

        if hist_det:
            hist_norm = hist_det.score
            hist_dir = "RISK_INCREASING"
            hist_val = f"{hist_det.value} past malicious scan(s)"
        elif hist_allow:
            hist_norm = 0.0
            hist_dir = "RISK_DECREASING"
            hist_val = f"{hist_allow.value} past safe scan(s)"
        else:
            hist_norm = 0.1
            hist_dir = "NEUTRAL"
            hist_val = "First observed scan"

        hist_contrib = round(hist_norm * hist_max, 1)
        factors.append(
            RiskFactor(
                scan_id=scan_id,
                factor_type="HISTORICAL_EVIDENCE",
                factor_name="CyberNeura Scan History",
                raw_value=hist_val,
                normalized_value=round(hist_norm, 3),
                weight=hist_weight,
                contribution=hist_contrib,
                max_contribution=hist_max,
                direction=hist_dir,
                description=f"Historical telemetry contributed {hist_contrib:.1f} of {hist_max:.1f} points.",
            )
        )

        # ── Total Risk Score Calculation ─────────────────────────────────────
        total_raw = sum(f.contribution for f in factors)
        raw_score = int(round(total_raw))

        # Check for critical lexical and structural spoofing indicators
        has_critical_spoof = any(
            e.evidence_type in {EvidenceType.IP_REPUTATION, EvidenceType.HOSTNAME_ANOMALY}
            for e in evidence_list if e.supports_risk
        )
        has_phish_indicators = any(
            e.evidence_type in {EvidenceType.SUSPICIOUS_PATH, EvidenceType.SUSPICIOUS_TLD}
            or "phish" in e.description.lower()
            for e in evidence_list if e.supports_risk
        )

        # 1. External Threat Intelligence Verified Floor
        if has_verified_match:
            final_score = max(VERIFIED_MATCH_FLOOR, raw_score)
            if len(confirmed_intel) >= 2:
                final_score = max(94, final_score)
        else:
            final_score = raw_score

        # Check for verified authority domains
        from app.services.risk_engine import is_verified_authority_domain, _get_registered_domain
        domain_name = _get_registered_domain(domain or url or "")
        if not domain_name:
            dns_ev = next((e for e in evidence_list if e.source == EvidenceSource.DNS), None)
            if dns_ev and dns_ev.value:
                domain_name = _get_registered_domain(str(dns_ev.value))

        feat_evs_risk = [e for e in evidence_list if e.source == EvidenceSource.URL_FEATURES and e.supports_risk]
        feat_dict = {e.evidence_type.value: 1 for e in feat_evs_risk}

        is_auth = bool(domain_name and is_verified_authority_domain(domain_name, feat_dict))
        if is_auth and not has_verified_match:
            return 0, factors

        # 2. Machine Learning Elevated Threat Floor:
        # Zero-day attacks and newly generated links are not yet listed in external blacklist feeds.
        # When the neural pattern engine detects high malicious probability, elevate the risk score.
        if ml_norm >= 0.80:
            ml_floor = int(72 + (ml_norm - 0.80) * 110)  # 0.80 -> 72 (Malicious), 0.90 -> 83, 0.99 -> 93
            final_score = max(final_score, ml_floor)
        elif ml_norm >= 0.55:
            ml_floor = int(45 + (ml_norm - 0.55) * 80)   # 0.55 -> 45 (Suspicious), 0.70 -> 57
            final_score = max(final_score, ml_floor)
        elif ml_norm >= 0.35:
            ml_floor = int(30 + (ml_norm - 0.35) * 60)   # 0.35 -> 30 (Suspicious threshold), 0.45 -> 36
            final_score = max(final_score, ml_floor)

        # 3. Lexical spoofing / brand impersonation boost
        if has_critical_spoof:
            final_score = max(final_score, 75)
        elif has_phish_indicators and ml_norm >= 0.40:
            final_score = max(final_score, 60)

        # 4. Legitimate mature domains with clean signals ceiling
        is_https = bool(url and url.lower().startswith("https://"))
        mature_domain = any(e.evidence_type == EvidenceType.DOMAIN_AGE and not e.supports_risk for e in evidence_list)
        has_phish_or_spoof = has_critical_spoof or has_phish_indicators
        if not has_verified_match and not has_phish_or_spoof and is_https and mature_domain and ml_norm < 0.30:
            final_score = min(final_score, 10)

        # Bound strictly to 0..100
        final_score = max(0, min(100, final_score))

        return final_score, factors

