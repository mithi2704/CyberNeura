"""
Evidence Normalizer for CyberNeura.
Converts heterogeneous signals from ML inference, threat intelligence providers,
DNS records, WHOIS data, lexical URL features, and historical scan stores into
normalized, strongly-typed Evidence objects.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.evidence.models import (
    Evidence,
    EvidenceSeverity,
    EvidenceSource,
    EvidenceState,
    EvidenceType,
)
from app.evidence.builder import EvidenceBuilder
from app.utils.logger import get_logger

logger = get_logger(__name__)


class EvidenceNormalizer:
    """Normalizes raw cybersecurity signals into standardized Evidence objects."""

    def normalize_all(
        self,
        *,
        scan_id: Optional[str] = None,
        url: str,
        domain: str,
        ml_prediction: str,
        probability: float,
        features: Dict[str, Any],
        whois_data: Dict[str, Any],
        dns_data: Dict[str, Any],
        intel_results: Dict[str, Any],
        history_data: Optional[Dict[str, Any]] = None,
    ) -> List[Evidence]:
        evidence_list: List[Evidence] = []

        # 1. ML Signals
        evidence_list.extend(
            self.normalize_ml(scan_id=scan_id, prediction=ml_prediction, probability=probability, features=features)
        )

        # 2. Threat Intelligence Signals (Google Web Risk, PhishTank, URLhaus)
        evidence_list.extend(
            self.normalize_threat_intel(scan_id=scan_id, intel_results=intel_results)
        )

        # 3. DNS Signals
        evidence_list.extend(
            self.normalize_dns(scan_id=scan_id, dns_data=dns_data, domain=domain)
        )

        # 4. WHOIS Signals
        evidence_list.extend(
            self.normalize_whois(scan_id=scan_id, whois_data=whois_data, domain=domain)
        )

        # 5. URL Features Signals
        evidence_list.extend(
            self.normalize_url_features(scan_id=scan_id, features=features, url=url)
        )

        # 6. Historical Scan Signals
        if history_data:
            evidence_list.extend(
                self.normalize_history(scan_id=scan_id, history_data=history_data, url=url, domain=domain)
            )

        return evidence_list

    # ── 1. ML Normalization ───────────────────────────────────────────────
    def normalize_ml(
        self,
        *,
        scan_id: Optional[str],
        prediction: str,
        probability: float,
        features: Dict[str, Any],
    ) -> List[Evidence]:
        items: List[Evidence] = []

        if probability >= 0.85:
            severity = EvidenceSeverity.CRITICAL if probability >= 0.95 else EvidenceSeverity.HIGH
            state = EvidenceState.CONFIRMED if probability >= 0.95 else EvidenceState.SUPPORTING
            supports_risk = True
            desc = f"Machine learning model predicted {prediction} with high probability ({probability:.1%})."
        elif probability >= 0.60:
            severity = EvidenceSeverity.MEDIUM
            state = EvidenceState.SUPPORTING
            supports_risk = True
            desc = f"Machine learning model indicated elevated risk ({probability:.1%})."
        elif probability <= 0.20:
            severity = EvidenceSeverity.INFO
            state = EvidenceState.CONTRADICTING
            supports_risk = False
            desc = f"Machine learning model classified URL as safe with high certainty (probability: {probability:.1%})."
        else:
            severity = EvidenceSeverity.LOW
            state = EvidenceState.SUPPORTING if probability >= 0.5 else EvidenceState.CONTRADICTING
            supports_risk = probability >= 0.5
            desc = f"Machine learning model prediction: {prediction} ({probability:.1%} probability)."

        builder = (
            EvidenceBuilder(EvidenceSource.ML, EvidenceType.ML_PREDICTION)
            .with_scan_id(scan_id)
            .with_category(prediction.upper())
            .with_severity(severity)
            .with_state(state)
            .with_value(prediction)
            .with_score(probability)
            .with_confidence(min(1.0, 0.5 + abs(probability - 0.5)))
            .supports_risk(supports_risk)
            .with_description(desc)
            .with_metadata({"probability": probability, "prediction": prediction})
        )
        items.append(builder.build())
        return items

    # ── 2. Threat Intel Normalization ─────────────────────────────────────
    def normalize_threat_intel(
        self,
        *,
        scan_id: Optional[str],
        intel_results: Dict[str, Any],
    ) -> List[Evidence]:
        items: List[Evidence] = []
        source_map = {
            "google_webrisk": EvidenceSource.GOOGLE_WEB_RISK,
            "phishtank": EvidenceSource.PHISHTANK,
            "urlhaus": EvidenceSource.URLHAUS,
        }

        for provider_name, res in intel_results.items():
            source = source_map.get(provider_name.lower(), EvidenceSource.GOOGLE_WEB_RISK)
            matched = getattr(res, "matched", False)
            available = getattr(res, "available", True)
            verdict = getattr(res, "verdict", None)
            verdict_str = verdict.value if hasattr(verdict, "value") else str(verdict or "")
            categories = getattr(res, "categories", []) or []
            confidence = getattr(res, "confidence", 0.9)
            error = getattr(res, "error", None)

            if not available:
                # INVARIANT: UNAVAILABLE != SAFE. Never treat provider failure as safe!
                desc = f"Provider {provider_name} was unavailable during analysis ({error or 'timeout/error'}). Not treated as safe."
                builder = (
                    EvidenceBuilder(source, EvidenceType.PROVIDER_UNAVAILABLE)
                    .with_scan_id(scan_id)
                    .with_severity(EvidenceSeverity.INFO)
                    .with_state(EvidenceState.UNAVAILABLE)
                    .with_value("UNAVAILABLE")
                    .with_score(0.0)
                    .with_confidence(0.0)
                    .supports_risk(False)
                    .with_description(desc)
                    .with_metadata({"error": error, "provider": provider_name})
                )
                items.append(builder.build())
                continue

            if matched:
                ev_type = EvidenceType.THREAT_INTEL_MATCH
                cat_str = ", ".join(categories) if categories else "MALICIOUS"
                if "PHISHING" in cat_str.upper() or provider_name.lower() == "phishtank":
                    ev_type = EvidenceType.PHISHING_DATABASE_MATCH
                elif "MALWARE" in cat_str.upper() or provider_name.lower() == "urlhaus":
                    ev_type = EvidenceType.MALWARE_DATABASE_MATCH

                desc = f"Verified threat match confirmed by {provider_name} ({cat_str})."
                builder = (
                    EvidenceBuilder(source, ev_type)
                    .with_scan_id(scan_id)
                    .with_category(cat_str)
                    .with_severity(EvidenceSeverity.CRITICAL)
                    .with_state(EvidenceState.CONFIRMED)
                    .with_value(verdict_str)
                    .with_score(1.0)
                    .with_confidence(confidence or 0.95)
                    .supports_risk(True)
                    .with_description(desc)
                    .with_metadata({
                        "categories": categories,
                        "raw_metadata": getattr(res, "metadata", {}),
                    })
                )
                items.append(builder.build())
            else:
                # No match found - neutral/contradicting risk
                desc = f"{provider_name} returned no known malicious matches."
                builder = (
                    EvidenceBuilder(source, EvidenceType.THREAT_INTEL_MATCH)
                    .with_scan_id(scan_id)
                    .with_severity(EvidenceSeverity.INFO)
                    .with_state(EvidenceState.CONTRADICTING)
                    .with_value("NO_MATCH")
                    .with_score(0.0)
                    .with_confidence(0.7)
                    .supports_risk(False)
                    .with_description(desc)
                    .with_metadata({"verdict": "NO_MATCH"})
                )
                items.append(builder.build())

        return items

    # ── 3. DNS Normalization ──────────────────────────────────────────────
    def normalize_dns(
        self,
        *,
        scan_id: Optional[str],
        dns_data: Dict[str, Any],
        domain: str,
    ) -> List[Evidence]:
        items: List[Evidence] = []
        if not dns_data or dns_data.get("status") == "error":
            items.append(
                EvidenceBuilder(EvidenceSource.DNS, EvidenceType.DNS_ANOMALY)
                .with_scan_id(scan_id)
                .with_severity(EvidenceSeverity.LOW)
                .with_state(EvidenceState.SUPPORTING)
                .with_value("RESOLUTION_FAILED")
                .with_score(0.3)
                .with_confidence(0.6)
                .supports_risk(True)
                .with_description(f"Domain {domain} failed DNS resolution. Supporting anomaly; not sole indicator.")
                .with_metadata({"dns_status": "error"})
                .build()
            )
            return items

        a_records = dns_data.get("a", [])
        ns_records = dns_data.get("ns", [])
        mx_records = dns_data.get("mx", [])

        if a_records:
            items.append(
                EvidenceBuilder(EvidenceSource.DNS, EvidenceType.DNS_RESOLUTION)
                .with_scan_id(scan_id)
                .with_severity(EvidenceSeverity.INFO)
                .with_state(EvidenceState.CONTRADICTING)
                .with_value(a_records)
                .with_score(0.0)
                .with_confidence(0.9)
                .supports_risk(False)
                .with_description(f"Domain {domain} resolves to {len(a_records)} valid IP address(es) ({a_records[0]}).")
                .with_metadata({"a_records": a_records, "ns_records": ns_records, "mx_records": mx_records})
                .build()
            )
        else:
            items.append(
                EvidenceBuilder(EvidenceSource.DNS, EvidenceType.DNS_ANOMALY)
                .with_scan_id(scan_id)
                .with_severity(EvidenceSeverity.MEDIUM)
                .with_state(EvidenceState.SUPPORTING)
                .with_value("NO_A_RECORD")
                .with_score(0.5)
                .with_confidence(0.75)
                .supports_risk(True)
                .with_description(f"Domain {domain} does not resolve to any IPv4 A records.")
                .build()
            )

        return items

    # ── 4. WHOIS Normalization ────────────────────────────────────────────
    def normalize_whois(
        self,
        *,
        scan_id: Optional[str],
        whois_data: Dict[str, Any],
        domain: str,
    ) -> List[Evidence]:
        items: List[Evidence] = []
        if not whois_data or whois_data.get("status") == "error":
            items.append(
                EvidenceBuilder(EvidenceSource.WHOIS, EvidenceType.REGISTRATION_STATUS)
                .with_scan_id(scan_id)
                .with_severity(EvidenceSeverity.INFO)
                .with_state(EvidenceState.UNAVAILABLE)
                .with_value("WHOIS_UNAVAILABLE")
                .with_score(0.1)
                .with_confidence(0.5)
                .supports_risk(False)
                .with_description(f"WHOIS data for {domain} was unavailable. Treated as inconclusive.")
                .build()
            )
            return items

        # Calculate domain age in days
        created_dt = whois_data.get("creation_date")
        age_days: Optional[int] = None

        if isinstance(created_dt, str):
            try:
                # parse ISO or standard format
                clean_str = re.sub(r"\+00:00$", "Z", created_dt)
                if clean_str.endswith("Z"):
                    parsed = datetime.fromisoformat(clean_str.replace("Z", "+00:00"))
                else:
                    parsed = datetime.fromisoformat(clean_str)
                age_days = (datetime.now(timezone.utc) - parsed).days
            except Exception:
                pass
        elif isinstance(created_dt, datetime):
            if created_dt.tzinfo is None:
                created_dt = created_dt.replace(tzinfo=timezone.utc)
            age_days = (datetime.now(timezone.utc) - created_dt).days

        registrar = whois_data.get("registrar") or "Unknown"

        if age_days is not None:
            if age_days < 7:
                items.append(
                    EvidenceBuilder(EvidenceSource.WHOIS, EvidenceType.DOMAIN_AGE)
                    .with_scan_id(scan_id)
                    .with_severity(EvidenceSeverity.MEDIUM)
                    .with_state(EvidenceState.SUPPORTING)
                    .with_value(f"{age_days} days")
                    .with_score(0.7)
                    .with_confidence(0.9)
                    .supports_risk(True)
                    .with_description(f"Domain is very young (registered {age_days} days ago). Moderate risk contribution.")
                    .with_metadata({"age_days": age_days, "registrar": registrar})
                    .build()
                )
            elif age_days < 30:
                items.append(
                    EvidenceBuilder(EvidenceSource.WHOIS, EvidenceType.DOMAIN_AGE)
                    .with_scan_id(scan_id)
                    .with_severity(EvidenceSeverity.LOW)
                    .with_state(EvidenceState.SUPPORTING)
                    .with_value(f"{age_days} days")
                    .with_score(0.4)
                    .with_confidence(0.85)
                    .supports_risk(True)
                    .with_description(f"Domain is recently registered ({age_days} days ago). Small risk contribution.")
                    .with_metadata({"age_days": age_days, "registrar": registrar})
                    .build()
                )
            elif age_days > 365:
                items.append(
                    EvidenceBuilder(EvidenceSource.WHOIS, EvidenceType.DOMAIN_AGE)
                    .with_scan_id(scan_id)
                    .with_severity(EvidenceSeverity.INFO)
                    .with_state(EvidenceState.CONTRADICTING)
                    .with_value(f"{round(age_days / 365, 1)} years")
                    .with_score(0.0)
                    .with_confidence(0.9)
                    .supports_risk(False)
                    .with_description(f"Mature, established domain registered over {round(age_days / 365, 1)} years ago. Supports safe assessment.")
                    .with_metadata({"age_days": age_days, "registrar": registrar})
                    .build()
                )

        if registrar != "Unknown":
            items.append(
                EvidenceBuilder(EvidenceSource.WHOIS, EvidenceType.REGISTRAR)
                .with_scan_id(scan_id)
                .with_severity(EvidenceSeverity.INFO)
                .with_state(EvidenceState.SUPPORTING if age_days and age_days < 30 else EvidenceState.CONTRADICTING)
                .with_value(registrar)
                .with_score(0.0)
                .with_confidence(0.9)
                .supports_risk(False)
                .with_description(f"Registered via {registrar}.")
                .with_metadata({"registrar": registrar})
                .build()
            )

        return items

    # ── 5. URL Features Normalization ─────────────────────────────────────
    def normalize_url_features(
        self,
        *,
        scan_id: Optional[str],
        features: Dict[str, Any],
        url: str,
    ) -> List[Evidence]:
        items: List[Evidence] = []

        # IP instead of hostname
        if features.get("is_ip") or features.get("is_ip_address"):
            items.append(
                EvidenceBuilder(EvidenceSource.URL_FEATURES, EvidenceType.IP_REPUTATION)
                .with_scan_id(scan_id)
                .with_severity(EvidenceSeverity.HIGH)
                .with_state(EvidenceState.SUPPORTING)
                .with_value(features.get("hostname", "IP"))
                .with_score(0.8)
                .with_confidence(0.95)
                .supports_risk(True)
                .with_description("URL utilizes a raw IP address instead of a standard registered domain name.")
                .build()
            )

        # Suspicious TLD
        if features.get("suspicious_tld") or features.get("is_suspicious_tld"):
            tld = features.get("tld", "suspicious")
            items.append(
                EvidenceBuilder(EvidenceSource.URL_FEATURES, EvidenceType.SUSPICIOUS_TLD)
                .with_scan_id(scan_id)
                .with_severity(EvidenceSeverity.MEDIUM)
                .with_state(EvidenceState.SUPPORTING)
                .with_value(tld)
                .with_score(0.6)
                .with_confidence(0.85)
                .supports_risk(True)
                .with_description(f"URL uses high-abuse top-level domain extension (.{tld}).")
                .build()
            )

        # High Shannon Entropy
        entropy = float(features.get("entropy") or features.get("shannon_entropy") or 0.0)
        if entropy > 4.5:
            items.append(
                EvidenceBuilder(EvidenceSource.URL_FEATURES, EvidenceType.URL_ENTROPY)
                .with_scan_id(scan_id)
                .with_severity(EvidenceSeverity.MEDIUM)
                .with_state(EvidenceState.SUPPORTING)
                .with_value(round(entropy, 2))
                .with_score(min(1.0, (entropy - 4.0) / 1.5))
                .with_confidence(0.8)
                .supports_risk(True)
                .with_description(f"High lexical randomness / Shannon entropy detected ({entropy:.2f}), common in obfuscation.")
                .build()
            )

        # URL length
        url_len = int(features.get("url_length") or len(url))
        if url_len > 120:
            items.append(
                EvidenceBuilder(EvidenceSource.URL_FEATURES, EvidenceType.URL_LENGTH)
                .with_scan_id(scan_id)
                .with_severity(EvidenceSeverity.LOW)
                .with_state(EvidenceState.SUPPORTING)
                .with_value(url_len)
                .with_score(0.4)
                .with_confidence(0.7)
                .supports_risk(True)
                .with_description(f"Abnormally long URL ({url_len} chars), typical of parameter stuffing or cloaking.")
                .build()
            )

        # Suspicious path / keywords
        suspicious_keywords = ["login", "signin", "verify", "secure", "banking", "account", "update", "wallet"]
        matched_kw = [kw for kw in suspicious_keywords if kw in url.lower()]
        if len(matched_kw) >= 2:
            items.append(
                EvidenceBuilder(EvidenceSource.URL_FEATURES, EvidenceType.SUSPICIOUS_PATH)
                .with_scan_id(scan_id)
                .with_severity(EvidenceSeverity.MEDIUM)
                .with_state(EvidenceState.SUPPORTING)
                .with_value(matched_kw)
                .with_score(0.6)
                .with_confidence(0.85)
                .supports_risk(True)
                .with_description(f"URL path mimics sensitive target services ({', '.join(matched_kw)}).")
                .build()
            )

        return items

    # ── 6. History Normalization ──────────────────────────────────────────
    def normalize_history(
        self,
        *,
        scan_id: Optional[str],
        history_data: Dict[str, Any],
        url: str,
        domain: str,
    ) -> List[Evidence]:
        items: List[Evidence] = []
        prior_scans = history_data.get("scans", [])
        if not prior_scans:
            return items

        malicious_scans = [s for s in prior_scans if s.get("prediction") == "malicious"]
        safe_scans = [s for s in prior_scans if s.get("prediction") == "safe"]

        if malicious_scans:
            most_recent = malicious_scans[0]
            scanned_at_str = most_recent.get("scanned_at") or most_recent.get("scannedAt")
            decay_factor = self._compute_time_decay(scanned_at_str)

            desc = f"Identified {len(malicious_scans)} previous malicious scan(s) for this target in CyberNeura history."
            items.append(
                EvidenceBuilder(EvidenceSource.HISTORY, EvidenceType.HISTORICAL_DETECTION)
                .with_scan_id(scan_id)
                .with_severity(EvidenceSeverity.HIGH if decay_factor > 0.5 else EvidenceSeverity.MEDIUM)
                .with_state(EvidenceState.CONFIRMED if decay_factor > 0.7 else EvidenceState.SUPPORTING)
                .with_value(len(malicious_scans))
                .with_score(0.85 * decay_factor)
                .with_confidence(0.9 * decay_factor)
                .supports_risk(True)
                .with_description(desc)
                .with_metadata({
                    "malicious_count": len(malicious_scans),
                    "decay_factor": round(decay_factor, 2),
                    "last_detected": scanned_at_str,
                })
                .build()
            )
        elif len(safe_scans) >= 3:
            items.append(
                EvidenceBuilder(EvidenceSource.HISTORY, EvidenceType.HISTORICAL_ALLOW)
                .with_scan_id(scan_id)
                .with_severity(EvidenceSeverity.INFO)
                .with_state(EvidenceState.CONTRADICTING)
                .with_value(len(safe_scans))
                .with_score(0.0)
                .with_confidence(0.85)
                .supports_risk(False)
                .with_description(f"Target has {len(safe_scans)} historical safe classifications in CyberNeura records.")
                .build()
            )

        return items

    def _compute_time_decay(self, iso_timestamp: Optional[str]) -> float:
        """Calculate exponential time decay (1.0 for recent <=24h, down to 0.2 for >180 days)."""
        if not iso_timestamp:
            return 0.5
        try:
            clean_str = re.sub(r"\+00:00$", "Z", iso_timestamp)
            if clean_str.endswith("Z"):
                dt = datetime.fromisoformat(clean_str.replace("Z", "+00:00"))
            else:
                dt = datetime.fromisoformat(clean_str)
            days_old = max(0, (datetime.now(timezone.utc) - dt).days)
            if days_old <= 1:
                return 1.0
            if days_old <= 7:
                return 0.9
            if days_old <= 30:
                return 0.75
            if days_old <= 90:
                return 0.5
            return 0.25
        except Exception:
            return 0.5
