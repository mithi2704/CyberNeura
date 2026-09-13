"""
Deterministic Recommendation Engine for CyberNeura Phase 3.
Synthesizes structured, actionable defensive security recommendations tied directly
to normalized evidence and correlated findings.
"""
from __future__ import annotations

import uuid
from typing import List
from app.evidence.models import Evidence, EvidenceSeverity, EvidenceSource, EvidenceState, EvidenceType, CorrelatedFinding
from app.risk.models import DetailedRecommendation


class RecommendationEngine:
    def generate_recommendations(
        self,
        *,
        prediction: str,
        risk_score: int,
        evidence_list: List[Evidence],
        correlated_findings: List[CorrelatedFinding],
    ) -> List[DetailedRecommendation]:
        recs: List[DetailedRecommendation] = []

        confirmed_intel = [
            e for e in evidence_list
            if e.source in {EvidenceSource.GOOGLE_WEB_RISK, EvidenceSource.PHISHTANK, EvidenceSource.URLHAUS}
            and e.state == EvidenceState.CONFIRMED
        ]
        is_phish = any(
            "PHISH" in str(e.category or "").upper() or e.evidence_type == EvidenceType.PHISHING_DATABASE_MATCH
            for e in evidence_list
        )
        is_malware = any(
            "MALWARE" in str(e.category or "").upper() or e.evidence_type == EvidenceType.MALWARE_DATABASE_MATCH
            for e in evidence_list
        )
        young_domain = any(e.source == EvidenceSource.WHOIS and e.supports_risk for e in evidence_list)
        is_ip_host = any(e.evidence_type == EvidenceType.IP_REPUTATION for e in evidence_list)
        unavail_providers = [e for e in evidence_list if e.state == EvidenceState.UNAVAILABLE]

        # 1. Confirmed malicious actions
        if prediction == "malicious" or risk_score >= 80:
            recs.append(
                DetailedRecommendation(
                    title="Block URL at Perimeter Gateway",
                    description="Immediately blacklist this domain and URL path across firewall, DNS resolver, and endpoint proxies.",
                    severity=EvidenceSeverity.CRITICAL,
                    reason="Target verified as an active threat destination by authoritative security intelligence.",
                    action="BLOCK_PERIMETER",
                )
            )
            if is_phish:
                recs.append(
                    DetailedRecommendation(
                        title="Prevent Credential Submission",
                        description="Do not input usernames, passwords, API tokens, or multi-factor authentication codes.",
                        severity=EvidenceSeverity.CRITICAL,
                        reason="URL exhibits deceptive social engineering hallmarks designed to harvest user credentials.",
                        action="ISOLATE_CREDENTIALS",
                    )
                )
            if is_malware:
                recs.append(
                    DetailedRecommendation(
                        title="Halt File Downloads & Invalidate Cached Payloads",
                        description="Prevent file downloads from this origin. Inspect endpoint download directories for matching hashes.",
                        severity=EvidenceSeverity.CRITICAL,
                        reason="Malware payload distribution activity has been registered for this target host.",
                        action="HALT_DOWNLOADS",
                    )
                )

        # 2. Suspicious risk actions
        elif prediction == "suspicious" or risk_score >= 40:
            recs.append(
                DetailedRecommendation(
                    title="Exercise Cautious Navigation",
                    description="Open in an isolated sandboxed browser or virtual environment before entering sensitive interactions.",
                    severity=EvidenceSeverity.MEDIUM,
                    reason="Structural anomalies detected without conclusive external blacklist confirmation.",
                    action="BROWSER_ISOLATION",
                )
            )
            if young_domain:
                recs.append(
                    DetailedRecommendation(
                        title="Verify Domain Authenticity",
                        description="Verify the organization through authenticated secondary channels (e.g. corporate intranet or known phone).",
                        severity=EvidenceSeverity.MEDIUM,
                        reason="Domain registration is recent, which is a frequent characteristic of disposable attack infrastructure.",
                        action="VERIFY_OUT_OF_BAND",
                    )
                )
            if is_ip_host:
                recs.append(
                    DetailedRecommendation(
                        title="Inspect Direct IP Communication",
                        description="Avoid direct IP web connections lacking standard SNI certificate identities.",
                        severity=EvidenceSeverity.MEDIUM,
                        reason="Raw IP addressing bypasses conventional DNS monitoring controls.",
                        action="RESTRICT_RAW_IP",
                    )
                )

        # 3. Safe URL actions
        else:
            recs.append(
                DetailedRecommendation(
                    title="Standard Safe Browsing",
                    description="No anomalous indicators identified. Standard security policies apply.",
                    severity=EvidenceSeverity.INFO,
                    reason="Domain footprint aligns with legitimate registered entities.",
                    action="ALLOW_STANDARD",
                )
            )

        # 4. Telemetry Gap Advisory
        if unavail_providers:
            prov_names = [e.source.value.replace("_", " ").title() for e in unavail_providers]
            recs.append(
                DetailedRecommendation(
                    title="Re-Scan When Providers Recover",
                    description=f"External telemetry for {', '.join(prov_names)} was degraded during this scan. Refresh intelligence when online.",
                    severity=EvidenceSeverity.LOW,
                    reason="Full multi-source consensus could not be verified due to upstream timeouts.",
                    action="RETRY_INTEL",
                )
            )

        return recs


recommendation_engine = RecommendationEngine()
