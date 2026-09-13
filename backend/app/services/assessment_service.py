"""
Unified Assessment Service for CyberNeura Phase 3.
Coordinates the complete end-to-end intelligence and risk analysis pipeline:
Feature Extraction → Concurrent DNS/WHOIS/ThreatIntel/History → ML Inference →
Evidence Normalization → Evidence Correlation → Deterministic Risk Scoring →
Confidence Calculation → Audit Explanations & Recommendations → Persistence.
"""
from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from app.evidence.normalizer import EvidenceNormalizer
from app.evidence.correlator import correlator
from app.risk.engine import risk_engine, RISK_ENGINE_VERSION
from app.risk.models import SecurityAssessment, RiskFactor
from app.services.feature_extractor import extract_features
from app.services.dns_service import resolve_dns, format_dns_for_display, get_primary_ip
from app.services.whois_service import query_whois, calculate_domain_age, format_whois_for_display
from app.intelligence.manager import threat_intel_manager
from app.ml.predictor import predict, get_model_version
from app.utils.validators import normalize_url, extract_domain
from app.services.scan_store import scan_store
from app.database import get_db
from app.realtime import event_publisher, RealtimeEventType, EntityType
from app.utils.logger import get_logger

logger = get_logger(__name__)


class AssessmentService:
    def __init__(self):
        self.normalizer = EvidenceNormalizer()
        self.correlator = correlator
        self.risk_engine = risk_engine

    async def execute_full_assessment(
        self,
        url: str,
        user_id: Optional[str] = None,
        scan_id: Optional[str] = None,
    ) -> Tuple[SecurityAssessment, Dict[str, Any]]:
        """
        Execute full Phase 3 assessment pipeline.
        Returns (SecurityAssessment, context_dict) containing all telemetry for response generation.
        """
        scan_id = scan_id or str(uuid.uuid4())
        normalized_url = normalize_url(url)
        domain = extract_domain(normalized_url)
        now = datetime.now(timezone.utc).isoformat()

        logger.info(f"[{scan_id}] Executing Phase 3 Assessment Pipeline for: {normalized_url}")

        # Real-time: Publish SCAN_STARTED
        await event_publisher.publish(
            event_type=RealtimeEventType.SCAN_STARTED,
            entity_type=EntityType.URL_SCAN,
            entity_id=scan_id,
            user_id=user_id,
            payload={"url": normalized_url, "scan_id": scan_id},
        )

        # ── Step 1: Concurrent Data Gathering ─────────────────────────────
        try:
            dns_task = asyncio.create_task(resolve_dns(domain))
            whois_task = asyncio.create_task(query_whois(domain))
            intel_task = asyncio.create_task(threat_intel_manager.lookup_all(normalized_url))

            dns_data, whois_data, intel_results = await asyncio.gather(
                dns_task, whois_task, intel_task, return_exceptions=False
            )
        except Exception as exc:
            logger.warning(f"[{scan_id}] Concurrent lookup warning: {exc}")
            dns_data = {"status": "error"}
            whois_data = {"status": "error"}
            intel_results = {}

        # Real-time: Check if any threat intelligence matched and publish THREAT_DETECTED
        for prov_name, res in intel_results.items():
            if getattr(res, "matched", False):
                await event_publisher.publish(
                    event_type=RealtimeEventType.THREAT_DETECTED,
                    entity_type=EntityType.THREAT_INTELLIGENCE,
                    entity_id=scan_id,
                    user_id=user_id,
                    payload={
                        "scan_id": scan_id,
                        "url": normalized_url,
                        "provider": prov_name,
                        "threat_category": getattr(res, "threat_type", "Malicious"),
                        "severity": "CRITICAL" if prov_name == "phishtank" else "HIGH",
                    },
                )

        # ── Step 2: Feature Extraction ────────────────────────────────────
        features = extract_features(normalized_url)

        # ── Step 3: Resolve IP ────────────────────────────────────────────
        ip_address = None
        if dns_data.get("a"):
            ip_address = dns_data["a"][0]
        else:
            try:
                ip_address = await asyncio.wait_for(get_primary_ip(domain), timeout=3)
            except asyncio.TimeoutError:
                pass

        # ── Step 4: Query Historical Evidence ─────────────────────────────
        history_data = scan_store.query_historical_evidence(
            url=normalized_url, domain=domain, ip_address=ip_address
        )

        # ── Step 5: Machine Learning Inference ────────────────────
        ml_prediction, probability, ml_confidence, feature_importance = predict(features)

        # ── Step 6: Evidence Normalization ────────────────────────────────
        evidence_list = self.normalizer.normalize_all(
            scan_id=scan_id,
            url=normalized_url,
            domain=domain,
            ml_prediction=ml_prediction,
            probability=probability,
            features=features,
            whois_data=whois_data,
            dns_data=dns_data,
            intel_results=intel_results,
            history_data=history_data,
        )

        # ── Step 7: Evidence Correlation ──────────────────────────────────
        correlated_findings = self.correlator.correlate(evidence_list, scan_id=scan_id)
        independent_confirmations = self.correlator.get_independent_confirmation_count(evidence_list)

        # ── Step 8: Risk Engine Assessment ────────────────────────────────
        assessment = self.risk_engine.assess(
            scan_id=scan_id,
            url=normalized_url,
            probability=probability,
            evidence_list=evidence_list,
            correlated_findings=correlated_findings,
        )

        # Context details for legacy frontend and persistence compatibility
        context = {
            "scan_id": scan_id,
            "url": normalized_url,
            "domain": domain,
            "now": now,
            "user_id": user_id,
            "probability": probability,
            "ml_prediction": ml_prediction,
            "feature_importance": feature_importance,
            "features": features,
            "dns_data": dns_data,
            "whois_data": whois_data,
            "intel_results": intel_results,
            "ip_address": ip_address,
            "domain_age": calculate_domain_age(whois_data),
            "hosting_provider": whois_data.get("registrar") if whois_data.get("status") == "ok" else None,
            "country": whois_data.get("country") if whois_data.get("status") == "ok" else None,
            "ssl_status": "valid" if normalized_url.startswith("https://") and not features.get("has_suspicious_port") else "none",
            "whois_record": format_whois_for_display(whois_data, domain),
            "dns_records": format_dns_for_display(dns_data),
            "model_version": get_model_version(),
            "independent_confirmations": independent_confirmations,
        }

        # ── Step 9: Persistence ───────────────────────────────────────────
        self._persist_assessment(assessment=assessment, context=context)

        # Real-time: Publish RISK_ASSESSMENT_COMPLETED
        await event_publisher.publish(
            event_type=RealtimeEventType.RISK_ASSESSMENT_COMPLETED,
            entity_type=EntityType.RISK_ASSESSMENT,
            entity_id=assessment.id,
            user_id=user_id,
            payload={
                "assessment_id": assessment.id,
                "scan_id": scan_id,
                "url": normalized_url,
                "risk_score": assessment.risk_score,
                "prediction": assessment.prediction,
                "confidence": assessment.confidence,
                "threat_category": assessment.threat_category,
                "severity": assessment.severity.value,
                "summary": assessment.summary,
            },
        )

        # Real-time: If high-risk or critical threat detected, publish alert & notification
        if assessment.risk_score >= 80 or assessment.severity.value in ("CRITICAL", "HIGH"):
            alert_payload = {
                "title": f"High Risk Threat: {assessment.threat_category}",
                "message": f"URL {normalized_url} flagged with risk score {assessment.risk_score}/100.",
                "severity": assessment.severity.value,
                "scan_id": scan_id,
                "url": normalized_url,
            }
            await event_publisher.publish(
                event_type=RealtimeEventType.SECURITY_ALERT_CREATED,
                entity_type=EntityType.SECURITY_ALERT,
                entity_id=scan_id,
                user_id=user_id,
                payload=alert_payload,
            )
            await event_publisher.publish(
                event_type=RealtimeEventType.NOTIFICATION_CREATED,
                entity_type=EntityType.NOTIFICATION,
                entity_id=f"notif-{uuid.uuid4().hex[:8]}",
                user_id=user_id,
                payload=alert_payload,
            )

        logger.info(
            f"[{scan_id}] Assessment complete: {assessment.prediction.upper()} "
            f"(Score: {assessment.risk_score}/100, Confidence: {assessment.confidence}%, "
            f"Evidence: {assessment.evidence_count}, Confirmations: {independent_confirmations})"
        )

        return assessment, context

    def _persist_assessment(self, assessment: SecurityAssessment, context: Dict[str, Any]):
        """Persist full assessment, evidence, findings, factors, and legacy scan records."""
        scan_id = assessment.scan_id
        now = context["now"]

        # Convert objects to dicts
        evidence_dicts = [e.model_dump() for e in assessment.evidence]
        findings_dicts = [f.model_dump() for f in assessment.correlated_findings]
        factor_dicts = [rf.model_dump() for rf in assessment.risk_factors]
        recs_list = [r.description for r in assessment.recommendations]
        threat_intel_dict = {
            name: res.model_dump()
            for name, res in context["intel_results"].items()
        }

        # 1. Save in-memory to scan_store
        scan_store.save_assessment(
            assessment_dict=assessment.model_dump(),
            evidence_list=evidence_dicts,
            findings_list=findings_dicts,
            factors_list=factor_dicts,
        )

        # 2. Add scan summary into scan_store for legacy tables & logs
        scan_store.add_scan({
            "id": scan_id,
            "url": assessment.url,
            "scannedBy": context.get("user_id"),
            "riskScore": assessment.risk_score,
            "prediction": assessment.prediction,
            "confidence": assessment.confidence,
            "threatCategory": assessment.threat_category,
            "domainAge": context.get("domain_age"),
            "hostingProvider": context.get("hosting_provider"),
            "ipAddress": context.get("ip_address"),
            "country": context.get("country"),
            "sslStatus": context.get("ssl_status"),
            "whoisRecord": context.get("whois_record"),
            "dnsRecords": context.get("dns_records"),
            "recommendations": recs_list,
            "threatIntelligence": threat_intel_dict,
            "scannedAt": now,
            "evidenceCount": assessment.evidence_count,
            "summary": assessment.summary,
        })

        scan_store.add_scan_intelligence(scan_id, [res.model_dump() for res in context["intel_results"].values()])

        # 3. Create threat log if malicious
        if assessment.prediction == "malicious":
            scan_store.add_threat({
                "id": f"t-{uuid.uuid4().hex[:8]}",
                "url": assessment.url,
                "severity": "critical" if assessment.risk_score >= 85 else "high",
                "category": assessment.threat_category or "Malicious",
                "sourceIp": context.get("ip_address") or "Unknown",
                "country": context.get("country") or "Unknown",
                "timestamp": now,
                "status": "blocked",
            })

        # 4. Fire-and-forget Supabase persistence if connected
        db = get_db()
        if db is None:
            return

        try:
            # url_scans table
            db.table("url_scans").insert({
                "id": scan_id,
                "url": assessment.url,
                "scanned_by": context.get("user_id"),
                "risk_score": assessment.risk_score,
                "prediction": assessment.prediction,
                "confidence": int(assessment.confidence),
                "threat_category": assessment.threat_category,
                "domain_age": context.get("domain_age"),
                "hosting_provider": context.get("hosting_provider"),
                "ip_address": context.get("ip_address"),
                "country": context.get("country"),
                "ssl_status": context.get("ssl_status"),
                "whois_record": context.get("whois_record"),
                "dns_records": context.get("dns_records"),
                "recommendations": recs_list,
                "scanned_at": now,
            }).execute()

            # risk_assessments table
            db.table("risk_assessments").insert({
                "id": assessment.id,
                "scan_id": scan_id,
                "risk_score": assessment.risk_score,
                "prediction": assessment.prediction,
                "confidence": assessment.confidence,
                "threat_category": assessment.threat_category,
                "severity": assessment.severity.value,
                "summary": assessment.summary,
                "evidence_count": assessment.evidence_count,
                "critical_evidence_count": assessment.critical_evidence_count,
                "supporting_evidence_count": assessment.supporting_evidence_count,
                "contradicting_evidence_count": assessment.contradicting_evidence_count,
                "explanation": assessment.explanation,
                "risk_engine_version": assessment.risk_engine_version,
                "config_version": assessment.config_version,
                "created_at": assessment.created_at,
            }).execute()

            # scan_evidence table
            if evidence_dicts:
                db_evs = [
                    {
                        "id": e["id"],
                        "scan_id": scan_id,
                        "source": e["source"],
                        "evidence_type": e["evidence_type"],
                        "category": e.get("category"),
                        "severity": e["severity"],
                        "state": e["state"],
                        "value": str(e.get("value")),
                        "score": e.get("score", 0.0),
                        "confidence": e.get("confidence", 1.0),
                        "weight": e.get("weight", 1.0),
                        "supports_risk": e.get("supports_risk", True),
                        "description": e.get("description"),
                        "metadata": e.get("metadata", {}),
                        "created_at": e.get("created_at", now),
                    }
                    for e in evidence_dicts
                ]
                db.table("scan_evidence").insert(db_evs).execute()

            # correlated_findings table
            if findings_dicts:
                db_findings = [
                    {
                        "id": f["id"],
                        "scan_id": scan_id,
                        "finding_type": f["finding_type"],
                        "severity": f["severity"],
                        "confidence": f["confidence"],
                        "description": f["description"],
                        "sources": f.get("sources", []),
                        "evidence_ids": f.get("evidence_ids", []),
                        "rule_id": f.get("rule_id"),
                        "created_at": f.get("created_at", now),
                    }
                    for f in findings_dicts
                ]
                db.table("correlated_findings").insert(db_findings).execute()

            # risk_factors table
            if factor_dicts:
                db_factors = [
                    {
                        "id": rf["id"],
                        "scan_id": scan_id,
                        "factor_type": rf["factor_type"],
                        "factor_name": rf["factor_name"],
                        "raw_value": str(rf.get("raw_value")),
                        "normalized_value": rf.get("normalized_value", 0.0),
                        "weight": rf.get("weight", 0.1),
                        "contribution": rf.get("contribution", 0.0),
                        "max_contribution": rf.get("max_contribution", 10.0),
                        "direction": rf.get("direction", "RISK_INCREASING"),
                        "description": rf.get("description"),
                        "created_at": rf.get("created_at", now),
                    }
                    for rf in factor_dicts
                ]
                db.table("risk_factors").insert(db_factors).execute()

        except Exception as exc:
            logger.warning(f"Could not persist Phase 3 assessment for {scan_id} to Supabase: {exc}")


assessment_service = AssessmentService()
