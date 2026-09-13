"""
Core URL Scan Orchestrator — Phase 2 Multi-Source Threat Intelligence Pipeline.
Coordinates: feature extraction → DNS/WHOIS → ML inference → external threat intel →
evidence correlation → risk scoring → persistence.
"""
from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List

from app.services.feature_extractor import extract_features
from app.services.dns_service import resolve_dns, format_dns_for_display, get_primary_ip
from app.services.whois_service import query_whois, calculate_domain_age, format_whois_for_display
from app.services.risk_engine import (
    calculate_risk_score, classify, get_threat_category,
    calculate_confidence, generate_recommendations, generate_explanation,
)
from app.services.evidence_service import compile_evidence, count_independent_confirmations
from app.intelligence.manager import threat_intel_manager
from app.ml.predictor import predict, get_model_version
from app.utils.validators import normalize_url, extract_domain
from app.schemas.scan import ScanResponse
from app.database import get_db
from app.services.scan_store import scan_store
from app.realtime import event_publisher, RealtimeEventType, EntityType
from app.utils.logger import get_logger

logger = get_logger(__name__)


async def execute_scan(url: str, user_id: Optional[str] = None) -> ScanResponse:
    """
    Phase 3 Full scan pipeline orchestrated by assessment_service:
    1. Validate & normalize URL
    2. Concurrent: DNS, WHOIS, Threat Intelligence, Feature Extraction, History
    3. ML inference
    4. Evidence Normalization & Correlation
    5. Deterministic Risk Scoring & Confidence Calculation
    6. Audit Explanations & Actionable Recommendations
    7. Persistence in scan_store and Supabase
    8. Return backwards-compatible ScanResponse enriched with Phase 3 models
    """
    from app.services.assessment_service import assessment_service

    assessment, ctx = await assessment_service.execute_full_assessment(url=url, user_id=user_id)

    threat_intel_dict = {
        name: res.model_dump()
        for name, res in ctx["intel_results"].items()
    }
    evidence_dicts = [e.model_dump() for e in assessment.evidence]
    factor_dicts = [rf.model_dump() for rf in assessment.risk_factors]
    findings_dicts = [cf.model_dump() for cf in assessment.correlated_findings]
    recommendation_strings = [r.description for r in assessment.recommendations]

    response = ScanResponse(
        id=assessment.scan_id,
        url=assessment.url,
        prediction=assessment.prediction,
        riskScore=assessment.risk_score,
        confidence=round(assessment.confidence, 1),
        probability=round(ctx["probability"], 4),
        threatCategory=assessment.threat_category if assessment.prediction != "safe" else None,
        isMalicious=assessment.prediction == "malicious",
        explanation=assessment.explanation,
        featureImportance=ctx["feature_importance"],
        domainAge=ctx.get("domain_age"),
        hostingProvider=ctx.get("hosting_provider"),
        ipAddress=ctx.get("ip_address"),
        country=ctx.get("country"),
        sslStatus=ctx.get("ssl_status"),
        whoisRecord=ctx.get("whois_record"),
        dnsRecords=ctx.get("dns_records"),
        recommendations=recommendation_strings,
        modelVersion=ctx["model_version"],
        scannedAt=ctx["now"],
        threatIntelligence=threat_intel_dict,
        evidence=evidence_dicts,
        independentConfirmations=ctx["independent_confirmations"],
        riskAssessment=assessment.model_dump(),
        riskFactors=factor_dicts,
        correlatedFindings=findings_dicts,
        evidenceCount=assessment.evidence_count,
        severity=assessment.severity.value,
        summary=assessment.summary,
    )

    # Real-time: Publish SCAN_COMPLETED
    await event_publisher.publish(
        event_type=RealtimeEventType.SCAN_COMPLETED,
        entity_type=EntityType.URL_SCAN,
        entity_id=assessment.scan_id,
        user_id=user_id,
        payload={
            "id": assessment.scan_id,
            "url": assessment.url,
            "riskScore": assessment.risk_score,
            "prediction": assessment.prediction,
            "confidence": assessment.confidence,
            "threatCategory": assessment.threat_category,
            "ipAddress": ctx.get("ip_address"),
            "sslStatus": ctx.get("ssl_status"),
            "scannedAt": ctx["now"],
            "severity": assessment.severity.value,
            "summary": assessment.summary,
        },
    )

    return response


def _persist_scan(*, scan_id: str, url: str, user_id: Optional[str], **kwargs):
    """Persist scan to in-memory store and fire-and-forget to Supabase if configured."""
    scan_store.add_scan({
        "id": scan_id,
        "url": url,
        "scannedBy": user_id,
        "riskScore": kwargs["risk_score"],
        "prediction": kwargs["prediction"],
        "confidence": float(kwargs["confidence"]),
        "threatCategory": kwargs.get("threat_category"),
        "domainAge": kwargs.get("domain_age"),
        "hostingProvider": kwargs.get("hosting_provider"),
        "ipAddress": kwargs.get("ip_address"),
        "country": kwargs.get("country"),
        "sslStatus": kwargs.get("ssl_status"),
        "whoisRecord": kwargs.get("whois_record"),
        "dnsRecords": kwargs.get("dns_records"),
        "recommendations": kwargs.get("recommendations", []),
        "threatIntelligence": kwargs.get("threat_intelligence", {}),
        "scannedAt": kwargs["scanned_at"],
    })

    db = get_db()
    if db is None:
        return
    try:
        db.table("url_scans").insert({
            "id": scan_id,
            "url": url,
            "scanned_by": user_id,
            "risk_score": kwargs["risk_score"],
            "prediction": kwargs["prediction"],
            "confidence": int(kwargs["confidence"]),
            "threat_category": kwargs.get("threat_category"),
            "domain_age": kwargs.get("domain_age"),
            "hosting_provider": kwargs.get("hosting_provider"),
            "ip_address": kwargs.get("ip_address"),
            "country": kwargs.get("country"),
            "ssl_status": kwargs.get("ssl_status"),
            "whois_record": kwargs.get("whois_record"),
            "dns_records": kwargs.get("dns_records"),
            "recommendations": kwargs.get("recommendations", []),
            "scanned_at": kwargs["scanned_at"],
        }).execute()
    except Exception as exc:
        logger.warning(f"Could not persist scan {scan_id} to Supabase: {exc}")


def _persist_threat_intelligence(scan_id: str, intel_results: Dict[str, Any], now: str):
    """Save threat intelligence records into scan_store and Supabase."""
    items = [res.model_dump() for res in intel_results.values()]
    scan_store.add_scan_intelligence(scan_id, items)

    db = get_db()
    if db is None:
        return

    try:
        records = []
        for p_name, res in intel_results.items():
            records.append({
                "id": str(uuid.uuid4()),
                "scan_id": scan_id,
                "provider": p_name,
                "indicator": res.indicator,
                "indicator_type": res.indicator_type,
                "status": res.verdict.value,
                "matched": res.matched,
                "verdict": res.verdict.value,
                "threat_type": ", ".join(res.categories) if res.categories else None,
                "confidence": res.confidence,
                "metadata": res.metadata,
                "checked_at": res.checked_at,
                "expires_at": res.expires_at,
                "latency_ms": res.latency_ms,
                "error_code": res.error,
                "created_at": now,
            })
        if records:
            db.table("threat_intelligence").insert(records).execute()
    except Exception as exc:
        logger.warning(f"Could not persist threat intelligence for {scan_id} to Supabase: {exc}")


def _create_threat_log(*, url: str, severity: str, threat_category: str,
                       ip_address: Optional[str], country: Optional[str], now: str):
    """Auto-create a threat log in scan_store and Supabase."""
    scan_store.add_threat({
        "id": f"t-{uuid.uuid4().hex[:8]}",
        "url": url,
        "severity": severity,
        "category": threat_category or "Malicious",
        "sourceIp": ip_address or "Unknown",
        "country": country or "Unknown",
        "timestamp": now,
        "status": "blocked",
    })

    db = get_db()
    if db is None:
        return
    try:
        existing = db.table("threat_logs").select("id").eq("url", url).limit(1).execute()
        if existing.data:
            return
        db.table("threat_logs").insert({
            "url": url,
            "severity": severity,
            "category": threat_category,
            "source_ip": ip_address or "Unknown",
            "country": country or "Unknown",
            "timestamp": now,
            "status": "blocked",
        }).execute()
    except Exception as exc:
        logger.warning(f"Could not create threat log in Supabase: {exc}")
