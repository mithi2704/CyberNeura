"""
Evidence API Routes for CyberNeura Phase 3.
Exposes endpoints for querying scan evidence, aggregated evidence stats, and taxonomy types.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException
from app.services.scan_store import scan_store
from app.evidence.models import EvidenceSource, EvidenceType, EvidenceSeverity, EvidenceState

router = APIRouter(prefix="/evidence", tags=["Evidence Engine"])


@router.get("/scan/{scan_id}", summary="Get all evidence items for a scan")
async def get_scan_evidence(scan_id: str):
    """Retrieve normalized evidence list compiled for a scan."""
    evidence = scan_store.get_assessment_evidence(scan_id)
    return {
        "scan_id": scan_id,
        "evidence": evidence,
        "count": len(evidence),
    }


@router.get("/stats", summary="Get aggregated evidence statistics")
async def get_evidence_stats():
    """Retrieve cross-scan evidence metrics by source and severity for Threat Intelligence displays."""
    return scan_store.get_evidence_stats()


@router.get("/types", summary="Get supported evidence taxonomy sources and types")
async def get_evidence_types():
    """Return dictionary of supported evidence sources, types, severities, and states."""
    return {
        "sources": [s.value for s in EvidenceSource],
        "types": [t.value for t in EvidenceType],
        "severities": [sev.value for sev in EvidenceSeverity],
        "states": [st.value for st in EvidenceState],
    }
