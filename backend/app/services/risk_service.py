"""
Risk Service for CyberNeura Phase 3.
Provides business logic for retrieving assessments, recalculating risk with active configurations,
querying risk factor breakdowns, and managing engine configs.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from app.risk.engine import risk_engine, RiskEngine
from app.risk.models import SecurityAssessment, RiskConfig
from app.evidence.models import Evidence, CorrelatedFinding
from app.services.scan_store import scan_store
from app.database import get_db
from app.utils.logger import get_logger

logger = get_logger(__name__)


class RiskService:
    def get_assessment(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve full SecurityAssessment by scan_id."""
        return scan_store.get_assessment(scan_id)

    def get_evidence(self, scan_id: str) -> List[Dict[str, Any]]:
        """Retrieve list of normalized Evidence objects for a scan."""
        return scan_store.get_assessment_evidence(scan_id)

    def get_factors(self, scan_id: str) -> List[Dict[str, Any]]:
        """Retrieve list of RiskFactor items for a scan."""
        return scan_store.get_assessment_factors(scan_id)

    def get_findings(self, scan_id: str) -> List[Dict[str, Any]]:
        """Retrieve list of CorrelatedFinding items for a scan."""
        return scan_store.get_assessment_findings(scan_id)

    def recalculate_assessment(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """
        Recalculate an existing assessment using the active risk engine configuration.
        Re-evaluates evidence and rules without re-running network calls.
        """
        raw_evidence = scan_store.get_assessment_evidence(scan_id)
        if not raw_evidence:
            return None

        # Re-instantiate Evidence objects
        evidence_objects = [Evidence(**e) for e in raw_evidence]

        # Re-instantiate CorrelatedFindings
        raw_findings = scan_store.get_assessment_findings(scan_id)
        findings_objects = [CorrelatedFinding(**f) for f in raw_findings] if raw_findings else []

        # Get active config
        active_config_dict = scan_store.get_active_risk_config()
        active_config = RiskConfig(**active_config_dict)
        custom_engine = RiskEngine(active_config)

        # Retrieve prior assessment or scan for base metadata
        existing_assessment = scan_store.get_assessment(scan_id) or {}
        url = existing_assessment.get("url", "")
        # Find probability from evidence
        ml_ev = next((e for e in evidence_objects if e.source.value == "ML"), None)
        prob = ml_ev.score if ml_ev else 0.5

        new_assessment = custom_engine.assess(
            scan_id=scan_id,
            url=url,
            probability=prob,
            evidence_list=evidence_objects,
            correlated_findings=findings_objects,
        )

        # Persist updated assessment
        assessment_dict = new_assessment.model_dump()
        scan_store.save_assessment(
            assessment_dict=assessment_dict,
            evidence_list=raw_evidence,
            findings_list=raw_findings,
            factors_list=[f.model_dump() for f in new_assessment.risk_factors],
        )

        return assessment_dict

    def get_config(self) -> Dict[str, Any]:
        """Return the active RiskConfig."""
        return scan_store.get_active_risk_config()

    def update_config(self, new_config: Dict[str, Any]) -> Dict[str, Any]:
        """Update the active RiskConfig."""
        return scan_store.update_risk_config(new_config)


risk_service = RiskService()
