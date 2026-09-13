"""
Tool 7: Risk Assessment Tool (`get_risk_assessment`).
Retrieves the authoritative Phase 3 deterministic security assessment.
"""
from __future__ import annotations

from typing import Any, Dict, Optional
from pydantic import BaseModel, Field
from app.agent.tools.base import AgentTool
from app.agent.tool_result import ToolResult, ToolStatus
from app.services.scan_store import scan_store


class RiskAssessmentInput(BaseModel):
    scan_id: Optional[str] = Field(None, description="The scan ID to retrieve the risk assessment for")
    url: Optional[str] = Field(None, description="Optional URL to look up corresponding assessment")


class RiskAssessmentTool(AgentTool):
    tool_name = "get_risk_assessment"
    description = "Retrieve the authoritative Phase 3 deterministic security assessment, risk score, factors, and recommendations."
    input_schema = RiskAssessmentInput

    async def execute(self, arguments: Dict[str, Any]) -> ToolResult:
        scan_id = arguments.get("scan_id")
        url = arguments.get("url")

        if not scan_id and url:
            hist = scan_store.query_historical_evidence(url=url)
            scans = hist.get("scans", [])
            if scans:
                scan_id = scans[0].get("id")

        if not scan_id:
            if url:
                try:
                    from app.services.assessment_service import assessment_service
                    assessment, _ = await assessment_service.execute_full_assessment(url=url)
                    scan_id = assessment.scan_id
                except Exception as e:
                    return ToolResult(
                        tool_name=self.tool_name,
                        status=ToolStatus.ERROR,
                        summary=f"Could not compute risk assessment for URL '{url}': {e}",
                        error=str(e),
                    )
            else:
                return ToolResult(
                    tool_name=self.tool_name,
                    status=ToolStatus.ERROR,
                    summary="Either a scan_id or URL must be provided to retrieve the risk assessment.",
                    error="MISSING_TARGET",
                )

        assessment = scan_store.get_assessment(scan_id)
        if not assessment:
            return ToolResult(
                tool_name=self.tool_name,
                status=ToolStatus.NO_DATA,
                data={"scan_id": scan_id},
                summary=f"No risk assessment found for scan ID '{scan_id}'.",
            )

        factors = scan_store.get_assessment_factors(scan_id)
        score = assessment.get("risk_score", 0)
        prediction = assessment.get("prediction", "SAFE")
        confidence = assessment.get("confidence", 0.0)
        category = assessment.get("threat_category", "Safe")
        severity = assessment.get("severity", "LOW")

        summary = (
            f"Phase 3 Assessment for '{scan_id}': {prediction.upper()} (Risk Score: {score}/100, "
            f"Confidence: {confidence:.1f}%, Category: {category}, Severity: {severity})."
        )

        return ToolResult(
            tool_name=self.tool_name,
            status=ToolStatus.SUCCESS,
            data={
                "scan_id": scan_id,
                "url": assessment.get("url"),
                "risk_score": score,
                "prediction": prediction,
                "confidence": confidence,
                "threat_category": category,
                "severity": severity,
                "risk_factors": factors,
                "explanation": assessment.get("explanation"),
                "recommendations": assessment.get("recommendations", []),
                "risk_engine_version": assessment.get("risk_engine_version", "1.0.0"),
                "config_version": assessment.get("config_version", "2026.09.1"),
                "created_at": assessment.get("created_at"),
            },
            summary=summary,
        )
