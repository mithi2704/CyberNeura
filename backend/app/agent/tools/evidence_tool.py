"""
Tool 6: Evidence Tool (`get_evidence`).
Wraps the Phase 3 Normalized Evidence Subsystem and Correlated Findings.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from app.agent.tools.base import AgentTool
from app.agent.tool_result import ToolResult, ToolStatus
from app.services.scan_store import scan_store


class EvidenceInput(BaseModel):
    scan_id: Optional[str] = Field(None, description="The scan ID to retrieve normalized evidence for")
    url: Optional[str] = Field(None, description="Optional URL to look up corresponding scan evidence")


class EvidenceTool(AgentTool):
    tool_name = "get_evidence"
    description = "Retrieve Phase 3 normalized evidence items, severities, observation states, and correlated findings."
    input_schema = EvidenceInput

    async def execute(self, arguments: Dict[str, Any]) -> ToolResult:
        scan_id = arguments.get("scan_id")
        url = arguments.get("url")

        # If scan_id not given but url is, locate scan_id from scan_store
        if not scan_id and url:
            hist = scan_store.query_historical_evidence(url=url)
            scans = hist.get("scans", [])
            if scans:
                scan_id = scans[0].get("id")

        if not scan_id:
            # Try to run full assessment to compile fresh evidence if URL is provided
            if url:
                try:
                    from app.services.assessment_service import assessment_service
                    assessment, _ = await assessment_service.execute_full_assessment(url=url)
                    scan_id = assessment.scan_id
                except Exception as e:
                    return ToolResult(
                        tool_name=self.tool_name,
                        status=ToolStatus.ERROR,
                        summary=f"Could not compile evidence for URL '{url}': {e}",
                        error=str(e),
                    )
            else:
                return ToolResult(
                    tool_name=self.tool_name,
                    status=ToolStatus.ERROR,
                    summary="Either a scan_id or URL must be provided to retrieve evidence.",
                    error="MISSING_TARGET",
                )

        evidence_items = scan_store.get_assessment_evidence(scan_id)
        findings = scan_store.get_assessment_findings(scan_id)

        if not evidence_items:
            return ToolResult(
                tool_name=self.tool_name,
                status=ToolStatus.NO_DATA,
                data={"scan_id": scan_id, "evidence": [], "findings": []},
                summary=f"No normalized evidence recorded for scan ID '{scan_id}'.",
            )

        # Categorize supporting vs contradicting vs neutral
        critical_count = sum(1 for e in evidence_items if e.get("severity") in ("CRITICAL", "HIGH"))
        unavailable_count = sum(1 for e in evidence_items if e.get("state") == "UNAVAILABLE")

        summary = (
            f"Retrieved {len(evidence_items)} normalized evidence item(s) and {len(findings)} correlated finding(s) "
            f"for scan '{scan_id}'. High/Critical items: {critical_count}, Unavailable sources: {unavailable_count}."
        )

        return ToolResult(
            tool_name=self.tool_name,
            status=ToolStatus.SUCCESS,
            data={
                "scan_id": scan_id,
                "evidence_count": len(evidence_items),
                "findings_count": len(findings),
                "evidence": evidence_items,
                "correlated_findings": findings,
                "critical_count": critical_count,
                "unavailable_count": unavailable_count,
            },
            summary=summary,
        )
