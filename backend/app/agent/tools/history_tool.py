"""
Tool 5: History Tool (`get_historical_evidence`).
Wraps the historical scan repository and time-decay observation queries.
"""
from __future__ import annotations

from typing import Any, Dict, Optional
from pydantic import BaseModel, Field
from app.agent.tools.base import AgentTool
from app.agent.tool_result import ToolResult, ToolStatus
from app.services.scan_store import scan_store
from app.utils.validators import normalize_domain


class HistoryInput(BaseModel):
    url: Optional[str] = Field(None, description="The URL to search in historical scans")
    domain: Optional[str] = Field(None, description="Optional domain to search in historical scans")
    scan_id: Optional[str] = Field(None, description="Optional scan ID to search for historical records")


class HistoryTool(AgentTool):
    tool_name = "get_historical_evidence"
    description = "Retrieve previous CyberNeura scan history, past predictions, risk scores, and detection frequency."
    input_schema = HistoryInput

    async def execute(self, arguments: Dict[str, Any]) -> ToolResult:
        url = arguments.get("url")
        domain = arguments.get("domain")
        scan_id = arguments.get("scan_id")

        if not url and scan_id:
            scan = scan_store.get_scan(scan_id)
            if scan:
                url = scan.get("url")

        target = url or domain
        if not target:
            return ToolResult(
                tool_name=self.tool_name,
                status=ToolStatus.ERROR,
                summary="A URL, domain, or scan_id must be provided for historical analysis.",
                error="MISSING_TARGET",
            )

        norm_domain = normalize_domain(target) if target else None
        try:
            hist = scan_store.query_historical_evidence(url=target, domain=norm_domain)
            scans = hist.get("scans", [])
            matched_count = hist.get("matched_count", 0)

            if matched_count == 0:
                return ToolResult(
                    tool_name=self.tool_name,
                    status=ToolStatus.NO_DATA,
                    data={"target": target, "matched_count": 0, "scans": []},
                    summary=f"No prior scan history found for '{target}'.",
                )

            malicious_count = sum(1 for s in scans if str(s.get("prediction", "")).lower() == "malicious")
            suspicious_count = sum(1 for s in scans if str(s.get("prediction", "")).lower() == "suspicious")
            latest_scan = scans[0] if scans else {}
            last_risk = latest_scan.get("riskScore", 0)
            last_date = latest_scan.get("scannedAt", "unknown")

            summary = (
                f"Found {matched_count} previous scan(s). Malicious detections: {malicious_count}, "
                f"Suspicious detections: {suspicious_count}. Latest risk score: {last_risk}/100 ({last_date})."
            )

            return ToolResult(
                tool_name=self.tool_name,
                status=ToolStatus.SUCCESS,
                data={
                    "target": target,
                    "matched_count": matched_count,
                    "malicious_count": malicious_count,
                    "suspicious_count": suspicious_count,
                    "latest_scan": latest_scan,
                    "scans_sample": [
                        {
                            "id": s.get("id"),
                            "url": s.get("url"),
                            "prediction": s.get("prediction"),
                            "risk_score": s.get("riskScore"),
                            "scanned_at": s.get("scannedAt"),
                        }
                        for s in scans[:5]
                    ],
                },
                summary=summary,
            )
        except Exception as exc:
            return ToolResult(
                tool_name=self.tool_name,
                status=ToolStatus.ERROR,
                summary=f"History query error: {exc}",
                error=str(exc),
            )
