"""
Tool 2: Threat Intelligence Tool (`lookup_threat_intelligence`).
Wraps the Phase 2 Threat Intelligence Subsystem (Google Web Risk, PhishTank, URLhaus).
"""
from __future__ import annotations

from typing import Any, Dict, Optional
from pydantic import BaseModel, Field
from app.agent.tools.base import AgentTool
from app.agent.tool_result import ToolResult, ToolStatus
from app.intelligence.manager import threat_intel_manager
from app.services.scan_store import scan_store


class ThreatIntelInput(BaseModel):
    url: Optional[str] = Field(None, description="The URL to lookup across threat intelligence feeds")
    scan_id: Optional[str] = Field(None, description="Optional scan ID to retrieve existing threat intelligence")


class ThreatIntelTool(AgentTool):
    tool_name = "lookup_threat_intelligence"
    description = "Query multi-source external threat intelligence feeds (Google Web Risk, PhishTank, URLhaus)."
    input_schema = ThreatIntelInput
    timeout_seconds = 10.0

    async def execute(self, arguments: Dict[str, Any]) -> ToolResult:
        url = arguments.get("url")
        scan_id = arguments.get("scan_id")

        if not url and scan_id:
            scan = scan_store.get_scan(scan_id)
            if scan:
                url = scan.get("url")

        if not url:
            return ToolResult(
                tool_name=self.tool_name,
                status=ToolStatus.ERROR,
                summary="A valid URL or scan_id must be provided for threat intelligence lookup.",
                error="MISSING_URL",
            )

        try:
            results_dict = await threat_intel_manager.lookup_all(url)
            results = list(results_dict.values())

            providers_data = []
            matches = []
            unavailable = []

            for r in results:
                # Sanitize provider result: zero secrets exposed
                verdict_str = r.verdict.value if hasattr(r.verdict, "value") else str(r.verdict)
                cat_str = r.categories[0] if r.categories else "SAFE"
                p_info = {
                    "provider": r.provider,
                    "available": r.available,
                    "matched": r.matched,
                    "verdict": verdict_str,
                    "categories": r.categories,
                    "confidence": r.confidence,
                    "checked_at": r.checked_at,
                }
                providers_data.append(p_info)

                if r.matched or verdict_str == "MATCH":
                    matches.append(f"{r.provider} ({cat_str})")
                elif not r.available or verdict_str in ("UNAVAILABLE", "ERROR"):
                    unavailable.append(r.provider)

            status = ToolStatus.SUCCESS
            if matches:
                summary = f"Threat intelligence MATCH detected by: {', '.join(matches)}."
            elif unavailable and len(unavailable) == len(results):
                status = ToolStatus.UNAVAILABLE
                summary = "All external threat intelligence providers were unavailable."
            else:
                summary = f"Threat intelligence checked across {len(results)} providers: no confirmed matches."

            return ToolResult(
                tool_name=self.tool_name,
                status=status,
                data={
                    "url": url,
                    "providers": providers_data,
                    "total_checked": len(results),
                    "matched_count": len(matches),
                    "unavailable_count": len(unavailable),
                },
                summary=summary,
            )
        except Exception as exc:
            return ToolResult(
                tool_name=self.tool_name,
                status=ToolStatus.ERROR,
                summary=f"Threat intelligence lookup failed: {exc}",
                error=str(exc),
            )
