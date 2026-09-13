"""
Tool 3: DNS Analysis Tool (`analyze_dns`).
Wraps the existing DNS intelligence service.
"""
from __future__ import annotations

from typing import Any, Dict, Optional
from pydantic import BaseModel, Field
from app.agent.tools.base import AgentTool
from app.agent.tool_result import ToolResult, ToolStatus
from app.services.dns_service import resolve_dns
from app.utils.validators import normalize_domain


class DNSAnalysisInput(BaseModel):
    domain: Optional[str] = Field(None, description="The domain or hostname to resolve")
    url: Optional[str] = Field(None, description="Optional URL from which to extract the domain")


class DNSAnalysisTool(AgentTool):
    tool_name = "analyze_dns"
    description = "Resolve DNS records (A, AAAA, MX, NS, TXT) and inspect infrastructure status."
    input_schema = DNSAnalysisInput

    async def execute(self, arguments: Dict[str, Any]) -> ToolResult:
        domain = arguments.get("domain")
        url = arguments.get("url")

        target = domain or url
        if not target:
            return ToolResult(
                tool_name=self.tool_name,
                status=ToolStatus.ERROR,
                summary="A domain or URL must be provided for DNS analysis.",
                error="MISSING_TARGET",
            )

        norm_domain = normalize_domain(target)
        if not norm_domain:
            return ToolResult(
                tool_name=self.tool_name,
                status=ToolStatus.ERROR,
                summary=f"Could not extract a valid domain from '{target}'.",
                error="INVALID_DOMAIN",
            )

        try:
            dns_data = await resolve_dns(norm_domain)
            status_str = dns_data.get("status", "ok")

            a_records = dns_data.get("a", [])
            ns_records = dns_data.get("ns", [])
            mx_records = dns_data.get("mx", [])

            anomalies = []
            if not a_records and status_str != "error":
                anomalies.append("No A records resolved")
            if not ns_records:
                anomalies.append("No nameservers found")
            if not mx_records:
                anomalies.append("No MX records configured")

            if status_str == "error":
                return ToolResult(
                    tool_name=self.tool_name,
                    status=ToolStatus.NO_DATA,
                    data={"domain": norm_domain, "raw": dns_data},
                    summary=f"DNS resolution failed for domain '{norm_domain}'.",
                )

            summary = (
                f"DNS resolved {len(a_records)} A record(s) and {len(ns_records)} NS record(s) "
                f"for domain '{norm_domain}'."
            )
            if anomalies:
                summary += f" Observations: {'; '.join(anomalies)}."

            return ToolResult(
                tool_name=self.tool_name,
                status=ToolStatus.SUCCESS,
                data={
                    "domain": norm_domain,
                    "records": dns_data,
                    "anomalies": anomalies,
                    "resolved_ips": a_records,
                    "nameservers": ns_records,
                },
                summary=summary,
            )
        except Exception as exc:
            return ToolResult(
                tool_name=self.tool_name,
                status=ToolStatus.ERROR,
                summary=f"DNS analysis error: {exc}",
                error=str(exc),
            )
