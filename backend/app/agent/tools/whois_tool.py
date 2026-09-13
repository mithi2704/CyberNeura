"""
Tool 4: WHOIS / Domain Analysis Tool (`analyze_domain`).
Wraps the existing WHOIS service.
"""
from __future__ import annotations

from typing import Any, Dict, Optional
from pydantic import BaseModel, Field
from app.agent.tools.base import AgentTool
from app.agent.tool_result import ToolResult, ToolStatus
from app.services.whois_service import query_whois
from app.utils.validators import normalize_domain


class DomainAnalysisInput(BaseModel):
    domain: Optional[str] = Field(None, description="The domain to query in WHOIS")
    url: Optional[str] = Field(None, description="Optional URL from which to extract the domain")


class DomainAnalysisTool(AgentTool):
    tool_name = "analyze_domain"
    description = "Retrieve WHOIS domain registration details including age, registrar, dates, and nameservers."
    input_schema = DomainAnalysisInput

    async def execute(self, arguments: Dict[str, Any]) -> ToolResult:
        domain = arguments.get("domain")
        url = arguments.get("url")

        target = domain or url
        if not target:
            return ToolResult(
                tool_name=self.tool_name,
                status=ToolStatus.ERROR,
                summary="A domain or URL must be provided for domain analysis.",
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
            whois_data = await query_whois(norm_domain)
            registrar = whois_data.get("registrar") or "Unknown"
            age_days = whois_data.get("domain_age_days")
            creation_date = whois_data.get("creation_date")
            expiration_date = whois_data.get("expiration_date")

            status = ToolStatus.SUCCESS
            if not creation_date and registrar == "Unknown":
                status = ToolStatus.NO_DATA
                summary = f"No public WHOIS registration data found for '{norm_domain}'."
            else:
                age_str = f"{age_days} days old" if age_days is not None else "age unknown"
                summary = f"Domain '{norm_domain}' registered via {registrar} ({age_str})."

            return ToolResult(
                tool_name=self.tool_name,
                status=status,
                data={
                    "domain": norm_domain,
                    "registrar": registrar,
                    "domain_age_days": age_days,
                    "creation_date": creation_date,
                    "expiration_date": expiration_date,
                    "name_servers": whois_data.get("name_servers", []),
                    "status": whois_data.get("status", "unknown"),
                    "raw": whois_data,
                },
                summary=summary,
            )
        except Exception as exc:
            return ToolResult(
                tool_name=self.tool_name,
                status=ToolStatus.ERROR,
                summary=f"Domain analysis error: {exc}",
                error=str(exc),
            )
