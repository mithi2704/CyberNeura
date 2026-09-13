"""
Tool 8: URL Structural Analysis Tool (`analyze_url_structure`).
Wraps the lexical feature extractor and structural URL parser.
"""
from __future__ import annotations

import urllib.parse
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field
from app.agent.tools.base import AgentTool
from app.agent.tool_result import ToolResult, ToolStatus
from app.services.feature_extractor import extract_features, calculate_shannon_entropy
from app.utils.validators import normalize_url


class URLAnalysisInput(BaseModel):
    url: str = Field(..., description="The URL to analyze structurally")


class URLAnalysisTool(AgentTool):
    tool_name = "analyze_url_structure"
    description = "Inspect URL characteristics including length, subdomain depth, entropy, encoded characters, and IP usage."
    input_schema = URLAnalysisInput

    async def execute(self, arguments: Dict[str, Any]) -> ToolResult:
        raw_url = arguments.get("url", "")
        if not raw_url:
            return ToolResult(
                tool_name=self.tool_name,
                status=ToolStatus.ERROR,
                summary="A URL must be provided for structural analysis.",
                error="MISSING_URL",
            )

        norm_url = normalize_url(raw_url)
        try:
            parsed = urllib.parse.urlparse(norm_url)
            features = extract_features(norm_url)
            entropy = calculate_shannon_entropy(norm_url)

            # Analyze structural components
            hostname = parsed.hostname or ""
            subdomains = [s for s in hostname.split(".") if s]
            subdomain_count = max(0, len(subdomains) - 2)

            is_ip = features.get("has_ip_hostname", 0) == 1
            has_brand_keywords = features.get("has_phishing_keyword", 0) == 1
            suspicious_tld = features.get("is_suspicious_tld", 0) == 1
            entropy_flag = entropy > 4.5

            anomalies = []
            if is_ip:
                anomalies.append("Hostname is a raw IP address")
            if has_brand_keywords:
                anomalies.append("Contains known brand spoofing keyword patterns")
            if suspicious_tld:
                anomalies.append(f"Uses suspicious or high-abuse TLD")
            if entropy_flag:
                anomalies.append(f"Elevated Shannon entropy ({entropy:.2f}) indicates obfuscation")
            if subdomain_count >= 3:
                anomalies.append(f"Excessive subdomain depth ({subdomain_count} subdomains)")

            summary = (
                f"URL structure analyzed (length {len(norm_url)}, entropy {entropy:.2f}). "
                f"Detected {len(anomalies)} structural anomaly/anomalies."
            )
            if anomalies:
                summary += f" Key observations: {'; '.join(anomalies)}."

            return ToolResult(
                tool_name=self.tool_name,
                status=ToolStatus.SUCCESS,
                data={
                    "url": norm_url,
                    "length": len(norm_url),
                    "hostname": hostname,
                    "path": parsed.path,
                    "query": parsed.query,
                    "entropy": entropy,
                    "subdomain_depth": subdomain_count,
                    "is_ip_host": is_ip,
                    "has_brand_keywords": has_brand_keywords,
                    "suspicious_tld": suspicious_tld,
                    "structural_anomalies": anomalies,
                    "features": features,
                },
                summary=summary,
            )
        except Exception as exc:
            return ToolResult(
                tool_name=self.tool_name,
                status=ToolStatus.ERROR,
                summary=f"URL structural analysis failed: {exc}",
                error=str(exc),
            )
