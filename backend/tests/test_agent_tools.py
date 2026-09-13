"""
Unit tests for CyberNeura Agent Tools, ToolRegistry, and schema validation.
"""
import pytest
import asyncio
from app.agent.tool_registry import ToolRegistry
from app.agent.tool_result import ToolStatus
from app.agent.tools import (
    create_standard_tool_registry,
    MLAnalysisTool,
    ThreatIntelTool,
    DNSAnalysisTool,
    DomainAnalysisTool,
    HistoryTool,
    EvidenceTool,
    RiskAssessmentTool,
    URLAnalysisTool,
)
from app.agent.tools.base import AgentTool
from pydantic import BaseModel


class DummySchema(BaseModel):
    pass


class DummyTimeoutTool(AgentTool):
    tool_name = "dummy_timeout"
    description = "Test timeout behavior"
    input_schema = DummySchema
    timeout_seconds = 0.05

    async def execute(self, arguments):
        await asyncio.sleep(0.5)
        return None


def test_tool_registry_registration():
    registry = create_standard_tool_registry()
    tools = registry.list_tool_names()
    assert "analyze_ml_prediction" in tools
    assert "lookup_threat_intelligence" in tools
    assert "analyze_dns" in tools
    assert "analyze_domain" in tools
    assert "get_historical_evidence" in tools
    assert "get_evidence" in tools
    assert "get_risk_assessment" in tools
    assert "analyze_url_structure" in tools
    assert len(tools) >= 8


def test_unregistered_tool_blocked():
    registry = ToolRegistry()
    res = asyncio.run(registry.execute("unapproved_shell_tool", {}))
    assert res.status == ToolStatus.BLOCKED
    assert "not in the approved tool registry" in res.summary


def test_tool_timeout_handling():
    registry = ToolRegistry()
    registry.register(DummyTimeoutTool())
    res = asyncio.run(registry.execute("dummy_timeout", {}))
    assert res.status == ToolStatus.TIMEOUT
    assert "timed out" in res.summary


def test_ml_tool_execution():
    tool = MLAnalysisTool()
    res = asyncio.run(tool.execute({"url": "https://malicious-phishing-bank.com/login"}))
    assert res.status == ToolStatus.SUCCESS
    assert "prediction" in res.data
    assert "probability" in res.data
    assert "confidence" in res.data


def test_threat_intel_tool_execution():
    tool = ThreatIntelTool()
    res = asyncio.run(tool.execute({"url": "https://google.com"}))
    assert res.status in (ToolStatus.SUCCESS, ToolStatus.UNAVAILABLE)
    assert "providers" in res.data


def test_dns_tool_execution():
    tool = DNSAnalysisTool()
    res = asyncio.run(tool.execute({"domain": "google.com"}))
    assert res.status == ToolStatus.SUCCESS
    assert "domain" in res.data
    assert res.data["domain"] == "google.com"


def test_domain_tool_execution():
    tool = DomainAnalysisTool()
    res = asyncio.run(tool.execute({"domain": "google.com"}))
    assert res.status == ToolStatus.SUCCESS
    assert "registrar" in res.data


def test_history_tool_execution():
    tool = HistoryTool()
    res = asyncio.run(tool.execute({"url": "https://malicious-bank-verify.ru"}))
    assert res.status == ToolStatus.SUCCESS
    assert res.data["matched_count"] > 0


def test_url_analysis_tool_execution():
    tool = URLAnalysisTool()
    res = asyncio.run(tool.execute({"url": "https://192.168.1.1/paypal-login-verify/auth.php?token=xyz"}))
    assert res.status == ToolStatus.SUCCESS
    assert res.data["is_ip_host"] is True
    assert res.data["has_brand_keywords"] is True
    assert len(res.data["structural_anomalies"]) >= 2
