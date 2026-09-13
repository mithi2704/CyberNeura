"""
CyberNeura Agent Tools package.
Exports standard tool implementations and helper to populate a ToolRegistry.
"""
from __future__ import annotations

from app.agent.tools.base import AgentTool
from app.agent.tools.ml_tool import MLAnalysisTool
from app.agent.tools.threat_intel_tool import ThreatIntelTool
from app.agent.tools.dns_tool import DNSAnalysisTool
from app.agent.tools.whois_tool import DomainAnalysisTool
from app.agent.tools.history_tool import HistoryTool
from app.agent.tools.evidence_tool import EvidenceTool
from app.agent.tools.risk_tool import RiskAssessmentTool
from app.agent.tools.url_analysis_tool import URLAnalysisTool
from app.agent.tools.media_tools import (
    AnalyzeImageTool,
    AnalyzeVideoTool,
    MediaEvidenceTool,
    MediaProvenanceTool,
    MediaForensicsTool,
    FrameAnalysisTool,
)


def create_standard_tool_registry():
    """Create and return a ToolRegistry populated with all standard defensive tools."""
    from app.agent.tool_registry import ToolRegistry
    registry = ToolRegistry()
    registry.register(MLAnalysisTool())
    registry.register(ThreatIntelTool())
    registry.register(DNSAnalysisTool())
    registry.register(DomainAnalysisTool())
    registry.register(HistoryTool())
    registry.register(EvidenceTool())
    registry.register(RiskAssessmentTool())
    registry.register(URLAnalysisTool())
    # Phase 7 Media Tools
    registry.register(AnalyzeImageTool())
    registry.register(AnalyzeVideoTool())
    registry.register(MediaEvidenceTool())
    registry.register(MediaProvenanceTool())
    registry.register(MediaForensicsTool())
    registry.register(FrameAnalysisTool())
    return registry


__all__ = [
    "AgentTool",
    "MLAnalysisTool",
    "ThreatIntelTool",
    "DNSAnalysisTool",
    "DomainAnalysisTool",
    "HistoryTool",
    "EvidenceTool",
    "RiskAssessmentTool",
    "URLAnalysisTool",
    "AnalyzeImageTool",
    "AnalyzeVideoTool",
    "MediaEvidenceTool",
    "MediaProvenanceTool",
    "MediaForensicsTool",
    "FrameAnalysisTool",
    "create_standard_tool_registry",
]
