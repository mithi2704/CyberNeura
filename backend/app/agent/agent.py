"""
CyberNeura AI Security Agent facade.
Provides a clean, unified programmatic interface to investigate targets,
query tools, and manage active sessions.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from app.agent.models import AgentInvestigationReport, AgentObjective
from app.agent.orchestrator import agent_orchestrator, AgentOrchestrator


class CyberNeuraAgent:
    """Primary entry point for the CyberNeura AI Security Agent."""

    def __init__(self, orchestrator: Optional[AgentOrchestrator] = None):
        self.orchestrator = orchestrator or agent_orchestrator

    async def investigate(
        self,
        url: str,
        question: Optional[str] = None,
        user_id: Optional[str] = None,
        scan_id: Optional[str] = None,
        session_id: Optional[str] = None,
        objective: AgentObjective = AgentObjective.URL_SAFETY_ASSESSMENT,
    ) -> AgentInvestigationReport:
        """Run a complete, defensive cybersecurity investigation against a target URL."""
        return await self.orchestrator.run_investigation(
            url=url,
            question=question,
            user_id=user_id,
            scan_id=scan_id,
            session_id=session_id,
            objective=objective,
        )

    def stop(self, session_id: str) -> bool:
        """Stop an ongoing investigation session."""
        return self.orchestrator.stop_session(session_id)

    def list_available_tools(self) -> List[Dict[str, Any]]:
        """List registered defensive security tools."""
        return self.orchestrator.registry.list_tools()


cyberneura_agent = CyberNeuraAgent()
