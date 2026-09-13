"""
CyberNeura Agent Orchestrator.
Manages the end-to-end investigation execution loop, state transitions,
audit event logging, and persistence.
"""
from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.agent.executor import AgentExecutor
from app.agent.guardrails import AgentGuardrails
from app.agent.memory import InvestigationMemory
from app.agent.models import (
    AgentEvent,
    AgentEventType,
    AgentFinding,
    AgentInvestigationReport,
    AgentObjective,
    AgentStatus,
    ReasoningStep,
    ToolCallRecord,
)
from app.agent.planner import AgentPlanner
from app.agent.providers.base import ReasoningProvider
from app.agent.providers.deterministic import DeterministicReasoningProvider
from app.agent.providers.llm import LLMReasoningProvider
from app.agent.reasoning import AgentReasoningEngine
from app.agent.state import AgentState
from app.agent.tool_registry import ToolRegistry
from app.agent.tools import create_standard_tool_registry
from app.config import settings
from app.database import get_db
from app.services.scan_store import scan_store
from app.realtime import event_publisher, RealtimeEventType, EntityType
from app.utils.logger import get_logger

logger = get_logger(__name__)


class AgentOrchestrator:
    """Coordinates session lifecycle, execution loop, guardrails, and audit logging."""

    def __init__(
        self,
        registry: Optional[ToolRegistry] = None,
        provider: Optional[ReasoningProvider] = None,
    ):
        self.registry = registry or create_standard_tool_registry()

        # Instantiate provider based on backend configuration
        if provider:
            self.provider = provider
        else:
            chosen = getattr(settings, "agent_reasoning_provider", "")
            if chosen and chosen.lower() in ("openai", "azure_openai"):
                self.provider = LLMReasoningProvider()
            else:
                self.provider = DeterministicReasoningProvider()

        self.planner = AgentPlanner(self.provider)
        self.reasoning = AgentReasoningEngine(self.provider)
        self._active_sessions: Dict[str, AgentState] = {}
        self._stopped_sessions: set[str] = set()

    def _create_event(
        self,
        session_id: str,
        user_id: Optional[str],
        event_type: AgentEventType,
        tool_name: Optional[str] = None,
        input_summary: Optional[str] = None,
        output_summary: Optional[str] = None,
        status: str = "SUCCESS",
        duration_ms: float = 0.0,
    ) -> AgentEvent:
        event = AgentEvent(
            id=f"evt-{uuid.uuid4().hex[:8]}",
            session_id=session_id,
            user_id=user_id,
            event_type=event_type,
            tool_name=tool_name,
            input_summary=input_summary,
            output_summary=output_summary,
            status=status,
            duration_ms=duration_ms,
        )
        scan_store.save_agent_event(event.model_dump())

        # Phase 5: Non-blocking broadcast to realtime subscribers
        try:
            from app.realtime import event_publisher, RealtimeEventType, EntityType
            type_map = {
                AgentEventType.INVESTIGATION_STARTED: RealtimeEventType.AGENT_STARTED,
                AgentEventType.TOOL_REQUESTED: RealtimeEventType.AGENT_TOOL_STARTED,
                AgentEventType.TOOL_EXECUTED: RealtimeEventType.AGENT_TOOL_COMPLETED,
                AgentEventType.INVESTIGATION_COMPLETED: RealtimeEventType.AGENT_COMPLETED,
                AgentEventType.INVESTIGATION_FAILED: RealtimeEventType.AGENT_FAILED,
            }
            rt_type = type_map.get(event_type)
            if rt_type:
                try:
                    loop = asyncio.get_running_loop()
                    loop.create_task(
                        event_publisher.publish(
                            event_type=rt_type,
                            entity_type=EntityType.AGENT_SESSION,
                            entity_id=session_id,
                            user_id=user_id,
                            payload={
                                "session_id": session_id,
                                "tool_name": tool_name,
                                "summary": output_summary or input_summary,
                                "status": status,
                                "duration_ms": duration_ms,
                            },
                        )
                    )
                except RuntimeError:
                    # If called outside an active event loop
                    pass
        except Exception:
            pass

        return event

    def stop_session(self, session_id: str) -> bool:
        """Safely stops an active investigation session."""
        if session_id in self._active_sessions:
            self._stopped_sessions.add(session_id)
            state = self._active_sessions[session_id]
            state.status = AgentStatus.STOPPED
            self._create_event(
                session_id=session_id,
                user_id=state.user_id,
                event_type=AgentEventType.INVESTIGATION_STOPPED,
                output_summary="Investigation stopped by user request.",
            )
            return True
        return False

    async def run_investigation(
        self,
        url: str,
        question: Optional[str] = None,
        user_id: Optional[str] = None,
        scan_id: Optional[str] = None,
        session_id: Optional[str] = None,
        objective: AgentObjective = AgentObjective.URL_SAFETY_ASSESSMENT,
    ) -> AgentInvestigationReport:
        """
        Execute the complete defensive analysis loop.
        """
        session_id = session_id or f"sess-{uuid.uuid4().hex[:12]}"
        start_time = time.time()

        # 1. Initialize session state and memory
        state = AgentState(
            session_id=session_id,
            user_id=user_id,
            scan_id=scan_id,
            url=url,
            question=question,
            objective=objective,
            status=AgentStatus.RUNNING,
        )
        memory = InvestigationMemory(session_id=session_id)
        executor = AgentExecutor(self.registry, memory)
        self._active_sessions[session_id] = state

        # 2. Log start event
        self._create_event(
            session_id=session_id,
            user_id=user_id,
            event_type=AgentEventType.INVESTIGATION_STARTED,
            input_summary=f"URL: {url}, Question: {question or 'Safety check'}",
        )
        await event_publisher.publish(
            event_type=RealtimeEventType.AGENT_STARTED,
            entity_type=EntityType.AGENT_SESSION,
            entity_id=session_id,
            user_id=user_id,
            payload={"session_id": session_id, "url": url},
        )

        # 3. Guardrails check for offensive intent
        if question and AgentGuardrails.is_offensive_intent(question):
            state.status = AgentStatus.FAILED
            refusal = "CyberNeura is a strictly defensive analysis platform. Requests to exploit systems or execute unauthorized code are refused."
            state.final_answer = refusal
            self._create_event(
                session_id=session_id,
                user_id=user_id,
                event_type=AgentEventType.INVESTIGATION_FAILED,
                output_summary="Request refused due to offensive intent violation.",
                status="BLOCKED",
            )
            report = AgentInvestigationReport(
                session_id=session_id,
                user_id=user_id,
                scan_id=scan_id,
                url=url,
                objective=objective.value,
                status=AgentStatus.FAILED,
                final_assessment={"status": "REFUSED", "reason": refusal},
                recommendations=["Use authorized defensive analysis tools only."],
                tools_used=[],
            )
            scan_store.save_agent_session(report.model_dump())
            return report

        max_steps = getattr(settings, "agent_max_steps", 8)
        max_tool_calls = getattr(settings, "agent_max_tool_calls", 12)

        try:
            # 4. Controlled Execution Loop
            while state.step_count < max_steps and state.total_tool_calls < max_tool_calls:
                if session_id in self._stopped_sessions:
                    state.status = AgentStatus.STOPPED
                    break

                # Plan next steps
                plan_steps = await self.planner.get_next_steps(state)
                if not plan_steps:
                    # Sufficient evidence gathered, ready for final synthesis
                    break

                self._create_event(
                    session_id=session_id,
                    user_id=user_id,
                    event_type=AgentEventType.PLAN_CREATED,
                    output_summary=f"Planned {len(plan_steps)} tool call(s): {[s['tool_name'] for s in plan_steps]}",
                )

                # Execute planned tool calls
                for step_info in plan_steps:
                    if session_id in self._stopped_sessions:
                        break

                    tool_name = step_info["tool_name"]
                    arguments = step_info.get("arguments", {})

                    # Enforce tool allowlist
                    if not AgentGuardrails.validate_tool_allowed(tool_name, self.registry.list_tool_names()):
                        continue

                    self._create_event(
                        session_id=session_id,
                        user_id=user_id,
                        event_type=AgentEventType.TOOL_REQUESTED,
                        tool_name=tool_name,
                        input_summary=str(arguments),
                    )

                    tool_result, tc_record = await executor.execute_tool(tool_name, arguments, state)
                    state.tool_calls.append(tc_record)
                    state.total_tool_calls += 1
                    scan_store.save_agent_tool_call(tc_record.model_dump())

                    self._create_event(
                        session_id=session_id,
                        user_id=user_id,
                        event_type=AgentEventType.TOOL_COMPLETED if tool_result.is_success else AgentEventType.TOOL_FAILED,
                        tool_name=tool_name,
                        output_summary=tool_result.summary,
                        status=tool_result.status.value,
                        duration_ms=tool_result.duration_ms,
                    )
                    await event_publisher.publish(
                        event_type=RealtimeEventType.AGENT_TOOL_COMPLETED if tool_result.is_success else RealtimeEventType.AGENT_FAILED,
                        entity_type=EntityType.AGENT_SESSION,
                        entity_id=session_id,
                        user_id=user_id,
                        payload={
                            "session_id": session_id,
                            "tool_name": tool_name,
                            "summary": tool_result.summary,
                            "status": tool_result.status.value,
                            "duration_ms": tool_result.duration_ms,
                        },
                    )

                    # Reason over tool result
                    reasoning_step = await self.reasoning.evaluate_step(state, tool_result)
                    state.reasoning.append(reasoning_step)

                state.step_count += 1

            # 5. Synthesize Findings & Final Assessment
            findings = await self.reasoning.synthesize_findings(state)
            state.findings = findings
            for f in findings:
                scan_store.save_agent_finding(f.model_dump())

            explanation_data = await self.reasoning.synthesize_explanation(state)
            state.recommendations = explanation_data.get("recommendations", [])
            state.uncertainties = explanation_data.get("uncertainties", [])
            state.final_answer = explanation_data.get("full_answer", "")

            if state.status != AgentStatus.STOPPED:
                state.status = AgentStatus.COMPLETED

            duration_ms = round((time.time() - start_time) * 1000, 2)
            completed_at = datetime.now(timezone.utc).isoformat()

            self._create_event(
                session_id=session_id,
                user_id=user_id,
                event_type=AgentEventType.INVESTIGATION_COMPLETED,
                output_summary=f"Investigation finished in {duration_ms}ms with {state.total_tool_calls} tool call(s).",
                duration_ms=duration_ms,
            )
            await event_publisher.publish(
                event_type=RealtimeEventType.AGENT_COMPLETED,
                entity_type=EntityType.AGENT_SESSION,
                entity_id=session_id,
                user_id=user_id,
                payload={
                    "session_id": session_id,
                    "url": state.url,
                    "status": state.status.value,
                    "duration_ms": duration_ms,
                },
            )

            # 6. Build Report
            report = AgentInvestigationReport(
                session_id=session_id,
                user_id=user_id,
                scan_id=state.scan_id,
                url=state.url,
                objective=state.objective.value,
                status=state.status,
                started_at=datetime.fromtimestamp(start_time, tz=timezone.utc).isoformat(),
                completed_at=completed_at,
                final_assessment=state.risk_assessment or {
                    "prediction": "SAFE",
                    "risk_score": 10,
                    "confidence": 85.0,
                    "threat_category": "Safe",
                },
                final_answer=state.final_answer,
                key_findings=state.findings,
                evidence_summary=state.evidence[:10],
                reasoning_summary=state.reasoning,
                uncertainties=state.uncertainties,
                recommendations=state.recommendations,
                tools_used=[tc.tool_name for tc in state.tool_calls],
                total_steps=state.step_count,
                total_tool_calls=state.total_tool_calls,
            )

            # Persist to store
            scan_store.save_agent_session(report.model_dump())

            return report

        except Exception as exc:
            logger.error(f"Agent investigation failed for session {session_id}: {exc}", exc_info=True)
            state.status = AgentStatus.FAILED
            self._create_event(
                session_id=session_id,
                user_id=user_id,
                event_type=AgentEventType.INVESTIGATION_FAILED,
                output_summary=f"Fatal error: {exc}",
                status="ERROR",
            )
            report = AgentInvestigationReport(
                session_id=session_id,
                user_id=user_id,
                scan_id=scan_id,
                url=url,
                objective=objective.value,
                status=AgentStatus.FAILED,
                final_assessment={"status": "ERROR", "error": str(exc)},
                uncertainties=[f"Investigation terminated due to internal error: {exc}"],
                recommendations=["Retry investigation or inspect system telemetry logs."],
                tools_used=[tc.tool_name for tc in state.tool_calls],
            )
            scan_store.save_agent_session(report.model_dump())
            return report
        finally:
            if session_id in self._active_sessions:
                del self._active_sessions[session_id]
            if session_id in self._stopped_sessions:
                self._stopped_sessions.remove(session_id)


# Global orchestrator instance
agent_orchestrator = AgentOrchestrator()
