"""
LLM Reasoning Provider for CyberNeura AI Security Agent.
Supports OpenAI / Anthropic reasoning models with strict JSON schema validation,
prompt injection immunity, and seamless fallback to DeterministicReasoningProvider.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, ValidationError

from app.agent.models import AgentFinding, ReasoningStep
from app.agent.prompts import AGENT_SYSTEM_PROMPT, REASONING_INSTRUCTIONS
from app.agent.providers.base import ReasoningProvider
from app.agent.providers.deterministic import DeterministicReasoningProvider
from app.agent.state import AgentState
from app.agent.tool_result import ToolResult
from app.config import settings
from app.utils.logger import get_logger

logger = get_logger(__name__)


class LLMPlanOutput(BaseModel):
    action: str = Field(..., description="'CALL_TOOL' or 'FINAL'")
    tool_name: Optional[str] = None
    arguments: Dict[str, Any] = Field(default_factory=dict)
    rationale: Optional[str] = None


class LLMExplanationOutput(BaseModel):
    direct_answer: str
    key_findings: List[str] = Field(default_factory=list)
    reasoning_summary: str
    uncertainties: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)


class LLMReasoningProvider(ReasoningProvider):
    """
    LLM reasoning provider wrapping OpenAI or compatible HTTP endpoints.
    Always maintains a deterministic fallback if unconfigured or encountering errors.
    """

    def __init__(self):
        self._fallback = DeterministicReasoningProvider()

    def _get_provider_config(self) -> tuple[str, str, str, str]:
        """
        Resolves (provider_name, endpoint_url, api_key, model_name).
        Supports Groq Cloud and OpenAI natively.
        """
        provider = (getattr(settings, "agent_reasoning_provider", "") or getattr(settings, "ai_provider", "")).lower()
        groq_key = getattr(settings, "groq_api_key", "")
        ai_key = getattr(settings, "ai_api_key", "")

        # Groq detection: provider explicitly set, groq_api_key provided, or key starts with gsk_
        if provider == "groq" or groq_key or (ai_key and ai_key.startswith("gsk_")):
            key = groq_key or ai_key
            model = getattr(settings, "agent_model", "") or getattr(settings, "ai_model", "")
            if not model or model == "gpt-4o-mini":
                model = "llama-3.3-70b-versatile"
            return "groq", "https://api.groq.com/openai/v1/chat/completions", key, model

        if provider in ("openai", "azure_openai", "llm") and ai_key:
            model = getattr(settings, "agent_model", "") or getattr(settings, "ai_model", "") or "gpt-4o-mini"
            return "openai", "https://api.openai.com/v1/chat/completions", ai_key, model

        return "", "", "", ""

    def _is_llm_available(self) -> bool:
        provider, endpoint, key, model = self._get_provider_config()
        return bool(provider and key and endpoint)

    async def plan(self, state: AgentState) -> List[Dict[str, Any]]:
        if not self._is_llm_available():
            return await self._fallback.plan(state)

        provider, endpoint, api_key, model = self._get_provider_config()

        try:
            import httpx

            # Compose tool list description
            tools_summary = [
                "analyze_ml_prediction: Run/retrieve ML model inference",
                "lookup_threat_intelligence: Query Google Web Risk, PhishTank, URLhaus",
                "analyze_dns: Resolve DNS records and check anomalies",
                "analyze_domain: Retrieve WHOIS registration dates and age",
                "get_historical_evidence: Retrieve past CyberNeura scan history",
                "get_evidence: Retrieve Phase 3 normalized evidence items",
                "get_risk_assessment: Retrieve authoritative Phase 3 risk score and factors",
                "analyze_url_structure: Analyze lexical length, depth, and entropy",
            ]

            system_prompt = (
                f"{AGENT_SYSTEM_PROMPT}\n\n"
                f"AVAILABLE TOOLS:\n" + "\n".join(f"- {t}" for t in tools_summary) + "\n\n"
                f"OUTPUT FORMAT: Return a valid JSON object matching:\n"
                f'{{"action": "CALL_TOOL"|"FINAL", "tool_name": "<name>", "arguments": {{...}}, "rationale": "..."}}'
            )

            user_prompt = (
                f"OBJECTIVE: {state.objective.value}\n"
                f"TARGET URL: {state.url}\n"
                f"QUESTION: {state.question or 'Evaluate URL safety'}\n"
                f"EXECUTED TOOLS: {[tc.tool_name for tc in state.tool_calls]}\n"
                f"Decide the next single tool call or declare 'FINAL' if evidence is sufficient."
            )

            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(
                    endpoint,
                    headers={"Authorization": f"Bearer {api_key}"},
                    json={
                        "model": model,
                        "messages": [
                            {"role": "system", "content": system_prompt},
                            {"role": "user", "content": user_prompt},
                        ],
                        "temperature": getattr(settings, "agent_temperature", 0.0),
                        "response_format": {"type": "json_object"},
                    },
                )
                if resp.status_code != 200:
                    logger.warning(f"LLM ({provider}) planning HTTP {resp.status_code}, falling back to deterministic.")
                    return await self._fallback.plan(state)

                data = resp.json()
                content = data["choices"][0]["message"]["content"]
                parsed = json.loads(content)
                validated = LLMPlanOutput(**parsed)

                if validated.action == "CALL_TOOL" and validated.tool_name:
                    return [{
                        "tool_name": validated.tool_name,
                        "arguments": validated.arguments or {"url": state.url, "scan_id": state.scan_id},
                        "rationale": validated.rationale or "Tool selected by reasoning model.",
                    }]
                return []
        except Exception as exc:
            logger.warning(f"LLM ({provider}) plan failed with exception ({exc}), using deterministic fallback.")
            return await self._fallback.plan(state)

    async def analyze_step(self, state: AgentState, tool_result: ToolResult) -> ReasoningStep:
        # Step analysis relies directly on the strict deterministic extractor for audit fidelity
        return await self._fallback.analyze_step(state, tool_result)

    async def generate_findings(self, state: AgentState) -> List[AgentFinding]:
        # Findings must adhere strictly to evidence facts without hallucination
        return await self._fallback.generate_findings(state)

    async def generate_explanation(self, state: AgentState) -> Dict[str, Any]:
        if not self._is_llm_available():
            return await self._fallback.generate_explanation(state)

        provider, endpoint, api_key, model = self._get_provider_config()

        try:
            import httpx

            deterministic_exp = await self._fallback.generate_explanation(state)
            system_prompt = (
                f"{AGENT_SYSTEM_PROMPT}\n\n{REASONING_INSTRUCTIONS}\n"
                f"OUTPUT FORMAT: Return a valid JSON object matching:\n"
                f'{{"direct_answer": "...", "key_findings": ["..."], "reasoning_summary": "...", "uncertainties": ["..."], "recommendations": ["..."]}}'
            )

            user_prompt = (
                f"URL: {state.url}\n"
                f"QUESTION: {state.question or 'Is this safe?'}\n"
                f"ASSESSMENT: {state.risk_assessment}\n"
                f"REASONING STEPS: {[s.model_dump() for s in state.reasoning]}\n"
                f"UNCERTAINTIES: {deterministic_exp.get('uncertainties', [])}\n"
                f"Format a coherent, professional cybersecurity analysis response."
            )

            async with httpx.AsyncClient(timeout=12.0) as client:
                resp = await client.post(
                    endpoint,
                    headers={"Authorization": f"Bearer {api_key}"},
                    json={
                        "model": model,
                        "messages": [
                            {"role": "system", "content": system_prompt},
                            {"role": "user", "content": user_prompt},
                        ],
                        "temperature": getattr(settings, "agent_temperature", 0.0),
                        "response_format": {"type": "json_object"},
                    },
                )
                if resp.status_code != 200:
                    return deterministic_exp

                data = resp.json()
                content = data["choices"][0]["message"]["content"]
                parsed = json.loads(content)
                validated = LLMExplanationOutput(**parsed)

                full_answer = (
                    f"### CyberNeura Assessment\n\n"
                    f"{validated.direct_answer}\n\n"
                    f"#### Key Findings\n"
                    + "\n".join(f"• {f}" for f in validated.key_findings)
                    + f"\n\n#### Telemetry & Uncertainty\n"
                    + "\n".join(f"• {u}" for u in validated.uncertainties)
                    + f"\n\n#### Recommended Actions\n"
                    + "\n".join(f"- {r}" for r in validated.recommendations)
                )

                return {
                    "direct_answer": validated.direct_answer,
                    "full_answer": full_answer,
                    "uncertainties": validated.uncertainties or deterministic_exp.get("uncertainties", []),
                    "recommendations": validated.recommendations or deterministic_exp.get("recommendations", []),
                }
        except Exception as exc:
            logger.warning(f"LLM explanation synthesis failed ({exc}); falling back to deterministic explanation.")
            return await self._fallback.generate_explanation(state)
