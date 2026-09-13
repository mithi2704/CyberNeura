"""
Unit tests for CyberNeura Agent reasoning layer, fact-inference separation, and citations.
"""
import asyncio
import pytest
from app.agent.models import AgentObjective, ReasoningStep
from app.agent.providers.deterministic import DeterministicReasoningProvider
from app.agent.state import AgentState
from app.agent.tool_result import ToolResult, ToolStatus


def test_deterministic_planner_prioritizes_risk_assessment():
    provider = DeterministicReasoningProvider()
    state = AgentState(
        session_id="sess-test-1",
        url="https://paypal-verify-alert.com",
        objective=AgentObjective.URL_SAFETY_ASSESSMENT,
    )

    steps = asyncio.run(provider.plan(state))
    assert len(steps) >= 1
    # First step must be get_risk_assessment
    assert steps[0]["tool_name"] == "get_risk_assessment"


def test_fact_inference_separation():
    provider = DeterministicReasoningProvider()
    state = AgentState(
        session_id="sess-test-2",
        url="https://phishing-site.tk",
        objective=AgentObjective.THREAT_EXPLANATION,
    )

    tr = ToolResult(
        tool_name="get_risk_assessment",
        status=ToolStatus.SUCCESS,
        data={
            "risk_score": 94,
            "prediction": "MALICIOUS",
            "confidence": 92.5,
        },
    )

    step = asyncio.run(provider.analyze_step(state, tr))
    assert isinstance(step, ReasoningStep)
    assert step.observation.startswith("FACT:")
    assert step.inference.startswith("INFERENCE:")
    assert "MALICIOUS" in step.observation
    assert "94/100" in step.observation


def test_evidence_citations_in_findings():
    provider = DeterministicReasoningProvider()
    state = AgentState(
        session_id="sess-test-3",
        url="https://paypal-fake.com",
        evidence=[
            {"id": "ev-ml-01", "source": "ML", "severity": "HIGH"},
            {"id": "ev-intel-01", "source": "THREAT_INTEL", "severity": "CRITICAL"},
        ],
        risk_assessment={
            "risk_score": 95,
            "prediction": "MALICIOUS",
            "confidence": 95.0,
            "threat_category": "Phishing",
        },
    )

    findings = asyncio.run(provider.generate_findings(state))
    assert len(findings) >= 1
    for f in findings:
        assert len(f.evidence_ids) > 0
        assert f.confidence > 0.0


def test_uncertainty_reporting_on_unavailable_provider():
    provider = DeterministicReasoningProvider()
    state = AgentState(
        session_id="sess-test-4",
        url="https://suspicious-unknown.org",
        uncertainties=["Google Web Risk provider timed out during query."],
        risk_assessment={"risk_score": 60, "prediction": "SUSPICIOUS", "confidence": 65.0},
    )

    explanation = asyncio.run(provider.generate_explanation(state))
    assert "uncertainties" in explanation
    assert len(explanation["uncertainties"]) >= 1
    assert "Google Web Risk" in explanation["uncertainties"][0]
