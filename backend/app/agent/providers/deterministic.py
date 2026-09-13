"""
Deterministic Reasoning Provider for CyberNeura AI Security Agent.
Provides 100% deterministic, audit-ready planning, correlation, fact-inference separation,
evidence citations, and explanation generation without any external LLM dependencies.
"""
from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional
from app.agent.models import AgentFinding, AgentObjective, ReasoningStep
from app.agent.providers.base import ReasoningProvider
from app.agent.state import AgentState
from app.agent.tool_result import ToolResult, ToolStatus


class DeterministicReasoningProvider(ReasoningProvider):
    """Zero-cost, fully auditable, non-hallucinating reasoning provider."""

    async def plan(self, state: AgentState) -> List[Dict[str, Any]]:
        executed = {tc.tool_name for tc in state.tool_calls}
        plan_steps: List[Dict[str, Any]] = []

        q = (state.question or "").lower()
        obj = state.objective

        # Rule 1: Always check for existing authoritative Phase 3 Risk Assessment first
        if "get_risk_assessment" not in executed:
            plan_steps.append({
                "tool_name": "get_risk_assessment",
                "arguments": {"scan_id": state.scan_id, "url": state.url},
                "rationale": "Retrieve authoritative deterministic Phase 3 baseline score and risk factors.",
            })
            return plan_steps

        # Rule 2: Retrieve normalized evidence if not yet collected
        if "get_evidence" not in executed:
            plan_steps.append({
                "tool_name": "get_evidence",
                "arguments": {"scan_id": state.scan_id, "url": state.url},
                "rationale": "Retrieve normalized evidence items and correlated security findings.",
            })
            return plan_steps

        # Rule 3: Target-specific tool selections based on inquiry
        if any(w in q for w in ["deep", "full", "comprehensive", "everything"]):
            # Deep investigation requests
            for tool_name in ["analyze_ml_prediction", "lookup_threat_intelligence", "analyze_dns", "analyze_domain", "get_historical_evidence", "analyze_url_structure"]:
                if tool_name not in executed:
                    plan_steps.append({
                        "tool_name": tool_name,
                        "arguments": {"url": state.url, "scan_id": state.scan_id},
                        "rationale": f"Execute {tool_name} for comprehensive defensive URL inspection.",
                    })
            return plan_steps

        if any(w in q for w in ["dns", "ip", "nameserver", "mx"]):
            if "analyze_dns" not in executed:
                plan_steps.append({
                    "tool_name": "analyze_dns",
                    "arguments": {"url": state.url},
                    "rationale": "Inspect DNS infrastructure and record anomalies as requested.",
                })
                return plan_steps

        if any(w in q for w in ["whois", "domain", "registrar", "age", "registered"]):
            if "analyze_domain" not in executed:
                plan_steps.append({
                    "tool_name": "analyze_domain",
                    "arguments": {"url": state.url},
                    "rationale": "Retrieve WHOIS registration data and domain age.",
                })
                return plan_steps

        if any(w in q for w in ["intel", "phishtank", "urlhaus", "google", "feed"]):
            if "lookup_threat_intelligence" not in executed:
                plan_steps.append({
                    "tool_name": "lookup_threat_intelligence",
                    "arguments": {"url": state.url},
                    "rationale": "Query external multi-source threat intelligence feeds.",
                })
                return plan_steps

        if any(w in q for w in ["history", "past", "previously", "prior"]):
            if "get_historical_evidence" not in executed:
                plan_steps.append({
                    "tool_name": "get_historical_evidence",
                    "arguments": {"url": state.url},
                    "rationale": "Query past CyberNeura scans and detection frequency.",
                })
                return plan_steps

        # If evidence indicates discrepancy or conflict, check threat intel or ML directly
        has_conflicts = any("contradict" in str(f).lower() for f in state.findings)
        if has_conflicts and "lookup_threat_intelligence" not in executed:
            plan_steps.append({
                "tool_name": "lookup_threat_intelligence",
                "arguments": {"url": state.url},
                "rationale": "Inspect specific threat intelligence feeds to resolve signal conflict.",
            })
            return plan_steps

        # Sufficient context gathered — no further tool calls needed
        return []

    async def analyze_step(self, state: AgentState, tool_result: ToolResult) -> ReasoningStep:
        step_num = len(state.reasoning) + 1
        tool_name = tool_result.tool_name
        data = tool_result.data or {}

        evidence_ids = []
        for ev in state.evidence:
            ev_id = ev.get("id")
            if ev_id:
                evidence_ids.append(ev_id)

        if tool_name == "get_risk_assessment":
            score = data.get("risk_score", 0)
            pred = data.get("prediction", "SAFE")
            conf = data.get("confidence", 80.0)
            return ReasoningStep(
                step=step_num,
                observation=f"FACT: Risk Engine assigns {pred.upper()} with score {score}/100 and {conf:.1f}% confidence.",
                evidence_ids=evidence_ids[:3],
                inference=f"INFERENCE: Authoritative deterministic assessment classifies target as {pred}.",
                confidence=min(1.0, conf / 100.0),
            )

        if tool_name == "get_evidence":
            count = data.get("evidence_count", 0)
            findings_count = data.get("findings_count", 0)
            crit = data.get("critical_count", 0)
            unavail = data.get("unavailable_count", 0)
            obs = f"FACT: Compiled {count} normalized evidence items and {findings_count} correlated findings ({crit} critical/high)."
            if unavail > 0:
                obs += f" {unavail} source(s) were unavailable."
            inf = (
                "INFERENCE: High multi-source agreement confirms elevated risk."
                if crit > 0
                else "INFERENCE: Absence of critical evidence supports low immediate threat level."
            )
            return ReasoningStep(
                step=step_num,
                observation=obs,
                evidence_ids=evidence_ids[:5],
                inference=inf,
                confidence=0.9 if unavail == 0 else 0.75,
            )

        if tool_name == "lookup_threat_intelligence":
            matches = data.get("matched_count", 0)
            unavail = data.get("unavailable_count", 0)
            obs = f"FACT: Threat intelligence queried; {matches} confirmed match(es), {unavail} provider(s) unavailable."
            inf = (
                "INFERENCE: Verified external intelligence match elevates risk to critical floor."
                if matches > 0
                else "INFERENCE: Feeds did not report active matches (lack of match does not guarantee safety)."
            )
            return ReasoningStep(
                step=step_num,
                observation=obs,
                evidence_ids=evidence_ids[:2],
                inference=inf,
                confidence=0.95 if matches > 0 else 0.8,
            )

        if tool_name == "analyze_ml_prediction":
            prob = data.get("probability", 0.0)
            pred = data.get("prediction", "SAFE")
            obs = f"FACT: ML model evaluated URL as {pred} with {prob:.1%} phishing probability."
            inf = (
                "INFERENCE: High model probability indicates strong structural and lexical resemblance to phishing."
                if prob >= 0.7
                else "INFERENCE: Model structural analysis indicates typical benign URL patterns."
            )
            return ReasoningStep(
                step=step_num,
                observation=obs,
                evidence_ids=evidence_ids[:2],
                inference=inf,
                confidence=data.get("confidence", 0.85),
            )

        if tool_name == "analyze_dns":
            records = data.get("records", {})
            anomalies = data.get("anomalies", [])
            obs = f"FACT: DNS resolved {len(records.get('a', []))} A record(s)."
            if anomalies:
                obs += f" Anomalies: {', '.join(anomalies)}."
            inf = (
                "INFERENCE: DNS infrastructure anomalies corroborate potential domain volatility."
                if anomalies
                else "INFERENCE: Standard DNS infrastructure configuration detected."
            )
            return ReasoningStep(
                step=step_num,
                observation=obs,
                evidence_ids=evidence_ids[:2],
                inference=inf,
                confidence=0.85,
            )

        if tool_name == "analyze_domain":
            age = data.get("domain_age_days")
            reg = data.get("registrar", "Unknown")
            obs = f"FACT: Domain registered via {reg}; age is {age} days." if age is not None else f"FACT: WHOIS registrar is {reg}."
            inf = (
                "INFERENCE: Young domain (<30 days) is a supporting risk factor, though not alone proof of malice."
                if age is not None and age < 30
                else "INFERENCE: Domain age profile does not indicate an ephemeral registration."
            )
            return ReasoningStep(
                step=step_num,
                observation=obs,
                evidence_ids=evidence_ids[:2],
                inference=inf,
                confidence=0.85,
            )

        # Default fallback step
        return ReasoningStep(
            step=step_num,
            observation=f"FACT: {tool_result.summary}",
            evidence_ids=evidence_ids[:2],
            inference="INFERENCE: Observation incorporated into defensive assessment context.",
            confidence=0.8,
        )

    async def generate_findings(self, state: AgentState) -> List[AgentFinding]:
        findings: List[AgentFinding] = []
        assessment = state.risk_assessment or {}
        risk_score = assessment.get("risk_score", 0)
        prediction = assessment.get("prediction", "SAFE")

        # Extract evidence IDs
        ev_ids = [e.get("id", "") for e in state.evidence if e.get("id")]

        # 1. Threat Intel Finding
        intel_tc = next((tc for tc in state.tool_calls if tc.tool_name == "lookup_threat_intelligence"), None)
        if intel_tc and "MATCH" in intel_tc.result_summary:
            findings.append(AgentFinding(
                id=f"fnd-{uuid.uuid4().hex[:8]}",
                session_id=state.session_id,
                finding_type="EXTERNAL_THREAT_CONFIRMATION",
                severity="CRITICAL",
                statement="External threat intelligence feeds confirmed active phishing or malware distribution.",
                evidence_ids=[eid for eid in ev_ids if "intel" in eid.lower() or "feed" in eid.lower()] or ev_ids[:2],
                confidence=0.98,
            ))

        # 2. ML Inference Finding
        ml_tc = next((tc for tc in state.tool_calls if tc.tool_name == "analyze_ml_prediction"), None)
        if ml_tc and ("MALICIOUS" in ml_tc.result_summary.upper() or "PHISHING" in ml_tc.result_summary.upper()):
            findings.append(AgentFinding(
                id=f"fnd-{uuid.uuid4().hex[:8]}",
                session_id=state.session_id,
                finding_type="ML_DETECTION",
                severity="HIGH",
                statement="Machine learning URL classifier detected high-confidence phishing indicators.",
                evidence_ids=[eid for eid in ev_ids if "ml" in eid.lower()] or ev_ids[:1],
                confidence=0.92,
            ))

        # 3. Overall Assessment Finding
        sev = "CRITICAL" if risk_score >= 80 else ("HIGH" if risk_score >= 60 else ("MEDIUM" if risk_score >= 40 else "INFORMATIONAL"))
        findings.append(AgentFinding(
            id=f"fnd-{uuid.uuid4().hex[:8]}",
            session_id=state.session_id,
            finding_type="ASSESSMENT_SUMMARY",
            severity=sev,
            statement=f"CyberNeura Risk Engine classifies URL as {prediction.upper()} with risk score {risk_score}/100.",
            evidence_ids=ev_ids[:3],
            confidence=assessment.get("confidence", 90.0) / 100.0,
        ))

        return findings

    async def generate_explanation(self, state: AgentState) -> Dict[str, Any]:
        assessment = state.risk_assessment or {}
        score = assessment.get("risk_score", 0)
        prediction = assessment.get("prediction", "SAFE").upper()
        confidence = assessment.get("confidence", 85.0)
        category = assessment.get("threat_category", "Safe")

        # Collect key facts
        facts = []
        for step in state.reasoning:
            facts.append(f"• {step.observation.replace('FACT: ', '')}")

        # Distinguish uncertainties
        uncertainties = list(state.uncertainties)
        for tc in state.tool_calls:
            if "unavailable" in tc.result_summary.lower():
                uncertainties.append(f"Provider availability limited: {tc.result_summary}")

        if not uncertainties:
            uncertainties.append("All queried security signals responded normally; no provider outages detected.")

        # Structured recommendations based on authoritative risk band
        recs = []
        if score >= 80:
            recs = [
                "Immediately avoid visiting this URL or entering any credentials.",
                "Block this domain at the perimeter firewall and DNS sinkhole.",
                "If accessed internally, investigate proxy logs and revoke active user sessions.",
            ]
        elif score >= 50:
            recs = [
                "Treat URL with caution; avoid entering personal or corporate credentials.",
                "Verify the sender and destination domain through secondary out-of-band channels.",
                "Monitor DNS and endpoint telemetry for anomalous connection attempts.",
            ]
        else:
            recs = [
                "No immediate indicators of phishing or malware were detected.",
                "Continue standard browsing security precautions and maintain MFA.",
            ]

        # Natural language synthesis
        why_bullets = "\n".join(facts[:4]) if facts else "• Standard multi-signal baseline analysis performed."
        direct_answer = f"CyberNeura currently classifies **{state.url}** as **{prediction}** (Risk Score: {score}/100, Confidence: {confidence:.1f}%)."

        full_answer = (
            f"### CyberNeura Assessment\n\n"
            f"**Verdict:** {prediction}  \n"
            f"**Risk Score:** {score}/100  \n"
            f"**Confidence:** {confidence:.1f}%  \n"
            f"**Threat Category:** {category}\n\n"
            f"#### Key Findings & Evidence\n"
            f"{why_bullets}\n\n"
            f"#### Uncertainty & Telemetry Status\n"
            f"• {uncertainties[0]}\n\n"
            f"#### Recommended Actions\n"
            + "\n".join(f"- {r}" for r in recs)
        )

        return {
            "direct_answer": direct_answer,
            "full_answer": full_answer,
            "uncertainties": uncertainties,
            "recommendations": recs,
        }
