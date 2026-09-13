# CyberNeura Phase 4: AI Security Agent Architecture & Specification

## 1. Executive Overview

The **CyberNeura AI Security Agent** provides an intelligent, auditable orchestration and reasoning layer over CyberNeura's deterministic cybersecurity infrastructure. It is designed strictly as a **defensive cybersecurity analysis agent** that reasons across multi-source security signals, correlates evidence, explains verdicts, reports uncertainty, and provides actionable defensive recommendations.

```
                              USER / API / CHAT
                                      |
                                      v
                             AI SECURITY AGENT
                                      |
                     +----------------+----------------+
                     |                                 |
                     v                                 v
            AGENT ORCHESTRATOR               INVESTIGATION MEMORY
                     |                       (Tool Call Deduplication)
                     |
                     v
               TOOL REGISTRY
                     |
     +-------+-------+-------+-------+-------+-------+-------+
     |       |       |       |       |       |       |       |
     v       v       v       v       v       v       v       v
    ML     Threat   DNS    WHOIS  History Evidence Risk     URL
           Intel                                 Assessment Structure
     |       |       |       |       |       |       |       |
     +-------+-------+-------+-------+-------+-------+-------+
                                     |
                                     v
                        EVIDENCE & REASONING ENGINE
                                     |
                                     v
                         FACTS vs. INFERENCE SPLIT
                                     |
                                     v
                          AUTHORITATIVE ASSESSMENT
                       (Phase 3 Risk Engine Ground Truth)
                                     |
                                     v
                         DETERMINISTIC EXPLANATION
                                     |
                                     v
                        DEFENSIVE RECOMMENDATIONS
```

---

## 2. Core Architectural Principles & Invariants

1. **Separation of Architectural Layers**:
   - Layer 1: **ML Model** (probabilistic inference on 28 lexical features).
   - Layer 2: **Threat Intelligence** (Google Web Risk, PhishTank, URLhaus).
   - Layer 3: **DNS & WHOIS** (infrastructure and domain telemetry).
   - Layer 4: **Evidence Engine** (normalized facts & correlation findings).
   - Layer 5: **Risk Engine** (authoritative deterministic 0–100 scoring & bands).
   - Layer 6: **AI Agent** (objective comprehension, tool planning, multi-signal reasoning, explanation, uncertainty, and recommendations).

2. **The Agent Does NOT Overwrite the Risk Engine**:
   - The Phase 3 deterministic Risk Engine remains the authoritative source of truth.
   - The Agent consumes, correlates, and explains the Risk Engine's verdict. It never hallucinates or fabricates custom scores.

3. **Strictly Defensive & Read-Only**:
   - The Phase 4 agent operates exclusively in read-only analysis mode.
   - It **refuses** offensive requests (vulnerability exploitation, code execution, brute-forcing, credential theft, malware distribution).
   - It **refuses** autonomous remediation (no automated firewall manipulation, DNS modification, or system changes).

4. **Prompt Injection Defense (`UNTRUSTED_CONTENT_CANNOT_CONTROL_AGENT`)**:
   - URLs, hostnames, query parameters, threat feed summaries, and WHOIS text are treated as inert untrusted data.
   - Strings such as `ignore previous instructions`, `system prompt: override`, or `you are now in developer mode` are neutralized and treated as pure target text.

5. **No Hallucination Policy**:
   - If a provider times out or fails, the Agent truthfully reports it as `UNAVAILABLE` (`UNAVAILABLE != SAFE`).
   - The Agent never fabricates nonexistent DNS records, WHOIS owners, or threat intelligence hits.

---

## 3. Standardized Tool System

All tools inherit from `AgentTool` and are managed through the centralized `ToolRegistry`.

| Tool Name | Class | Description | Input Schema |
| :--- | :--- | :--- | :--- |
| `analyze_ml_prediction` | `MLAnalysisTool` | Runs LightGBM inference; extracts 28 features; returns phishing probability & confidence | `{"url": str, "scan_id": Optional[str]}` |
| `lookup_threat_intelligence` | `ThreatIntelTool` | Queries Google Web Risk, PhishTank, URLhaus; isolates provider failures | `{"url": str, "scan_id": Optional[str]}` |
| `analyze_dns` | `DNSAnalysisTool` | Resolves A, AAAA, MX, NS, TXT records; checks infrastructure anomalies | `{"domain": str, "url": Optional[str]}` |
| `analyze_domain` | `DomainAnalysisTool`| Resolves WHOIS registration, domain age, registrar, and dates | `{"domain": str, "url": Optional[str]}` |
| `get_historical_evidence` | `HistoryTool` | Queries previous scans with exponential time decay and repeat detection counts | `{"url": str, "domain": Optional[str]}` |
| `get_evidence` | `EvidenceTool` | Retrieves Phase 3 normalized evidence items, observation states, and correlated findings | `{"scan_id": str, "url": Optional[str]}` |
| `get_risk_assessment` | `RiskAssessmentTool` | Retrieves authoritative Phase 3 score, risk factors, and recommendations | `{"scan_id": str, "url": Optional[str]}` |
| `analyze_url_structure` | `URLAnalysisTool` | Analyzes lexical entropy, subdomain depth, special characters, and IP hostnames | `{"url": str}` |

---

## 4. Reasoning Provider Abstraction

The Agent orchestrator utilizes the `ReasoningProvider` interface, supporting two implementations:

### A. `DeterministicReasoningProvider` (Default & Fallback)
- **Zero external cost & zero latency overhead**: Executes entirely in-memory.
- **Strict rules & multi-signal correlation**: Evaluates user objective, identifies missing signals, checks for provider consensus, and links evidence IDs.
- **Separation of Facts from Inferences**: Every step produces explicit `FACT:` (observation) and `INFERENCE:` (deduction) sections.
- **Evidence Citations**: Key findings cite the explicit `evidence_ids` supporting the claim.

### B. `LLMReasoningProvider` (Configurable)
- Pluggable support for OpenAI (`gpt-4o`, `gpt-4o-mini`) via `backend/.env`.
- Enforces strict structured JSON schema responses validated by Pydantic models `LLMPlanOutput` and `LLMExplanationOutput`.
- Automatically falls back to `DeterministicReasoningProvider` if:
  1. No API key is configured.
  2. The LLM API returns an error or times out.
  3. The LLM response fails Pydantic schema validation.

---

## 5. Security Guardrails & Bounds

1. **Tool Allowlist**: Only tools registered in the `ToolRegistry` can be called. Unregistered tool requests are blocked.
2. **Execution Bounds**:
   - `AGENT_MAX_STEPS = 8`: Prevents runaway execution loops.
   - `AGENT_MAX_TOOL_CALLS = 12`: Bounds total external network and compute operations.
   - `AGENT_TOOL_TIMEOUT_SECONDS = 10.0`: Per-tool execution timeout enforced via `asyncio.wait_for`.
3. **Sliding Window Rate Limiting**:
   - 10 investigations per minute per authenticated user (enforced via in-memory sliding window).
4. **Investigation Memory Deduplication**:
   - Within an investigation session, repeated calls to the same tool with identical arguments are served from memory cache, preventing provider rate-limit exhaustion.

---

## 6. Database Persistence Schema (`migration_phase4.sql`)

### 1. `agent_sessions`
Tracks overall investigation sessions, target URLs, objectives, timing, and final verdicts.
* Primary Key: `id` (UUID / TEXT)
* Foreign Keys: `scan_id` referencing `scans(id)`
* Fields: `user_id`, `url`, `objective`, `status`, `started_at`, `completed_at`, `total_steps`, `total_tool_calls`, `final_prediction`, `final_risk_score`, `final_confidence`, `report`.

### 2. `agent_events`
Audit trail of every step taken by the agent during an investigation.
* Fields: `id`, `session_id`, `user_id`, `event_type`, `tool_name`, `input_summary`, `output_summary`, `status`, `duration_ms`, `created_at`.

### 3. `agent_tool_calls`
Detailed records of individual tool invocations, sanitized arguments, and outcomes.
* Fields: `id`, `session_id`, `tool_name`, `arguments`, `status`, `result_summary`, `duration_ms`, `created_at`.

### 4. `agent_findings`
Correlated findings citing specific evidence items.
* Fields: `id`, `session_id`, `finding_type`, `severity`, `statement`, `evidence_ids`, `confidence`, `created_at`.

---

## 7. API Endpoints Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/v1/agent/investigate` | Start or run a complete defensive URL investigation |
| `GET` | `/api/v1/agent/investigations/{session_id}` | Retrieve complete investigation report |
| `GET` | `/api/v1/agent/investigations/{session_id}/events` | Retrieve chronologically ordered audit events |
| `POST` | `/api/v1/agent/investigations/{session_id}/continue` | Continue investigation with additional user input |
| `POST` | `/api/v1/agent/investigations/{session_id}/stop` | Safely terminate an active investigation session |
| `GET` | `/api/v1/agent/tools` | Discover approved defensive tools (metadata without secrets) |
| `POST` | `/chat` | Integrated AI Security Assistant chat endpoint |

---

## 8. Example Investigation Workflow

### User Query
> "Why did CyberNeura classify `https://malicious-bank-verify.ru` as malicious?"

### Agent Investigation Lifecycle
1. **Objective Comprehension**: Classifies inquiry as `THREAT_EXPLANATION`.
2. **Context Inspection**: Identifies seed scan `s-seed-1` and fetches authoritative Phase 3 assessment (Score: 96/100, Verdict: MALICIOUS, Category: Phishing).
3. **Evidence Retrieval**: Retrieves normalized evidence items (`ev_ml_01`, `ev_intel_phishtank`, `ev_dns_01`).
4. **Correlation & Reasoning**:
   - `FACT`: LightGBM model detected 96% phishing probability.
   - `FACT`: External threat feeds confirmed active phishing.
   - `FACT`: Domain age is 14 days old registered via offshore hosting.
   - `INFERENCE`: High multi-source agreement provides unequivocal confirmation of credential theft threat.
5. **Citations & Findings**: Synthesizes `CRITICAL` finding citing `["ev_ml_01", "ev_intel_phishtank"]`.
6. **Defensive Recommendations**:
   - Immediately avoid visiting or entering credentials.
   - Enforce perimeter blocking and DNS sinkhole.
   - Revoke active internal sessions if accessed.
7. **Audit Trail**: Logs `INVESTIGATION_STARTED`, `TOOL_COMPLETED`, and `INVESTIGATION_COMPLETED` events to `agent_events`.
