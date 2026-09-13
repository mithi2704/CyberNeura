# CyberNeura: AI-Powered Cybersecurity Threat Detection Platform

CyberNeura is a modern, enterprise-grade cybersecurity threat detection platform combining machine learning URL analysis with real-time multi-source external threat intelligence feeds.

---

## System Architecture

```
                       EXISTING REACT DASHBOARD (Vite + TypeScript)
                                         |
                                         | REST API (FastAPI /api/v1)
                                         v
                             FASTAPI APPLICATION BACKEND
                                         |
                        +----------------+----------------+
                        |                                 |
                        v                                 v
               CYBERNEURA AI AGENT                PHASE 3 RISK ENGINE
         (Multi-Step Defensive Analyst)         (Deterministic Floor & Weights)
                        |                                 |
         +--------------+--------------+                  |
         |              |              |                  |
         v              v              v                  v
     DEFENSIVE     INVESTIGATION   GUARDRAILS &     EVIDENCE SUBSYSTEM
       TOOLS          MEMORY       PROMPT DEFENSE         |
         |              |              |                  +---> ML Model (LightGBM)
         +--------------+--------------+                  +---> Threat Intel Feeds
                        |                                 +---> DNS Infrastructure
                        v                                 +---> WHOIS Registry
               INVESTIGATION REPORT                       +---> Lexical / Shannon Entropy
           (Facts, Inferences, Citations)                 +---> Historical Time-Decay
```

---

## Phase 4: CyberNeura AI Security Agent

Phase 4 introduces an autonomous, multi-step **Defensive Cybersecurity AI Agent** acting as an expert incident investigator and advisor. The agent orchestrates investigations across all platform capabilities while strictly adhering to defensive boundaries:

1. **Defensive-Only Execution Boundaries**:
   - Strictly read-only analysis and investigative reasoning.
   - **NO** autonomous remediation (no firewall reconfigurations, no DNS modifications, no automated account lockouts).
   - **NO** offensive capabilities (no exploit execution, no vulnerability probing, no shell command execution).
   - Authoritative Phase 3 Risk Engine and ML model cannot be overwritten or downgraded by the agent.

2. **Multi-Step Agent Architecture (`backend/app/agent/`)**:
   - **Orchestrator (`orchestrator.py`)**: Manages the investigative lifecycle (`STARTING`, `PLANNING`, `EXECUTING_TOOLS`, `SYNTHESIZING`, `COMPLETED`, `FAILED`).
   - **Planner (`planner.py`)**: Prioritizes existing scan evidence and chooses targeted investigative tool calls without redundant querying.
   - **Executor (`executor.py`)**: Enforces per-tool execution timeouts (`asyncio.wait_for`), argument validation, and error boundaries.
   - **Investigation Memory (`memory.py`)**: Tracks evidence, finding state, and prevents duplicate tool invocations via deterministic JSON argument hashing.
   - **Reasoning Engine (`reasoning.py`)**: Coordinates fact-inference separation, citing specific evidence IDs for every conclusion.
   - **Dual Reasoning Providers (`backend/app/agent/providers/`)**:
     - `DeterministicReasoningProvider`: Out-of-the-box, zero-cost, fully auditable rule-based multi-signal reasoning.
     - `LLMReasoningProvider`: Structured JSON synthesis with Pydantic validation and automatic deterministic fallback.

3. **9 Defensive Agent Tools (`backend/app/agent/tools/`)**:
   - `analyze_url_structure`: Lexical and Shannon entropy analysis.
   - `analyze_ml_prediction`: LightGBM probability, feature importance, and decision path.
   - `lookup_threat_intelligence`: Google Web Risk, PhishTank, and URLhaus verification.
   - `analyze_dns`: DNS record enumeration, fast-flux detection, and nameserver analysis.
   - `analyze_domain`: WHOIS domain age, registrar reputation, and expiry proximity.
   - `get_historical_evidence`: Prior scan history with time-decay weighting.
   - `get_evidence`: Phase 3 normalized evidence catalog with severity ratings.
   - `get_risk_assessment`: Authoritative Phase 3 risk score, classification, and directional factors.

4. **Security Guardrails & Prompt Injection Defense (`guardrails.py`)**:
   - **Untrusted Content Isolation**: All external URLs, WHOIS strings, and threat feed content are wrapped in XML delimiters and tagged as inert, untrusted data (`UNTRUSTED_CONTENT_CANNOT_CONTROL_AGENT`).
   - **Injection Pattern Detection**: Rejection and sanitization of prompt injection attempts (e.g., `ignore previous instructions`, `system override`, roleplay prompts).
   - **Offensive Intent Refusal**: Rejection of user queries requesting exploit generation, DDoSing, brute forcing, or attack tooling.
   - **Sliding-Window Rate Limiting**: Maximum 10 agent requests/minute per client.

---

## Phase 3: CyberNeura Risk & Evidence Engine

Phase 3 elevates CyberNeura into a fully auditable, multi-signal threat correlation and deterministic risk assessment system:

1. **Normalized Evidence Subsystem (`backend/app/evidence/`)**:
   - Compiles security signals across 6 heterogeneous sources: ML Inference, External Threat Intelligence (Google Web Risk, PhishTank, URLhaus), DNS Infrastructure, WHOIS Domain Registry, Lexical/Structural Features, and Historical Scan Context.
   - Converts all raw signals into strongly-typed `Evidence` instances with source attribution, severity levels (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFORMATIONAL`), observation states (`CONFIRMED`, `UNAVAILABLE`, `NEUTRAL`, `CONTRADICTORY`), confidence scores, and audit-ready metadata.

2. **Deterministic Correlation Rules (`backend/app/evidence/rules.py`)**:
   - `RULE-1: High-Confidence Phishing Consensus` (ML Phishing + PhishTank verified).
   - `RULE-2: PhishTank Verified Match` (Direct active community phishing confirmation).
   - `RULE-3: URLhaus Active Malware Distribution` (Payload/host distribution confirmation).
   - `RULE-4: ML & Historical Database Correlation` (Predictive model corroborates historical threat status).
   - `RULE-5: Multi-Source Intelligence Consensus` (Two or more external threat intelligence feeds match).
   - `RULE-6: Isolated Threat Intel Provider Failure` (Isolates unavailable providers without compromising detection).
   - `RULE-7: DNS Infrastructure Anomaly Supporting ML` (Fast-flux, suspicious nameservers, or missing records).
   - `RULE-8: Newly Registered Domain with Suspicious Lexical Features` (Age < 30 days combined with high lexical entropy/heuristics).
   - `RULE-9: Persistent Historical Threat` (Recurring malicious classification with time-decay weighting).

3. **Multi-Factor Risk Scoring Engine (`backend/app/risk/`)**:
   - **Deterministic Weighted Baseline**: ML Model (30%), Threat Intelligence (30%), DNS Infrastructure (10%), WHOIS Registry (10%), Lexical Features (10%), Historical Context (10%).
   - **Verified Threat Risk Floor**: Any confirmed external threat match immediately enforces a minimum floor of **>= 85/100** (CRITICAL).
   - **Independent Confidence Calculation**: Risk score and evidence confidence are decoupled. Missing or unavailable providers penalize confidence without lowering risk scores.
   - **Deterministic Explanation Engine**: Transparent, auditable natural language synthesis without generative hallucination or external LLM dependencies.
   - **Structured Defensive Recommendations**: Prioritized, role-tailored mitigation playbooks (immediate containment, perimeter blocking, credential reset, DNS sinks).

4. **Dual-Layer Persistence & Retrospective Recalculation**:
   - Supabase tables `risk_assessments`, `scan_evidence`, `correlated_findings`, `risk_factors`, and `risk_engine_configs` with composite indexes and RLS policies.
   - Instant in-memory recalculation API (`POST /api/v1/risk/assess/{id}/recalculate`) allowing historical scans to be re-evaluated under modified risk weights.

---

## Phase 2: Multi-Source Threat Intelligence

Phase 2 elevates CyberNeura from an ML-only detector into a real-time correlated intelligence platform:

1. **Deterministic Multi-Provider Intelligence**:
   - **Google Web Risk**: Lookup API verifying against Google's global malware, social engineering, and unwanted software datasets.
   - **PhishTank**: Real-time verified phishing database lookups with strict rate limit protection and custom User-Agent compliance.
   - **URLhaus (abuse.ch)**: Lookup-only queries against known malware distribution URLs and payloads.

2. **Core Security Principles**:
   - **External Intel as Evidence**: Intelligence sources are evidence layers, not blind verdicts. They enrich and correlate with ML features.
   - **Independent Confirmations**: Verified matches from multiple distinct providers scale risk and boost detection confidence transparently.
   - **Guaranteed Risk Floor**: Any verified match by an authoritative external provider sets a minimum risk floor of **85/100**, preventing false negatives.
   - **Fail-Safe Invariant (UNAVAILABLE != SAFE)**: When an intelligence provider times out, fails, or is unconfigured, it is strictly classified as `UNAVAILABLE` or `NOT_CONFIGURED`—never `SAFE`.
   - **Zero Secret Leaks**: Provider API keys never leave the backend environment. Frontend clients and client-side bundles receive only normalized provider results and evidence breakdowns.

3. **Performance & Resiliency**:
   - Asynchronous parallel querying with `asyncio.gather` and semaphore-based concurrency control (`THREAT_INTEL_MAX_CONCURRENT_REQUESTS=3`).
   - Provider-level timeouts (default 5.0 seconds) ensuring external latency never blocks scanning pipelines.
   - Intelligent TTL caching with support for provider-supplied cache expiry headers (e.g., Google Web Risk `expireTime`).
   - Circuit breakers preventing continuous failures during upstream provider outages or rate limits.

---

## Configuration & Environment Variables

All threat intelligence configuration is managed via `backend/.env`.

### Environment Settings (`backend/.env`)

```ini
# Database & Base Settings
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_KEY=your-service-role-or-anon-key
CORS_ORIGINS=["http://localhost:5173", "http://127.0.0.1:5173"]

# Phase 2 Threat Intelligence Providers
GOOGLE_WEB_RISK_API_KEY=your_google_cloud_webrisk_api_key_here
PHISHTANK_APP_KEY=your_phishtank_api_key_here
URLHAUS_AUTH_KEY=your_urlhaus_api_key_here

# Provider Toggles (true/false)
ENABLE_GOOGLE_WEB_RISK=true
ENABLE_PHISHTANK=true
ENABLE_URLHAUS=true

# Operational Parameters
THREAT_INTEL_TIMEOUT_SECONDS=5.0
THREAT_INTEL_CACHE_TTL_SECONDS=3600
THREAT_INTEL_MAX_CONCURRENT_REQUESTS=3

# Development & Offline Mode
# When set to true, mock provider results are simulated without network calls
THREAT_INTEL_MOCK_MODE=false
```

---

## Provider Setup & Obtaining API Keys

### 1. Google Web Risk
1. Go to [Google Cloud Console](https://console.cloud.google.com/).
2. Enable the **Web Risk API** for your project.
3. Create an API Key in **Credentials**.
4. Set `GOOGLE_WEB_RISK_API_KEY` in `backend/.env`.
5. *Note*: If the key is not set, the provider reports `NOT_CONFIGURED` and does not crash the system.

### 2. PhishTank
1. Register an account at [PhishTank](https://phishtank.org/).
2. Request an API Application Key.
3. Set `PHISHTANK_APP_KEY` in `backend/.env`.
4. PhishTank requires requests to specify a custom User-Agent (`CyberNeura-ThreatIntel/2.0`). CyberNeura handles this automatically.

### 3. URLhaus (abuse.ch)
1. Register at [abuse.ch](https://urlhaus.abuse.ch/).
2. Obtain your Auth-Key.
3. Set `URLHAUS_AUTH_KEY` in `backend/.env`.
4. *Important*: CyberNeura performs **lookup queries only** (`/v1/url/`). No automated URL submissions are performed.

---

## Database Migration (Supabase / PostgreSQL)

Run the Phase 2 migration to create the `threat_intelligence` table:

```sql
-- Execute backend/scripts/migration_phase2.sql in Supabase SQL Editor:
CREATE TABLE IF NOT EXISTS public.threat_intelligence (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES public.scans(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    provider TEXT NOT NULL,
    verdict TEXT NOT NULL,
    threat_category TEXT,
    confidence FLOAT,
    raw_response JSONB,
    cached BOOLEAN DEFAULT FALSE,
    checked_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_threat_intel_url ON public.threat_intelligence (url);
CREATE INDEX IF NOT EXISTS idx_threat_intel_provider_verdict ON public.threat_intelligence (provider, verdict);
```

---

## API Endpoints

### Scanning & Analysis
- `POST /api/v1/scan`: Full scan pipeline executing ML inference and parallel threat intelligence correlation.
- `GET /api/v1/scans`: Paginated scan history with enriched threat intelligence summaries.
- `GET /api/v1/scans/{id}`: Detailed scan record including full provider verdicts and evidence items.

### Threat Intelligence Subsystem
- `POST /api/v1/intelligence/lookup`: Direct on-demand threat intelligence lookup for any URL.
- `GET /api/v1/intelligence/scan/{id}`: Fetch intelligence records for a prior scan.
- `POST /api/v1/intelligence/scan/{id}/refresh`: Invalidate cache and re-query providers for an existing scan.
- `GET /api/v1/intelligence/providers/status`: Check live operational health and configuration state of all providers.

### Risk & Evidence Engine Endpoints
- `GET /api/v1/risk/config`: Retrieve current weights, thresholds, and version metadata.
- `PUT /api/v1/risk/config`: Update weight allocations and risk thresholds (Admin RBAC).
- `GET /api/v1/risk/assess/{id}`: Fetch full security assessment, classification, explanation, and recommendations.
- `GET /api/v1/risk/assess/{id}/evidence`: Query normalized evidence items for a scan.
- `GET /api/v1/risk/assess/{id}/factors`: Query directional risk factor points breakdown.
- `GET /api/v1/risk/assess/{id}/findings`: Fetch correlated findings triggered for a scan.
- `POST /api/v1/risk/assess/{id}/recalculate`: Retrospectively re-score a scan using updated config weights.
- `GET /api/v1/evidence/scan/{id}`: Alternative endpoint for scan evidence items.
- `GET /api/v1/evidence/stats`: Global evidence aggregation and telemetry statistics.
- `GET /api/v1/evidence/types`: Enumeration of supported evidence types and categories.

### AI Security Agent Endpoints
- `POST /api/v1/agent/investigate`: Launch an autonomous, multi-step investigation for a URL or prior scan.
- `GET /api/v1/agent/investigations/{session_id}`: Fetch full investigation report, timeline, and structured findings.
- `GET /api/v1/agent/investigations/{session_id}/events`: Stream or query audit events for an active investigation.
- `POST /api/v1/agent/investigations/{session_id}/continue`: Send follow-up inquiry or additional instruction to an existing session.
- `POST /api/v1/agent/investigations/{session_id}/stop`: Gracefully terminate an in-progress investigation.
- `GET /api/v1/agent/tools`: List all registered defensive agent tools, schemas, and descriptions.
- `POST /api/v1/chat`: Conversational security assistant endpoint routing URL inquiries through the AI Agent.

### Analytics & Feeds
- `GET /api/v1/threats/trends`: Provider-attributed threat distribution over 7, 30, and 90 day windows.
- `GET /api/v1/threats/breakdown`: Category breakdown across all intelligence providers.
- `GET /api/v1/dashboard/stats`: Platform metrics including provider match rates and confirmed threats.
- `GET /api/v1/health/detail`: Deep health check reporting database, ML engine, and threat intelligence status.
- `GET /api/v1/realtime/health`: Real-time subsystem health check and channel count.
- `GET /api/v1/realtime/events`: Missed-event catchup query with timestamp filtering (`since`).
- `GET /api/v1/realtime/status`: Real-time connection and polling fallback configuration.

---

## Phase 5: Real-Time Cybersecurity Platform

Phase 5 transforms CyberNeura into a **real-time security monitoring platform**:

1. **Real-Time Event Engine (`backend/app/realtime/`)**:
   - 15 canonical security event types spanning scan lifecycle, threat detection, risk assessment, AI agent tool execution, and alerting.
   - Fail-safe event publishing: failures in broadcasting never interrupt or degrade core security scans.
   - Recursive secret sanitization (`sanitize_payload`) guarantees API keys and credentials are never broadcast or leaked to clients.
   - Dual-buffer persistence: in-memory ring buffer (`ScanStore`) + PostgreSQL `realtime_events` with Row-Level Security (RLS).

2. **Frontend Real-Time Subsystem (`frontend/src/realtime/`)**:
   - Singleton Supabase Realtime client managing channel subscriptions (`user:*`, `table:*`, `agent:*`).
   - Exponential backoff reconnection (1s to 30s) with automatic 30-second HTTP polling fallback on connection degradation.
   - Missed-event catchup mechanism on reconnect via `/api/v1/realtime/events?since={timestamp}`.
   - In-memory LRU deduplication cache (500 events) preventing duplicate rendering and protecting against out-of-order deliveries.

3. **Live Dashboard Components**:
   - **Header**: Live connection badge (`● Live` / `● Reconnecting...` / `● Polling (30s)` / `● Offline`) and live security notification counter.
   - **Dashboard**: Live scan feed prepending, real-time threat detection badges, and dynamic KPI metric updates.
   - **URL Logs**: Live scan row insertion with risk badges and metadata without page reloads.
   - **Threat Intelligence**: Real-time streaming indicator feed categorized by provider.
   - **AI Assistant**: Live agent activity indicators rendering real-time tool execution states.

---

---

## Phase 6: Chrome Browser Extension

Phase 6 introduces a production-grade Chrome extension (Manifest V3 + TypeScript) that delivers real-time URL security analysis as users browse:

1. **Extension Architecture (`extension/`)**:
   - **Service Worker (`src/background/service-worker.ts`)**: Listens for top-level navigation (`chrome.webNavigation.onBeforeNavigate` with `frameId === 0`), canonicalizes URLs, consults local 300s cache, queries backend API with 8s timeout, enforces decisions, and updates tab badges.
   - **URL Normalizer (`src/security/url-normalizer.ts`)**: Canonicalizes scheme/host, preserves query parameters, and ignores internal/non-routable schemes (`chrome:`, `about:`, `file:`, `data:`, localhost).
   - **Local Storage Cache (`src/storage/storage.ts`)**: 300-second TTL in-memory/Chrome storage cache preventing redundant backend calls on back/forward or intra-site clicks.
   - **Policy Engine (`backend/app/extension/policy.py`)**: Authoritative backend engine mapping risk scores, predictions, confidence, and external threat intel matches into `ALLOW`, `WARN`, or `BLOCK` decisions.
   - **Isolated Interstitial (`src/interstitial/`)**: Clean, responsive warning/blocking interstitial UI with risk breakdown, security explanation, threat categories, and optional "Continue Anyway" override flow.
   - **Popup UI (`src/popup/`)**: On-demand real-time status card showing current tab risk score, prediction badge, confidence, threat categories, refresh button, and false-positive/negative reporting form.
   - **Options Page (`src/options/`)**: User configuration for notification preferences, backend URL, and cache clearing.

2. **Security & Privacy by Design**:
   - **Zero Secrets**: The extension bundle contains NO API keys, NO ML model weights, NO database credentials, and NO LLM tokens.
   - **Privacy Invariants**: Only top-level navigation URLs (`frameId === 0`) are inspected. NO DOM content, NO passwords, NO cookies, NO form inputs, and NO browsing history are ever accessed or transmitted.
   - **Fail-Safe Invariant (Fail-Open with Caution)**: If the backend is unreachable or times out (>8000ms), the extension defaults to `ALLOW` with a subtle caution badge (`?`) and warning notification, ensuring browsing is never interrupted unless `EXTENSION_STRICT_MODE=true` is set.
   - **Audit & Real-Time Sync**: Every extension scan event, interstitial warning, block, and override is persisted to `extension_events` and broadcast to the dashboard via Phase 5 Realtime.

3. **Extension Configuration (`backend/.env`)**:
   ```ini
   # Phase 6 Chrome Extension Settings
   EXTENSION_ENABLED=true
   EXTENSION_RATE_LIMIT_PER_MINUTE=120
   EXTENSION_CACHE_TTL_SECONDS=300
   EXTENSION_ANALYSIS_TIMEOUT_SECONDS=8.0
   EXTENSION_STRICT_MODE=false
   EXTENSION_ALLOW_OVERRIDE=true
   ```

4. **Extension API Endpoints**:
   - `POST /api/v1/extension/analyze`: Fast real-time URL risk analysis returning decision (`ALLOW` / `WARN` / `BLOCK`), risk score, explanation, and threat categories.
   - `GET /api/v1/extension/status`: Extension subsystem health and operational configuration.
   - `GET /api/v1/extension/policy`: Current policy thresholds and strict mode rules.
   - `POST /api/v1/extension/override`: Audit trail submission when user clicks "Continue Anyway" on an interstitial warning.
   - `POST /api/v1/extension/report`: Direct user feedback submission (false positive / false negative / missed threat).
   - `GET /api/v1/extension/events`: Paginated event query with client/decision filters.
   - `GET /api/v1/extension/stats`: Telemetry aggregating decisions, overrides, and threat distribution.

---

## Development & Testing

### Running the Backend
```bash
cd backend
python -m uvicorn app.main:app --reload --port 8000
```

### Running the Frontend
```bash
cd frontend
npm run dev
```

### Building the Chrome Extension
```bash
cd extension
npm install
npm run build
```
The compiled extension bundle will be output to `extension/dist/`. Load it unpacked in Chrome via `chrome://extensions` -> **Load unpacked** -> select `extension/dist`.

### Executing Tests
```bash
# Backend pytest suite (145 tests)
cd backend
python -m pytest tests/ -v

# Extension unit tests (12 tests)
cd extension
npm test

# Frontend TypeScript check and production build
cd frontend
npm run build
```
All **145** backend unit, correlation, risk scoring, confidence, agent, real-time, extension, and media security tests pass:
- Feature extraction & entropy validation
- SSRF prevention & input validation
- Provider isolation & timeout handling
- Evidence correlation & score floors
- Unavailable provider fail-safe invariants
- Evidence normalizer & correlation rules (RULE-1 to RULE-9)
- Independent risk scoring and confidence engine
- Deterministic explanation and structured recommendations
- Retrospective recalculation and pipeline compatibility
- Defensive agent tool schemas, execution, and timeouts
- Agent memory deduplication and canonical argument hashing
- Guardrails, prompt injection neutralization, and offensive intent refusal
- Dual reasoning providers (Deterministic and LLM fallback)
- Orchestrator multi-step investigative lifecycle and event auditing
- Chat endpoint integration with real agent delegation
- Real-time event schemas, Pydantic v2 serialization, and topic routing
- Secret stripping and credential redaction from event payloads
- In-memory buffer persistence, database persistence, and error boundary isolation
- Real-time API endpoints (`/health`, `/events`, `/status`) and timestamp filtering
- End-to-end pipeline scan and AI agent real-time event emission
- Extension policy evaluation (`ALLOW`, `WARN`, `BLOCK`, strict mode)
- Extension API endpoints (`/analyze`, `/status`, `/policy`, `/override`, `/report`, `/events`, `/stats`)
- Extension service coordination, caching, override persistence, and Realtime event emission
- Media validation, magic byte checking, and decompression bomb boundary guards
- Multimodal neural models (`cyberneura-image-detector`, `cyberneura-video-detector`) & Model Registry
- 2D Spectral FFT frequency residual analysis and spatial Laplacian edge variance
- Cryptographic C2PA / Content Credentials verification (`PROVENANCE_ABSENT != AI-GENERATED`)
- Error Level Analysis (ELA) compression forensics and quadrant noise variance
- Privacy-preserving face detection (zero biometrics/identity indexing) and IoU tracking
- Temporal optical flow stability and boundary jitter analysis
- Asynchronous video job queue with semaphore concurrency and Realtime progress reporting
- 6 AI Agent media tools (`analyze_image`, `analyze_video`, `get_media_evidence`, `get_media_provenance`, `get_media_forensics`, `get_frame_analysis`)

---

## Invariant Enforcement & Troubleshooting

| Scenario | System Behavior |
| :--- | :--- |
| **Provider API key missing** | System boots cleanly. Provider returns status `NOT_CONFIGURED`. |
| **Provider HTTP 500 or timeout** | Isolated exception handling; other providers complete. Provider marked `UNAVAILABLE`, not `SAFE`. |
| **Rate limit exceeded (HTTP 429/509)** | Provider circuit breaker trips; logs warning without exposing credentials. |
| **ML says Safe, URLhaus says Malware** | Risk score elevated to **>= 85/100** (`MALICIOUS`). Evidence details specific provider match. |
| **Realtime WebSocket disconnected** | Frontend initiates exponential backoff (1s -> 30s); falls back to 30s REST polling after 3 retries. UI indicates `● Polling (30s)`. |
| **Extension backend unreachable/timeout** | Extension fails open gracefully to `ALLOW` with caution badge `?` and warning notification. User browsing never breaks. |
| **User clicks "Continue Anyway" on WARN** | Interstitial unblocks target URL for 30 minutes and dispatches `EXTENSION_OVERRIDE` event to backend audit log. |
| **Image without C2PA manifest** | Provenance marked `PROVENANCE_ABSENT` (neutral observation). Absence does NOT imply manipulation. |
| **Face detected in video** | Face bounding box & blur quality analyzed for boundary blending seams. Zero biometric indexing or identity matching is performed or stored. |
| **Video processing takes >10 seconds** | Handled via asynchronous job queue (`/api/v1/media/jobs/{job_id}`); client polls or receives Realtime progress events. |
| **Offline development** | Set `THREAT_INTEL_MOCK_MODE=true` in `backend/.env` to run full simulation without API keys. |


