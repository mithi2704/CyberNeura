# CyberNeura Phase 5: Real-Time Cybersecurity Platform Architecture & Specification

## 1. Executive Overview

CyberNeura Phase 5 transitions the CyberNeura platform from a passive request/response dashboard into an **active, real-time security monitoring platform**. 

Every security occurrence—from the initial receipt of a target URL, through multi-source threat intelligence ingestion, DNS/WHOIS queries, ML inference, and risk synthesis, to defensive AI agent reasoning—is broadcast as an immutable, strongly-typed security event. The React dashboard updates live with zero manual page refreshes, while strictly maintaining security boundaries, user isolation, idempotency, and high resilience against network degradation.

```
                  +-------------------------------------------------------------+
                  |                     SECURITY OCCURRENCE                     |
                  |     (URL Scan, Threat Intel Match, Risk Score, Agent)       |
                  +------------------------------+------------------------------+
                                                 |
                                                 v
                  +-------------------------------------------------------------+
                  |                    FASTAPI EVENT ENGINE                     |
                  |  - Schema Validation (RealtimeEvent Pydantic v2)            |
                  |  - Secret Stripping (Scrub API Keys, Tokens, Headers)       |
                  |  - In-Memory Dual-Ring Buffer (ScanStore)                   |
                  |  - PostgreSQL Persistence (realtime_events table)           |
                  |  - Fail-Safe Non-Blocking Broadcast (asyncio.shield)        |
                  +------------------------------+------------------------------+
                                                 |
                                                 v
                  +-------------------------------------------------------------+
                  |                 SUPABASE POSTGRESQL LAYER                   |
                  |  - supabase_realtime publication (CDC logical replication)  |
                  |  - Row-Level Security (RLS) User Isolation Policies         |
                  |  - Composite Indexing (user_id, created_at, event_type)     |
                  +------------------------------+------------------------------+
                                                 |
                                                 v
                  +-------------------------------------------------------------+
                  |                  SUPABASE REALTIME WEBSOCKET                |
                  |  - Channel Isolation (user:{id}, table:*, agent:*)          |
                  |  - Realtime postgres_changes + Broadcast Events             |
                  +------------------------------+------------------------------+
                                                 |
                                                 v
                  +-------------------------------------------------------------+
                  |                 REACT CLIENT RUNTIME LAYER                  |
                  |  - Connection Lifecycle Manager                             |
                  |  - Exponential Backoff Reconnection (1s -> 30s)             |
                  |  - Automatic 30-Second Polling Fallback on Disconnect       |
                  |  - Missed-Event Catchup Resync (/api/v1/realtime/events)    |
                  |  - LRU Bounded Deduplicator (500 events) + Sequencing       |
                  +------------------------------+------------------------------+
                                                 |
                                                 v
                  +-------------------------------------------------------------+
                  |                 LIVE CYBERSECURITY DASHBOARD                |
                  |  - Header Connection Badge (● Live / Reconnecting / Polling)|
                  |  - Live Scan Feeds & Metric Cards                           |
                  |  - URL Logs Live Row Insertion                              |
                  |  - Live Threat Intelligence Stream                          |
                  |  - Real-Time AI Security Agent Tool Activity Trace          |
                  +-------------------------------------------------------------+
```

---

## 2. Real-Time Security Invariants

1. **Deterministic Security Ground Truth**:
   Real-time notifications are reflections of real database state. Simulated or randomly generated mock threats are strictly prohibited.
2. **Fail-Safe Publishing Isolation**:
   Broadcasting or WebSocket latency failures **NEVER** interrupt, fail, or roll back core security operations. URL scanning, threat intelligence retrieval, risk calculation, and agent investigations always run to completion regardless of event publication success.
3. **Strict Secret Scrubbing & Data Hygiene**:
   Sensitive configuration items (API keys for Google Web Risk, PhishTank, URLhaus, Groq, OpenAI, Supabase Service Role keys, internal auth headers) are recursively scrubbed from all real-time event payloads prior to persistence and broadcast.
4. **Tenant Isolation & RLS**:
   All events carry a `user_id` context. Supabase Row-Level Security ensures users receive only events authorized for their session. System broadcasts are public only when designated.
5. **Idempotency & Monotonic Sequencing**:
   Every event carries a unique `event_id` (UUIDv4) and an ISO 8601 UTC `created_at` timestamp. Frontend handlers filter duplicate deliveries and out-of-order events using an LRU bounded memory ring.

---

## 3. Real-Time Event Catalog

CyberNeura defines 15 canonical security event types:

| Event Type | Category | Description | Primary Payload Keys |
| :--- | :--- | :--- | :--- |
| `scan:started` | Lifecycle | Emitted when a URL scan is initiated | `scan_id`, `url`, `domain`, `user_id` |
| `scan:completed` | Lifecycle | Emitted when all scan stages complete | `scan_id`, `url`, `risk_level`, `risk_score`, `threat_types` |
| `scan:failed` | Lifecycle | Emitted if an unrecoverable scan error occurs | `scan_id`, `url`, `error_code`, `message` |
| `threat:detected` | Detection | Emitted when any threat intelligence provider matches | `scan_id`, `indicator`, `provider`, `threat_type`, `severity` |
| `threat:cleared` | Detection | Emitted when multi-source checks return clean | `scan_id`, `indicator`, `providers_checked` |
| `risk:calculated` | Assessment | Emitted when preliminary score is synthesized | `scan_id`, `risk_score`, `confidence`, `primary_factor` |
| `risk:updated` | Assessment | Emitted when comprehensive assessment is stored | `scan_id`, `risk_score`, `risk_level`, `confidence`, `factors_count` |
| `evidence:collected`| Evidence | Emitted when an evidence item is validated | `scan_id`, `source`, `evidence_type`, `severity`, `details` |
| `agent:started` | AI Agent | Emitted when the AI Agent initiates an investigation | `investigation_id`, `query`, `target_url`, `context` |
| `agent:tool_started`| AI Agent | Emitted when an investigation tool begins execution | `investigation_id`, `tool_name`, `parameters` |
| `agent:tool_completed`| AI Agent | Emitted when an investigation tool finishes execution | `investigation_id`, `tool_name`, `duration_ms`, `findings_summary` |
| `agent:completed` | AI Agent | Emitted when AI Agent synthesis is complete | `investigation_id`, `verdict`, `confidence`, `evidence_count` |
| `alert:created` | Alerting | Emitted when high/critical security alert fires | `alert_id`, `severity`, `title`, `description`, `scan_id` |
| `notification:created`| Notification | Emitted for user-facing security messages | `notification_id`, `type`, `title`, `body`, `read` |
| `system:health` | Infrastructure | Emitted for platform heartbeat and connection status | `status`, `active_channels`, `timestamp` |

### JSON Event Schema Example (`threat:detected`)

```json
{
  "event_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
  "event_type": "threat:detected",
  "entity_type": "threat",
  "entity_id": "ti-8842-urlhaus",
  "user_id": "00000000-0000-0000-0000-000000000001",
  "created_at": "2026-09-13T12:30:00.123456Z",
  "payload": {
    "scan_id": "scan-7712",
    "indicator": "http://malicious-payload-bank.xyz/login.exe",
    "threat_type": "malware",
    "provider": "urlhaus",
    "severity": "critical",
    "details": {
      "signature": "Win32.Trojan.Agent",
      "reporter": "abuse_ch"
    }
  }
}
```

---

## 4. Backend Real-Time Subsystem (`app/realtime/`)

### Architecture & Components

```
backend/app/realtime/
  ├── __init__.py           # Package exports (EventPublisher, models, serializer)
  ├── models.py             # Strongly typed Pydantic models (RealtimeEvent, EventType)
  ├── serializer.py         # Secret stripping & JSON serialization
  ├── topics.py             # Channel & topic naming standards
  ├── events.py             # Event factory helper functions
  └── publisher.py          # Centralized event publishing engine with error boundaries
```

### Secret Stripping Filter

The `sanitize_payload()` utility inspects dictionaries recursively. Any key matching known secret tokens is redacted:
```python
SENSITIVE_KEYS = {
    "api_key", "apikey", "secret", "token", "password", "credential",
    "authorization", "auth_header", "service_role", "bearer",
    "google_web_risk_api_key", "phishtank_app_key", "urlhaus_auth_key",
    "groq_api_key", "openai_api_key", "supabase_key", "supabase_service_key",
}
```
If a payload contains an object or nested map with any of these keys, the value is replaced with `"[REDACTED]"`.

### Non-Blocking Async Publishing with Error Boundaries

The `EventPublisher` publishes events synchronously or asynchronously without blocking caller request execution:
```python
async def publish(self, event: RealtimeEvent, channel: Optional[str] = None) -> bool:
    try:
        # 1. Sanitize payload
        event.payload = sanitize_payload(event.payload)
        
        # 2. In-memory buffer persistence
        scan_store.save_realtime_event(event.model_dump())
        
        # 3. Database persistence (non-blocking)
        if self.supabase:
            try:
                self.supabase.table("realtime_events").insert(event.model_dump()).execute()
            except Exception as db_err:
                logger.warning(f"Failed to persist realtime event to database: {db_err}")
                
        # 4. Supabase Realtime broadcast
        # ... broadcast to channel ...
        return True
    except Exception as e:
        logger.error(f"EventPublisher: publishing error isolated: {e}")
        return False
```

---

## 5. Persistence & Supabase Realtime Configuration

### Database Schema (`migration_phase5.sql`)

```sql
CREATE TABLE IF NOT EXISTS realtime_events (
    event_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

-- Performance Composite Indexes
CREATE INDEX IF NOT EXISTS idx_realtime_events_user_created 
    ON realtime_events (user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_realtime_events_type_created 
    ON realtime_events (event_type, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_realtime_events_entity 
    ON realtime_events (entity_type, entity_id);

-- Publication Configuration for Supabase Realtime CDC
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_publication WHERE pubname = 'supabase_realtime') THEN
        CREATE PUBLICATION supabase_realtime;
    END IF;
END $$;

ALTER PUBLICATION supabase_realtime ADD TABLE realtime_events;
ALTER PUBLICATION supabase_realtime ADD TABLE url_scans;
ALTER PUBLICATION supabase_realtime ADD TABLE risk_assessments;
ALTER PUBLICATION supabase_realtime ADD TABLE threat_intelligence;
ALTER PUBLICATION supabase_realtime ADD TABLE notifications;
ALTER PUBLICATION supabase_realtime ADD TABLE agent_events;
```

### Row-Level Security (RLS)

```sql
ALTER TABLE realtime_events ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can read own realtime events" ON realtime_events
    FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY "Users can read public realtime events" ON realtime_events
    FOR SELECT USING (user_id IS NULL);
```

---

## 6. Frontend Real-Time Subsystem (`frontend/src/realtime/`)

### Architecture & Components

```
frontend/src/realtime/
  ├── eventTypes.ts          # Strong TypeScript interfaces for events and payloads
  ├── handlers.ts            # Deduplication LRU cache & sequencing logic
  ├── connectionManager.ts   # Connection lifecycle, backoff, polling fallback, resync
  ├── realtimeClient.ts      # Singleton Supabase Realtime client wrapper
  └── subscriptions.ts       # Topic multiplexer for scans, threats, agent, notifications
frontend/src/services/
  └── realtimeService.ts     # Developer-friendly API facade used across React views
```

### Connection State Machine

```
   [DISCONNECTED]
         |
         | (initialize())
         v
   [CONNECTING] ------------------------+
         |                              | (Connection Error)
         | (Connected)                  v
         v                      [RECONNECTING]
    [CONNECTED]                  (Backoff: 1s, 2s, 4s... 30s)
         |                              |
         | (Connection Lost)            | (Attempts >= 3)
         v                              v
   [RECONNECTING] ------------> [POLLING_FALLBACK]
                                 (30s REST poll intervals)
                                        |
                                        | (Backoff probe succeeds)
                                        v
                                   [CONNECTED]
                                        |
                                        v
                            [MISSED-EVENT RESYNC]
```

### Deduplication & Out-Of-Order Protection

The `EventDeduplicator` (`src/realtime/handlers.ts`) guarantees:
1. **LRU Bounded Set (500 items)**: Prevents unbounded memory growth while catching duplicate broadcasts.
2. **Timestamp Sequencing**: Rejects events arriving older than the latest acknowledged timestamp for an entity.

```typescript
export class EventDeduplicator {
  private seenIds = new Set<string>();
  private idQueue: string[] = [];
  private lastTimestamps = new Map<string, number>();

  isDuplicate(eventId: string): boolean {
    if (this.seenIds.has(eventId)) return true;
    this.seenIds.add(eventId);
    this.idQueue.push(eventId);
    if (this.idQueue.length > 500) {
      const oldest = this.idQueue.shift()!;
      this.seenIds.delete(oldest);
    }
    return false;
  }
}
```

### 30-Second Polling Fallback

If WebSocket connectivity degrades and reconnection attempts reach threshold or WebSocket fails to connect, `ConnectionManager` seamlessly activates a **30-second REST fallback poller**:
- Polls `GET /api/v1/realtime/events?since={last_event_timestamp}&limit=50`.
- Feeds retrieved events through the exact same deduplication and subscription pipelines.
- UI displays `● Polling (30s)` badge in blue, informing the user that real-time monitoring remains operational in fallback mode.
- Continues background health probing; when WebSockets recover, restores `● Live` mode and stops the polling loop.

---

## 7. Live UI Integration

The real-time platform updates existing dashboard components in real time without altering layouts:

1. **`Header.tsx`**:
   - **Connection Status Badge**:
     - `● Live` (Emerald Green): Active Supabase WebSocket connection.
     - `● Reconnecting...` (Amber Pulse): Active backoff retry loop.
     - `● Polling (30s)` (Sky Blue): Operating on HTTP REST polling fallback.
     - `● Offline` (Slate Gray): Connection suspended.
   - **Live Notifications**:
     - Subscribes to `notification:created` and `alert:created`.
     - Automatically increments unread count and prepends alerts to the dropdown menu.

2. **`DashboardPage.tsx`**:
   - Subscribes to `scan:started`, `scan:completed`, `risk:updated`, and `threat:detected`.
   - New scans appear instantly at the top of the recent scan list.
   - Aggregated metrics (total scans, threats detected, average risk) dynamically recompute.
   - On reconnection, triggers automatic missed-event sync.

3. **`URLLogsPage.tsx`**:
   - Subscribes to `scan:completed` and `scan:started`.
   - Prepend new URL logs to the log table dynamically with matching risk status, badges, and metadata.

4. **`ThreatIntelPage.tsx`**:
   - Subscribes to `threat:detected`.
   - Directly streams incoming threat indicators into the active provider feed and updates detection category counters.

5. **`AIAssistant.tsx`**:
   - Subscribes to `agent:started`, `agent:tool_started`, `agent:tool_completed`, and `agent:completed`.
   - Renders a "Realtime Agent Active" badge and live tool execution cards (`Investigating URLhaus...`, `Calculating Risk Assessment...`).

---

## 8. REST Catch-Up & Health API Endpoints

### 1. `GET /api/v1/realtime/health`
Checks the operating health of the real-time subsystem.
```json
{
  "status": "healthy",
  "channels_active": 4,
  "events_published_total": 428,
  "supabase_connected": true,
  "database_persisted": true,
  "timestamp": "2026-09-13T12:35:00Z"
}
```

### 2. `GET /api/v1/realtime/events?since={ISO_TIMESTAMP}&limit=50`
Missed-event catchup endpoint used upon client reconnection or by the 30-second fallback poller.
```json
{
  "events": [
    {
      "event_id": "c71a3962-e64e-4fa0-827b-1fcbf596d669",
      "event_type": "scan:completed",
      "entity_type": "scan",
      "entity_id": "scan-1234",
      "user_id": null,
      "created_at": "2026-09-13T12:34:55.120000Z",
      "payload": {
        "scan_id": "scan-1234",
        "url": "https://secure-login.test",
        "risk_level": "low",
        "risk_score": 12.5
      }
    }
  ],
  "total": 1,
  "has_more": false
}
```

### 3. `GET /api/v1/realtime/status`
Returns configuration settings for client reconnection schedules:
```json
{
  "enabled": true,
  "fallback_enabled": true,
  "fallback_interval_seconds": 30,
  "retention_days": 30,
  "max_events_per_request": 100
}
```

---

## 9. Verification & Test Suite

The Phase 5 real-time architecture is verified with end-to-end automated tests:

- `tests/test_realtime_events.py`:
  - Validates all 15 event types against Pydantic models.
  - Tests recursive secret stripping for sensitive API keys.
  - Verifies JSON schema serialization and topic naming standards.
- `tests/test_realtime_publisher.py`:
  - Verifies in-memory ring buffering in `ScanStore`.
  - Verifies error boundary isolation (simulated Supabase failure does not fail caller).
  - Tests event persistence query filtering.
- `tests/test_realtime_api.py`:
  - Tests `/api/v1/realtime/health` endpoint structure.
  - Tests `/api/v1/realtime/events` missed-event filtering by timestamp.
  - Tests `/api/v1/realtime/status` configuration parameters.
- `tests/test_realtime_integration.py`:
  - Tests complete pipeline scan lifecycle emission (`scan:started` -> `risk:updated` -> `scan:completed`).
  - Tests AI agent investigation event lifecycle emission (`agent:started` -> `agent:tool_completed` -> `agent:completed`).

### Test Results
```
============================== 113 passed, 2 warnings in 44.82s ===============================
```
All 113 tests in the full backend suite passed with zero regressions.
Frontend TypeScript compilation (`tsc -b && vite build`) passed with zero errors.
