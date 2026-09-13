-- ============================================================
-- CYBERNEURA PHASE 4: AI SECURITY AGENT DATABASE MIGRATION
-- Tables: agent_sessions, agent_events, agent_tool_calls, agent_findings
-- Includes composite performance indexes and Row Level Security (RLS)
-- ============================================================

-- 1. Agent Sessions Table
CREATE TABLE IF NOT EXISTS public.agent_sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT,
    scan_id TEXT REFERENCES public.scans(id) ON DELETE SET NULL,
    url TEXT NOT NULL,
    objective TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'RUNNING',
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    total_steps INTEGER NOT NULL DEFAULT 0,
    total_tool_calls INTEGER NOT NULL DEFAULT 0,
    final_prediction TEXT,
    final_risk_score INTEGER,
    final_confidence FLOAT,
    report JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 2. Agent Events Audit Table
CREATE TABLE IF NOT EXISTS public.agent_events (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES public.agent_sessions(id) ON DELETE CASCADE,
    user_id TEXT,
    event_type TEXT NOT NULL,
    tool_name TEXT,
    input_summary TEXT,
    output_summary TEXT,
    status TEXT NOT NULL DEFAULT 'SUCCESS',
    duration_ms FLOAT NOT NULL DEFAULT 0.0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 3. Agent Tool Calls Table
CREATE TABLE IF NOT EXISTS public.agent_tool_calls (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES public.agent_sessions(id) ON DELETE CASCADE,
    tool_name TEXT NOT NULL,
    arguments JSONB NOT NULL DEFAULT '{}'::jsonb,
    status TEXT NOT NULL DEFAULT 'SUCCESS',
    result_summary TEXT,
    duration_ms FLOAT NOT NULL DEFAULT 0.0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 4. Agent Correlated Findings Table
CREATE TABLE IF NOT EXISTS public.agent_findings (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES public.agent_sessions(id) ON DELETE CASCADE,
    finding_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    statement TEXT NOT NULL,
    evidence_ids TEXT[] NOT NULL DEFAULT '{}',
    confidence FLOAT NOT NULL DEFAULT 1.0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Composite and Query Indexes
CREATE INDEX IF NOT EXISTS idx_agent_sessions_user_id ON public.agent_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_agent_sessions_scan_id ON public.agent_sessions(scan_id);
CREATE INDEX IF NOT EXISTS idx_agent_sessions_status ON public.agent_sessions(status);
CREATE INDEX IF NOT EXISTS idx_agent_sessions_created_at ON public.agent_sessions(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_agent_events_session_id ON public.agent_events(session_id);
CREATE INDEX IF NOT EXISTS idx_agent_events_type ON public.agent_events(event_type);
CREATE INDEX IF NOT EXISTS idx_agent_events_created_at ON public.agent_events(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_agent_tool_calls_session ON public.agent_tool_calls(session_id, tool_name);
CREATE INDEX IF NOT EXISTS idx_agent_findings_session ON public.agent_findings(session_id, severity);

-- Enable Row Level Security (RLS)
ALTER TABLE public.agent_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.agent_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.agent_tool_calls ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.agent_findings ENABLE ROW LEVEL SECURITY;

-- RLS Policies
CREATE POLICY "Users can view their own agent sessions"
    ON public.agent_sessions FOR SELECT
    USING (auth.uid()::text = user_id OR user_id IS NULL);

CREATE POLICY "Users can create their own agent sessions"
    ON public.agent_sessions FOR INSERT
    WITH CHECK (auth.uid()::text = user_id OR user_id IS NULL);

CREATE POLICY "Users can update their own agent sessions"
    ON public.agent_sessions FOR UPDATE
    USING (auth.uid()::text = user_id OR user_id IS NULL);

CREATE POLICY "Users can view events for their sessions"
    ON public.agent_events FOR SELECT
    USING (EXISTS (
        SELECT 1 FROM public.agent_sessions
        WHERE public.agent_sessions.id = public.agent_events.session_id
          AND (public.agent_sessions.user_id = auth.uid()::text OR public.agent_sessions.user_id IS NULL)
    ));

CREATE POLICY "Users can view tool calls for their sessions"
    ON public.agent_tool_calls FOR SELECT
    USING (EXISTS (
        SELECT 1 FROM public.agent_sessions
        WHERE public.agent_sessions.id = public.agent_tool_calls.session_id
          AND (public.agent_sessions.user_id = auth.uid()::text OR public.agent_sessions.user_id IS NULL)
    ));

CREATE POLICY "Users can view findings for their sessions"
    ON public.agent_findings FOR SELECT
    USING (EXISTS (
        SELECT 1 FROM public.agent_sessions
        WHERE public.agent_sessions.id = public.agent_findings.session_id
          AND (public.agent_sessions.user_id = auth.uid()::text OR public.agent_sessions.user_id IS NULL)
    ));
