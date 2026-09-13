-- ============================================================
-- CYBERNEURA PHASE 5: REAL-TIME CYBERSECURITY PLATFORM MIGRATION
-- Tables: realtime_events
-- Publication: supabase_realtime configuration
-- Indexes: Composite query & timestamp ordering indexes
-- Security: Row Level Security (RLS) policies
-- ============================================================

-- 1. Create Realtime Events Table
CREATE TABLE IF NOT EXISTS public.realtime_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    user_id TEXT,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 2. Performance and Query Indexes
CREATE INDEX IF NOT EXISTS idx_realtime_events_user_id ON public.realtime_events (user_id);
CREATE INDEX IF NOT EXISTS idx_realtime_events_event_type ON public.realtime_events (event_type);
CREATE INDEX IF NOT EXISTS idx_realtime_events_entity ON public.realtime_events (entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_realtime_events_created_at ON public.realtime_events (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_realtime_events_sync ON public.realtime_events (user_id, created_at DESC);

-- 3. Enable Row Level Security (RLS)
ALTER TABLE public.realtime_events ENABLE ROW LEVEL SECURITY;

-- Policy: Users can view their own private events or system/public events (user_id is NULL)
DROP POLICY IF EXISTS "Users can read own or public realtime events" ON public.realtime_events;
CREATE POLICY "Users can read own or public realtime events" ON public.realtime_events
    FOR SELECT
    USING (
        auth.uid()::text = user_id 
        OR user_id IS NULL
    );

-- Policy: Service role can insert events
DROP POLICY IF EXISTS "Service role can insert realtime events" ON public.realtime_events;
CREATE POLICY "Service role can insert realtime events" ON public.realtime_events
    FOR INSERT
    WITH CHECK (true);

-- 4. Enable Supabase Realtime for Security Tables
-- Ensures Postgres Changes events are emitted via websockets
DO $$
BEGIN
    -- Add realtime_events
    IF NOT EXISTS (
        SELECT 1 FROM pg_publication_tables 
        WHERE pubname = 'supabase_realtime' AND schemaname = 'public' AND tablename = 'realtime_events'
    ) THEN
        ALTER PUBLICATION supabase_realtime ADD TABLE public.realtime_events;
    END IF;

    -- Add url_scans
    IF NOT EXISTS (
        SELECT 1 FROM pg_publication_tables 
        WHERE pubname = 'supabase_realtime' AND schemaname = 'public' AND tablename = 'url_scans'
    ) THEN
        ALTER PUBLICATION supabase_realtime ADD TABLE public.url_scans;
    END IF;

    -- Add risk_assessments
    IF NOT EXISTS (
        SELECT 1 FROM pg_publication_tables 
        WHERE pubname = 'supabase_realtime' AND schemaname = 'public' AND tablename = 'risk_assessments'
    ) THEN
        ALTER PUBLICATION supabase_realtime ADD TABLE public.risk_assessments;
    END IF;

    -- Add threat_intelligence
    IF NOT EXISTS (
        SELECT 1 FROM pg_publication_tables 
        WHERE pubname = 'supabase_realtime' AND schemaname = 'public' AND tablename = 'threat_intelligence'
    ) THEN
        ALTER PUBLICATION supabase_realtime ADD TABLE public.threat_intelligence;
    END IF;

    -- Add notifications
    IF NOT EXISTS (
        SELECT 1 FROM pg_publication_tables 
        WHERE pubname = 'supabase_realtime' AND schemaname = 'public' AND tablename = 'notifications'
    ) THEN
        ALTER PUBLICATION supabase_realtime ADD TABLE public.notifications;
    END IF;

    -- Add agent_events
    IF NOT EXISTS (
        SELECT 1 FROM pg_publication_tables 
        WHERE pubname = 'supabase_realtime' AND schemaname = 'public' AND tablename = 'agent_events'
    ) THEN
        ALTER PUBLICATION supabase_realtime ADD TABLE public.agent_events;
    END IF;
END $$;
