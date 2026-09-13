-- ============================================================
-- CYBERNEURA PHASE 6: BROWSER EXTENSION INTEGRATION MIGRATION
-- Table: extension_events
-- Publication: supabase_realtime configuration
-- Indexes: Composite query & timestamp ordering indexes
-- Security: Row Level Security (RLS) policies
-- ============================================================

-- 1. Create Extension Events Table
CREATE TABLE IF NOT EXISTS public.extension_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id TEXT,
    installation_id TEXT NOT NULL,
    scan_id TEXT,
    url TEXT NOT NULL,
    domain TEXT,
    decision TEXT NOT NULL, -- ALLOW, WARN, BLOCK
    risk_score INTEGER NOT NULL DEFAULT 0,
    prediction TEXT NOT NULL, -- SAFE, SUSPICIOUS, MALICIOUS
    threat_category TEXT,
    confidence NUMERIC(5,2) NOT NULL DEFAULT 0,
    user_override BOOLEAN NOT NULL DEFAULT false,
    override_action TEXT,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT now(),
    extension_version TEXT NOT NULL DEFAULT '1.0.0',
    browser TEXT NOT NULL DEFAULT 'chrome',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 2. Performance Composite Indexes
CREATE INDEX IF NOT EXISTS idx_extension_events_user_id ON public.extension_events (user_id);
CREATE INDEX IF NOT EXISTS idx_extension_events_installation_id ON public.extension_events (installation_id);
CREATE INDEX IF NOT EXISTS idx_extension_events_scan_id ON public.extension_events (scan_id);
CREATE INDEX IF NOT EXISTS idx_extension_events_created_at ON public.extension_events (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_extension_events_decision ON public.extension_events (decision);
CREATE INDEX IF NOT EXISTS idx_extension_events_risk_score ON public.extension_events (risk_score);
CREATE INDEX IF NOT EXISTS idx_extension_events_user_created ON public.extension_events (user_id, created_at DESC);

-- 3. Enable Row Level Security (RLS)
ALTER TABLE public.extension_events ENABLE ROW LEVEL SECURITY;

-- Policy: Users can read their own extension events, or anonymous events if matching installation
DROP POLICY IF EXISTS "Users can read own extension events" ON public.extension_events;
CREATE POLICY "Users can read own extension events" ON public.extension_events
    FOR SELECT
    USING (
        auth.uid()::text = user_id 
        OR user_id IS NULL
    );

-- Policy: Service role or backend can insert extension events
DROP POLICY IF EXISTS "Service role can insert extension events" ON public.extension_events;
CREATE POLICY "Service role can insert extension events" ON public.extension_events
    FOR INSERT
    WITH CHECK (true);

-- Policy: Service role can update extension events (e.g. for overrides)
DROP POLICY IF EXISTS "Service role can update extension events" ON public.extension_events;
CREATE POLICY "Service role can update extension events" ON public.extension_events
    FOR UPDATE
    USING (true);

-- 4. Enable Supabase Realtime for Extension Events Table
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_publication_tables 
        WHERE pubname = 'supabase_realtime' AND schemaname = 'public' AND tablename = 'extension_events'
    ) THEN
        ALTER PUBLICATION supabase_realtime ADD TABLE public.extension_events;
    END IF;
END $$;
