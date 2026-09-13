-- ==============================================================================
-- CyberNeura Phase 7: AI Media Security Database Migration
-- Tables for Media Assets, Assessments, Evidence, Frame Results, Face Results,
-- Provenance Records, Forensics, and Asynchronous Jobs.
-- ==============================================================================

-- Enable UUID extension if not present
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 1. Media Assets Table
CREATE TABLE IF NOT EXISTS public.media_assets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id VARCHAR(128) REFERENCES public.profiles(id) ON DELETE SET NULL,
    media_type VARCHAR(20) NOT NULL CHECK (media_type IN ('IMAGE', 'VIDEO')),
    storage_path TEXT NOT NULL,
    original_filename TEXT NOT NULL,
    mime_type VARCHAR(100) NOT NULL,
    file_size BIGINT NOT NULL,
    sha256 VARCHAR(64) NOT NULL,
    width INT,
    height INT,
    duration FLOAT,
    frame_count INT,
    created_at TIMESTAMPTZ DEFAULT now(),
    expires_at TIMESTAMPTZ DEFAULT (now() + INTERVAL '30 days')
);

CREATE INDEX IF NOT EXISTS idx_media_assets_sha256 ON public.media_assets (sha256);
CREATE INDEX IF NOT EXISTS idx_media_assets_user_id ON public.media_assets (user_id);
CREATE INDEX IF NOT EXISTS idx_media_assets_created_at ON public.media_assets (created_at DESC);

-- 2. Media Assessments Table
CREATE TABLE IF NOT EXISTS public.media_assessments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    media_id UUID NOT NULL REFERENCES public.media_assets(id) ON DELETE CASCADE,
    user_id VARCHAR(128) REFERENCES public.profiles(id) ON DELETE SET NULL,
    media_type VARCHAR(20) NOT NULL CHECK (media_type IN ('IMAGE', 'VIDEO')),
    classification VARCHAR(50) NOT NULL CHECK (classification IN (
        'LIKELY_AUTHENTIC', 'SUSPICIOUS', 'LIKELY_AI_GENERATED', 'LIKELY_DEEPFAKE', 'INCONCLUSIVE'
    )),
    risk_score INT NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
    confidence FLOAT NOT NULL CHECK (confidence BETWEEN 0.0 AND 100.0),
    severity VARCHAR(20) NOT NULL DEFAULT 'INFO' CHECK (severity IN ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    summary TEXT NOT NULL,
    limitations JSONB DEFAULT '[]'::jsonb,
    model_version VARCHAR(50) NOT NULL,
    analysis_version VARCHAR(50) NOT NULL,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_media_assessments_media_id ON public.media_assessments (media_id);
CREATE INDEX IF NOT EXISTS idx_media_assessments_classification ON public.media_assessments (classification);
CREATE INDEX IF NOT EXISTS idx_media_assessments_risk_score ON public.media_assessments (risk_score DESC);

-- 3. Media Evidence Table
CREATE TABLE IF NOT EXISTS public.media_evidence (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    media_id UUID NOT NULL REFERENCES public.media_assets(id) ON DELETE CASCADE,
    source VARCHAR(50) NOT NULL,
    evidence_type VARCHAR(50) NOT NULL,
    category VARCHAR(50),
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    state VARCHAR(20) NOT NULL DEFAULT 'SUPPORTING' CHECK (state IN ('CONFIRMED', 'SUPPORTING', 'CONTRADICTING', 'UNKNOWN', 'UNAVAILABLE')),
    value JSONB,
    score FLOAT DEFAULT 0.0 CHECK (score BETWEEN 0.0 AND 1.0),
    confidence FLOAT DEFAULT 1.0 CHECK (confidence BETWEEN 0.0 AND 1.0),
    supports_risk BOOLEAN DEFAULT true,
    description TEXT NOT NULL,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_media_evidence_media_id ON public.media_evidence (media_id);
CREATE INDEX IF NOT EXISTS idx_media_evidence_source ON public.media_evidence (source);

-- 4. Media Frame Results (Sampled video frames)
CREATE TABLE IF NOT EXISTS public.media_frame_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    media_id UUID NOT NULL REFERENCES public.media_assets(id) ON DELETE CASCADE,
    frame_number INT NOT NULL,
    timestamp FLOAT NOT NULL,
    model_probability FLOAT NOT NULL,
    model_confidence FLOAT NOT NULL,
    face_count INT DEFAULT 0,
    face_quality FLOAT DEFAULT 1.0,
    classification VARCHAR(50) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_media_frame_results_media_id ON public.media_frame_results (media_id);
CREATE INDEX IF NOT EXISTS idx_media_frame_results_timestamp ON public.media_frame_results (media_id, timestamp);

-- 5. Media Face Results (Face-level manipulation indicators - NO BIOMETRIC/IDENTITY DATA)
CREATE TABLE IF NOT EXISTS public.media_face_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    frame_result_id UUID NOT NULL REFERENCES public.media_frame_results(id) ON DELETE CASCADE,
    face_index INT NOT NULL DEFAULT 0,
    bounding_box JSONB NOT NULL, -- { x, y, width, height }
    quality_score FLOAT NOT NULL,
    manipulation_probability FLOAT NOT NULL,
    confidence FLOAT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_media_face_results_frame_id ON public.media_face_results (frame_result_id);

-- 6. Media Provenance Table (C2PA / Content Credentials)
CREATE TABLE IF NOT EXISTS public.media_provenance (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    media_id UUID NOT NULL REFERENCES public.media_assets(id) ON DELETE CASCADE,
    status VARCHAR(50) NOT NULL CHECK (status IN (
        'PROVENANCE_CONFIRMED', 'PROVENANCE_PRESENT', 'PROVENANCE_ABSENT', 'PROVENANCE_INVALID', 'PROVENANCE_UNAVAILABLE'
    )),
    format VARCHAR(50), -- e.g. "C2PA", "EXIF_SIGNATURE", "NONE"
    verified BOOLEAN DEFAULT false,
    issuer TEXT,
    claims JSONB DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_media_provenance_media_id ON public.media_provenance (media_id);

-- 7. Media Forensic Results Table
CREATE TABLE IF NOT EXISTS public.media_forensic_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    media_id UUID NOT NULL REFERENCES public.media_assets(id) ON DELETE CASCADE,
    signal_type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    confidence FLOAT NOT NULL CHECK (confidence BETWEEN 0.0 AND 1.0),
    value JSONB,
    description TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_media_forensics_media_id ON public.media_forensic_results (media_id);

-- 8. Media Processing Jobs Table (Asynchronous queue tracking)
CREATE TABLE IF NOT EXISTS public.media_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    media_id UUID REFERENCES public.media_assets(id) ON DELETE CASCADE,
    user_id VARCHAR(128) REFERENCES public.profiles(id) ON DELETE SET NULL,
    media_type VARCHAR(20) NOT NULL CHECK (media_type IN ('IMAGE', 'VIDEO')),
    status VARCHAR(30) NOT NULL DEFAULT 'QUEUED' CHECK (status IN (
        'QUEUED', 'PROCESSING', 'COMPLETED', 'FAILED', 'CANCELLED'
    )),
    progress INT NOT NULL DEFAULT 0 CHECK (progress BETWEEN 0 AND 100),
    current_stage VARCHAR(100) DEFAULT 'INITIALIZING',
    error_message TEXT,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_media_jobs_status ON public.media_jobs (status);
CREATE INDEX IF NOT EXISTS idx_media_jobs_media_id ON public.media_jobs (media_id);
CREATE INDEX IF NOT EXISTS idx_media_jobs_user_id ON public.media_jobs (user_id);

-- Enable Row Level Security (RLS) on all media tables
ALTER TABLE public.media_assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.media_assessments ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.media_evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.media_frame_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.media_face_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.media_provenance ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.media_forensic_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.media_jobs ENABLE ROW LEVEL SECURITY;

-- Standard user isolation RLS policies
CREATE POLICY "Users can access own media assets" ON public.media_assets
    FOR ALL USING (auth.uid()::text = user_id OR user_id IS NULL);

CREATE POLICY "Users can access own media assessments" ON public.media_assessments
    FOR ALL USING (auth.uid()::text = user_id OR user_id IS NULL);

CREATE POLICY "Users can access own media jobs" ON public.media_jobs
    FOR ALL USING (auth.uid()::text = user_id OR user_id IS NULL);

-- Real-time CDC publication
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_publication_tables 
        WHERE pubname = 'supabase_realtime' AND tablename = 'media_jobs'
    ) THEN
        ALTER PUBLICATION supabase_realtime ADD TABLE public.media_jobs;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_publication_tables 
        WHERE pubname = 'supabase_realtime' AND tablename = 'media_assessments'
    ) THEN
        ALTER PUBLICATION supabase_realtime ADD TABLE public.media_assessments;
    END IF;
END $$;
