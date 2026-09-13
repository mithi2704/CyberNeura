-- CyberNeura Phase 2 Database Migration
-- Adds threat_intelligence table and indexes for multi-source intelligence correlation.
-- Preserves existing Phase 1 data without modifications.

CREATE TABLE IF NOT EXISTS threat_intelligence (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES url_scans(id) ON DELETE CASCADE,
    provider VARCHAR(64) NOT NULL,
    indicator TEXT NOT NULL,
    indicator_type VARCHAR(32) NOT NULL DEFAULT 'url',
    status VARCHAR(32) NOT NULL DEFAULT 'NO_MATCH',
    matched BOOLEAN NOT NULL DEFAULT FALSE,
    verdict VARCHAR(32) NOT NULL DEFAULT 'NO_MATCH',
    threat_type TEXT,
    confidence FLOAT,
    metadata JSONB DEFAULT '{}'::jsonb,
    checked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    latency_ms INTEGER DEFAULT 0,
    error_code TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Performance and query indexes
CREATE INDEX IF NOT EXISTS idx_threat_intel_scan_id ON threat_intelligence(scan_id);
CREATE INDEX IF NOT EXISTS idx_threat_intel_provider ON threat_intelligence(provider);
CREATE INDEX IF NOT EXISTS idx_threat_intel_indicator ON threat_intelligence(indicator);
CREATE INDEX IF NOT EXISTS idx_threat_intel_matched ON threat_intelligence(matched);
CREATE INDEX IF NOT EXISTS idx_threat_intel_verdict ON threat_intelligence(verdict);
CREATE INDEX IF NOT EXISTS idx_threat_intel_checked_at ON threat_intelligence(checked_at DESC);
CREATE INDEX IF NOT EXISTS idx_threat_intel_expires_at ON threat_intelligence(expires_at);

-- Composite index for fast deduplicated cache lookup
CREATE INDEX IF NOT EXISTS idx_threat_intel_provider_indicator 
ON threat_intelligence(provider, indicator, checked_at DESC);
