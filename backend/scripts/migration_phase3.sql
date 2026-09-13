-- ============================================================
-- CyberNeura Phase 3 Migration: Risk + Evidence Engine Schema
-- ============================================================

-- 1. Risk Assessments Table
CREATE TABLE IF NOT EXISTS public.risk_assessments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES public.url_scans(id) ON DELETE CASCADE,
    risk_score INT NOT NULL CHECK (risk_score >= 0 AND risk_score <= 100),
    prediction TEXT NOT NULL,
    confidence FLOAT NOT NULL CHECK (confidence >= 0.0 AND confidence <= 100.0),
    threat_category TEXT NOT NULL,
    severity TEXT NOT NULL,
    summary TEXT,
    evidence_count INT DEFAULT 0,
    critical_evidence_count INT DEFAULT 0,
    supporting_evidence_count INT DEFAULT 0,
    contradicting_evidence_count INT DEFAULT 0,
    explanation TEXT,
    risk_engine_version TEXT DEFAULT '1.0.0',
    config_version TEXT DEFAULT '2026.09.1',
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);

-- 2. Scan Evidence Table
CREATE TABLE IF NOT EXISTS public.scan_evidence (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES public.url_scans(id) ON DELETE CASCADE,
    source TEXT NOT NULL,
    evidence_type TEXT NOT NULL,
    category TEXT,
    severity TEXT NOT NULL,
    state TEXT NOT NULL,
    value TEXT,
    score FLOAT DEFAULT 0.0,
    confidence FLOAT DEFAULT 1.0,
    weight FLOAT DEFAULT 1.0,
    supports_risk BOOLEAN DEFAULT TRUE,
    description TEXT,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ DEFAULT now()
);

-- 3. Correlated Findings Table
CREATE TABLE IF NOT EXISTS public.correlated_findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES public.url_scans(id) ON DELETE CASCADE,
    finding_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence FLOAT NOT NULL,
    description TEXT NOT NULL,
    sources JSONB DEFAULT '[]'::jsonb,
    evidence_ids JSONB DEFAULT '[]'::jsonb,
    rule_id TEXT,
    created_at TIMESTAMPTZ DEFAULT now()
);

-- 4. Risk Factors Table
CREATE TABLE IF NOT EXISTS public.risk_factors (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES public.url_scans(id) ON DELETE CASCADE,
    factor_type TEXT NOT NULL,
    factor_name TEXT NOT NULL,
    raw_value TEXT,
    normalized_value FLOAT DEFAULT 0.0,
    weight FLOAT DEFAULT 0.1,
    contribution FLOAT DEFAULT 0.0,
    max_contribution FLOAT DEFAULT 10.0,
    direction TEXT DEFAULT 'RISK_INCREASING',
    description TEXT,
    created_at TIMESTAMPTZ DEFAULT now()
);

-- 5. Risk Engine Configuration Table
CREATE TABLE IF NOT EXISTS public.risk_engine_configs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL UNIQUE,
    version TEXT NOT NULL,
    weights JSONB NOT NULL,
    thresholds JSONB NOT NULL,
    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);

-- Seed default configuration
INSERT INTO public.risk_engine_configs (name, version, weights, thresholds, enabled)
VALUES (
    'default',
    '2026.09.1',
    '{"ml": 0.30, "threat_intel": 0.30, "dns": 0.10, "whois": 0.10, "url_features": 0.10, "history": 0.10}'::jsonb,
    '{"safe": 20, "suspicious": 40, "high": 60, "malicious": 80}'::jsonb,
    TRUE
)
ON CONFLICT (name) DO UPDATE SET
    version = EXCLUDED.version,
    weights = EXCLUDED.weights,
    thresholds = EXCLUDED.thresholds,
    updated_at = now();

-- ── Indexes for high-performance querying ────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_risk_assessments_scan_id ON public.risk_assessments(scan_id);
CREATE INDEX IF NOT EXISTS idx_risk_assessments_prediction ON public.risk_assessments(prediction);
CREATE INDEX IF NOT EXISTS idx_risk_assessments_threat_cat ON public.risk_assessments(threat_category);
CREATE INDEX IF NOT EXISTS idx_risk_assessments_created_at ON public.risk_assessments(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_scan_evidence_scan_id ON public.scan_evidence(scan_id);
CREATE INDEX IF NOT EXISTS idx_scan_evidence_source ON public.scan_evidence(source);
CREATE INDEX IF NOT EXISTS idx_scan_evidence_type ON public.scan_evidence(evidence_type);

CREATE INDEX IF NOT EXISTS idx_correlated_findings_scan_id ON public.correlated_findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_risk_factors_scan_id ON public.risk_factors(scan_id);

-- ── Row Level Security (RLS) ──────────────────────────────────────────────
ALTER TABLE public.risk_assessments ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scan_evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.correlated_findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.risk_factors ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.risk_engine_configs ENABLE ROW LEVEL SECURITY;

-- Allow authenticated users to read assessments and supporting evidence
CREATE POLICY "Allow authenticated read on risk assessments"
    ON public.risk_assessments FOR SELECT
    TO authenticated
    USING (true);

CREATE POLICY "Allow authenticated read on scan evidence"
    ON public.scan_evidence FOR SELECT
    TO authenticated
    USING (true);

CREATE POLICY "Allow authenticated read on correlated findings"
    ON public.correlated_findings FOR SELECT
    TO authenticated
    USING (true);

CREATE POLICY "Allow authenticated read on risk factors"
    ON public.risk_factors FOR SELECT
    TO authenticated
    USING (true);

CREATE POLICY "Allow authenticated read on risk configs"
    ON public.risk_engine_configs FOR SELECT
    TO authenticated
    USING (true);

-- Allow service role full access
CREATE POLICY "Allow service role full access to assessments"
    ON public.risk_assessments FOR ALL
    TO service_role
    USING (true);

CREATE POLICY "Allow service role full access to evidence"
    ON public.scan_evidence FOR ALL
    TO service_role
    USING (true);

CREATE POLICY "Allow service role full access to findings"
    ON public.correlated_findings FOR ALL
    TO service_role
    USING (true);

CREATE POLICY "Allow service role full access to factors"
    ON public.risk_factors FOR ALL
    TO service_role
    USING (true);

CREATE POLICY "Allow service role full access to configs"
    ON public.risk_engine_configs FOR ALL
    TO service_role
    USING (true);
