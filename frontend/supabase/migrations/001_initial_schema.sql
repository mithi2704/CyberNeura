-- Supabase Database Schema for CyberNeura
-- Enables UUID generation extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 1. Roles table
CREATE TABLE IF NOT EXISTS public.roles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(50) UNIQUE NOT NULL,
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 2. Profiles table (linked to auth.users UID from Firebase / Supabase auth)
CREATE TABLE IF NOT EXISTS public.profiles (
    id VARCHAR(128) PRIMARY KEY, -- matches auth ID
    email VARCHAR(255) UNIQUE NOT NULL,
    display_name VARCHAR(100),
    avatar_url TEXT,
    role VARCHAR(50) NOT NULL REFERENCES public.roles(name) DEFAULT 'user',
    fcm_token TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 3. Permissions table
CREATE TABLE IF NOT EXISTS public.permissions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    role VARCHAR(50) NOT NULL REFERENCES public.roles(name),
    resource VARCHAR(100) NOT NULL,
    action VARCHAR(50) NOT NULL, -- create, read, update, delete, *
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 4. Threat Categories table
CREATE TABLE IF NOT EXISTS public.threat_categories (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(100) UNIQUE NOT NULL,
    code VARCHAR(50) UNIQUE NOT NULL, -- phishing, malware, suspicious, safe
    description TEXT,
    count INT DEFAULT 0
);

-- 5. URL Scans table
CREATE TABLE IF NOT EXISTS public.url_scans (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    url TEXT NOT NULL,
    risk_score INT CHECK (risk_score BETWEEN 0 AND 100),
    prediction VARCHAR(50) NOT NULL, -- safe, suspicious, malicious
    confidence INT CHECK (confidence BETWEEN 0 AND 100),
    threat_category VARCHAR(50) REFERENCES public.threat_categories(code),
    domain_age VARCHAR(100),
    hosting_provider VARCHAR(255),
    ip_address VARCHAR(100),
    country VARCHAR(100),
    ssl_status VARCHAR(50), -- valid, invalid, expired, none
    whois_record TEXT,
    dns_records TEXT,
    recommendations TEXT[], -- list of action items
    scanned_by VARCHAR(128) REFERENCES public.profiles(id) ON DELETE SET NULL,
    scanned_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 6. Scan Reports table
CREATE TABLE IF NOT EXISTS public.scan_reports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID UNIQUE NOT NULL REFERENCES public.url_scans(id) ON DELETE CASCADE,
    pdf_url TEXT,
    threat_screenshot_url TEXT,
    csv_export_url TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 7. Threat Logs table (Real-time telemetry)
CREATE TABLE IF NOT EXISTS public.threat_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    url TEXT NOT NULL,
    severity VARCHAR(50) NOT NULL, -- critical, high, medium, low
    category VARCHAR(100) NOT NULL,
    source_ip VARCHAR(100) NOT NULL,
    country VARCHAR(100) NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(50) DEFAULT 'active' -- active, blocked, flagged, resolved
);

-- 8. Notifications table
CREATE TABLE IF NOT EXISTS public.notifications (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id VARCHAR(128) REFERENCES public.profiles(id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    body TEXT NOT NULL,
    type VARCHAR(50) NOT NULL, -- critical_alert, daily_report, weekly_report, threat_alert, system_update
    is_read BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 9. ML Models table
CREATE TABLE IF NOT EXISTS public.ml_models (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    version VARCHAR(50) UNIQUE NOT NULL,
    algorithm VARCHAR(255) NOT NULL,
    accuracy NUMERIC(5,2) NOT NULL,
    precision NUMERIC(5,2) NOT NULL,
    recall NUMERIC(5,2) NOT NULL,
    f1_score NUMERIC(5,2) NOT NULL,
    training_samples INT NOT NULL,
    last_training_date DATE NOT NULL,
    deployment_status VARCHAR(50) NOT NULL -- production, staging, deprecated
);

-- 10. System Settings table
CREATE TABLE IF NOT EXISTS public.system_settings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id VARCHAR(128) UNIQUE NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
    real_time_protection BOOLEAN DEFAULT TRUE,
    auto_block BOOLEAN DEFAULT TRUE,
    email_scanning BOOLEAN DEFAULT FALSE,
    browser_protection BOOLEAN DEFAULT TRUE,
    api_access BOOLEAN DEFAULT FALSE,
    notification_preferences JSONB DEFAULT '{"criticalAlerts": true, "dailyReports": true, "weeklyAnalytics": true, "systemUpdates": false, "newFeatures": false}'::jsonb,
    license_key VARCHAR(100) DEFAULT 'CNEU-2024-XXXX-XXXX',
    license_valid_until DATE DEFAULT '2026-12-31',
    api_usage_limit INT DEFAULT 50000,
    api_usage_count INT DEFAULT 0,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 11. Activity Logs table
CREATE TABLE IF NOT EXISTS public.activity_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id VARCHAR(128) REFERENCES public.profiles(id) ON DELETE SET NULL,
    user_email VARCHAR(255) NOT NULL,
    action VARCHAR(255) NOT NULL,
    description TEXT,
    ip_address VARCHAR(100),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 12. API Usage table
CREATE TABLE IF NOT EXISTS public.api_usage (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id VARCHAR(128) REFERENCES public.profiles(id) ON DELETE CASCADE,
    endpoint VARCHAR(255) NOT NULL,
    request_count INT DEFAULT 1,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 13. Feedback table
CREATE TABLE IF NOT EXISTS public.feedback (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id VARCHAR(128) REFERENCES public.profiles(id) ON DELETE SET NULL,
    scan_id UUID NOT NULL REFERENCES public.url_scans(id) ON DELETE CASCADE,
    is_correct BOOLEAN NOT NULL,
    comments TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 14. Chat History table
CREATE TABLE IF NOT EXISTS public.chat_history (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id VARCHAR(128) REFERENCES public.profiles(id) ON DELETE CASCADE,
    role VARCHAR(50) CHECK (role IN ('user', 'assistant')) NOT NULL,
    content TEXT NOT NULL,
    scan_id UUID REFERENCES public.url_scans(id) ON DELETE SET NULL,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Enable Row Level Security (RLS) on all tables
ALTER TABLE public.roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.permissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.threat_categories ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.url_scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scan_reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.threat_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.notifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ml_models ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.system_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.activity_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.api_usage ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.feedback ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.chat_history ENABLE ROW LEVEL SECURITY;
