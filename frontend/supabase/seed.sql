-- Seed data for CyberNeura platform

-- 1. Insert default roles
INSERT INTO public.roles (name, description) VALUES
('admin', 'Full platform administrator with database write access and user management rights.'),
('analyst', 'Security analyst with scan rights and threat intelligence log write access.'),
('viewer', 'Read-only access to threat feeds, scans, and system telemetry.'),
('user', 'Standard user who can scan URLs and configure local settings.')
ON CONFLICT (name) DO NOTHING;

-- 2. Insert default threat categories
INSERT INTO public.threat_categories (name, code, description, count) VALUES
('Phishing', 'phishing', 'Social engineering websites designed to harvest credentials or banking information.', 307),
('Malware', 'malware', 'Domains hosting viruses, spyware, exploit kits, or command-and-control payloads.', 170),
('Suspicious', 'suspicious', 'Unverified domains with short ages, excessive redirects, or grey network status.', 93),
('Safe', 'safe', 'Legitimate verified web domains exhibiting secure network characteristics.', 847)
ON CONFLICT (code) DO NOTHING;

-- 3. Insert default ML Model version metrics
INSERT INTO public.ml_models (version, algorithm, accuracy, precision, recall, f1_score, training_samples, last_training_date, deployment_status) VALUES
('v2.4.1', 'Deep Neural Network (Transformers)', 98.70, 96.30, 94.80, 95.50, 2400000, '2026-04-12', 'production')
ON CONFLICT (version) DO NOTHING;
