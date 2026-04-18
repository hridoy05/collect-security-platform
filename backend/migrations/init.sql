-- ============================================================
-- Connect Security Analytics Platform
-- Database Schema
-- ============================================================

-- Users table (with bcrypt password hashing)
CREATE TABLE IF NOT EXISTS users (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email       VARCHAR(255) UNIQUE NOT NULL,
  password    VARCHAR(255) NOT NULL,        -- bcrypt hash
  role        VARCHAR(50) DEFAULT 'analyst', -- admin, analyst, viewer
  full_name   VARCHAR(255),
  created_at  TIMESTAMPTZ DEFAULT NOW(),
  last_login  TIMESTAMPTZ,
  is_active   BOOLEAN DEFAULT true
);

-- Cryptographic Asset Inventory (CBOM)
CREATE TABLE IF NOT EXISTS crypto_assets (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  asset_id         VARCHAR(255) UNIQUE NOT NULL,
  asset_type       VARCHAR(100) NOT NULL,  -- certificate, jwt-key, db-key, ssh-key, api-key
  algorithm        VARCHAR(100) NOT NULL,  -- RSA-2048, AES-256-GCM, ECDSA, etc.
  key_length       INTEGER,
  hash_algorithm   VARCHAR(100),
  system_name      VARCHAR(255) NOT NULL,
  environment      VARCHAR(50) DEFAULT 'production', -- production, staging, dev
  owner_team       VARCHAR(255),
  issuer           VARCHAR(255),
  expiry_date      TIMESTAMPTZ,
  days_to_expiry   INTEGER,
  last_rotated     TIMESTAMPTZ,
  rotation_policy  VARCHAR(100),          -- 30days, 90days, annual, none
  quantum_safe     BOOLEAN DEFAULT false,
  risk_rating      VARCHAR(20) DEFAULT 'amber', -- red, amber, green
  issues           TEXT,
  notes            TEXT,
  created_at       TIMESTAMPTZ DEFAULT NOW(),
  updated_at       TIMESTAMPTZ DEFAULT NOW()
);

-- Security Alerts (SIEM)
CREATE TABLE IF NOT EXISTS security_alerts (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  alert_id        VARCHAR(255) UNIQUE NOT NULL,
  title           VARCHAR(500) NOT NULL,
  description     TEXT,
  severity        VARCHAR(20) NOT NULL,   -- critical, high, medium, low
  status          VARCHAR(50) DEFAULT 'open', -- open, investigating, resolved, false_positive
  source_type     VARCHAR(100),           -- firewall, ids, auth, app, ml
  source_ip       INET,
  dest_ip         INET,
  affected_user   VARCHAR(255),
  affected_system VARCHAR(255),
  mitre_tactic    VARCHAR(255),
  mitre_technique VARCHAR(255),
  alert_score     DECIMAL(5,2),           -- 0-100
  es_index        VARCHAR(255),           -- Elasticsearch index reference
  raw_event       JSONB,                  -- original log event
  threat_intel    JSONB,                  -- enrichment from threat feeds
  assigned_to     VARCHAR(255),
  resolved_at     TIMESTAMPTZ,
  created_at      TIMESTAMPTZ DEFAULT NOW(),
  updated_at      TIMESTAMPTZ DEFAULT NOW()
);

-- IOC (Indicators of Compromise)
CREATE TABLE IF NOT EXISTS threat_indicators (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  ioc_type     VARCHAR(100) NOT NULL,  -- ip, domain, hash, url, email
  ioc_value    VARCHAR(1000) NOT NULL,
  threat_actor VARCHAR(255),           -- APT29, FIN7, etc.
  campaign     VARCHAR(255),
  confidence   INTEGER DEFAULT 50,    -- 0-100
  severity     VARCHAR(20),
  source       VARCHAR(255),          -- MISP, OTX, CISA, manual
  tags         TEXT[],
  first_seen   TIMESTAMPTZ,
  last_seen    TIMESTAMPTZ,
  is_active    BOOLEAN DEFAULT true,
  created_at   TIMESTAMPTZ DEFAULT NOW()
);

-- CVE Tracking
CREATE TABLE IF NOT EXISTS cve_tracking (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  cve_id          VARCHAR(50) UNIQUE NOT NULL,  -- CVE-2021-44228
  cvss_score      DECIMAL(3,1),                  -- 0.0-10.0
  cvss_severity   VARCHAR(20),                   -- critical, high, medium, low
  epss_score      DECIMAL(5,4),                  -- 0.0000-1.0000
  is_kev          BOOLEAN DEFAULT false,          -- CISA Known Exploited
  description     TEXT,
  affected_product VARCHAR(500),
  patch_available BOOLEAN DEFAULT false,
  patched_at      TIMESTAMPTZ,
  status          VARCHAR(50) DEFAULT 'open',    -- open, patched, accepted_risk
  created_at      TIMESTAMPTZ DEFAULT NOW(),
  updated_at      TIMESTAMPTZ DEFAULT NOW()
);

-- Audit Log (every API action tracked)

CREATE TABLE IF NOT EXISTS audit_logs (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     UUID REFERENCES users(id),
  action      VARCHAR(255) NOT NULL,
  resource    VARCHAR(255),
  resource_id VARCHAR(255),
  ip_address  INET,
  user_agent  TEXT,
  details     JSONB,
  created_at  TIMESTAMPTZ DEFAULT NOW()
);

-- ML Anomaly Results
CREATE TABLE IF NOT EXISTS ml_anomalies (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  model_type      VARCHAR(100) NOT NULL,  -- zscore, isolation_forest, ueba, entropy
  entity_type     VARCHAR(100),           -- user, ip, host, dns_query
  entity_value    VARCHAR(500),
  anomaly_score   DECIMAL(5,4),           -- 0.0-1.0
  threshold       DECIMAL(5,4),
  is_anomaly      BOOLEAN DEFAULT false,
  features        JSONB,                  -- feature vector used
  description     TEXT,
  alert_created   BOOLEAN DEFAULT false,
  created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- ─────────────────────────
-- SEED DATA
-- ─────────────────────────

-- Default admin user (password: Admin@123)
INSERT INTO users (email, password, role, full_name) VALUES
('admin@connect.com',
 '$2a$12$wBtlOJVg5CIUE4SpfhfEcO9yF6tF.9gsojNX/4on6i8EK/Yc3mEBa',
 'admin', 'Connect Admin'),
('analyst@connect.com',
 '$2a$12$wBtlOJVg5CIUE4SpfhfEcO9yF6tF.9gsojNX/4on6i8EK/Yc3mEBa',
 'analyst', 'Security Analyst')
ON CONFLICT (email) DO NOTHING;

-- Sample CBOM entries
INSERT INTO crypto_assets (asset_id, asset_type, algorithm, key_length, system_name, environment, owner_team, expiry_date, days_to_expiry, quantum_safe, risk_rating, issues, rotation_policy) VALUES
('cert-api-prod-001', 'TLS Certificate', 'RSA-2048', 2048, 'api.paybdapp.com', 'production', 'platform-team', NOW() + INTERVAL '180 days', 180, false, 'amber', 'Quantum-vulnerable RSA algorithm', '90days'),
('cert-auth-prod-001', 'TLS Certificate', 'RSA-4096', 4096, 'auth.paybdapp.com', 'production', 'platform-team', NOW() + INTERVAL '7 days', 7, false, 'red', 'Expires in 7 days! Quantum-vulnerable', '90days'),
('jwt-signing-001', 'JWT Signing Key', 'RS256', 2048, 'auth-service', 'production', 'backend-team', NOW() - INTERVAL '5 days', -5, false, 'red', 'EXPIRED! Immediate rotation required', 'annual'),
('db-encrypt-001', 'Database Key', 'AES-256-GCM', 256, 'postgresql-prod', 'production', 'db-team', NULL, NULL, true, 'green', NULL, '90days'),
('ssh-key-ex-dev', 'SSH Key', 'RSA-2048', 2048, 'prod-server-01', 'production', 'devops', NULL, NULL, false, 'red', 'Orphaned key — ex-employee. Revoke immediately!', 'none'),
('api-key-payment', 'API Key', 'HMAC-SHA256', 256, 'payment-gateway', 'production', 'backend-team', NOW() + INTERVAL '30 days', 30, true, 'amber', 'Expires in 30 days', '90days'),
('cert-internal-001', 'TLS Certificate', 'ECDSA-P256', 256, 'internal-api.paybdapp.com', 'production', 'platform-team', NOW() + INTERVAL '365 days', 365, false, 'amber', 'Quantum-vulnerable ECC', 'annual'),
('db-encrypt-staging', 'Database Key', 'AES-128-CBC', 128, 'postgresql-staging', 'staging', 'db-team', NULL, NULL, false, 'red', 'AES-128 below recommended 256-bit. CBC mode lacks authentication.', 'none')
ON CONFLICT (asset_id) DO NOTHING;

-- Sample IOCs
INSERT INTO threat_indicators (ioc_type, ioc_value, threat_actor, campaign, confidence, severity, source, tags) VALUES
('ip', '45.33.32.156', 'FIN7', 'Operation SilkBean', 90, 'critical', 'OTX', ARRAY['c2-server', 'fintech-target']),
('ip', '185.220.101.45', 'APT29', 'SolarWinds Campaign', 85, 'critical', 'CISA', ARRAY['c2-server', 'nation-state']),
('domain', 'malware-c2.xyz', 'Unknown', NULL, 70, 'high', 'MISP', ARRAY['c2-server', 'malware']),
('hash', 'd41d8cd98f00b204e9800998ecf8427e', 'FIN7', 'Carbanak', 95, 'critical', 'VirusTotal', ARRAY['ransomware', 'emotet']),
('ip', '192.168.100.250', 'Insider', NULL, 60, 'medium', 'internal', ARRAY['suspicious', 'internal'])
ON CONFLICT DO NOTHING;

-- Sample CVEs
INSERT INTO cve_tracking (cve_id, cvss_score, cvss_severity, epss_score, is_kev, description, affected_product, patch_available) VALUES
('CVE-2021-44228', 10.0, 'critical', 0.9754, true, 'Log4Shell - Remote code execution in Apache Log4j', 'Apache Log4j 2.x', true),
('CVE-2023-44487', 7.5, 'high', 0.8231, true, 'HTTP/2 Rapid Reset Attack - DDoS amplification', 'Multiple HTTP/2 implementations', true),
('CVE-2024-3094', 10.0, 'critical', 0.9100, true, 'XZ Utils backdoor - supply chain attack', 'XZ Utils 5.6.0-5.6.1', true),
('CVE-2023-23397', 9.8, 'critical', 0.7654, true, 'Microsoft Outlook NTLM hash leak', 'Microsoft Outlook', true),
('CVE-2022-0847', 7.8, 'high', 0.6543, false, 'Dirty Pipe - Linux kernel privilege escalation', 'Linux Kernel 5.8+', true)
ON CONFLICT (cve_id) DO NOTHING;

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON security_alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON security_alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_created ON security_alerts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_cbom_risk ON crypto_assets(risk_rating);
CREATE INDEX IF NOT EXISTS idx_cbom_expiry ON crypto_assets(expiry_date);
CREATE INDEX IF NOT EXISTS idx_ioc_value ON threat_indicators(ioc_value);
CREATE INDEX IF NOT EXISTS idx_ml_anomaly ON ml_anomalies(is_anomaly, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(user_id, created_at DESC);
