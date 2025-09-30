-- PostgreSQL schema for MalwareScan project
-- Run this in psql or pgAdmin before starting the backend.
-- Adjust schema name or ownership as needed.

-- Drop tables (ONLY for development resets) - comment out in production
-- DROP TABLE IF EXISTS vendor_warning CASCADE;
-- DROP TABLE IF EXISTS scan CASCADE;
-- DROP TABLE IF EXISTS file CASCADE;
-- DROP TABLE IF EXISTS users CASCADE;

CREATE TABLE IF NOT EXISTS users (
  user_id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password TEXT NOT NULL,
  email_verified BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS file (
  file_id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  file_hash TEXT NOT NULL,
  file_name TEXT NOT NULL,
  file_type TEXT,
  uploaded_at TIMESTAMP DEFAULT NOW(),
  CONSTRAINT uq_file_user UNIQUE (user_id, file_hash)
);

CREATE TABLE IF NOT EXISTS scan (
  scan_id SERIAL PRIMARY KEY,
  file_id INTEGER NOT NULL REFERENCES file(file_id) ON DELETE CASCADE,
  scan_report JSONB, -- enriched report JSON
  vt_score INTEGER DEFAULT 0,
  total_analyzers INTEGER DEFAULT 0,
  created_at TIMESTAMP DEFAULT NOW()
);

-- Optional extra indexes for faster history queries
CREATE INDEX IF NOT EXISTS idx_file_user ON file(user_id);
CREATE INDEX IF NOT EXISTS idx_scan_file ON scan(file_id);
CREATE INDEX IF NOT EXISTS idx_scan_vt_score ON scan(vt_score);

CREATE TABLE IF NOT EXISTS vendor_warning (
  id SERIAL PRIMARY KEY,
  file_id INTEGER NOT NULL REFERENCES file(file_id) ON DELETE CASCADE,
  scan_id INTEGER NOT NULL REFERENCES scan(scan_id) ON DELETE CASCADE,
  vendor_name TEXT NOT NULL,
  warning_message TEXT,
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_vendor_warning_scan ON vendor_warning(scan_id);
CREATE INDEX IF NOT EXISTS idx_vendor_warning_file ON vendor_warning(file_id);

-- Email verification support
CREATE TABLE IF NOT EXISTS email_verification (
  verification_id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at TIMESTAMP NOT NULL,
  used BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_email_verification_user ON email_verification(user_id);
CREATE INDEX IF NOT EXISTS idx_email_verification_expires ON email_verification(expires_at);

-- View for easier history aggregation (optional)
CREATE OR REPLACE VIEW vw_file_latest_scan AS
SELECT f.file_id,
       f.user_id,
       f.file_name,
       f.file_type,
       f.file_hash,
       f.uploaded_at,
       s.scan_id,
       s.vt_score,
       s.total_analyzers,
       s.scan_report,
       s.created_at AS scan_created_at
FROM file f
LEFT JOIN LATERAL (
    SELECT sc.* FROM scan sc
    WHERE sc.file_id = f.file_id
    ORDER BY sc.scan_id DESC
    LIMIT 1
) s ON TRUE;

-- Seed test user (change password hash!)
-- Password hash below corresponds to 'password123' (bcrypt cost 10). Generate your own for real usage.
INSERT INTO users (name, email, password)
SELECT 'Usuario Demo', 'demo@example.com', '$2a$10$CwTycUXWue0Thq9StjUM0uJ8aJQ1YQB8yWfBqXc9EwSgUxzjGJaku'
WHERE NOT EXISTS (SELECT 1 FROM users WHERE email='demo@example.com');

-- Example query to test
-- SELECT * FROM vw_file_latest_scan ORDER BY uploaded_at DESC LIMIT 10;