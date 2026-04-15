-- ═══════════════════════════════════════════════════════
-- LinkGuard Phase 2 — Supabase Schema
-- Run this in Supabase SQL Editor to set up your project.
-- ═══════════════════════════════════════════════════════

-- ─── Central blocklist ───────────────────────────────────
-- Community-maintained + imported from external feeds.
-- Readable by anyone with the anon key; write restricted to service role.
CREATE TABLE IF NOT EXISTS urls (
  id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  url          text        NOT NULL,
  verdict      text        NOT NULL CHECK (verdict IN ('dangerous', 'suspicious')),
  source       text        NOT NULL DEFAULT 'community',
  reported_at  timestamptz DEFAULT now(),
  region       text        DEFAULT 'global',
  confirmed    boolean     DEFAULT false
);
CREATE UNIQUE INDEX IF NOT EXISTS urls_url_idx ON urls (url);
CREATE        INDEX IF NOT EXISTS urls_reported_at_idx ON urls (reported_at DESC);

-- ─── User reports ────────────────────────────────────────
-- Raw submissions from extension "Report this link" button.
-- Anyone with anon key can insert; only service role can read.
CREATE TABLE IF NOT EXISTS reports (
  id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  url             text        NOT NULL,
  reporter_id     uuid        REFERENCES auth.users(id) ON DELETE SET NULL,
  context         text,
  verdict_at_time text,
  ts              timestamptz DEFAULT now()
);
CREATE INDEX IF NOT EXISTS reports_url_idx ON reports (url);
CREATE INDEX IF NOT EXISTS reports_ts_idx  ON reports (ts DESC);

-- ─── Scan logs (ML training dataset) ────────────────────
-- Silent telemetry: only dangerous/suspicious verdicts are logged.
-- Anyone with anon key can insert; only service role can read.
CREATE TABLE IF NOT EXISTS scan_logs (
  id      uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  url     text        NOT NULL,
  verdict text        NOT NULL,
  source  text,                         -- which engine caught it
  user_id uuid        REFERENCES auth.users(id) ON DELETE SET NULL,
  device  text        DEFAULT 'chrome-extension',
  ts      timestamptz DEFAULT now()
);
CREATE INDEX IF NOT EXISTS scan_logs_url_idx ON scan_logs (url);
CREATE INDEX IF NOT EXISTS scan_logs_ts_idx  ON scan_logs (ts DESC);

-- ═══════════════════════════════════════════════════════
-- Row Level Security
-- ═══════════════════════════════════════════════════════
ALTER TABLE urls       ENABLE ROW LEVEL SECURITY;
ALTER TABLE reports    ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_logs  ENABLE ROW LEVEL SECURITY;

-- urls: public read, service-role write
CREATE POLICY "Public read urls"
  ON urls FOR SELECT USING (true);

CREATE POLICY "Service insert urls"
  ON urls FOR INSERT WITH CHECK (auth.role() = 'service_role');

-- reports: public insert, service-role read
CREATE POLICY "Public insert reports"
  ON reports FOR INSERT WITH CHECK (true);

CREATE POLICY "Service read reports"
  ON reports FOR SELECT USING (auth.role() = 'service_role');

-- scan_logs: public insert, service-role read
CREATE POLICY "Public insert scan_logs"
  ON scan_logs FOR INSERT WITH CHECK (true);

CREATE POLICY "Service read scan_logs"
  ON scan_logs FOR SELECT USING (auth.role() = 'service_role');

-- ═══════════════════════════════════════════════════════
-- Auto-promote user reports → urls blocklist
-- Runs with SECURITY DEFINER so it can bypass the
-- service-role-only INSERT policy on urls.
-- Every new report is immediately added to the blocklist.
-- ═══════════════════════════════════════════════════════
CREATE OR REPLACE FUNCTION promote_report_to_blocklist()
RETURNS TRIGGER
SECURITY DEFINER
LANGUAGE plpgsql AS $$
BEGIN
  INSERT INTO urls (url, verdict, source)
  VALUES (
    NEW.url,
    COALESCE(NULLIF(TRIM(NEW.verdict_at_time), ''), 'suspicious'),
    'user-report'
  )
  ON CONFLICT (url) DO NOTHING;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS auto_promote_reports ON reports;
CREATE TRIGGER auto_promote_reports
  AFTER INSERT ON reports
  FOR EACH ROW
  EXECUTE FUNCTION promote_report_to_blocklist();
