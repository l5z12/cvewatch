-- The CISA Known Exploited Vulnerabilities catalog, checked by the cron run.
CREATE TABLE kev_poll_state (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  last_modified TEXT,
  next_poll_at INTEGER NOT NULL DEFAULT 0,
  last_success_at INTEGER,
  last_error TEXT
);
-- Every CVE the catalog has listed, so only additions are alerted. Entries removed
-- from the catalog stay, so a stale copy of it cannot cause them to be alerted again.
CREATE TABLE kev_catalog (cve_id TEXT PRIMARY KEY);
-- A CVE added to the catalog is requested with its KEV details as JSON, and sent as
-- a new message even if it was alerted before.
ALTER TABLE send_requests ADD COLUMN kev TEXT;
