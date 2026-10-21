-- Requests to send an existing CVE. The live monitor resolves and queues each one.
CREATE TABLE send_requests (
  cve_id TEXT PRIMARY KEY,
  requested_at INTEGER NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  next_attempt_at INTEGER NOT NULL DEFAULT 0,
  failed_at INTEGER,
  last_error TEXT
);
