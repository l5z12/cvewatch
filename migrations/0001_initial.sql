CREATE TABLE poll_state (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  not_before INTEGER NOT NULL,
  watermark INTEGER NOT NULL,
  window_start INTEGER,
  window_end INTEGER,
  page_index INTEGER NOT NULL DEFAULT 0,
  next_poll_at INTEGER NOT NULL DEFAULT 0,
  last_success_at INTEGER,
  last_error TEXT
);

CREATE TABLE run_lock (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  owner TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE TABLE cves (
  id TEXT PRIMARY KEY,
  published_at INTEGER NOT NULL,
  payload TEXT NOT NULL,
  discovered_at INTEGER NOT NULL
);

CREATE TABLE deliveries (
  cve_id TEXT NOT NULL REFERENCES cves(id),
  channel TEXT NOT NULL CHECK (channel IN ('telegram', 'discord')),
  attempts INTEGER NOT NULL DEFAULT 0,
  next_attempt_at INTEGER NOT NULL DEFAULT 0,
  sent_at INTEGER,
  last_error TEXT,
  PRIMARY KEY (cve_id, channel)
);

CREATE INDEX deliveries_pending ON deliveries(channel, next_attempt_at, cve_id)
  WHERE sent_at IS NULL;

CREATE TABLE channel_state (
  channel TEXT PRIMARY KEY,
  next_send_at INTEGER NOT NULL DEFAULT 0
);
INSERT INTO channel_state (channel) VALUES ('telegram'), ('discord');

CREATE TABLE live_poll_state (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  watermark INTEGER NOT NULL,
  window_start INTEGER,
  window_end INTEGER,
  page_number INTEGER NOT NULL DEFAULT 1,
  next_poll_at INTEGER NOT NULL DEFAULT 0,
  failure_count INTEGER NOT NULL DEFAULT 0,
  last_success_at INTEGER,
  last_error TEXT
);
