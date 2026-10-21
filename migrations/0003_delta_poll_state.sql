CREATE TABLE delta_poll_state (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  fetch_time INTEGER,
  next_index INTEGER NOT NULL DEFAULT 0,
  last_success_at INTEGER,
  last_error TEXT
);
