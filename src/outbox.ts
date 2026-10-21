import type { Channel, Cve } from './types';

// These two statements must be committed in the same batch as a source cursor.
export function enqueueStatements(
  db: D1Database,
  cves: Cve[],
  discoveredAt: number,
  channels: Channel[],
): D1PreparedStatement[] {
  const rows = JSON.stringify(cves.map((cve) => ({ id: cve.id, published: Date.parse(cve.published), payload: cve })));
  return [
    db
      .prepare(
        `INSERT OR IGNORE INTO cves (id, published_at, payload, discovered_at)
      SELECT json_extract(value, '$.id'), json_extract(value, '$.published'),
        json_extract(value, '$.payload'), ? FROM json_each(?)`,
      )
      .bind(discoveredAt, rows),
    db
      .prepare(
        `INSERT OR IGNORE INTO deliveries (cve_id, channel)
      SELECT json_extract(j.value, '$.id'), s.channel FROM json_each(?) j CROSS JOIN channel_state s
      WHERE s.channel IN (SELECT value FROM json_each(?))`,
      )
      .bind(rows, JSON.stringify(channels)),
  ];
}

// Requested CVEs are resent even if already delivered, with a refreshed payload.
// Commit these in the same batch that removes the request.
export function resendStatements(
  db: D1Database,
  cve: Cve,
  requestedAt: number,
  channels: Channel[],
): D1PreparedStatement[] {
  return [
    db
      .prepare(
        `INSERT INTO cves (id, published_at, payload, discovered_at) VALUES (?, ?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET payload = excluded.payload`,
      )
      .bind(cve.id, Date.parse(cve.published), JSON.stringify(cve), requestedAt),
    db
      .prepare(
        `INSERT INTO deliveries (cve_id, channel)
      SELECT ?, channel FROM channel_state WHERE channel IN (SELECT value FROM json_each(?))
      ON CONFLICT(cve_id, channel) DO UPDATE SET attempts = 0, next_attempt_at = 0, sent_at = NULL, last_error = NULL`,
      )
      .bind(cve.id, JSON.stringify(channels)),
  ];
}
