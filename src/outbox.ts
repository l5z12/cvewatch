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

// Adds a newly published score to stored CVEs that were queued without one. Sent
// alerts are queued again to be edited; unsent ones go out with the score. A stored
// score is never replaced, so sources that disagree cannot keep editing an alert.
export function scoreStatements(db: D1Database, cves: Cve[]): D1PreparedStatement[] {
  const scored = cves.filter((cve) => cve.score !== null);
  if (scored.length === 0) return [];
  // A merge patch removes null members, so set only the fields that have values.
  const rows = JSON.stringify(
    scored.map((cve) => ({
      id: cve.id,
      patch: {
        severity: cve.severity,
        score: cve.score,
        ...(cve.cvssVersion ? { cvssVersion: cve.cvssVersion } : {}),
        ...(cve.exploited ? { exploited: true } : {}),
      },
    })),
  );
  return [
    // Runs first: it finds the alerts to edit by their missing score.
    db
      .prepare(
        `UPDATE deliveries SET sent_at = NULL, attempts = 0, next_attempt_at = 0, last_error = NULL
      WHERE sent_at IS NOT NULL AND message_id IS NOT NULL AND cve_id IN (
        SELECT c.id FROM cves c JOIN json_each(?) j ON c.id = json_extract(j.value, '$.id')
        WHERE json_extract(c.payload, '$.score') IS NULL)`,
      )
      .bind(rows),
    db
      .prepare(
        `UPDATE cves SET payload = json_patch(payload, json_extract(j.value, '$.patch')) FROM json_each(?) j
      WHERE cves.id = json_extract(j.value, '$.id') AND json_extract(cves.payload, '$.score') IS NULL`,
      )
      .bind(rows),
  ];
}

// Requested CVEs are resent even if already delivered, with a refreshed payload, as
// a new message. Commit these in the same batch that removes the request.
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
      ON CONFLICT(cve_id, channel) DO UPDATE SET attempts = 0, next_attempt_at = 0, sent_at = NULL, last_error = NULL,
        message_id = NULL`,
      )
      .bind(cve.id, JSON.stringify(channels)),
  ];
}
