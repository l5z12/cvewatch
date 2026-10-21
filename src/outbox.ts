import type { Cve } from './types';

// These two statements must be committed in the same batch as a source cursor.
export function enqueueStatements(db: D1Database, cves: Cve[], discoveredAt: number): D1PreparedStatement[] {
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
      SELECT json_extract(j.value, '$.id'), s.channel FROM json_each(?) j CROSS JOIN channel_state s`,
      )
      .bind(rows),
  ];
}
