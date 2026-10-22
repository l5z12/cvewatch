import { serviceRequest } from './request';
import {
  type BotEnv,
  type KevDetails,
  type Runtime,
  integer,
  readJson,
  record,
  retryAfter,
  ServiceError,
} from './types';

// The cisagov/kev-data mirror on GitHub is updated hours after this feed.
export const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const MINUTE = 60_000;
const DAY = 24 * 60 * MINUTE;

interface KevEntry {
  id: string;
  kev: KevDetails;
}

function date(value: unknown): value is string {
  return typeof value === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(value) && Number.isFinite(Date.parse(value));
}

// Rejects an empty or incomplete catalog. Stored as the baseline, it would make every
// entry it lacks look like an addition later.
export function parseCatalog(body: unknown): KevEntry[] {
  if (
    !record(body) ||
    !Array.isArray(body.vulnerabilities) ||
    body.vulnerabilities.length === 0 ||
    body.count !== body.vulnerabilities.length
  ) {
    throw new ServiceError('Invalid CISA KEV catalog');
  }
  return body.vulnerabilities.map((entry: unknown) => {
    if (
      !record(entry) ||
      typeof entry.cveID !== 'string' ||
      !/^CVE-\d{4}-\d{4,}$/.test(entry.cveID) ||
      !date(entry.dateAdded)
    ) {
      throw new ServiceError('Invalid CISA KEV entry');
    }
    return {
      id: entry.cveID,
      kev: {
        added: entry.dateAdded,
        due: date(entry.dueDate) ? entry.dueDate : null,
        ransomware: entry.knownRansomwareCampaignUse === 'Known',
      },
    };
  });
}

// Returns null if the catalog has not changed. The feed answers If-Modified-Since with
// 304 but ignores its ETag, so polls download nothing until CISA updates it.
export async function fetchCatalog(
  since: string | null,
  env: BotEnv,
  rt: Runtime,
): Promise<{ entries: KevEntry[]; lastModified: string | null } | null> {
  const result = await serviceRequest(
    'CISA KEV',
    KEV_URL,
    {
      headers: {
        Accept: 'application/json',
        'User-Agent': env.SOURCE_USER_AGENT,
        ...(since ? { 'If-Modified-Since': since } : {}),
      },
    },
    rt,
    30_000,
    async (response) => {
      if (response.status === 304) {
        await response.body?.cancel();
        return null;
      }
      if (!response.ok) {
        const delay = retryAfter(response, null, rt.now());
        await response.body?.cancel();
        throw new ServiceError(`CISA KEV HTTP ${response.status}`, delay);
      }
      return { body: await readJson(response, 16 * 1024 * 1024), lastModified: response.headers.get('last-modified') };
    },
  );
  return result && { entries: parseCatalog(result.body), lastModified: result.lastModified };
}

interface KevState {
  last_modified: string | null;
  next_poll_at: number;
}

// Queues every CVE the catalog has not listed before as a send request. The first
// catalog is the baseline: of its entries, only those added within the initial
// lookback are alerted.
export async function pollKev(env: BotEnv, rt: Runtime): Promise<void> {
  const now = rt.now();
  const lookback = integer(env.INITIAL_LOOKBACK_HOURS, 'INITIAL_LOOKBACK_HOURS', 0, 2160) * 60 * MINUTE;
  await env.DB.prepare('INSERT OR IGNORE INTO kev_poll_state (id) VALUES (1)').run();
  const state = await env.DB.prepare(
    'SELECT last_modified, next_poll_at FROM kev_poll_state WHERE id = 1',
  ).first<KevState>();
  if (!state || state.next_poll_at > now) return;
  const catalog = await fetchCatalog(state.last_modified, env, rt);
  if (!catalog) {
    await env.DB.prepare(
      'UPDATE kev_poll_state SET next_poll_at = ?, last_success_at = ?, last_error = NULL WHERE id = 1',
    )
      .bind(now + MINUTE, rt.now())
      .run();
    return;
  }
  const baseline = !(await env.DB.prepare('SELECT EXISTS (SELECT 1 FROM kev_catalog) AS known').first('known'));
  const unseen = await env.DB.prepare(
    'SELECT value FROM json_each(?) WHERE value NOT IN (SELECT cve_id FROM kev_catalog)',
  )
    .bind(JSON.stringify(catalog.entries.map((entry) => entry.id)))
    .all<{ value: string }>();
  const ids = new Set(unseen.results.map(({ value }) => value));
  // The catalog only records the day of each addition, so the lookback covers whole days.
  const added = catalog.entries.filter(
    ({ id, kev }) => ids.has(id) && (!baseline || (lookback > 0 && Date.parse(kev.added) + DAY > now - lookback)),
  );
  await env.DB.batch([
    env.DB.prepare('INSERT OR IGNORE INTO kev_catalog (cve_id) SELECT value FROM json_each(?)').bind(
      JSON.stringify([...ids]),
    ),
    // Like the send-cve script, this clears an earlier failure to send the CVE.
    env.DB.prepare(
      `INSERT INTO send_requests (cve_id, requested_at, kev)
      SELECT json_extract(value, '$.id'), ?, json_extract(value, '$.kev') FROM json_each(?) WHERE true
      ON CONFLICT(cve_id) DO UPDATE SET kev = excluded.kev, attempts = 0, next_attempt_at = 0,
        failed_at = NULL, last_error = NULL`,
    ).bind(now, JSON.stringify(added)),
    env.DB.prepare(
      'UPDATE kev_poll_state SET last_modified = ?, next_poll_at = ?, last_success_at = ?, last_error = NULL WHERE id = 1',
    ).bind(catalog.lastModified, now + MINUTE, rt.now()),
  ]);
  console.log(JSON.stringify({ event: 'kev_catalog', entries: catalog.entries.length, added: added.length, baseline }));
}
