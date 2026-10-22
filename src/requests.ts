import { fetchRecord } from './cve-list';
import { parseCveRecord } from './cve-search';
import { fetchCve } from './nvd';
import { resendStatements } from './outbox';
import { enabledChannels } from './messages';
import { type BotEnv, type Cve, type Runtime, safeError, ServiceError } from './types';

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
// Bounds subrequests per run: each request fetches the CVE List and possibly NVD.
const MAX_REQUESTS = 5;

interface SendRequest {
  cve_id: string;
  attempts: number;
}

// Returns the reason when the CVE can never be sent, so it is not retried.
async function resolve(id: string, env: BotEnv, rt: Runtime): Promise<Cve | string> {
  const body = await fetchRecord(id, env, rt);
  if (body === null) return 'Not found in the CVE List';
  const cve = parseCveRecord(body);
  if (!cve) return 'Not a published CVE';
  if (cve.id !== id) throw new ServiceError('Invalid CVE Program record');
  if (cve.score !== null) return cve;
  // Older records often lack CNA metrics that NVD has since scored.
  try {
    const nvd = await fetchCve(id, env.NVD_API_KEY, rt);
    if (nvd && nvd.score !== null) {
      return { ...nvd, ...(cve.title ? { title: cve.title } : {}), exploited: nvd.exploited || cve.exploited };
    }
  } catch (error) {
    console.error(JSON.stringify({ event: 'request_nvd_failed', cve: id, error: safeError(error) }));
  }
  return cve;
}

// The send-cve script inserts requests; this queues each for every enabled destination.
export async function processRequests(env: BotEnv, rt: Runtime): Promise<void> {
  const requests = await env.DB.prepare(
    `SELECT cve_id, attempts FROM send_requests WHERE failed_at IS NULL AND next_attempt_at <= ?
    ORDER BY requested_at, cve_id LIMIT ?`,
  )
    .bind(rt.now(), MAX_REQUESTS)
    .all<SendRequest>();
  await Promise.all(
    requests.results.map(async ({ cve_id: id, attempts }) => {
      let result: Cve | string;
      try {
        result = /^CVE-\d{4}-\d{4,}$/.test(id) ? await resolve(id, env, rt) : 'Invalid CVE ID';
      } catch (error) {
        const backoff = Math.min(6 * HOUR, MINUTE * 2 ** Math.min(attempts, 12));
        const retryAt = rt.now() + Math.max(backoff, error instanceof ServiceError ? error.retryAfterMs : MINUTE);
        await env.DB.prepare(
          'UPDATE send_requests SET attempts = attempts + 1, next_attempt_at = ?, last_error = ? WHERE cve_id = ?',
        )
          .bind(retryAt, safeError(error), id)
          .run();
        console.error(JSON.stringify({ event: 'request_failed', cve: id, error: safeError(error), retryAt }));
        return;
      }
      if (typeof result === 'string') {
        await env.DB.prepare(
          'UPDATE send_requests SET attempts = attempts + 1, failed_at = ?, last_error = ? WHERE cve_id = ?',
        )
          .bind(rt.now(), result, id)
          .run();
        console.error(JSON.stringify({ event: 'request_rejected', cve: id, reason: result }));
        return;
      }
      await env.DB.batch([
        ...resendStatements(env.DB, { ...result, requested: true }, rt.now(), enabledChannels(env)),
        env.DB.prepare('DELETE FROM send_requests WHERE cve_id = ?').bind(id),
      ]);
      console.log(JSON.stringify({ event: 'request_queued', cve: id, source: result.source }));
    }),
  );
}
