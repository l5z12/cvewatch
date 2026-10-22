import { fetchPage } from './nvd';
import { pollDelta } from './cve-list';
import { pollRecent } from './cve-search';
import { enqueueStatements, scoreStatements } from './outbox';
import { edit, enabledChannels, send, validateSecrets } from './messages';
import { processRequests } from './requests';
import { type BotEnv, type Channel, type Cve, type Runtime, integer, runtime, safeError, ServiceError } from './types';

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;

interface PollState {
  not_before: number;
  watermark: number;
  window_start: number | null;
  window_end: number | null;
  page_index: number;
  next_poll_at: number;
}

export async function poll(env: BotEnv, rt: Runtime): Promise<void> {
  const now = rt.now();
  const lookback = integer(env.INITIAL_LOOKBACK_HOURS, 'INITIAL_LOOKBACK_HOURS', 0, 2160) * HOUR;
  const interval = integer(env.POLL_INTERVAL_MINUTES, 'POLL_INTERVAL_MINUTES', 1, 1440) * MINUTE;
  await env.DB.prepare('INSERT OR IGNORE INTO poll_state (id, not_before, watermark) VALUES (1, ?, ?)')
    .bind(now - lookback, now - lookback)
    .run();
  const state = await env.DB.prepare('SELECT * FROM poll_state WHERE id = 1').first<PollState>();
  if (!state || state.next_poll_at > now) return;
  // A fixed end makes pagination resumable. Overlap catches boundary/indexing delays.
  const start = state.window_start ?? Math.max(state.not_before, state.watermark - HOUR);
  const end = state.window_end ?? Math.min(now - 2 * MINUTE, state.watermark + 24 * HOUR);
  if (end <= start) return;
  await env.DB.prepare('UPDATE poll_state SET window_start = ?, window_end = ? WHERE id = 1').bind(start, end).run();
  const page = await fetchPage(start, end, state.page_index, env.NVD_API_KEY, rt);
  const cves = page.cves.filter((cve) => Date.parse(cve.published) >= state.not_before);
  const nextIndex = state.page_index + page.count;
  const complete = nextIndex >= page.total;
  // A transaction stores every alert before advancing the cursor. json_each keeps
  // query count bounded even when the source returns a full page.
  await env.DB.batch([
    ...enqueueStatements(env.DB, cves, now, enabledChannels(env)),
    // Modification windows also return CVEs that have just been scored.
    ...scoreStatements(env.DB, page.cves),
    complete
      ? env.DB.prepare(
          `UPDATE poll_state SET watermark = ?, window_start = NULL, window_end = NULL,
          page_index = 0, next_poll_at = ?, last_success_at = ?, last_error = NULL WHERE id = 1`,
        ).bind(end, end < now - 2 * MINUTE ? now + MINUTE : now + interval, now)
      : env.DB.prepare(
          `UPDATE poll_state SET page_index = ?, next_poll_at = ?, last_success_at = ?, last_error = NULL WHERE id = 1`,
        ).bind(nextIndex, now + MINUTE, now),
  ]);
  console.log(
    JSON.stringify({ event: 'nvd_page', records: page.count, eligible: cves.length, complete, nextIndex, start, end }),
  );
}

interface PendingDelivery {
  cve_id: string;
  payload: string;
  attempts: number;
  // Set when the alert was sent without a score and is queued again to add it.
  message_id: string | null;
  published_at: number;
  discovered_at: number;
}

export async function deliver(env: BotEnv, rt: Runtime, deadline: number): Promise<void> {
  const batch = integer(env.DELIVERY_BATCH_SIZE, 'DELIVERY_BATCH_SIZE', 1, 10);
  const channels = enabledChannels(env);
  // Interleave platforms so one slow destination cannot consume the whole run.
  const blocked = new Set<Channel>();
  for (let i = 0; i < batch; i++) {
    for (const channel of channels) {
      if (rt.now() >= deadline) return;
      if (blocked.has(channel)) continue;
      const state = await env.DB.prepare('SELECT next_send_at, stopped_at FROM channel_state WHERE channel = ?')
        .bind(channel)
        .first<{ next_send_at: number; stopped_at: number | null }>();
      // Checked before every message, so an emergency stop interrupts a run in progress.
      if (state && state.stopped_at !== null) {
        blocked.add(channel);
        continue;
      }
      const wait = Math.max(0, (state?.next_send_at ?? 0) - rt.now());
      if (wait > 1500 || rt.now() + wait >= deadline) {
        blocked.add(channel);
        continue;
      }
      if (wait > 0) await rt.sleep(wait);
      const row = await env.DB.prepare(
        `SELECT d.cve_id, d.attempts, d.message_id, c.payload, c.published_at, c.discovered_at FROM deliveries d
        JOIN cves c ON c.id = d.cve_id WHERE d.channel = ? AND d.sent_at IS NULL
        AND d.next_attempt_at <= ? ORDER BY c.published_at DESC, d.next_attempt_at, d.cve_id LIMIT 1`,
      )
        .bind(channel, rt.now())
        .first<PendingDelivery>();
      if (!row) {
        blocked.add(channel);
        continue;
      }
      let messageId = row.message_id;
      let edited = false;
      try {
        const cve = JSON.parse(row.payload) as Cve;
        if (messageId === null) messageId = await send(channel, cve, env, rt);
        else edited = await edit(channel, cve, messageId, env, rt);
      } catch (error) {
        const backoff = Math.min(6 * HOUR, MINUTE * 2 ** Math.min(row.attempts, 12));
        const retryAt = rt.now() + Math.max(backoff, error instanceof ServiceError ? error.retryAfterMs : MINUTE);
        await env.DB.batch([
          env.DB.prepare(
            `UPDATE deliveries SET attempts = attempts + 1, next_attempt_at = ?, last_error = ?
            WHERE cve_id = ? AND channel = ?`,
          ).bind(retryAt, safeError(error), row.cve_id, channel),
          env.DB.prepare('UPDATE channel_state SET next_send_at = ? WHERE channel = ?').bind(retryAt, channel),
        ]);
        console.error(
          JSON.stringify({ event: 'delivery_failed', channel, cve: row.cve_id, error: safeError(error), retryAt }),
        );
        blocked.add(channel);
        continue;
      }
      // Persist confirmation before trying another CVE. A crash between the API
      // accepting a message and this write can still cause an at-least-once retry.
      await env.DB.batch([
        env.DB.prepare(
          `UPDATE deliveries SET sent_at = ?, attempts = attempts + 1, last_error = NULL, message_id = ?
          WHERE cve_id = ? AND channel = ?`,
        ).bind(rt.now(), messageId, row.cve_id, channel),
        env.DB.prepare('UPDATE channel_state SET next_send_at = ? WHERE channel = ?').bind(rt.now() + 1100, channel),
      ]);
      console.log(
        JSON.stringify(
          row.message_id === null
            ? {
                event: 'delivered',
                channel,
                cve: row.cve_id,
                publicationToDiscoveryMs: row.discovered_at - row.published_at,
                publicationToDeliveryMs: rt.now() - row.published_at,
                queueDelayMs: rt.now() - row.discovered_at,
              }
            : // A skipped edit leaves the original alert unscored.
              { event: edited ? 'score_added' : 'score_edit_skipped', channel, cve: row.cve_id },
        ),
      );
    }
  }
}

async function withLease(env: BotEnv, rt: Runtime, task: () => Promise<void>): Promise<void> {
  validateSecrets(env);
  integer(env.INITIAL_LOOKBACK_HOURS, 'INITIAL_LOOKBACK_HOURS', 0, 2160);
  integer(env.POLL_INTERVAL_MINUTES, 'POLL_INTERVAL_MINUTES', 1, 1440);
  integer(env.DELIVERY_BATCH_SIZE, 'DELIVERY_BATCH_SIZE', 1, 10);
  const now = rt.now();
  const owner = crypto.randomUUID();
  // Longer than the platform's 15-minute scheduled invocation limit. Normal work
  // stops at 45 seconds; crashed invocations release their lease after 20 minutes.
  const lock = await env.DB.prepare(
    `INSERT INTO run_lock (id, owner, expires_at) VALUES (1, ?, ?)
    ON CONFLICT(id) DO UPDATE SET owner = excluded.owner, expires_at = excluded.expires_at
    WHERE run_lock.expires_at <= ? RETURNING owner`,
  )
    .bind(owner, now + 20 * MINUTE, now)
    .first();
  if (!lock) return;
  try {
    await task();
  } finally {
    await env.DB.prepare('DELETE FROM run_lock WHERE id = 1 AND owner = ?').bind(owner).run();
  }
}

export async function run(env: BotEnv, rt: Runtime = runtime): Promise<void> {
  const now = rt.now();
  await withLease(env, rt, async () => {
    try {
      await poll(env, rt);
    } catch (error) {
      const nextPoll = rt.now() + Math.max(5 * MINUTE, error instanceof ServiceError ? error.retryAfterMs : 0);
      await env.DB.prepare('UPDATE poll_state SET next_poll_at = ?, last_error = ? WHERE id = 1')
        .bind(nextPoll, safeError(error))
        .run();
      console.error(
        JSON.stringify({ event: 'poll_failed', error: safeError(error), nextPoll, elapsedMs: rt.now() - now }),
      );
    }
    await deliver(env, rt, now + 45_000);
  });
}

export async function runLive(env: BotEnv, rt: Runtime = runtime): Promise<void> {
  const now = rt.now();
  await withLease(env, rt, async () => {
    // The CVE List is the fastest source. CVE Search catches deltas it misses.
    try {
      await pollDelta(env, rt);
    } catch (error) {
      await env.DB.prepare('UPDATE delta_poll_state SET last_error = ? WHERE id = 1').bind(safeError(error)).run();
      console.error(JSON.stringify({ event: 'cve_list_failed', error: safeError(error), elapsedMs: rt.now() - now }));
    }
    try {
      await pollRecent(env, rt);
    } catch (error) {
      const failures =
        (await env.DB.prepare('SELECT failure_count FROM live_poll_state WHERE id = 1').first<number>(
          'failure_count',
        )) ?? 0;
      const backoff = Math.min(6 * HOUR, MINUTE * 2 ** Math.min(failures, 12));
      const nextPoll = rt.now() + Math.max(backoff, error instanceof ServiceError ? error.retryAfterMs : 0);
      await env.DB.prepare(
        `UPDATE live_poll_state SET next_poll_at = ?, last_error = ?,
        failure_count = failure_count + 1 WHERE id = 1`,
      )
        .bind(nextPoll, safeError(error))
        .run();
      console.error(
        JSON.stringify({
          event: 'cve_search_failed',
          error: safeError(error),
          nextPoll,
          failures: failures + 1,
          elapsedMs: rt.now() - now,
        }),
      );
    }
    try {
      await processRequests(env, rt);
    } catch (error) {
      console.error(JSON.stringify({ event: 'requests_failed', error: safeError(error), elapsedMs: rt.now() - now }));
    }
    await deliver(env, rt, now + 45_000);
  });
}
