import { enabledChannels, validateSecrets } from './messages';
import type { BotEnv, Channel } from './types';

type HealthStatus = 'pass' | 'warn' | 'fail';

interface HealthCheck {
  componentId: string;
  componentType: 'component' | 'datastore';
  status: HealthStatus;
  time: string;
  observedValue?: number;
  observedUnit?: string;
  output?: string;
}

interface PollState {
  last_success_at: number | null;
  last_error: string | null;
}

// A backstop source only fails once its data is stale; a single failed poll is a warning.
function pollCheck(
  componentId: string,
  state: PollState | null,
  maxAge: number,
  now: number,
  backstop = false,
): HealthCheck {
  const age = state?.last_success_at ? now - state.last_success_at : undefined;
  const fresh = age !== undefined && age < maxAge;
  const status = !fresh ? 'fail' : !state?.last_error ? 'pass' : backstop ? 'warn' : 'fail';
  return {
    componentId,
    componentType: 'component',
    status,
    time: new Date(now).toISOString(),
    observedValue: age,
    observedUnit: 'ms',
    output:
      status === 'pass'
        ? undefined
        : state?.last_error
          ? `The last poll failed: ${state.last_error}`
          : age === undefined
            ? 'No successful poll yet.'
            : 'The last successful poll is stale.',
  };
}

function response(
  status: HealthStatus,
  details: { checks?: Record<string, HealthCheck[]>; output?: string },
): Response {
  return Response.json(
    { status, serviceId: 'cvewatch', description: 'CVE publication notifications', ...details },
    {
      status: status === 'fail' ? 503 : 200,
      headers: { 'Content-Type': 'application/health+json', 'Cache-Control': 'no-store' },
    },
  );
}

// draft-inadarei-api-health-check-06. Inspect stored state without triggering polls or sends.
export async function health(env: BotEnv, channel?: Channel): Promise<Response> {
  try {
    validateSecrets(env);
    const enabled = enabledChannels(env);
    if (channel && !enabled.includes(channel)) {
      return response('fail', { output: `${channel} is not configured.` });
    }
    const channels = channel ? [channel] : enabled;
    const state = await env.DB.prepare(
      'SELECT last_success_at, last_error FROM poll_state WHERE id = 1',
    ).first<PollState>();
    const live = await env.DB.prepare(
      'SELECT last_success_at, last_error FROM live_poll_state WHERE id = 1',
    ).first<PollState>();
    const delta = await env.DB.prepare(
      'SELECT last_success_at, last_error FROM delta_poll_state WHERE id = 1',
    ).first<PollState>();
    const pending = await env.DB.prepare(
      `SELECT channel, COUNT(*) AS pending,
      SUM(CASE WHEN last_error IS NOT NULL THEN 1 ELSE 0 END) AS retrying
      FROM deliveries WHERE sent_at IS NULL
      AND channel IN (SELECT value FROM json_each(?)) GROUP BY channel`,
    )
      .bind(JSON.stringify(channels))
      .all<{ channel: Channel; pending: number; retrying: number }>();
    const now = Date.now();
    const time = new Date(now).toISOString();
    const checks: Record<string, HealthCheck[]> = {
      database: [{ componentId: 'DB', componentType: 'datastore', status: 'pass', time }],
      nvd: [pollCheck('nvd', state, Math.max(30, Number(env.POLL_INTERVAL_MINUTES) * 3) * 60_000, now, true)],
      'cve-list': [pollCheck('cve-list', delta, Math.max(120, Number(env.LIVE_POLL_SECONDS) * 3) * 1000, now)],
      'cve-search': [pollCheck('cve-search', live, Math.max(120, Number(env.LIVE_POLL_SECONDS) * 3) * 1000, now)],
    };
    for (const channel of channels) {
      const queue = pending.results.find((row) => row.channel === channel);
      const retrying = queue?.retrying ?? 0;
      checks[channel] = [
        {
          componentId: channel,
          componentType: 'component',
          status: retrying === 0 ? 'pass' : 'fail',
          time,
          observedValue: queue?.pending ?? 0,
          observedUnit: 'messages',
          output: retrying > 0 ? `${retrying} pending deliveries are awaiting retry.` : undefined,
        },
      ];
    }
    const statuses = Object.values(checks).flatMap((entries) => entries.map((check) => check.status));
    const status = statuses.includes('fail') ? 'fail' : statuses.includes('warn') ? 'warn' : 'pass';
    return response(status, { checks });
  } catch {
    // Do not expose database exceptions or credentials in a public response.
    return response('fail', { output: 'Configuration or storage is unavailable.' });
  }
}
