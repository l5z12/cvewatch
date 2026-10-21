import { run } from './bot';
import { validateSecrets } from './messages';
import { type BotEnv, safeError } from './types';
export { PublicationMonitor } from './monitor';

export default {
  async scheduled(_controller, env): Promise<void> {
    try {
      // Cron repairs a missing alarm and performs the independent NVD recovery scan.
      await env.MONITOR.getByName('publications').ensureStarted();
      await run(env);
    } catch (error) {
      console.error(JSON.stringify({ event: 'run_failed', error: safeError(error) }));
      throw new Error(safeError(error));
    }
  },
  async fetch(request, env): Promise<Response> {
    if (request.method !== 'GET' || new URL(request.url).pathname !== '/health') {
      return new Response('Not found', { status: 404 });
    }
    try {
      validateSecrets(env);
      const state = await env.DB.prepare(`SELECT last_success_at, last_error FROM poll_state WHERE id = 1`).first<{
        last_success_at: number | null;
        last_error: string | null;
      }>();
      const live = await env.DB.prepare('SELECT last_success_at, last_error FROM live_poll_state WHERE id = 1').first<{
        last_success_at: number | null;
        last_error: string | null;
      }>();
      const pending = await env.DB.prepare(
        `SELECT channel, COUNT(*) AS pending,
        SUM(CASE WHEN last_error IS NOT NULL THEN 1 ELSE 0 END) AS retrying
        FROM deliveries WHERE sent_at IS NULL GROUP BY channel`,
      ).all<{ channel: string; pending: number; retrying: number }>();
      const healthy =
        !!state?.last_success_at &&
        !state.last_error &&
        Date.now() - state.last_success_at < Math.max(30, Number(env.POLL_INTERVAL_MINUTES) * 3) * 60_000 &&
        !!live?.last_success_at &&
        !live.last_error &&
        Date.now() - live.last_success_at < Math.max(120, Number(env.LIVE_POLL_SECONDS) * 3) * 1000 &&
        pending.results.every((channel) => channel.retrying === 0);
      return Response.json(
        {
          service: 'cvewatch',
          status: healthy ? 'ok' : 'starting_or_degraded',
          lastPoll: state?.last_success_at ? new Date(state.last_success_at).toISOString() : null,
          liveSource: 'CVE Program Search API (beta)',
          livePollSeconds: Number(env.LIVE_POLL_SECONDS),
          lastLivePoll: live?.last_success_at ? new Date(live.last_success_at).toISOString() : null,
          pending: pending.results,
        },
        { status: healthy ? 200 : 503, headers: { 'Cache-Control': 'no-store' } },
      );
    } catch {
      return Response.json({ service: 'cvewatch', status: 'unconfigured_or_unavailable' }, { status: 503 });
    }
  },
} satisfies ExportedHandler<BotEnv>;
