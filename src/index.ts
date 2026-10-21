import { run } from './bot';
import { health } from './health';
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
    if (request.method === 'GET') {
      switch (new URL(request.url).pathname) {
        case '/health':
          return health(env);
        case '/health/telegram':
          return health(env, 'telegram');
        case '/health/discord':
          return health(env, 'discord');
      }
    }
    return new Response('Not found', { status: 404 });
  },
} satisfies ExportedHandler<BotEnv>;
