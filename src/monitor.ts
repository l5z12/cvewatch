import { DurableObject } from 'cloudflare:workers';
import { runLive } from './bot';
import { type BotEnv, integer, safeError } from './types';

// One monitor coordinates this deployment's Telegram/Discord destination pair.
export class PublicationMonitor extends DurableObject<BotEnv> {
  async ensureStarted(): Promise<void> {
    if ((await this.ctx.storage.getAlarm()) === null) {
      await this.ctx.storage.setAlarm(Date.now() + 1);
    }
  }

  async alarm(): Promise<void> {
    const interval = integer(this.env.LIVE_POLL_SECONDS, 'LIVE_POLL_SECONDS', 15, 3600) * 1000;
    const next = Date.now() + interval;
    // Arm before external I/O, so a crash cannot silently stop the monitor.
    await this.ctx.storage.setAlarm(next);
    try {
      await runLive(this.env);
    } catch (error) {
      console.error(JSON.stringify({ event: 'live_run_failed', error: safeError(error) }));
    } finally {
      await this.ctx.storage.setAlarm(Math.max(next, Date.now() + 1000));
    }
  }
}
