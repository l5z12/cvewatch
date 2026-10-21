import { bindings, defineConfig, exports, triggers } from 'cf/config';

// Keep this ID in sync with db:migrate:local. Production uses D1_DATABASE_ID.
const LOCAL_D1_ID = '00000000-0000-4000-8000-00000000d1d1';
const WORKER = 'cvewatch';

export default defineConfig(({ mode }) => ({
  worker: {
    name: WORKER,
    entrypoint: './src/index.ts',
    compatibilityDate: '2026-10-19',
    compatibilityFlags: ['nodejs_compat'],
    workersDev: true,
    domains: ['cvewatch.l5z12.dev'],
    assets: { runWorkerFirst: ['/api/*'] },
    exports: {
      PublicationMonitor: exports.durableObject({ storage: 'sqlite' }),
    },
    triggers: [triggers.scheduled({ schedule: '* * * * *' })],
    env: {
      DB: bindings.d1({
        name: 'cvewatch-db',
        id: mode === 'development' ? LOCAL_D1_ID : process.env.D1_DATABASE_ID,
      }),
      MONITOR: bindings.durableObject({ worker: WORKER, exportName: 'PublicationMonitor' }),
      INITIAL_LOOKBACK_HOURS: bindings.text('24'),
      POLL_INTERVAL_MINUTES: bindings.text('5'),
      LIVE_POLL_SECONDS: bindings.text('15'),
      SOURCE_USER_AGENT: bindings.text('cvewatch/1.0 (https://github.com/l5z12/cvewatch)'),
      DELIVERY_BATCH_SIZE: bindings.text('4'),
      // CI supplies empty secrets for disabled destinations.
      TELEGRAM_BOT_TOKEN: bindings.secret(),
      TELEGRAM_CHAT_ID: bindings.secret(),
      DISCORD_WEBHOOK_URL: bindings.secret(),
      NVD_API_KEY: bindings.secret(),
    },
    observability: {
      enabled: true,
      logs: { enabled: true, headSamplingRate: 1 },
      // Messaging URLs contain credentials, so do not sample outbound traces.
      traces: { enabled: true, headSamplingRate: 0 },
    },
  },
}));
