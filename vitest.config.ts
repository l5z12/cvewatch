import { cloudflareTest, readD1Migrations } from '@cloudflare/vitest-plugin';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  plugins: [
    cloudflareTest(async () => ({
      experimental: { newConfig: { configPath: './cloudflare.config.ts' } },
      miniflare: {
        // The pinned local workerd runtime supports dates through October 19.
        compatibilityDate: '2026-10-19',
        // Vitest renames the Worker; bind its own class instead of the production service name.
        durableObjects: { MONITOR: { className: 'PublicationMonitor', useSQLite: true } },
        bindings: {
          TEST_MIGRATIONS: await readD1Migrations('./migrations'),
          TELEGRAM_BOT_TOKEN: '123456789:test-token',
          TELEGRAM_CHAT_ID: '@test_channel',
          DISCORD_WEBHOOK_URL: 'https://discord.com/api/webhooks/123456789/test-token',
          NVD_API_KEY: '',
        },
      },
    })),
  ],
  test: { include: ['test/**/*.test.ts'] },
});
