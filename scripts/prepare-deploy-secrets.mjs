import { writeFileSync } from 'node:fs';

const output = process.argv[2];
if (!output) {
  console.error('Usage: node scripts/prepare-deploy-secrets.mjs <output-file>');
  process.exit(1);
}

const names = ['TELEGRAM_BOT_TOKEN', 'TELEGRAM_CHAT_ID', 'DISCORD_WEBHOOK_URL', 'NVD_API_KEY'];
const secrets = Object.fromEntries(names.map((name) => [name, process.env[name]?.trim() || '']));
if (Boolean(secrets.TELEGRAM_BOT_TOKEN) !== Boolean(secrets.TELEGRAM_CHAT_ID)) {
  console.error('Set both TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID, or leave both empty.');
  process.exit(1);
}
if (!secrets.TELEGRAM_BOT_TOKEN && !secrets.DISCORD_WEBHOOK_URL) {
  console.error('Configure Telegram or Discord before deploying.');
  process.exit(1);
}

// Keep optional bindings present. JSON preserves special characters without shell expansion.
writeFileSync(output, JSON.stringify(secrets), { mode: 0o600, flag: 'wx' });
