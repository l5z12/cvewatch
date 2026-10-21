import { writeFileSync } from 'node:fs';

const output = process.argv[2];
if (!output) {
  console.error('Usage: node scripts/prepare-deploy-secrets.mjs <output-file>');
  process.exit(1);
}

const required = ['TELEGRAM_BOT_TOKEN', 'TELEGRAM_CHAT_ID', 'DISCORD_WEBHOOK_URL'];
const secrets = Object.fromEntries([...required, 'NVD_API_KEY'].map((name) => [name, process.env[name]?.trim() || '']));
const missing = required.filter((name) => !secrets[name]);
if (missing.length) {
  console.error(`Missing required Worker secrets: ${missing.join(', ')}`);
  process.exit(1);
}

// Keep optional bindings present. JSON preserves special characters without shell expansion.
writeFileSync(output, JSON.stringify(secrets), { mode: 0o600, flag: 'wx' });
