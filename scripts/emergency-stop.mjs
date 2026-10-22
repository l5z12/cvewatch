import { appendFileSync } from 'node:fs';
import { setTimeout as sleep } from 'node:timers/promises';

// Stops or resumes alerts through the D1 API. The Worker checks before every message,
// so a stop takes effect within seconds. Uses only built-in modules, so CI can run it
// without installing dependencies.
const [action, destination = 'all'] = process.argv.slice(2);
const values = { stop: 'COALESCE(stopped_at, unixepoch() * 1000)', resume: 'NULL' };
const channels = { all: ['telegram', 'discord'], telegram: ['telegram'], discord: ['discord'] };
if (!Object.hasOwn(values, action) || !Object.hasOwn(channels, destination) || process.argv.length > 4) {
  console.error('Usage: node scripts/emergency-stop.mjs <stop|resume> [all|telegram|discord]');
  process.exit(1);
}

function required(name) {
  const value = process.env[name]?.trim();
  if (value) return value;
  console.error(`Set ${name}.`);
  process.exit(1);
}
const token = required('CLOUDFLARE_API_TOKEN');
const url = `https://api.cloudflare.com/client/v4/accounts/${required('CLOUDFLARE_ACCOUNT_ID')}/d1/database/${required('D1_DATABASE_ID')}/query`;

// Both queries are idempotent, so retrying after a lost response is safe.
async function query(sql, params = []) {
  for (let attempt = 1; ; attempt++) {
    let response;
    let body;
    try {
      response = await fetch(url, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ sql, params }),
        signal: AbortSignal.timeout(30_000),
      });
      body = await response.json().catch(() => null);
    } catch (error) {
      if (attempt === 3) throw new Error(error.name === 'TimeoutError' ? 'Request timed out' : 'Request failed');
      await sleep(2000 * attempt);
      continue;
    }
    const [result] = body?.result ?? [];
    if (response.ok && body?.success && result?.success) return result.results;
    // Cloudflare error messages do not include credentials.
    const errors = (body?.errors ?? []).map((error) => error.message).join('; ');
    if (attempt === 3 || (response.status < 500 && response.status !== 429)) {
      throw new Error(`HTTP ${response.status}${errors ? `: ${errors}` : ''}`);
    }
    await sleep(2000 * attempt);
  }
}

try {
  await query(
    `UPDATE channel_state SET stopped_at = ${values[action]} WHERE channel IN (SELECT value FROM json_each(?1))`,
    [JSON.stringify(channels[destination])],
  );
  const rows = await query(
    `SELECT channel, stopped_at, (SELECT COUNT(*) FROM deliveries d WHERE d.channel = c.channel AND d.sent_at IS NULL)
    AS queued FROM channel_state c ORDER BY channel`,
  );
  const state = (row) =>
    row.stopped_at === null ? 'Sending' : `Stopped since ${new Date(row.stopped_at).toISOString()}`;
  const table = [
    `### Alerts: ${action} ${destination}`,
    '',
    '| Destination | State | Queued alerts |',
    '| --- | --- | --- |',
    ...rows.map((row) => `| ${row.channel} | ${state(row)} | ${row.queued} |`),
  ].join('\n');
  console.log(table);
  if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${table}\n`);
} catch (error) {
  console.error(`Could not ${action} alerts: ${error.message}`);
  process.exit(1);
}
