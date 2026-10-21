import { execFileSync } from 'node:child_process';
import { setTimeout as sleep } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';

const id = process.argv[2]?.trim().toUpperCase();
const database = process.env.D1_DATABASE_ID?.trim();
if (!id || process.argv.length > 3) {
  console.error('Usage: node scripts/send-cve.mjs <CVE-ID>');
  process.exit(1);
}
if (!/^CVE-\d{4}-\d{4,}$/.test(id)) {
  console.error(`Not a CVE ID: ${id}`);
  process.exit(1);
}
if (!database) {
  console.error('Set D1_DATABASE_ID to the production database ID.');
  process.exit(1);
}

// Run the pinned CLI without a shell. Parameters keep the ID out of the SQL text.
const cli = fileURLToPath(new URL('../node_modules/cf/bin/cf', import.meta.url));
function query(sql, ...params) {
  const output = execFileSync(process.execPath, [cli, 'd1', 'query', database, '--sql', sql, '--params', ...params], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'inherit'],
  });
  // The CLI prints the API result; accept it with or without the response envelope.
  const value = output.trim() ? JSON.parse(output) : [];
  const results = Array.isArray(value) ? value : value.result;
  return results?.at(-1)?.results ?? [];
}

// Requesting a CVE again clears an earlier failure.
query(
  `INSERT INTO send_requests (cve_id, requested_at) VALUES (?1, unixepoch() * 1000)
  ON CONFLICT(cve_id) DO UPDATE SET requested_at = excluded.requested_at,
  attempts = 0, next_attempt_at = 0, failed_at = NULL, last_error = NULL`,
  id,
);
console.log(`Requested ${id}. Waiting for the Worker, which checks every 15 seconds...`);

// The live monitor deletes a request once the CVE is queued for delivery.
let lastError = null;
for (let attempt = 0; attempt < 24; attempt++) {
  await sleep(5000);
  const [row] = query('SELECT failed_at, last_error FROM send_requests WHERE cve_id = ?1', id);
  if (!row) {
    console.log(`Queued ${id} for delivery.`);
    process.exit(0);
  }
  if (row.failed_at !== null) {
    console.error(`Could not send ${id}: ${row.last_error}.`);
    process.exit(1);
  }
  lastError = row.last_error;
}
console.error(`${id} is still pending${lastError ? ` (last error: ${lastError})` : ''}. The Worker keeps retrying it.`);
process.exit(1);
