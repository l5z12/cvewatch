# CVE Watch

Sends newly published CVEs to Telegram and Discord.

Checks CVE Search every **15 seconds**, with NVD recovery every **5 minutes**. Includes unscored CVEs, deduplicates IDs, and retries failed deliveries. Upstream indexing and rate limits can delay alerts; exact publication-time delivery is not guaranteed. A crash after sending can occasionally cause a duplicate.

## Deploy with GitHub Actions

Uses the [Cloudflare CLI](https://developers.cloudflare.com/cf/) (`cf`) and Vite. Requires pnpm and a Cloudflare account; pnpm installs the pinned Node.js 24.22 runtime.

1. Create a Telegram bot with [BotFather](https://t.me/BotFather), give it permission to post in your channel, and note the channel username or numeric ID. Create a Discord webhook under **Channel Settings > Integrations**.
2. Install and create the database:

   ```sh
   pnpm install --frozen-lockfile
   pnpm exec cf login
   pnpm exec cf d1 create --name cvewatch-db
   ```

3. Configure GitHub Actions (repository or `production` environment):
   - Secrets: `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID`, `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`, `DISCORD_WEBHOOK_URL`. The deploy token needs **Workers Scripts: Edit** and **D1: Edit**.
   - Variable: `D1_DATABASE_ID`, using the returned database ID.
   - Optional secret: `NVD_API_KEY`.
4. Push or merge to `main`. CI checks the code, applies migrations, and deploys with the Worker secrets. Both destinations are required. Polling starts after cron propagation.

## Settings

Config is in `cloudflare.config.ts`:

| Variable                 | Default | Purpose                                                             |
| ------------------------ | ------- | ------------------------------------------------------------------- |
| `LIVE_POLL_SECONDS`      | `15`    | Recent-publication polling interval                                 |
| `POLL_INTERVAL_MINUTES`  | `5`     | NVD recovery interval                                               |
| `INITIAL_LOOKBACK_HOURS` | `24`    | Startup history; set `0` before first run for new publications only |
| `DELIVERY_BATCH_SIZE`    | `4`     | Messages per channel per run                                        |

## Development

Run `pnpm hooks:install` once per clone to enable [prek](https://prek.j178.dev/) commit hooks. `pnpm hooks:check` checks all tracked files; CI also runs the file checks.

Use `pnpm format` to format files with Prettier or `pnpm format:check` to check them. The commit hook formats staged files; `pnpm check` verifies formatting in CI.

Copy `.dev.vars.example` to `.dev.vars` and add test-channel credentials.

```sh
pnpm db:migrate:local
pnpm dev
```

Trigger the first run from another terminal:

```sh
curl "http://localhost:8787/cdn-cgi/local/scheduled?cron=*+*+*+*+*"
```

This starts recurring alarms and sends real messages. Local NVD recovery needs repeated calls. Stop the dev server to stop activity. `pnpm check` uses mocked messaging APIs.

## Monitoring

Use Cloudflare's Worker logs dashboard or `GET /health` for source freshness and delivery status. Delivery logs include publication-to-send latency. HTTP 503 indicates startup, missing configuration, or degraded operation.

This product uses data from the NVD API but is not endorsed or certified by the NVD.

## License

[Apache-2.0](LICENSE). See [NOTICE](NOTICE) for attribution. CVE data remains subject to the [CVE Terms of Use](https://www.cve.org/Legal/TermsOfUse).
