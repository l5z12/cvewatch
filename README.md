<img src="public/icon.svg" width="64" height="64" alt="Globe Shield icon">

# CVE Watch

Sends newly published CVEs to Telegram, Discord, or both.

Checks the CVE List's GitHub delta and CVE Search every **15 seconds**, with NVD recovery every **5 minutes**. New CVEs usually arrive within minutes of publication. Includes unscored CVEs, deduplicates IDs, and retries failed deliveries. Upstream indexing and rate limits can delay alerts; exact publication-time delivery is not guaranteed. A crash after sending can occasionally cause a duplicate.

## Deploy with GitHub Actions

Uses the [Cloudflare CLI](https://developers.cloudflare.com/cf/) (`cf`) and Vite. Requires pnpm and a Cloudflare account; pnpm installs the pinned Node.js 24.22 runtime.

1. Choose your destinations: for Telegram, create a bot with [BotFather](https://t.me/BotFather), give it permission to post, and note the channel username or numeric ID. For Discord, create a webhook under **Channel Settings > Integrations**.
2. Install and create the database:

   ```sh
   pnpm install --frozen-lockfile
   pnpm exec cf login
   pnpm exec cf d1 create --name cvewatch-db
   ```

3. Configure GitHub Actions (repository or `production` environment):
   - Deploy secrets: `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID`. The token needs **Workers Scripts: Edit** and **D1: Edit**.
   - Destination secrets: `TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID`, `DISCORD_WEBHOOK_URL`, or both. Configure at least one destination.
   - Variable: `D1_DATABASE_ID`, using the returned database ID.
   - Optional secret: `NVD_API_KEY`.
4. Push or merge to `main`. CI checks the code, applies migrations, and deploys with the Worker secrets. Polling starts after cron propagation.

Omit or leave unused destination secrets empty. Disabling a destination pauses its existing queue and stops adding new deliveries for it; queued alerts resume if you re-enable it.

Discord alerts use the project icon hosted at `/icon.png`. For Telegram, upload [public/icon.png](public/icon.png) as the bot's profile picture through [BotFather](https://t.me/BotFather). Icon attribution and its MIT license are included in [NOTICE](NOTICE).

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

Open `/health` for a status page. Use `/api/health/` for overall status, or `/api/health/telegram/` and `/api/health/discord/` for each destination. HTTP 200 means healthy, with status `warn` if the last NVD recovery poll failed but NVD data is still fresh; HTTP 503 means unavailable or degraded. Check Cloudflare Worker logs for details.

## Send an existing CVE

Run the **Send CVE** workflow from the Actions tab and enter a CVE ID. It uses the deploy secrets and variable, waits for the Worker, and fails if the CVE cannot be sent. From a terminal signed in with `cf login`:

```sh
D1_DATABASE_ID=<database-id> pnpm send CVE-2024-3094
```

The Worker picks up the request within about 15 seconds and sends the CVE List record, using NVD scores when the record has none. The CVE is sent to every enabled destination, even if it was alerted before, and queues behind newer pending alerts. Its message starts with the ID instead of "New CVE". The request is stored in the production database, so this does not work with the local dev server.

This product uses data from the NVD API but is not endorsed or certified by the NVD.

## License

[Apache-2.0](LICENSE). See [NOTICE](NOTICE) for attribution. CVE data remains subject to the [CVE Terms of Use](https://www.cve.org/Legal/TermsOfUse).
