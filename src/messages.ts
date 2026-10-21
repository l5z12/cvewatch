import { type BotEnv, type Channel, type Cve, type Runtime, record, readJson, retryAfter, ServiceError } from './types';

function clip(text: string, length: number): string {
  const chars = Array.from(text);
  return chars.length > length ? `${chars.slice(0, length - 1).join('')}…` : text;
}

export function message(cve: Cve): string {
  const score =
    cve.score === null
      ? 'not scored yet'
      : `${cve.score.toFixed(1)}/10${cve.cvssVersion ? ` (CVSS ${cve.cvssVersion})` : ''}`;
  return [
    `New CVE: ${cve.id}`,
    `${cve.severity} · ${score}`,
    `Published: ${cve.published.replace('T', ' ').replace('.000Z', ' UTC').replace('Z', ' UTC')}`,
    `Source: ${cve.source ?? 'NVD'}`,
    ...(cve.exploited ? ['Known exploited vulnerability (CISA KEV)'] : []),
    '',
    clip(cve.description, 1200),
    '',
    `https://www.cve.org/CVERecord?id=${cve.id}`,
    `https://nvd.nist.gov/vuln/detail/${cve.id}`,
  ].join('\n');
}

export function enabledChannels(env: BotEnv): Channel[] {
  const channels: Channel[] = [];
  if (env.TELEGRAM_BOT_TOKEN?.trim() && env.TELEGRAM_CHAT_ID?.trim()) channels.push('telegram');
  if (env.DISCORD_WEBHOOK_URL?.trim()) channels.push('discord');
  return channels;
}

export function validateSecrets(env: BotEnv): void {
  if (env.TELEGRAM_BOT_TOKEN?.trim() || env.TELEGRAM_CHAT_ID?.trim()) {
    if (!env.TELEGRAM_BOT_TOKEN || !/^\d+:[\w-]+$/.test(env.TELEGRAM_BOT_TOKEN)) {
      throw new ServiceError('Configure TELEGRAM_BOT_TOKEN');
    }
    if (!env.TELEGRAM_CHAT_ID || !/^(?:-?\d+|@[a-zA-Z0-9_]+)$/.test(env.TELEGRAM_CHAT_ID)) {
      throw new ServiceError('Configure TELEGRAM_CHAT_ID');
    }
  }
  const channels = enabledChannels(env);
  if (channels.length === 0) throw new ServiceError('Configure Telegram or Discord');
  if (!channels.includes('discord')) return;
  let url: URL;
  try {
    url = new URL(env.DISCORD_WEBHOOK_URL ?? '');
  } catch {
    throw new ServiceError('Configure DISCORD_WEBHOOK_URL');
  }
  if (
    url.protocol !== 'https:' ||
    !['discord.com', 'discordapp.com'].includes(url.hostname) ||
    url.username ||
    url.password ||
    url.port ||
    url.hash ||
    !/^\/api(?:\/v\d+)?\/webhooks\/\d+\/[\w-]+$/.test(url.pathname)
  ) {
    throw new ServiceError('Configure a valid Discord webhook URL');
  }
}

export async function send(channel: Channel, cve: Cve, env: BotEnv, rt: Runtime): Promise<void> {
  const text = message(cve);
  const url =
    channel === 'telegram'
      ? new URL(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/sendMessage`)
      : new URL(env.DISCORD_WEBHOOK_URL!);
  if (channel === 'discord') url.searchParams.set('wait', 'true');
  const payload =
    channel === 'telegram'
      ? { chat_id: env.TELEGRAM_CHAT_ID, text, link_preview_options: { is_disabled: true } }
      : {
          username: 'CVE Watch',
          avatar_url: 'https://cvewatch.l5z12.dev/icon.png',
          allowed_mentions: { parse: [] },
          embeds: [{ description: text, color: cve.severity === 'CRITICAL' ? 0xdc2626 : 0x2563eb }],
        };
  const response = await rt.fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(10_000),
    redirect: 'error',
  });
  const body = await readJson(response, 128 * 1024).catch(() => null);
  const valid = record(body) && (channel === 'telegram' ? body.ok === true : typeof body.id === 'string');
  if (!response.ok || !valid) {
    const code = record(body) && typeof body.error_code === 'number' ? body.error_code : response.status;
    throw new ServiceError(`${channel} HTTP/API ${code}`, retryAfter(response, body, rt.now()));
  }
}
