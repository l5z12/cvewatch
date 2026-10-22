import { type BotEnv, type Channel, type Cve, type Runtime, record, readJson, retryAfter, ServiceError } from './types';
import { serviceRequest } from './request';

function clip(text: string, length: number): string {
  const chars = Array.from(text);
  return chars.length > length ? `${chars.slice(0, length - 1).join('')}…` : text;
}

// Some CNAs publish a placeholder like "No description provided". It matches
// NVD's own "No description is available yet." too.
const PLACEHOLDER = /^(?:no description(?: is)?(?: provided| available)?(?: yet)?|n\/?a|tbd|none)?\.?$/i;

export function message(cve: Cve): string {
  const score =
    cve.score === null
      ? 'not scored yet'
      : `${cve.score.toFixed(1)}/10${cve.cvssVersion ? ` (CVSS ${cve.cvssVersion})` : ''}`;
  const summary = cve.title && PLACEHOLDER.test(cve.description.trim()) ? cve.title : cve.description;
  return [
    cve.requested ? cve.id : `New CVE: ${cve.id}`,
    `${cve.severity} · ${score}`,
    `Published: ${cve.published.replace('T', ' ').replace(/(?:\.\d+)?Z$/, ' UTC')}`,
    `Source: ${cve.source ?? 'NVD'}`,
    ...(cve.exploited ? ['Known exploited vulnerability (CISA KEV)'] : []),
    '',
    clip(summary, 1200),
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

function content(channel: Channel, cve: Cve, env: BotEnv): Record<string, unknown> {
  const text = message(cve);
  return channel === 'telegram'
    ? { chat_id: env.TELEGRAM_CHAT_ID, text, link_preview_options: { is_disabled: true } }
    : {
        allowed_mentions: { parse: [] },
        embeds: [{ description: text, color: cve.severity === 'CRITICAL' ? 0xdc2626 : 0x2563eb }],
      };
}

// Returns the confirmed API response, or null for an edit that retrying cannot fix.
async function request(
  channel: Channel,
  url: URL,
  method: 'POST' | 'PATCH',
  payload: Record<string, unknown>,
  editing: boolean,
  rt: Runtime,
): Promise<Record<string, unknown> | null> {
  return serviceRequest(
    channel,
    url,
    { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) },
    rt,
    10_000,
    async (response) => {
      const body = await readJson(response, 128 * 1024).catch((error) => {
        if (response.ok && response.status !== 204) throw error;
        return null;
      });
      if (response.ok && record(body) && (channel === 'telegram' ? body.ok === true : typeof body.id === 'string')) {
        return body;
      }
      const code = record(body) && typeof body.error_code === 'number' ? body.error_code : response.status;
      // The message was deleted, the destination has changed since it was sent, or
      // (on Telegram) the message already shows this text.
      if (editing && code >= 400 && code < 500 && code !== 429) return null;
      throw new ServiceError(`${channel} HTTP/API ${code}`, retryAfter(response, body, rt.now()));
    },
  );
}

// Returns the sent message's ID for later edits, or null if the API returned none.
export async function send(channel: Channel, cve: Cve, env: BotEnv, rt: Runtime): Promise<string | null> {
  const url =
    channel === 'telegram'
      ? new URL(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/sendMessage`)
      : new URL(env.DISCORD_WEBHOOK_URL!);
  if (channel === 'discord') url.searchParams.set('wait', 'true');
  const payload =
    channel === 'telegram'
      ? content(channel, cve, env)
      : { username: 'CVE Watch', avatar_url: 'https://cvewatch.l5z12.dev/icon.png', ...content(channel, cve, env) };
  const body = await request(channel, url, 'POST', payload, false, rt);
  if (channel === 'telegram') {
    const id = record(body?.result) ? body.result.message_id : undefined;
    return Number.isSafeInteger(id) && (id as number) > 0 ? String(id) : null;
  }
  // The ID becomes part of the edit URL.
  return typeof body?.id === 'string' && /^\d{1,20}$/.test(body.id) ? body.id : null;
}

// Replaces a sent alert's text. Returns false if the message can no longer be edited.
export async function edit(channel: Channel, cve: Cve, messageId: string, env: BotEnv, rt: Runtime): Promise<boolean> {
  const url =
    channel === 'telegram'
      ? new URL(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/editMessageText`)
      : new URL(env.DISCORD_WEBHOOK_URL!);
  // Keeps the webhook's thread_id parameter, which Discord needs to find thread messages.
  if (channel === 'discord') url.pathname += `/messages/${messageId}`;
  const payload =
    channel === 'telegram'
      ? { ...content(channel, cve, env), message_id: Number(messageId) }
      : content(channel, cve, env);
  return (await request(channel, url, channel === 'telegram' ? 'POST' : 'PATCH', payload, true, rt)) !== null;
}
