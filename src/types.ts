import type { PublicationMonitor } from './monitor';

declare global {
  namespace Cloudflare {
    interface Env {
      // The config's string Worker reference cannot infer the RPC class.
      MONITOR: DurableObjectNamespace<PublicationMonitor>;
    }
  }
}

// Validate absent credentials at runtime, including partially configured deployments.
type SecretName = 'TELEGRAM_BOT_TOKEN' | 'TELEGRAM_CHAT_ID' | 'DISCORD_WEBHOOK_URL' | 'NVD_API_KEY';
export type BotEnv = Omit<Env, SecretName> & Partial<Pick<Env, SecretName>>;

export type Channel = 'telegram' | 'discord';

export interface Cve {
  id: string;
  published: string;
  description: string;
  severity: string;
  score: number | null;
  cvssVersion: string | null;
  exploited: boolean;
  source?: 'CVE Program' | 'NVD';
  // The parser version that stored a CVE Program alert. Absent means version 1.
  parser?: number;
  // Sent on request rather than discovered, so it may not be new.
  requested?: boolean;
  // Sent because the CVE was added to the CISA KEV catalog.
  kev?: KevDetails;
}

export interface KevDetails {
  // Dates as the catalog gives them, such as 2026-10-20.
  added: string;
  due: string | null;
  ransomware: boolean;
}

export interface Runtime {
  fetch: typeof fetch;
  now: () => number;
  sleep: (ms: number) => Promise<void>;
}

export const runtime: Runtime = {
  fetch: (...args) => fetch(...args),
  now: () => Date.now(),
  sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
};

export function integer(value: string, name: string, min: number, max: number): number {
  const parsed = Number(value);
  if (!value.trim() || !Number.isInteger(parsed) || parsed < min || parsed > max) {
    throw new Error(`Invalid ${name}`);
  }
  return parsed;
}

export function record(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export class ServiceError extends Error {
  constructor(
    message: string,
    readonly retryAfterMs = 60_000,
  ) {
    super(message);
  }
}

// Never log fetch error text or remote response bodies: they can contain tokens/URLs.
export function errorDetails(error: unknown): { errorType: string; causeCode?: string } {
  const names = ['Error', 'TypeError', 'RangeError', 'SyntaxError', 'ReferenceError', 'TimeoutError', 'AbortError'];
  const errorType =
    error instanceof ServiceError
      ? 'ServiceError'
      : error instanceof Error && names.includes(error.name)
        ? error.name
        : 'UnknownError';
  const cause = error instanceof Error && record(error.cause) ? error.cause : undefined;
  const codes = ['ENOTFOUND', 'EAI_AGAIN', 'ECONNRESET', 'ECONNREFUSED', 'ETIMEDOUT', 'UND_ERR_CONNECT_TIMEOUT'];
  const causeCode = typeof cause?.code === 'string' && codes.includes(cause.code) ? cause.code : undefined;
  return { errorType, causeCode };
}

export function safeError(error: unknown): string {
  if (error instanceof ServiceError) return error.message;
  const { errorType, causeCode } = errorDetails(error);
  if (errorType === 'TimeoutError') return 'Request timed out';
  if (errorType === 'AbortError') return 'Request aborted';
  if (errorType === 'SyntaxError') return 'Invalid JSON response';
  return `Request or processing failed (${errorType}${causeCode ? `, ${causeCode}` : ''})`;
}

export async function readJson(response: Response, limit: number): Promise<unknown> {
  if (!response.body) throw new ServiceError('Empty service response');
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > limit) {
        await reader.cancel();
        throw new ServiceError('Service response exceeded size limit');
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const data = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    data.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return JSON.parse(new TextDecoder().decode(data));
}

export function retryAfter(response: Response, body: unknown, now: number): number {
  const header = response.headers.get('retry-after');
  let seconds = header ? Number(header) : 0;
  if (header && !Number.isFinite(seconds)) seconds = (Date.parse(header) - now) / 1000;
  if (record(body)) {
    const parameters = record(body.parameters) ? body.parameters : {};
    const value = body.retry_after ?? parameters.retry_after;
    if (typeof value === 'number') seconds = Math.max(seconds || 0, value);
  }
  return Number.isFinite(seconds) ? Math.max(60_000, Math.ceil(seconds * 1000)) : 60_000;
}
