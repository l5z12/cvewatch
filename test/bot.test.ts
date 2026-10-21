import { env } from 'cloudflare:workers';
import { applyD1Migrations, runDurableObjectAlarm, runInDurableObject } from 'cloudflare:test';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { deliver, poll, run, runLive } from '../src/bot';
import { fetchRecentPage, parseCveRecord, pollRecent } from '../src/cve-search';
import worker from '../src/index';
import { message, send, validateSecrets } from '../src/messages';
import { fetchPage, parseCve } from '../src/nvd';
import { type BotEnv, type Cve, type Runtime, readJson, ServiceError } from '../src/types';

const NOW = Date.parse('2026-10-22T06:00:00Z');
const secrets = {
  TELEGRAM_BOT_TOKEN: '123456789:test-token',
  TELEGRAM_CHAT_ID: '@test_channel',
  DISCORD_WEBHOOK_URL: 'https://discord.com/api/webhooks/123456789/test-token',
};
const botEnv = (): BotEnv => ({ ...env, ...secrets });
const rawCve = (id = 'CVE-2026-12345', extra: Record<string, unknown> = {}) => ({
  id,
  published: '2026-10-22T05:00:00.000',
  lastModified: '2026-10-22T05:00:00.000',
  vulnStatus: 'Received',
  descriptions: [{ lang: 'en', value: 'A new vulnerability.' }],
  ...extra,
});
const cve = (): Cve => parseCve(rawCve())!;
const page = (items: unknown[], startIndex = 0, totalResults = items.length) =>
  Response.json({
    resultsPerPage: items.length,
    startIndex,
    totalResults,
    vulnerabilities: items.map((item) => ({ cve: item })),
  });

function clock() {
  let now = NOW;
  const mockFetch = vi.fn<typeof fetch>();
  const rt: Runtime = {
    fetch: (input, init) => {
      // Exercise Workers' native option validation before the mocked network.
      // In particular, Workers rejects redirect: 'error' before making a request.
      new Request(input, init);
      return mockFetch(input, init);
    },
    now: () => now,
    sleep: async (ms) => {
      now += ms;
    },
  };
  return {
    rt,
    mockFetch,
    advance: (ms: number) => {
      now += ms;
    },
  };
}

async function seed(items = [cve()]) {
  for (const item of items) {
    await env.DB.prepare('INSERT INTO cves (id, published_at, payload, discovered_at) VALUES (?, ?, ?, ?)')
      .bind(item.id, Date.parse(item.published), JSON.stringify(item), NOW)
      .run();
    await env.DB.batch(
      ['telegram', 'discord'].map((channel) =>
        env.DB.prepare('INSERT INTO deliveries (cve_id, channel) VALUES (?, ?)').bind(item.id, channel),
      ),
    );
  }
}

beforeAll(async () => {
  await applyD1Migrations(env.DB, env.TEST_MIGRATIONS);
  vi.stubGlobal(
    'fetch',
    vi.fn(() => {
      throw new Error('Unexpected network access in tests');
    }),
  );
});
afterAll(() => vi.unstubAllGlobals());
beforeEach(async () => {
  await env.DB.batch([
    ...['deliveries', 'cves', 'poll_state', 'live_poll_state', 'run_lock'].map((table) =>
      env.DB.prepare(`DELETE FROM ${table}`),
    ),
    env.DB.prepare('UPDATE channel_state SET next_send_at = 0'),
  ]);
});

describe('feed ingestion', () => {
  it('ingests every severity, unscored CVEs, and deduplicates overlapping polls', async () => {
    const { rt, mockFetch, advance } = clock();
    const items = [
      rawCve(),
      rawCve('CVE-2026-12346', {
        metrics: {
          cvssMetricV31: [{ type: 'Primary', cvssData: { version: '3.1', baseScore: 2, baseSeverity: 'LOW' } }],
        },
      }),
    ];
    mockFetch.mockImplementation(async () => page(items));
    await poll(botEnv(), rt);
    advance(5 * 60_000);
    await poll(botEnv(), rt);
    expect(await env.DB.prepare('SELECT COUNT(*) AS n FROM cves').first('n')).toBe(2);
    expect(await env.DB.prepare('SELECT COUNT(*) AS n FROM deliveries').first('n')).toBe(4);
    const url = new URL(String(mockFetch.mock.calls[0]![0]));
    expect(url.searchParams.has('lastModStartDate')).toBe(true);
    expect(url.searchParams.has('cvssV3Severity')).toBe(false);
  });

  it('filters old publications and rejected IDs but keeps late arrivals with recent modifications', async () => {
    const { rt, mockFetch } = clock();
    mockFetch.mockResolvedValue(
      page([
        rawCve(),
        rawCve('CVE-2026-12346', { published: '2020-01-01T00:00:00.000' }),
        rawCve('CVE-2026-12347', { vulnStatus: 'Rejected' }),
        rawCve('CVE-2026-12348', { published: '2026-10-21T07:00:00.000' }),
      ]),
    );
    await poll(botEnv(), rt);
    expect((await env.DB.prepare('SELECT id FROM cves ORDER BY id').all()).results).toEqual([
      { id: 'CVE-2026-12345' },
      { id: 'CVE-2026-12348' },
    ]);
  });

  it('resumes pagination after a failed page without advancing the watermark', async () => {
    const { rt, mockFetch, advance } = clock();
    const items = Array.from({ length: 200 }, (_, i) => rawCve(`CVE-2026-${20000 + i}`));
    mockFetch.mockResolvedValueOnce(page(items, 0, 201));
    await poll(botEnv(), rt);
    const before = await env.DB.prepare('SELECT * FROM poll_state').first();
    expect(before?.page_index).toBe(200);
    expect(before?.last_success_at).toBe(NOW);
    advance(60_000);
    mockFetch.mockResolvedValueOnce(new Response('Unavailable', { status: 503 }));
    await expect(poll(botEnv(), rt)).rejects.toThrow('NVD HTTP 503');
    expect(await env.DB.prepare('SELECT watermark FROM poll_state').first('watermark')).toBe(before?.watermark);
    mockFetch.mockResolvedValueOnce(page([rawCve('CVE-2026-99999')], 200, 201));
    await poll(botEnv(), rt);
    const after = await env.DB.prepare('SELECT * FROM poll_state').first();
    expect(after?.page_index).toBe(0);
    expect(after?.window_end).toBeNull();
    expect(after?.watermark).toBe(before?.window_end);
    expect(await env.DB.prepare('SELECT COUNT(*) AS n FROM deliveries').first('n')).toBe(402);
    const urls = mockFetch.mock.calls.map(([url]) => new URL(String(url)));
    expect(urls[0]!.searchParams.get('lastModEndDate')).toBe(urls[2]!.searchParams.get('lastModEndDate'));
  });

  it('catches up a long outage in bounded windows', async () => {
    const { rt, mockFetch } = clock();
    const old = NOW - 200 * 24 * 60 * 60_000;
    await env.DB.prepare('INSERT INTO poll_state (id, not_before, watermark) VALUES (1, ?, ?)').bind(old, old).run();
    mockFetch.mockResolvedValue(page([]));
    await poll(botEnv(), rt);
    const url = new URL(String(mockFetch.mock.calls[0]![0]));
    expect(
      Date.parse(url.searchParams.get('lastModEndDate')!) - Date.parse(url.searchParams.get('lastModStartDate')!),
    ).toBe(24 * 60 * 60_000);
    expect(await env.DB.prepare('SELECT next_poll_at FROM poll_state').first('next_poll_at')).toBe(NOW + 60_000);
  });

  it('rolls back CVE storage and the cursor if delivery insertion fails', async () => {
    const { rt, mockFetch } = clock();
    await env.DB.prepare(
      `CREATE TRIGGER fail_delivery BEFORE INSERT ON deliveries BEGIN
      SELECT RAISE(ABORT, 'test failure'); END`,
    ).run();
    try {
      mockFetch.mockResolvedValue(page([rawCve()]));
      await expect(poll(botEnv(), rt)).rejects.toThrow();
      expect(await env.DB.prepare('SELECT COUNT(*) AS n FROM cves').first('n')).toBe(0);
      expect(await env.DB.prepare('SELECT watermark FROM poll_state').first('watermark')).toBe(NOW - 24 * 60 * 60_000);
    } finally {
      await env.DB.prepare('DROP TRIGGER fail_delivery').run();
    }
  });

  it('rejects malformed pages instead of silently losing records', async () => {
    const { rt, mockFetch } = clock();
    mockFetch.mockResolvedValueOnce(page([], 0, 10));
    await expect(fetchPage(NOW - 1000, NOW, 0, undefined, rt)).rejects.toThrow('incomplete page');
    mockFetch.mockResolvedValueOnce(page([rawCve('bad-id')]));
    await expect(fetchPage(NOW - 1000, NOW, 0, undefined, rt)).rejects.toThrow('Invalid NVD CVE');
  });
});

describe('delivery and recovery', () => {
  it('does not resend successful Telegram delivery when Discord must retry', async () => {
    const { rt, mockFetch, advance } = clock();
    await seed();
    mockFetch
      .mockResolvedValueOnce(Response.json({ ok: true, result: { message_id: 1 } }))
      .mockResolvedValueOnce(Response.json({ retry_after: 120 }, { status: 429 }));
    await deliver(botEnv(), rt, NOW + 45_000);
    expect(await env.DB.prepare("SELECT sent_at FROM deliveries WHERE channel = 'telegram'").first('sent_at')).toBe(
      NOW,
    );
    expect(
      await env.DB.prepare("SELECT next_send_at FROM channel_state WHERE channel = 'discord'").first('next_send_at'),
    ).toBe(NOW + 120_000);
    advance(120_000);
    mockFetch.mockResolvedValueOnce(Response.json({ id: 'discord-message' }));
    await deliver(botEnv(), rt, rt.now() + 45_000);
    expect(mockFetch).toHaveBeenCalledTimes(3);
    expect(String(mockFetch.mock.calls[2]![0])).toContain('discord.com');
    expect(await env.DB.prepare('SELECT COUNT(*) AS n FROM deliveries WHERE sent_at IS NULL').first('n')).toBe(0);
  });

  it('honors Telegram flood control for the entire channel, while Discord keeps working', async () => {
    const { rt, mockFetch } = clock();
    await seed([cve(), { ...cve(), id: 'CVE-2026-12346' }]);
    mockFetch.mockImplementation(async (url) =>
      String(url).includes('telegram')
        ? Response.json({ ok: false, error_code: 429, parameters: { retry_after: 600 } }, { status: 429 })
        : Response.json({ id: 'sent' }),
    );
    await deliver(botEnv(), rt, NOW + 45_000);
    expect(mockFetch.mock.calls.filter(([url]) => String(url).includes('telegram'))).toHaveLength(1);
    expect(
      await env.DB.prepare(
        "SELECT COUNT(*) AS n FROM deliveries WHERE channel = 'discord' AND sent_at IS NOT NULL",
      ).first('n'),
    ).toBe(2);
    expect(
      await env.DB.prepare("SELECT next_send_at FROM channel_state WHERE channel = 'telegram'").first('next_send_at'),
    ).toBe(NOW + 600_000);
  });

  it('keeps pending alerts on network failure without storing credential-bearing errors', async () => {
    const { rt, mockFetch } = clock();
    await seed();
    mockFetch.mockRejectedValue(new Error(`Fetch failed at ${secrets.DISCORD_WEBHOOK_URL}`));
    await deliver(botEnv(), rt, NOW + 45_000);
    expect(await env.DB.prepare('SELECT COUNT(*) AS n FROM deliveries WHERE sent_at IS NULL').first('n')).toBe(2);
    expect(JSON.stringify((await env.DB.prepare('SELECT last_error FROM deliveries').all()).results)).not.toContain(
      'test-token',
    );
  });

  it('continues delivering stored alerts when NVD is down', async () => {
    const { rt, mockFetch } = clock();
    await seed();
    mockFetch.mockImplementation(async (url) =>
      String(url).includes('nist.gov')
        ? new Response('Unavailable', { status: 503 })
        : String(url).includes('telegram')
          ? Response.json({ ok: true })
          : Response.json({ id: 'sent' }),
    );
    await run(botEnv(), rt);
    expect(await env.DB.prepare('SELECT COUNT(*) AS n FROM deliveries WHERE sent_at IS NULL').first('n')).toBe(0);
    expect(await env.DB.prepare('SELECT last_error FROM poll_state').first('last_error')).toBe('NVD HTTP 503');
  });

  it('serializes overlapping cron invocations and recovers expired leases', async () => {
    const { rt, mockFetch, advance } = clock();
    await env.DB.prepare('INSERT INTO run_lock VALUES (1, ?, ?)')
      .bind('other-run', NOW + 60_000)
      .run();
    await run(botEnv(), rt);
    expect(mockFetch).not.toHaveBeenCalled();
    advance(60_001);
    mockFetch.mockResolvedValue(page([]));
    await run(botEnv(), rt);
    expect(mockFetch).toHaveBeenCalledTimes(1);
    expect(await env.DB.prepare('SELECT COUNT(*) AS n FROM run_lock').first('n')).toBe(0);
  });

  it('caps deliveries per run and leaves the remaining queue intact', async () => {
    const { rt, mockFetch } = clock();
    await seed(Array.from({ length: 8 }, (_, i) => ({ ...cve(), id: `CVE-2026-${30000 + i}` })));
    mockFetch.mockImplementation(async (url) =>
      String(url).includes('telegram') ? Response.json({ ok: true }) : Response.json({ id: 'sent' }),
    );
    await deliver(botEnv(), rt, NOW + 45_000);
    expect(mockFetch).toHaveBeenCalledTimes(8);
    expect(await env.DB.prepare('SELECT COUNT(*) AS n FROM deliveries WHERE sent_at IS NULL').first('n')).toBe(8);
  });

  it('allows only one of two simultaneous cron runs to poll and send', async () => {
    const { rt, mockFetch } = clock();
    mockFetch.mockImplementation(async (url) =>
      String(url).includes('nist.gov')
        ? page([rawCve()])
        : String(url).includes('telegram')
          ? Response.json({ ok: true })
          : Response.json({ id: 'sent' }),
    );
    await Promise.all([run(botEnv(), rt), run(botEnv(), rt)]);
    expect(mockFetch).toHaveBeenCalledTimes(3);
    expect(await env.DB.prepare('SELECT COUNT(*) AS n FROM deliveries WHERE sent_at IS NOT NULL').first('n')).toBe(2);
  });
});

describe('formatting and configuration', () => {
  it('uses primary CVSS v4 with fallbacks and preserves unscored records', () => {
    expect(parseCve(rawCve())?.score).toBeNull();
    expect(
      parseCve(
        rawCve('', {
          id: 'CVE-2026-12345',
          metrics: {
            cvssMetricV40: [
              { type: 'Secondary', cvssData: { baseScore: 4, version: '4.0' } },
              { type: 'Primary', cvssData: { baseScore: 9.5, version: '4.0' } },
            ],
          },
        }),
      ),
    ).toMatchObject({ score: 9.5, severity: 'CRITICAL', cvssVersion: '4.0' });
  });

  it('bounds messages, uses Telegram plain text, and disables Discord mentions', async () => {
    const { rt, mockFetch } = clock();
    const alert = { ...cve(), description: '@everyone <b>unsafe</b> ' + '😀'.repeat(6000) };
    expect(message(alert).length).toBeLessThan(4096);
    mockFetch.mockResolvedValueOnce(Response.json({ ok: true })).mockResolvedValueOnce(Response.json({ id: 'sent' }));
    await send('telegram', alert, botEnv(), rt);
    await send('discord', alert, botEnv(), rt);
    const telegram = JSON.parse(String(mockFetch.mock.calls[0]![1]?.body));
    const discord = JSON.parse(String(mockFetch.mock.calls[1]![1]?.body));
    expect(telegram.parse_mode).toBeUndefined();
    expect(discord.allowed_mentions).toEqual({ parse: [] });
    expect(new URL(String(mockFetch.mock.calls[1]![0])).searchParams.get('wait')).toBe('true');
  });

  it('requires confirmed API success, even for HTTP 200', async () => {
    const { rt, mockFetch } = clock();
    mockFetch
      .mockResolvedValueOnce(Response.json({ ok: false, error_code: 400 }))
      .mockResolvedValueOnce(new Response(null, { status: 204 }));
    await expect(send('telegram', cve(), botEnv(), rt)).rejects.toThrow('400');
    await expect(send('discord', cve(), botEnv(), rt)).rejects.toThrow('204');
  });

  it('rejects missing credentials and non-Discord URLs before polling', async () => {
    const { rt, mockFetch } = clock();
    await expect(run({ ...botEnv(), TELEGRAM_BOT_TOKEN: undefined }, rt)).rejects.toThrow('TELEGRAM_BOT_TOKEN');
    expect(mockFetch).not.toHaveBeenCalled();
    expect(() =>
      validateSecrets({ ...botEnv(), DISCORD_WEBHOOK_URL: 'https://example.com/api/webhooks/123/token' }),
    ).toThrow('Discord webhook');
  });

  it('bounds response bodies', async () => {
    await expect(readJson(new Response('x'.repeat(1024)), 64)).rejects.toBeInstanceOf(ServiceError);
  });

  it('reports the failure reason before the first successful poll', async () => {
    const { rt, mockFetch } = clock();
    mockFetch.mockRejectedValue(new DOMException('secret timeout detail', 'TimeoutError'));
    await runLive(botEnv(), rt);
    const response = await worker.fetch(new Request('https://worker.test/api/health/telegram'), botEnv());
    expect(response.status).toBe(503);
    const body = await response.json();
    expect(body).toMatchObject({
      checks: { 'cve-search': [{ output: 'The last poll failed: CVE Search request failed: Request timed out' }] },
    });
    expect(JSON.stringify(body)).not.toContain('secret');
  });

  it.each(['nvd', 'cve-search', 'telegram', 'discord'] as const)(
    'rejects %s redirects without forwarding credentials',
    async (service) => {
      const { rt, mockFetch } = clock();
      mockFetch.mockResolvedValue(new Response(null, { status: 302, headers: { Location: 'https://example.com/' } }));
      const request =
        service === 'nvd'
          ? fetchPage(NOW - 1000, NOW, 0, 'test-api-key', rt)
          : service === 'cve-search'
            ? fetchRecentPage(NOW - 1000, NOW, 1, botEnv(), rt)
            : send(service, cve(), botEnv(), rt);
      await expect(request).rejects.toThrow('302');
      expect(mockFetch).toHaveBeenCalledTimes(1);
      expect(mockFetch.mock.calls[0]![1]?.redirect).toBe('manual');
    },
  );

  it('has no public endpoint that can trigger notifications', async () => {
    for (const path of ['/run', '/api/health', '/api/health/telegram', '/api/health/discord']) {
      const response = await worker.fetch(new Request(`https://worker.test${path}`, { method: 'POST' }), botEnv());
      expect(response.status).toBe(404);
      expect(
        (await worker.fetch(new Request(`https://worker.test${path}/`, { method: 'POST' }), botEnv())).status,
      ).toBe(404);
    }
    for (const path of ['/api/health/slack', '/health', '/health/telegram', '/health/discord']) {
      expect((await worker.fetch(new Request(`https://worker.test${path}`), botEnv())).status).toBe(404);
    }
    expect((await worker.fetch(new Request('https://worker.test/api/health/'), botEnv())).status).toBe(503);
  });

  it('reports degraded health when a destination is failing or polling is stale', async () => {
    const now = Date.now();
    await seed();
    await env.DB.prepare('INSERT INTO poll_state (id, not_before, watermark, last_success_at) VALUES (1, ?, ?, ?)')
      .bind(now, now, now)
      .run();
    await env.DB.prepare('INSERT INTO live_poll_state (id, watermark, last_success_at) VALUES (1, ?, ?)')
      .bind(now, now)
      .run();
    const health = () => worker.fetch(new Request('https://worker.test/api/health/'), botEnv());
    expect((await health()).status).toBe(200);
    await env.DB.prepare("UPDATE deliveries SET last_error = 'discord HTTP/API 403' WHERE channel = 'discord'").run();
    expect((await health()).status).toBe(503);
    await env.DB.prepare('UPDATE deliveries SET last_error = NULL').run();
    await env.DB.prepare('UPDATE poll_state SET last_success_at = ?')
      .bind(now - 60 * 60_000)
      .run();
    expect((await health()).status).toBe(503);
  });
});

describe('destination health endpoints', () => {
  const health = (path: string, config = botEnv()) => worker.fetch(new Request(`https://worker.test${path}`), config);

  beforeEach(async () => {
    const now = Date.now();
    await seed();
    await env.DB.prepare('INSERT INTO poll_state (id, not_before, watermark, last_success_at) VALUES (1, ?, ?, ?)')
      .bind(now, now, now)
      .run();
    await env.DB.prepare('INSERT INTO live_poll_state (id, watermark, last_success_at) VALUES (1, ?, ?)')
      .bind(now, now)
      .run();
  });

  it.each(['telegram', 'discord'] as const)('isolates %s delivery health without sending messages', async (channel) => {
    const other = channel === 'telegram' ? 'discord' : 'telegram';
    const network = vi.mocked(fetch);
    network.mockClear();
    await env.DB.prepare('UPDATE deliveries SET last_error = ? WHERE channel = ?')
      .bind(`${other} HTTP/API 403`, other)
      .run();

    const response = await health(`/api/health/${channel}/`);
    expect(response.status).toBe(200);
    expect(response.headers.get('Content-Type')).toBe('application/health+json');
    expect(response.headers.get('Cache-Control')).toBe('no-store');
    const body = await response.json();
    expect(body).toMatchObject({
      status: 'pass',
      checks: {
        database: [{ status: 'pass' }],
        nvd: [{ status: 'pass' }],
        'cve-search': [{ status: 'pass' }],
        [channel]: [{ componentId: channel, status: 'pass', observedValue: 1, observedUnit: 'messages' }],
      },
    });
    expect(body).not.toHaveProperty(`checks.${other}`);
    expect((await health('/api/health')).status).toBe(503);

    await env.DB.prepare('UPDATE deliveries SET last_error = ? WHERE channel = ?')
      .bind(`${channel} HTTP/API 403`, channel)
      .run();
    const failed = await health(`/api/health/${channel}`);
    expect(failed.status).toBe(503);
    expect(await failed.json()).toMatchObject({
      status: 'fail',
      checks: { [channel]: [{ status: 'fail', output: '1 pending deliveries are awaiting retry.' }] },
    });
    expect(network).not.toHaveBeenCalled();
    expect(await env.DB.prepare('SELECT COUNT(*) AS n FROM deliveries WHERE sent_at IS NULL').first('n')).toBe(2);
  });

  it.each(['poll_state', 'live_poll_state'])('includes shared %s failures in both endpoints', async (table) => {
    await env.DB.prepare(`UPDATE ${table} SET last_success_at = ?`)
      .bind(Date.now() - 60 * 60_000)
      .run();
    for (const channel of ['telegram', 'discord']) {
      expect((await health(`/api/health/${channel}/`)).status).toBe(503);
    }
  });

  it.each(['telegram', 'discord'] as const)(
    'fails for disabled %s without affecting the enabled destination',
    async (channel) => {
      const config = {
        ...botEnv(),
        ...(channel === 'telegram' ? { TELEGRAM_BOT_TOKEN: '', TELEGRAM_CHAT_ID: '' } : { DISCORD_WEBHOOK_URL: '' }),
      };
      const response = await health(`/api/health/${channel}/`, config);
      expect(response.status).toBe(503);
      expect(await response.json()).toMatchObject({ status: 'fail', output: `${channel} is not configured.` });
      expect((await health('/api/health', config)).status).toBe(200);
      expect((await health(`/api/health/${channel === 'telegram' ? 'discord' : 'telegram'}`, config)).status).toBe(200);
    },
  );

  it('fails both endpoints when shared configuration prevents polling', async () => {
    for (const channel of ['telegram', 'discord']) {
      const response = await health(`/api/health/${channel}/`, { ...botEnv(), TELEGRAM_BOT_TOKEN: undefined });
      expect(response.status).toBe(503);
      expect(await response.json()).toMatchObject({
        status: 'fail',
        output: 'Configuration or storage is unavailable.',
      });
    }
  });
});

const programRecord = (id = 'CVE-2026-50000', published = new Date(NOW - 1000).toISOString()) => ({
  dataType: 'CVE_RECORD',
  dataVersion: '5.2',
  cveMetadata: { cveId: id, state: 'PUBLISHED', datePublished: published, dateUpdated: published },
  containers: { cna: { descriptions: [{ lang: 'en', value: 'Recently published vulnerability.' }] } },
});

const searchPage = (records: unknown[], pageNumber = 1, totalResults = records.length, totalIsExact = true) =>
  Response.json({
    apiVersion: '1.0',
    status: 'ok',
    warnings: [],
    records,
    pagination: {
      page: pageNumber,
      pageSize: 200,
      resultsReturned: records.length,
      totalResults,
      totalPages: Math.ceil(totalResults / 200),
      totalIsExact,
    },
  });

describe('recent publications from the CVE Program', () => {
  it('sends a one-second-old unscored publication to both destinations without NVD', async () => {
    const { rt, mockFetch } = clock();
    mockFetch.mockImplementation(async (url) =>
      String(url).includes('search.cve.org')
        ? searchPage([programRecord()])
        : String(url).includes('telegram')
          ? Response.json({ ok: true })
          : Response.json({ id: 'sent' }),
    );
    await runLive(botEnv(), rt);
    expect(mockFetch).toHaveBeenCalledTimes(3);
    expect(mockFetch.mock.calls.every(([url]) => !String(url).includes('nist.gov'))).toBe(true);
    expect(await env.DB.prepare('SELECT COUNT(*) AS n FROM deliveries WHERE sent_at IS NOT NULL').first('n')).toBe(2);
    const request = JSON.parse(String(mockFetch.mock.calls[0]![1]?.body));
    expect(request.pubEndDate).toBe(new Date(NOW).toISOString());
    expect(request).not.toHaveProperty('cvssV3Severity');
    const stored = JSON.parse((await env.DB.prepare('SELECT payload FROM cves').first<string>('payload'))!);
    expect(stored).toMatchObject({ source: 'CVE Program', score: null });
  });

  it('deduplicates records found later through NVD', async () => {
    const { rt, mockFetch } = clock();
    mockFetch.mockResolvedValueOnce(searchPage([programRecord()]));
    await pollRecent(botEnv(), rt);
    mockFetch.mockResolvedValueOnce(page([rawCve('CVE-2026-50000')]));
    await poll(botEnv(), rt);
    expect(await env.DB.prepare('SELECT COUNT(*) AS n FROM cves').first('n')).toBe(1);
    expect(await env.DB.prepare('SELECT COUNT(*) AS n FROM deliveries').first('n')).toBe(2);
    expect(JSON.parse((await env.DB.prepare('SELECT payload FROM cves').first<string>('payload'))!).source).toBe(
      'CVE Program',
    );
  });

  it('persists the 15-second cadence, keeps overlap, and skips premature polls', async () => {
    const { rt, mockFetch, advance } = clock();
    mockFetch.mockImplementation(async () => searchPage([programRecord()]));
    await pollRecent(botEnv(), rt);
    advance(14_000);
    await pollRecent(botEnv(), rt);
    expect(mockFetch).toHaveBeenCalledTimes(1);
    advance(1000);
    await pollRecent(botEnv(), rt);
    expect(mockFetch).toHaveBeenCalledTimes(2);
    const request = JSON.parse(String(mockFetch.mock.calls[1]![1]?.body));
    expect(Date.parse(request.pubStartDate)).toBe(NOW - 5 * 60_000);
    expect(await env.DB.prepare('SELECT COUNT(*) AS n FROM cves').first('n')).toBe(1);
  });

  it('persists pages and a fixed window rather than dropping a publication burst', async () => {
    const { rt, mockFetch, advance } = clock();
    const records = Array.from({ length: 200 }, (_, i) => programRecord(`CVE-2026-${60000 + i}`));
    mockFetch.mockResolvedValueOnce(searchPage(records, 1, 201));
    await pollRecent(botEnv(), rt);
    const before = await env.DB.prepare('SELECT * FROM live_poll_state').first();
    expect(before?.page_number).toBe(2);
    expect(before?.last_success_at).toBe(NOW);
    advance(15_000);
    mockFetch.mockResolvedValueOnce(searchPage([programRecord('CVE-2026-60200')], 2, 201));
    await pollRecent(botEnv(), rt);
    const after = await env.DB.prepare('SELECT * FROM live_poll_state').first();
    expect(after?.watermark).toBe(before?.window_end);
    expect(after?.window_end).toBeNull();
    expect(await env.DB.prepare('SELECT COUNT(*) AS n FROM cves').first('n')).toBe(201);
  });

  it('respects 429 backoff without stopping delivery of already queued alerts', async () => {
    const { rt, mockFetch, advance } = clock();
    await seed();
    mockFetch.mockImplementation(async (url) =>
      String(url).includes('search.cve.org')
        ? new Response('Too many requests', { status: 429, headers: { 'Retry-After': '120' } })
        : String(url).includes('telegram')
          ? Response.json({ ok: true })
          : Response.json({ id: 'sent' }),
    );
    await runLive(botEnv(), rt);
    expect(await env.DB.prepare('SELECT next_poll_at FROM live_poll_state').first('next_poll_at')).toBe(NOW + 120_000);
    expect(await env.DB.prepare('SELECT COUNT(*) AS n FROM deliveries WHERE sent_at IS NULL').first('n')).toBe(0);
    advance(15_000);
    await runLive(botEnv(), rt);
    expect(mockFetch.mock.calls.filter(([url]) => String(url).includes('search.cve.org'))).toHaveLength(1);
  });

  it('rejects partial results and overflow instead of treating them as a complete scan', async () => {
    const { rt, mockFetch } = clock();
    mockFetch
      .mockResolvedValueOnce(searchPage([], 1, 10001))
      .mockResolvedValueOnce(searchPage([], 1, 0, false))
      .mockResolvedValueOnce(searchPage([programRecord()], 1, 100));
    await expect(fetchRecentPage(NOW - 1000, NOW, 1, botEnv(), rt)).rejects.toThrow('result window exceeded');
    await expect(fetchRecentPage(NOW - 1000, NOW, 1, botEnv(), rt)).rejects.toThrow('Incomplete');
    await expect(fetchRecentPage(NOW - 1000, NOW, 1, botEnv(), rt)).rejects.toThrow('incomplete page');
  });

  it('increases source failure delays and resets them after recovery', async () => {
    const { rt, mockFetch, advance } = clock();
    mockFetch.mockImplementation(async () => new Response('Unavailable', { status: 503 }));
    await runLive(botEnv(), rt);
    expect(await env.DB.prepare('SELECT next_poll_at FROM live_poll_state').first('next_poll_at')).toBe(NOW + 60_000);
    advance(60_000);
    await runLive(botEnv(), rt);
    expect(await env.DB.prepare('SELECT next_poll_at FROM live_poll_state').first('next_poll_at')).toBe(NOW + 180_000);
    advance(120_000);
    mockFetch.mockImplementation(async () => searchPage([]));
    await runLive(botEnv(), rt);
    expect(await env.DB.prepare('SELECT failure_count FROM live_poll_state').first('failure_count')).toBe(0);
    expect(await env.DB.prepare('SELECT next_poll_at FROM live_poll_state').first('next_poll_at')).toBe(NOW + 195_000);
  });

  it('leaves historical recovery to NVD and limits recent searches after a long outage', async () => {
    const { rt, mockFetch } = clock();
    await env.DB.prepare(
      `INSERT INTO live_poll_state (id, watermark, window_start, window_end, page_number)
      VALUES (1, ?, ?, ?, 12)`,
    )
      .bind(NOW - 86_400_000, NOW - 86_400_000, NOW - 86_000_000)
      .run();
    mockFetch.mockResolvedValueOnce(searchPage([]));
    await pollRecent(botEnv(), rt);
    const request = JSON.parse(String(mockFetch.mock.calls[0]![1]?.body));
    expect(Date.parse(request.pubStartDate)).toBe(NOW - 15 * 60_000);
    expect(request.pageNumber).toBe(1);
  });

  it('prioritizes newly published alerts over startup backfill', async () => {
    const { rt, mockFetch } = clock();
    await seed([
      ...Array.from({ length: 6 }, (_, i) => ({ ...cve(), id: `CVE-2026-${40000 + i}` })),
      { ...cve(), id: 'CVE-2026-99999', published: new Date(NOW - 1000).toISOString() },
    ]);
    mockFetch.mockImplementation(async (url) =>
      String(url).includes('telegram') ? Response.json({ ok: true }) : Response.json({ id: 'sent' }),
    );
    await deliver(botEnv(), rt, NOW + 45_000);
    expect(String(mockFetch.mock.calls[0]![1]?.body)).toContain('CVE-2026-99999');
    expect(String(mockFetch.mock.calls[1]![1]?.body)).toContain('CVE-2026-99999');
  });

  it('reads CNA and ADP CVSS metrics and ignores rejected records', () => {
    const record = programRecord();
    expect(parseCveRecord({ ...record, cveMetadata: { ...record.cveMetadata, state: 'REJECTED' } })).toBeNull();
    expect(
      parseCveRecord({
        ...record,
        containers: {
          ...record.containers,
          adp: [
            {
              providerMetadata: { shortName: 'CISA-ADP' },
              metrics: [
                { cvssV3_1: { version: '3.1', baseScore: 7.5, baseSeverity: 'HIGH' } },
                { other: { type: 'kev', content: { dateAdded: '2026-10-22' } } },
              ],
            },
          ],
        },
      }),
    ).toMatchObject({ score: 7.5, severity: 'HIGH', exploited: true });
  });

  it('rolls back recent records when an outbox transaction fails', async () => {
    const { rt, mockFetch } = clock();
    await env.DB.prepare(
      `CREATE TRIGGER fail_live_delivery BEFORE INSERT ON deliveries BEGIN
      SELECT RAISE(ABORT, 'test failure'); END`,
    ).run();
    try {
      mockFetch.mockResolvedValue(searchPage([programRecord()]));
      await expect(pollRecent(botEnv(), rt)).rejects.toThrow();
      expect(await env.DB.prepare('SELECT COUNT(*) AS n FROM cves').first('n')).toBe(0);
      expect(await env.DB.prepare('SELECT last_success_at FROM live_poll_state').first('last_success_at')).toBeNull();
    } finally {
      await env.DB.prepare('DROP TRIGGER fail_live_delivery').run();
    }
  });
});

describe('persistent publication monitor', () => {
  it('keeps an existing alarm when cron checks it again', async () => {
    const stub = env.MONITOR.getByName(`test-${crypto.randomUUID()}`);
    const scheduled = Date.now() + 3_600_000;
    await runInDurableObject(stub, async (_instance, state) => {
      await state.storage.setAlarm(scheduled);
    });
    try {
      await stub.ensureStarted();
      expect(await runInDurableObject(stub, async (_instance, state) => state.storage.getAlarm())).toBe(scheduled);
    } finally {
      await runInDurableObject(stub, async (_instance, state) => {
        await state.storage.deleteAlarm();
      });
    }
  });

  it('reschedules its alarm after a failed source request', async () => {
    const stub = env.MONITOR.getByName(`test-${crypto.randomUUID()}`);
    await runInDurableObject(stub, async (_instance, state) => {
      await state.storage.setAlarm(Date.now() + 3_600_000);
    });
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response('Unavailable', { status: 503 })),
    );
    try {
      const before = Date.now();
      expect(await runDurableObjectAlarm(stub)).toBe(true);
      const next = await runInDurableObject(stub, async (_instance, state) => state.storage.getAlarm());
      expect(next).toBeGreaterThanOrEqual(before + 15_000);
      expect(await env.DB.prepare('SELECT last_error FROM live_poll_state').first('last_error')).toBe(
        'CVE Search HTTP 503',
      );
    } finally {
      await runInDurableObject(stub, async (_instance, state) => {
        await state.storage.deleteAlarm();
      });
      vi.stubGlobal(
        'fetch',
        vi.fn(() => {
          throw new Error('Unexpected network access in tests');
        }),
      );
    }
  });
});
