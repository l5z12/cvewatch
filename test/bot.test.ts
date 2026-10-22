import { env } from 'cloudflare:workers';
import { applyD1Migrations, runDurableObjectAlarm, runInDurableObject } from 'cloudflare:test';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { deliver, poll, run, runLive } from '../src/bot';
import { DELTA_URL, pollDelta, recordUrl } from '../src/cve-list';
import { fetchRecentPage, PARSER_VERSION, parseCveRecord, pollRecent } from '../src/cve-search';
import { fetchCatalog, KEV_URL, pollKev } from '../src/kev';
import worker from '../src/index';
import { message, send, validateSecrets } from '../src/messages';
import { fetchPage, NVD_URL, PAGE_SIZE, parseCve } from '../src/nvd';
import { processRequests } from '../src/requests';
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
    ...[
      'deliveries',
      'cves',
      'poll_state',
      'live_poll_state',
      'delta_poll_state',
      'kev_poll_state',
      'kev_catalog',
      'run_lock',
      'send_requests',
    ].map((table) => env.DB.prepare(`DELETE FROM ${table}`)),
    env.DB.prepare('UPDATE channel_state SET next_send_at = 0, stopped_at = NULL'),
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
    const items = Array.from({ length: PAGE_SIZE }, (_, i) => rawCve(`CVE-2026-${20000 + i}`));
    mockFetch.mockResolvedValueOnce(page(items, 0, PAGE_SIZE + 1));
    await poll(botEnv(), rt);
    const before = await env.DB.prepare('SELECT * FROM poll_state').first();
    expect(before?.page_index).toBe(PAGE_SIZE);
    expect(before?.last_success_at).toBe(NOW);
    advance(60_000);
    mockFetch.mockResolvedValueOnce(new Response('Unavailable', { status: 503 }));
    await expect(poll(botEnv(), rt)).rejects.toThrow('NVD HTTP 503');
    expect(await env.DB.prepare('SELECT watermark FROM poll_state').first('watermark')).toBe(before?.watermark);
    mockFetch.mockResolvedValueOnce(page([rawCve('CVE-2026-99999')], PAGE_SIZE, PAGE_SIZE + 1));
    await poll(botEnv(), rt);
    const after = await env.DB.prepare('SELECT * FROM poll_state').first();
    expect(after?.page_index).toBe(0);
    expect(after?.window_end).toBeNull();
    expect(after?.watermark).toBe(before?.window_end);
    expect(await env.DB.prepare('SELECT COUNT(*) AS n FROM deliveries').first('n')).toBe(2 * (PAGE_SIZE + 1));
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

  it('parses alerts queued by an older parser again, keeping a score and KEV details added since', async () => {
    const { rt, mockFetch } = clock();
    // Stored before placeholders were replaced, then scored by NVD.
    const stale = (id: string): Cve => ({
      ...cve(),
      id,
      description: 'No description provided',
      source: 'CVE Program',
      score: 7.5,
      severity: 'HIGH',
      cvssVersion: '3.1',
      kev: { added: '2026-10-22', due: null, ransomware: false },
    });
    await seed([stale('CVE-2026-50000'), stale('CVE-2026-50001')]);
    mockFetch.mockImplementation(async (url) => {
      if (String(url) === recordUrl('CVE-2026-50000')) return Response.json(programRecord('CVE-2026-50000'));
      // The CVE List is unavailable for the other alert.
      if (String(url) === recordUrl('CVE-2026-50001')) return new Response(null, { status: 503 });
      return String(url).includes('telegram')
        ? Response.json({ ok: true, result: { message_id: 1 } })
        : Response.json({ id: 'sent' });
    });
    await deliver(botEnv(), rt, NOW + 45_000);
    const bodies = mockFetch.mock.calls
      .filter(([, init]) => init?.method === 'POST')
      .map(([, init]) => String(init?.body));
    expect(bodies).toHaveLength(4);
    // The refreshed payload is stored once and used for both destinations.
    expect(mockFetch.mock.calls.filter(([url]) => String(url) === recordUrl('CVE-2026-50000'))).toHaveLength(1);
    const payload = async (id: string) =>
      JSON.parse((await env.DB.prepare('SELECT payload FROM cves WHERE id = ?').bind(id).first<string>('payload'))!);
    expect(await payload('CVE-2026-50000')).toMatchObject({
      description: 'Recently published vulnerability.',
      score: 7.5,
      severity: 'HIGH',
      kev: { added: '2026-10-22' },
      parser: PARSER_VERSION,
    });
    expect(bodies.filter((body) => body.includes('CVE-2026-50000'))).toHaveLength(2);
    for (const body of bodies.filter((body) => body.includes('CVE-2026-50000'))) {
      expect(body).toContain('Added to CISA KEV: CVE-2026-50000');
      expect(body).toContain('Recently published vulnerability.');
      expect(body).toContain('HIGH · 7.5/10 (CVSS 3.1)');
    }
    // The other alert goes out as stored rather than waiting for the CVE List.
    expect(await payload('CVE-2026-50001')).toMatchObject({ description: 'No description provided' });
    expect(await payload('CVE-2026-50001')).not.toHaveProperty('parser');
    expect(await env.DB.prepare('SELECT COUNT(*) AS n FROM deliveries WHERE sent_at IS NULL').first('n')).toBe(0);
  });

  it('stops sending and editing mid-run until an emergency stop is lifted', async () => {
    const { rt, mockFetch } = clock();
    await seed([cve(), { ...cve(), id: 'CVE-2026-12346' }, { ...cve(), id: 'CVE-2026-12347' }]);
    // A sent alert queued again to add a score.
    await env.DB.prepare("UPDATE deliveries SET message_id = '7' WHERE cve_id = 'CVE-2026-12347'").run();
    const stop = env.DB.prepare("UPDATE channel_state SET stopped_at = ? WHERE channel = 'telegram'").bind(NOW);
    mockFetch.mockImplementation(async (url) => {
      if (!String(url).includes('telegram')) return Response.json({ id: 'sent' });
      // The workflow stops Telegram while the first message is in flight.
      await stop.run();
      return Response.json({ ok: true, result: { message_id: 1 } });
    });
    const telegram = () => mockFetch.mock.calls.filter(([url]) => String(url).includes('telegram')).length;
    const pending = (channel: string) =>
      env.DB.prepare('SELECT COUNT(*) AS n FROM deliveries WHERE channel = ? AND sent_at IS NULL')
        .bind(channel)
        .first('n');
    await deliver(botEnv(), rt, NOW + 45_000);
    expect(telegram()).toBe(1);
    expect(await pending('telegram')).toBe(2);
    expect(await pending('discord')).toBe(0);
    await deliver(botEnv(), rt, rt.now() + 45_000);
    expect(telegram()).toBe(1);

    await env.DB.prepare('UPDATE channel_state SET stopped_at = NULL').run();
    mockFetch.mockImplementation(async () => Response.json({ ok: true, result: { message_id: 2 } }));
    await deliver(botEnv(), rt, rt.now() + 45_000);
    expect(await pending('telegram')).toBe(0);
    expect(mockFetch.mock.calls.some(([url]) => String(url).endsWith('/editMessageText'))).toBe(true);
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
    // NVD and the KEV catalog.
    expect(mockFetch).toHaveBeenCalledTimes(2);
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
    // NVD, the KEV catalog, and one message per destination.
    expect(mockFetch).toHaveBeenCalledTimes(4);
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

  it('shows descriptions literally: as plain text on Telegram and in a code block on Discord', async () => {
    const { rt, mockFetch } = clock();
    const description = 'A __CONTENT__ payload, *glob*, ||x|| and [link](https://evil.test).\n\n# See ```code```.';
    const alert = { ...cve(), description };
    mockFetch.mockResolvedValueOnce(Response.json({ ok: true })).mockResolvedValueOnce(Response.json({ id: 'sent' }));
    await send('telegram', alert, botEnv(), rt);
    await send('discord', alert, botEnv(), rt);
    const telegram = JSON.parse(String(mockFetch.mock.calls[0]![1]?.body)).text;
    const discord = JSON.parse(String(mockFetch.mock.calls[1]![1]?.body)).embeds[0].description;
    expect(telegram).toContain(`\n\n${description}\n\n`);
    expect(discord).toContain(
      `\n\n\`\`\`\n${description.replaceAll('```', '``\u200b`')}\n\`\`\`\n\nhttps://www.cve.org/`,
    );
    // Only the block's own fences remain.
    expect(discord.match(/```/g)).toHaveLength(2);
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

  it.each(['nvd', 'cve-search', 'cisa-kev', 'telegram', 'discord'] as const)(
    'rejects %s redirects without forwarding credentials',
    async (service) => {
      const { rt, mockFetch } = clock();
      mockFetch.mockResolvedValue(new Response(null, { status: 302, headers: { Location: 'https://example.com/' } }));
      const request =
        service === 'nvd'
          ? fetchPage(NOW - 1000, NOW, 0, 'test-api-key', rt)
          : service === 'cve-search'
            ? fetchRecentPage(NOW - 1000, NOW, 1, botEnv(), rt)
            : service === 'cisa-kev'
              ? fetchCatalog(null, botEnv(), rt)
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
    await env.DB.prepare('INSERT INTO delta_poll_state (id, last_success_at) VALUES (1, ?)').bind(now).run();
    await env.DB.prepare('INSERT INTO kev_poll_state (id, last_success_at) VALUES (1, ?)').bind(now).run();
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

  it('warns about a failed NVD poll until NVD data is stale', async () => {
    const now = Date.now();
    await env.DB.prepare(
      'INSERT INTO poll_state (id, not_before, watermark, last_success_at, last_error) VALUES (1, ?, ?, ?, ?)',
    )
      .bind(now, now, now - 60_000, 'NVD request failed: Request timed out')
      .run();
    await env.DB.prepare('INSERT INTO live_poll_state (id, watermark, last_success_at) VALUES (1, ?, ?)')
      .bind(now, now)
      .run();
    await env.DB.prepare('INSERT INTO delta_poll_state (id, last_success_at) VALUES (1, ?)').bind(now).run();
    await env.DB.prepare('INSERT INTO kev_poll_state (id, last_success_at) VALUES (1, ?)').bind(now).run();
    const health = () => worker.fetch(new Request('https://worker.test/api/health/'), botEnv());
    const response = await health();
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({
      status: 'warn',
      checks: { nvd: [{ status: 'warn', output: 'The last poll failed: NVD request failed: Request timed out' }] },
    });
    await env.DB.prepare('UPDATE poll_state SET last_success_at = ?')
      .bind(now - 60 * 60_000)
      .run();
    expect((await health()).status).toBe(503);
    // Live sources still fail on any error.
    await env.DB.prepare('UPDATE poll_state SET last_success_at = ?, last_error = NULL').bind(now).run();
    await env.DB.prepare("UPDATE live_poll_state SET last_error = 'CVE Search HTTP 503'").run();
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
    await env.DB.prepare('INSERT INTO delta_poll_state (id, last_success_at) VALUES (1, ?)').bind(now).run();
    await env.DB.prepare('INSERT INTO kev_poll_state (id, last_success_at) VALUES (1, ?)').bind(now).run();
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
        'cve-list': [{ status: 'pass' }],
        'cve-search': [{ status: 'pass' }],
        'cisa-kev': [{ status: 'pass' }],
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

  it('warns while a destination is stopped, even with deliveries awaiting retry', async () => {
    await env.DB.prepare("UPDATE channel_state SET stopped_at = ? WHERE channel = 'telegram'")
      .bind(Date.parse('2026-10-22T20:00:00Z'))
      .run();
    await env.DB.prepare("UPDATE deliveries SET last_error = 'telegram HTTP/API 401' WHERE channel = 'telegram'").run();
    const response = await health('/api/health/telegram/');
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({
      status: 'warn',
      checks: {
        telegram: [
          {
            status: 'warn',
            observedValue: 1,
            output:
              'Stopped by the Emergency stop workflow at 2026-10-22T20:00:00.000Z. 1 pending deliveries are awaiting retry.',
          },
        ],
      },
    });
    expect(await (await health('/api/health/discord/')).json()).toMatchObject({ status: 'pass' });
  });

  it.each(['poll_state', 'live_poll_state', 'delta_poll_state', 'kev_poll_state'])(
    'includes shared %s failures in both endpoints',
    async (table) => {
      await env.DB.prepare(`UPDATE ${table} SET last_success_at = ?`)
        .bind(Date.now() - 60 * 60_000)
        .run();
      for (const channel of ['telegram', 'discord']) {
        expect((await health(`/api/health/${channel}/`)).status).toBe(503);
      }
    },
  );

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
      // Matches the live API, which reports page 0 when nothing matches.
      page: totalResults === 0 ? 0 : pageNumber,
      pageSize: 200,
      resultsReturned: records.length,
      totalResults,
      totalPages: Math.ceil(totalResults / 200),
      totalIsExact,
    },
  });

const delta = (ids: string[], fetchTime = new Date(NOW - 1000).toISOString()) =>
  Response.json({
    fetchTime,
    numberOfChanges: ids.length,
    new: ids.map((cveId) => ({ cveId })),
    updated: [],
    error: [],
  });

describe('new records from the CVE List', () => {
  it('fetches only newly listed records, once', async () => {
    const { rt, mockFetch } = clock();
    const id = 'CVE-2026-114383';
    mockFetch.mockImplementation(async (url) =>
      String(url) === DELTA_URL ? delta([id]) : Response.json(programRecord(id)),
    );
    await pollDelta(botEnv(), rt);
    expect(recordUrl(id)).toBe(
      'https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/114xxx/CVE-2026-114383.json',
    );
    expect(mockFetch.mock.calls.map(([url]) => String(url))).toEqual([DELTA_URL, recordUrl(id)]);
    expect(await env.DB.prepare('SELECT COUNT(*) AS n FROM deliveries').first('n')).toBe(2);
    const stored = JSON.parse((await env.DB.prepare('SELECT payload FROM cves').first<string>('payload'))!);
    expect(stored).toMatchObject({ id, source: 'CVE Program' });
    await pollDelta(botEnv(), rt);
    expect(mockFetch).toHaveBeenCalledTimes(3);
  });

  it('skips known records, continues large deltas, and ignores stale copies', async () => {
    const { rt, mockFetch, advance } = clock();
    const ids = Array.from({ length: 25 }, (_, i) => `CVE-2026-${70000 + i}`);
    await seed([{ ...cve(), id: ids[0]! }]);
    mockFetch.mockImplementation(async (url) =>
      String(url) === DELTA_URL ? delta(ids) : Response.json(programRecord(String(url).match(/CVE-[\d-]+/)![0])),
    );
    await pollDelta(botEnv(), rt);
    expect(mockFetch).toHaveBeenCalledTimes(20);
    advance(15_000);
    await pollDelta(botEnv(), rt);
    expect(mockFetch).toHaveBeenCalledTimes(26);
    expect(await env.DB.prepare('SELECT COUNT(*) AS n FROM cves').first('n')).toBe(25);
    mockFetch.mockImplementationOnce(async () => delta(['CVE-2026-79999'], new Date(NOW - 60_000).toISOString()));
    await pollDelta(botEnv(), rt);
    expect(mockFetch).toHaveBeenCalledTimes(27);
    expect(await env.DB.prepare('SELECT next_index FROM delta_poll_state').first('next_index')).toBe(25);
  });

  it('keeps polling CVE Search when the CVE List fails', async () => {
    const { rt, mockFetch } = clock();
    mockFetch.mockImplementation(async (url) =>
      String(url) === DELTA_URL
        ? new Response('Unavailable', { status: 503 })
        : String(url).includes('search.cve.org')
          ? searchPage([programRecord()])
          : String(url).includes('telegram')
            ? Response.json({ ok: true })
            : Response.json({ id: 'sent' }),
    );
    await runLive(botEnv(), rt);
    expect(await env.DB.prepare('SELECT last_error FROM delta_poll_state').first('last_error')).toBe(
      'CVE List HTTP 503',
    );
    expect(await env.DB.prepare('SELECT COUNT(*) AS n FROM cves').first('n')).toBe(1);
  });
});

describe('recent publications from the CVE Program', () => {
  it('sends a one-second-old unscored publication to both destinations without NVD', async () => {
    const { rt, mockFetch } = clock();
    mockFetch.mockImplementation(async (url) =>
      String(url) === DELTA_URL
        ? delta([])
        : String(url).includes('search.cve.org')
          ? searchPage([programRecord()])
          : String(url).includes('telegram')
            ? Response.json({ ok: true })
            : Response.json({ id: 'sent' }),
    );
    await runLive(botEnv(), rt);
    expect(mockFetch).toHaveBeenCalledTimes(4);
    expect(mockFetch.mock.calls.every(([url]) => !String(url).includes('nist.gov'))).toBe(true);
    expect(await env.DB.prepare('SELECT COUNT(*) AS n FROM deliveries WHERE sent_at IS NOT NULL').first('n')).toBe(2);
    const search = mockFetch.mock.calls.find(([url]) => String(url).includes('search.cve.org'))!;
    const request = JSON.parse(String(search[1]?.body));
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
    expect(Date.parse(request.pubStartDate)).toBe(NOW - 60 * 60_000);
    expect(await env.DB.prepare('SELECT COUNT(*) AS n FROM cves').first('n')).toBe(1);
  });

  it('finds publications that the search index lists late', async () => {
    const { rt, mockFetch, advance } = clock();
    mockFetch.mockResolvedValueOnce(searchPage([]));
    await pollRecent(botEnv(), rt);
    advance(15 * 60_000);
    mockFetch.mockResolvedValueOnce(searchPage([programRecord()]));
    await pollRecent(botEnv(), rt);
    const request = JSON.parse(String(mockFetch.mock.calls[1]![1]?.body));
    expect(Date.parse(request.pubStartDate)).toBeLessThan(NOW - 1000);
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

  it('accepts an empty recent window', async () => {
    const { rt, mockFetch } = clock();
    mockFetch.mockResolvedValueOnce(searchPage([]));
    await expect(fetchRecentPage(NOW - 1000, NOW, 1, botEnv(), rt)).resolves.toEqual({ cves: [], complete: true });
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
    expect(Date.parse(request.pubStartDate)).toBe(NOW - 120 * 60_000);
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

  it('replaces placeholder descriptions with the record details', () => {
    const parse = (cna: Record<string, unknown>, description = 'No description provided') =>
      parseCveRecord({
        ...programRecord('CVE-2026-79891', '2026-10-22T19:06:26.615Z'),
        containers: { cna: { descriptions: [{ lang: 'en', value: description }], ...cna } },
      })!;
    const title = 'Unauthenticated Buffer Overflow Vulnerability leads to Remote Code Execution in AOS-8';
    // Placeholders seen from HPE and OX, which have published dozens of them.
    const hpe = parse({
      title,
      affected: [{ vendor: 'Hewlett Packard Enterprise (HPE)', product: 'Unknown product' }],
    });
    expect(message(hpe)).toContain(`\n\n${title}\n\n`);
    expect(message(hpe)).toContain('Published: 2026-10-22 19:06:26 UTC\n');
    expect(
      parse(
        {
          affected: [
            { vendor: 'Open-Xchange GmbH', product: 'OX Dovecot Pro' },
            { vendor: 'Open-Xchange GmbH', product: 'OX Dovecot CE' },
          ],
          problemTypes: [{ descriptions: [{ lang: 'en', type: 'CWE', description: 'Improper Access Control' }] }],
        },
        'None None None No publicly available exploits are known.',
      ).description,
    ).toBe('Improper Access Control in OX Dovecot Pro, OX Dovecot CE');
    expect(
      parse({ affected: [{ vendor: 'Hewlett Packard Enterprise (HPE)', product: 'Unknown product' }] }).description,
    ).toBe('Vulnerability in Hewlett Packard Enterprise (HPE)');
    expect(parse({ title: 'n/a', problemTypes: [{ descriptions: [{ description: 'n/a' }] }] }, ' ').description).toBe(
      'No description is available yet.',
    );
    // Real descriptions are kept, including short and non-English ones.
    for (const description of [
      'Recently published vulnerability.',
      'IBM Langflow OSS 1.0.0 through 1.11.5.',
      '缓冲区溢出',
    ]) {
      expect(parse({ title }, description).description).toBe(description);
    }
    // Wrapped lines are joined, but paragraph breaks and list items are kept.
    expect(
      parse({}, 'A NULL pointer dereference occurs when the\nremote peer sends keys.\nFixed by:\n- one\n2) two')
        .description,
    ).toBe('A NULL pointer dereference occurs when the remote peer sends keys. Fixed by:\n- one\n2) two');
    // Apache separates paragraphs with four line breaks.
    expect(
      parse({}, 'Exhausts a worker pool.\r\n\r\n\r\n\r\n  This issue affects\tX.\n\n\n\nUpgrade.').description,
    ).toBe('Exhausts a worker pool.\n\nThis issue affects X.\n\nUpgrade.');
    // NVD records have no other fields to fall back on.
    const nvd = parseCve(
      rawCve('CVE-2026-79891', { descriptions: [{ lang: 'en', value: 'No description provided' }] }),
    );
    expect(nvd?.description).toBe('No description is available yet.');
  });

  it('shows a severity the CNA rated in words until a CVSS score is published', () => {
    const rated = (metrics: unknown[]) =>
      parseCveRecord({ ...programRecord(), containers: { cna: { ...programRecord().containers.cna, metrics } } })!;
    // As Apache, OpenSSL, and Red Hat publish them.
    const apache = rated([{ other: { type: 'Textual description of severity', content: { text: 'moderate' } } }]);
    expect(apache).toMatchObject({ severity: 'MODERATE', score: null, parser: PARSER_VERSION });
    expect(message(apache)).toContain('\nMODERATE · no CVSS score yet\n');
    const openssl = { type: 'https://openssl-library.org/policies/general/security-policy/', content: { text: 'Low' } };
    expect(rated([{ format: 'other', other: openssl }]).severity).toBe('LOW');
    const redhat = {
      type: 'Red Hat severity rating',
      content: { value: 'Important', namespace: 'https://redhat.test' },
    };
    expect(rated([{ other: redhat }]).severity).toBe('IMPORTANT');
    expect(
      rated([
        { other: { type: 'Textual description of severity', content: { text: 'low' } } },
        { cvssV3_1: { version: '3.1', baseScore: 9.8, baseSeverity: 'CRITICAL' } },
      ]),
    ).toMatchObject({ severity: 'CRITICAL', score: 9.8 });
    // Other text in "other" metrics is not a rating.
    expect(rated([{ other: { type: 'Impact', content: { text: 'Remote code execution' } } }]).severity).toBe('UNKNOWN');
    expect(message(rated([]))).toContain('\nUNKNOWN · not scored yet\n');
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

describe('requested CVEs', () => {
  const ID = 'CVE-2021-44228';
  const PUBLISHED = '2021-12-10T10:15:09.143Z';
  const request = (id = ID) =>
    env.DB.prepare('INSERT INTO send_requests (cve_id, requested_at) VALUES (?, ?)').bind(id, NOW).run();
  const requestRow = (id = ID) =>
    env.DB.prepare('SELECT attempts, next_attempt_at, failed_at, last_error FROM send_requests WHERE cve_id = ?')
      .bind(id)
      .first();
  const scored = (id = ID, published = PUBLISHED) => {
    const record = programRecord(id, published);
    return {
      ...record,
      containers: {
        cna: {
          ...record.containers.cna,
          metrics: [{ cvssV3_1: { version: '3.1', baseScore: 10, baseSeverity: 'CRITICAL' } }],
        },
      },
    };
  };

  it('resends an already delivered CVE to both destinations on the next live run', async () => {
    const { rt, mockFetch } = clock();
    await seed([{ ...cve(), id: ID, published: PUBLISHED }]);
    await env.DB.prepare("UPDATE deliveries SET sent_at = ?, attempts = 1, message_id = '7'")
      .bind(NOW - 60_000)
      .run();
    await request();
    mockFetch.mockImplementation(async (url) =>
      String(url) === DELTA_URL
        ? delta([])
        : String(url).includes('search.cve.org')
          ? searchPage([])
          : String(url) === recordUrl(ID)
            ? Response.json(scored())
            : String(url).includes('telegram')
              ? Response.json({ ok: true })
              : Response.json({ id: 'sent' }),
    );
    await runLive(botEnv(), rt);
    expect(mockFetch.mock.calls.every(([url]) => !String(url).includes('nist.gov'))).toBe(true);
    const sends = mockFetch.mock.calls.filter(([url]) => /telegram|discord/.test(String(url)));
    expect(sends).toHaveLength(2);
    // A resend posts a new message rather than editing the earlier alert.
    expect(String(sends[0]![0])).toMatch(/\/sendMessage$/);
    expect(sends.map(([, init]) => init?.method)).toEqual(['POST', 'POST']);
    expect(JSON.parse(String(sends[0]![1]?.body)).text).toMatch(/^CVE-2021-44228\nCRITICAL · 10\.0\/10/);
    expect(await env.DB.prepare('SELECT COUNT(*) AS n FROM deliveries WHERE sent_at = ?').bind(NOW).first('n')).toBe(2);
    expect(await requestRow()).toBeNull();
    const stored = JSON.parse((await env.DB.prepare('SELECT payload FROM cves').first<string>('payload'))!);
    expect(stored).toMatchObject({ requested: true, source: 'CVE Program', score: 10 });
  });

  it('uses NVD scores for records without CNA metrics', async () => {
    const { rt, mockFetch } = clock();
    await request();
    mockFetch.mockImplementation(async (url) =>
      String(url) === recordUrl(ID)
        ? Response.json(programRecord(ID, PUBLISHED))
        : page([
            rawCve(ID, {
              published: '2021-12-10T10:15:09.143',
              cisaExploitAdd: '2021-12-10',
              metrics: {
                cvssMetricV31: [
                  { type: 'Primary', cvssData: { version: '3.1', baseScore: 10, baseSeverity: 'CRITICAL' } },
                ],
              },
            }),
          ]),
    );
    await processRequests(botEnv(), rt);
    const nvd = new URL(String(mockFetch.mock.calls[1]![0]));
    expect(nvd.origin + nvd.pathname).toBe(NVD_URL);
    expect(nvd.searchParams.get('cveId')).toBe(ID);
    const stored = JSON.parse((await env.DB.prepare('SELECT payload FROM cves').first<string>('payload'))!);
    expect(stored).toMatchObject({
      source: 'NVD',
      description: 'Recently published vulnerability.',
      score: 10,
      exploited: true,
      requested: true,
    });
    expect(await env.DB.prepare('SELECT COUNT(*) AS n FROM deliveries WHERE sent_at IS NULL').first('n')).toBe(2);
  });

  it('sends the unscored record when NVD is unavailable', async () => {
    const { rt, mockFetch } = clock();
    await request();
    mockFetch.mockImplementation(async (url) =>
      String(url) === recordUrl(ID) ? Response.json(programRecord(ID, PUBLISHED)) : new Response(null, { status: 503 }),
    );
    await processRequests(botEnv(), rt);
    const stored = JSON.parse((await env.DB.prepare('SELECT payload FROM cves').first<string>('payload'))!);
    expect(stored).toMatchObject({ source: 'CVE Program', score: null, published: PUBLISHED });
    expect(await requestRow()).toBeNull();
  });

  it('fails missing, unpublished, and malformed IDs once without retrying', async () => {
    const { rt, mockFetch, advance } = clock();
    const rejected = programRecord('CVE-2026-50001');
    await Promise.all([request('CVE-2026-50000'), request('CVE-2026-50001'), request('cve-1')]);
    mockFetch.mockImplementation(async (url) =>
      String(url) === recordUrl('CVE-2026-50001')
        ? Response.json({ ...rejected, cveMetadata: { ...rejected.cveMetadata, state: 'REJECTED' } })
        : new Response('404: Not Found', { status: 404 }),
    );
    await processRequests(botEnv(), rt);
    expect(mockFetch).toHaveBeenCalledTimes(2);
    expect(await requestRow('CVE-2026-50000')).toMatchObject({
      failed_at: NOW,
      last_error: 'Not found in the CVE List',
    });
    expect(await requestRow('CVE-2026-50001')).toMatchObject({ failed_at: NOW, last_error: 'Not a published CVE' });
    expect(await requestRow('cve-1')).toMatchObject({ failed_at: NOW, last_error: 'Invalid CVE ID' });
    advance(24 * 60 * 60_000);
    await processRequests(botEnv(), rt);
    expect(mockFetch).toHaveBeenCalledTimes(2);
    expect(await env.DB.prepare('SELECT COUNT(*) AS n FROM cves').first('n')).toBe(0);
  });

  it('backs off transient failures and then queues the CVE', async () => {
    const { rt, mockFetch, advance } = clock();
    await request();
    mockFetch.mockResolvedValueOnce(new Response('Unavailable', { status: 503 }));
    await processRequests(botEnv(), rt);
    expect(await requestRow()).toMatchObject({
      attempts: 1,
      next_attempt_at: NOW + 60_000,
      failed_at: null,
      last_error: 'CVE List HTTP 503',
    });
    await processRequests(botEnv(), rt);
    expect(mockFetch).toHaveBeenCalledTimes(1);
    advance(60_000);
    mockFetch.mockResolvedValueOnce(Response.json(scored()));
    await processRequests(botEnv(), rt);
    expect(await requestRow()).toBeNull();
    expect(await env.DB.prepare('SELECT COUNT(*) AS n FROM deliveries').first('n')).toBe(2);
  });

  it('does not let a later poll send a requested CVE again', async () => {
    const { rt, mockFetch } = clock();
    const id = 'CVE-2026-50000';
    await request(id);
    mockFetch.mockResolvedValueOnce(Response.json(scored(id, new Date(NOW - 1000).toISOString())));
    await processRequests(botEnv(), rt);
    expect(mockFetch).toHaveBeenCalledTimes(1);
    await env.DB.prepare('UPDATE deliveries SET sent_at = ?').bind(NOW).run();
    mockFetch.mockResolvedValueOnce(searchPage([programRecord(id)]));
    await pollRecent(botEnv(), rt);
    expect(await env.DB.prepare('SELECT COUNT(*) AS n FROM deliveries WHERE sent_at IS NULL').first('n')).toBe(0);
  });
});

describe('scores published later', () => {
  const ID = 'CVE-2026-50000';
  const MESSAGE = '1300000000000000001';
  const nvdScored = (baseScore = 7.5) =>
    rawCve(ID, {
      metrics: {
        cvssMetricV31: [{ type: 'Primary', cvssData: { version: '3.1', baseScore, baseSeverity: 'HIGH' } }],
      },
    });
  const messaging = async (url: RequestInfo | URL) =>
    String(url).includes('telegram')
      ? Response.json({ ok: true, result: { message_id: 42 } })
      : Response.json({ id: MESSAGE });
  const sends = (mockFetch: ReturnType<typeof clock>['mockFetch']) =>
    mockFetch.mock.calls.filter(([url]) => /telegram|discord/.test(String(url)));
  const deliveries = async () =>
    (
      await env.DB.prepare(
        'SELECT cve_id, channel, sent_at, message_id, last_error FROM deliveries ORDER BY cve_id, channel',
      ).all()
    ).results;

  it('edits sent alerts in place once NVD scores them, and only once', async () => {
    const { rt, mockFetch, advance } = clock();
    mockFetch.mockImplementation(async (url) =>
      String(url).includes('search.cve.org') ? searchPage([programRecord(ID)]) : messaging(url),
    );
    await pollRecent(botEnv(), rt);
    await deliver(botEnv(), rt, NOW + 45_000);
    expect(await deliveries()).toMatchObject([
      { channel: 'discord', message_id: MESSAGE },
      { channel: 'telegram', message_id: '42' },
    ]);

    advance(5 * 60_000);
    mockFetch.mockReset();
    mockFetch.mockImplementation(async (url) =>
      String(url).includes('nist.gov') ? page([nvdScored()]) : messaging(url),
    );
    await run(botEnv(), rt);
    expect(sends(mockFetch)).toHaveLength(2);
    const [telegram, discord] = sends(mockFetch);
    expect(String(telegram![0])).toMatch(/\/editMessageText$/);
    const edited = JSON.parse(String(telegram![1]?.body));
    expect(edited).toMatchObject({ chat_id: '@test_channel', message_id: 42 });
    expect(edited.text).toMatch(/^New CVE: CVE-2026-50000\nHIGH · 7\.5\/10 \(CVSS 3\.1\)\n.*\nSource: CVE Program\n/);
    expect(discord![1]?.method).toBe('PATCH');
    expect(String(discord![0])).toBe(`https://discord.com/api/webhooks/123456789/test-token/messages/${MESSAGE}`);
    const patch = JSON.parse(String(discord![1]?.body));
    expect(patch).not.toHaveProperty('username');
    expect(patch.embeds[0].description).toContain('HIGH · 7.5/10 (CVSS 3.1)');
    expect(await deliveries()).toMatchObject([
      { channel: 'discord', message_id: MESSAGE, last_error: null },
      { channel: 'telegram', message_id: '42', last_error: null },
    ]);
    expect(await env.DB.prepare('SELECT COUNT(*) AS n FROM deliveries WHERE sent_at IS NULL').first('n')).toBe(0);

    // Another source's different score does not edit the alert again.
    advance(5 * 60_000);
    mockFetch.mockReset();
    mockFetch.mockImplementation(async (url) =>
      String(url).includes('nist.gov') ? page([nvdScored(9.8)]) : messaging(url),
    );
    await run(botEnv(), rt);
    expect(sends(mockFetch)).toHaveLength(0);
    const stored = JSON.parse((await env.DB.prepare('SELECT payload FROM cves').first<string>('payload'))!);
    expect(stored).toMatchObject({ score: 7.5, severity: 'HIGH', cvssVersion: '3.1', source: 'CVE Program' });
  });

  it('sends the score with unsent alerts and leaves alerts sent without a message ID', async () => {
    const { rt, mockFetch } = clock();
    await seed([{ ...cve(), id: ID }]);
    await env.DB.prepare("UPDATE deliveries SET sent_at = ? WHERE channel = 'telegram'")
      .bind(NOW - 60_000)
      .run();
    const record = programRecord(ID);
    const metrics = [{ cvssV4_0: { version: '4.0', baseScore: 9.3, baseSeverity: 'CRITICAL' } }];
    mockFetch.mockImplementation(async (url) =>
      String(url).includes('search.cve.org')
        ? searchPage([{ ...record, containers: { cna: { ...record.containers.cna, metrics } } }])
        : messaging(url),
    );
    await pollRecent(botEnv(), rt);
    await deliver(botEnv(), rt, NOW + 45_000);
    expect(sends(mockFetch)).toHaveLength(1);
    const [url, init] = sends(mockFetch)[0]!;
    expect(new URL(String(url)).searchParams.get('wait')).toBe('true');
    expect(init?.method).toBe('POST');
    const embed = JSON.parse(String(init?.body)).embeds[0];
    expect(embed.color).toBe(0xdc2626);
    expect(embed.description).toContain('CRITICAL · 9.3/10 (CVSS 4.0)');
    expect(await deliveries()).toMatchObject([
      { channel: 'discord', message_id: MESSAGE },
      { channel: 'telegram', sent_at: NOW - 60_000, message_id: null },
    ]);
  });

  it('drops edits that cannot succeed without blocking new alerts, and retries the rest', async () => {
    const { rt, mockFetch, advance } = clock();
    const older = 'CVE-2026-50001';
    await seed([
      { ...cve(), id: ID },
      { ...cve(), id: older, published: '2026-10-21T05:00:00.000Z' },
    ]);
    await env.DB.prepare("UPDATE deliveries SET sent_at = ?, message_id = '42' WHERE cve_id = ?")
      .bind(NOW - 60_000, ID)
      .run();
    mockFetch.mockResolvedValueOnce(page([nvdScored()]));
    await poll(botEnv(), rt);
    expect(await env.DB.prepare('SELECT COUNT(*) AS n FROM deliveries WHERE sent_at IS NULL').first('n')).toBe(4);

    mockFetch.mockImplementation(async (url) =>
      String(url).includes('editMessageText')
        ? Response.json(
            { ok: false, error_code: 400, description: 'Bad Request: message to edit not found' },
            { status: 400 },
          )
        : String(url).includes('/messages/')
          ? new Response('Unavailable', { status: 503 })
          : messaging(url),
    );
    await deliver(botEnv(), rt, NOW + 45_000);
    expect(await deliveries()).toEqual([
      { cve_id: ID, channel: 'discord', sent_at: null, message_id: '42', last_error: 'discord HTTP/API 503' },
      { cve_id: ID, channel: 'telegram', sent_at: NOW, message_id: '42', last_error: null },
      { cve_id: older, channel: 'discord', sent_at: null, message_id: null, last_error: null },
      { cve_id: older, channel: 'telegram', sent_at: NOW + 1100, message_id: '42', last_error: null },
    ]);

    advance(60_000);
    mockFetch.mockReset();
    mockFetch.mockImplementation(messaging);
    await deliver(botEnv(), rt, rt.now() + 45_000);
    expect(sends(mockFetch).map(([url, init]) => [init?.method, new URL(String(url)).pathname])).toEqual([
      ['PATCH', '/api/webhooks/123456789/test-token/messages/42'],
      ['POST', '/api/webhooks/123456789/test-token'],
    ]);
    expect(await env.DB.prepare('SELECT COUNT(*) AS n FROM deliveries WHERE sent_at IS NULL').first('n')).toBe(0);
  });
});

describe('CISA KEV additions', () => {
  const ID = 'CVE-2021-44228';
  const PUBLISHED = '2021-12-10T10:15:09.143Z';
  const LAST_MODIFIED = 'Thu, 22 Oct 2026 05:00:00 GMT';
  const entry = (cveID: string, dateAdded = '2026-10-22', extra: Record<string, unknown> = {}) => ({
    cveID,
    vendorProject: 'Apache',
    product: 'Log4j2',
    vulnerabilityName: 'Apache Log4j2 Remote Code Execution Vulnerability',
    dateAdded,
    shortDescription: 'Apache Log4j2 contains a remote code execution vulnerability.',
    requiredAction: 'Apply updates per vendor instructions.',
    dueDate: '2026-11-12',
    knownRansomwareCampaignUse: 'Unknown',
    notes: '',
    cwes: ['CWE-20'],
    ...extra,
  });
  const catalog = (entries: unknown[]) =>
    Response.json(
      {
        title: 'CISA Catalog of Known Exploited Vulnerabilities',
        catalogVersion: '2026.10.22',
        dateReleased: '2026-10-22T05:00:00.000Z',
        count: entries.length,
        vulnerabilities: entries,
      },
      { headers: { 'Last-Modified': LAST_MODIFIED } },
    );
  const requests = async () =>
    (
      await env.DB.prepare('SELECT cve_id, kev FROM send_requests ORDER BY cve_id').all<{
        cve_id: string;
        kev: string;
      }>()
    ).results.map(({ cve_id, kev }) => ({ id: cve_id, kev: JSON.parse(kev) }));
  const catalogSize = () => env.DB.prepare('SELECT COUNT(*) AS n FROM kev_catalog').first('n');

  it('stores the first catalog as a baseline, then requests only CVEs it has not listed before', async () => {
    const { rt, mockFetch, advance } = clock();
    // NOW is 06:00 UTC on October 22, so the 24-hour lookback includes additions on October 21.
    mockFetch.mockResolvedValueOnce(
      catalog([entry('CVE-2026-50001', '2026-10-21'), entry('CVE-2026-50000', '2026-10-20'), entry(ID, '2021-12-10')]),
    );
    await pollKev(botEnv(), rt);
    expect(await requests()).toEqual([
      { id: 'CVE-2026-50001', kev: { added: '2026-10-21', due: '2026-11-12', ransomware: false } },
    ]);
    expect(await catalogSize()).toBe(3);
    await env.DB.prepare('DELETE FROM send_requests').run();

    // An unchanged catalog is not downloaded again.
    advance(60_000);
    mockFetch.mockResolvedValueOnce(new Response(null, { status: 304 }));
    await pollKev(botEnv(), rt);
    expect(new Headers(mockFetch.mock.calls[1]![1]?.headers).get('If-Modified-Since')).toBe(LAST_MODIFIED);
    expect(await env.DB.prepare('SELECT last_success_at FROM kev_poll_state').first('last_success_at')).toBe(
      NOW + 60_000,
    );

    // An old CVE is requested when it is added. An entry removed and listed again is not.
    advance(60_000);
    mockFetch.mockResolvedValueOnce(
      catalog([entry('CVE-2019-0708', '2026-10-22', { knownRansomwareCampaignUse: 'Known' }), entry(ID, '2021-12-10')]),
    );
    await pollKev(botEnv(), rt);
    advance(60_000);
    mockFetch.mockResolvedValueOnce(catalog([entry('CVE-2026-50000', '2026-10-20'), entry(ID, '2021-12-10')]));
    await pollKev(botEnv(), rt);
    expect(await requests()).toEqual([
      { id: 'CVE-2019-0708', kev: { added: '2026-10-22', due: '2026-11-12', ransomware: true } },
    ]);
    expect(await catalogSize()).toBe(4);
  });

  it('sends no earlier additions from the first catalog without a lookback', async () => {
    const { rt, mockFetch } = clock();
    mockFetch.mockResolvedValueOnce(catalog([entry('CVE-2026-50000')]));
    // The generated types only allow the configured value.
    await pollKev({ ...botEnv(), INITIAL_LOOKBACK_HOURS: '0' } as unknown as BotEnv, rt);
    expect(await requests()).toEqual([]);
    expect(await catalogSize()).toBe(1);
  });

  it('sends an already alerted CVE again as a new message with its KEV details', async () => {
    const { rt, mockFetch } = clock();
    await seed([{ ...cve(), id: ID, published: PUBLISHED }]);
    await env.DB.prepare("UPDATE deliveries SET sent_at = ?, attempts = 1, message_id = '7'")
      .bind(NOW - 60_000)
      .run();
    await env.DB.prepare("INSERT INTO kev_catalog (cve_id) VALUES ('CVE-2020-0001')").run();
    const record = programRecord(ID, PUBLISHED);
    const metrics = [{ cvssV3_1: { version: '3.1', baseScore: 10, baseSeverity: 'CRITICAL' } }];
    mockFetch.mockImplementation(async (url) =>
      String(url) === KEV_URL
        ? catalog([entry(ID, '2026-10-22', { knownRansomwareCampaignUse: 'Known' }), entry('CVE-2020-0001')])
        : String(url) === recordUrl(ID)
          ? Response.json({ ...record, containers: { cna: { ...record.containers.cna, metrics } } })
          : String(url).includes('telegram')
            ? Response.json({ ok: true, result: { message_id: 8 } })
            : Response.json({ id: '1300000000000000002' }),
    );
    await pollKev(botEnv(), rt);
    await processRequests(botEnv(), rt);
    await deliver(botEnv(), rt, NOW + 45_000);
    const sends = mockFetch.mock.calls.filter(([url]) => /telegram|discord/.test(String(url)));
    expect(sends).toHaveLength(2);
    expect(String(sends[0]![0])).toMatch(/\/sendMessage$/);
    expect(sends.map(([, init]) => init?.method)).toEqual(['POST', 'POST']);
    const text = JSON.parse(String(sends[0]![1]?.body)).text;
    expect(text).toMatch(
      /^Added to CISA KEV: CVE-2021-44228\nCRITICAL · 10\.0\/10 \(CVSS 3\.1\)\nPublished: 2021-12-10 10:15:09 UTC\nSource: CVE Program\nKEV: added 2026-10-22, due 2026-11-12\nKnown ransomware campaign use\n\nRecently published vulnerability\.\n/,
    );
    expect(text).not.toContain('Known exploited vulnerability (CISA KEV)');
    expect(JSON.parse(String(sends[1]![1]?.body)).embeds[0].color).toBe(0xdc2626);
    expect(
      (await env.DB.prepare('SELECT channel, sent_at, message_id FROM deliveries ORDER BY channel').all()).results,
    ).toEqual([
      { channel: 'discord', sent_at: NOW, message_id: '1300000000000000002' },
      { channel: 'telegram', sent_at: NOW, message_id: '8' },
    ]);
    const stored = JSON.parse((await env.DB.prepare('SELECT payload FROM cves').first<string>('payload'))!);
    expect(stored).toMatchObject({
      kev: { added: '2026-10-22', due: '2026-11-12', ransomware: true },
      exploited: true,
      score: 10,
    });
    expect(stored).not.toHaveProperty('requested');
    expect(await requests()).toEqual([]);
  });

  it('retries a KEV request until the CVE List has the record', async () => {
    const { rt, mockFetch, advance } = clock();
    await env.DB.prepare('INSERT INTO send_requests (cve_id, requested_at, kev) VALUES (?, ?, ?)')
      .bind(ID, NOW, JSON.stringify({ added: '2026-10-22', due: null, ransomware: false }))
      .run();
    mockFetch.mockResolvedValueOnce(new Response('404: Not Found', { status: 404 }));
    await processRequests(botEnv(), rt);
    expect(
      await env.DB.prepare('SELECT attempts, next_attempt_at, failed_at, last_error FROM send_requests').first(),
    ).toEqual({ attempts: 1, next_attempt_at: NOW + 60_000, failed_at: null, last_error: 'Not found in the CVE List' });
    advance(60_000);
    // The record has no score, and NVD is unavailable.
    mockFetch
      .mockResolvedValueOnce(Response.json(programRecord(ID, PUBLISHED)))
      .mockResolvedValueOnce(new Response(null, { status: 503 }));
    await processRequests(botEnv(), rt);
    expect(await requests()).toEqual([]);
    const stored = JSON.parse((await env.DB.prepare('SELECT payload FROM cves').first<string>('payload'))!);
    expect(stored).toMatchObject({ score: null, kev: { due: null } });
    expect(message(stored)).toContain('\nKEV: added 2026-10-22\n');
  });

  it('rejects empty or incomplete catalogs without storing a baseline', async () => {
    const { rt, mockFetch } = clock();
    const valid = { count: 1, vulnerabilities: [entry(ID)] };
    for (const [body, error] of [
      [{ count: 0, vulnerabilities: [] }, 'Invalid CISA KEV catalog'],
      [{ ...valid, count: 2 }, 'Invalid CISA KEV catalog'],
      [{ ...valid, vulnerabilities: [entry('CVE-1')] }, 'Invalid CISA KEV entry'],
      [{ ...valid, vulnerabilities: [entry(ID, '22 October 2026')] }, 'Invalid CISA KEV entry'],
    ] as const) {
      mockFetch.mockResolvedValueOnce(Response.json(body));
      await expect(pollKev(botEnv(), rt)).rejects.toThrow(error);
    }
    expect(await catalogSize()).toBe(0);
  });

  it('backs off a failed catalog poll without stopping NVD recovery', async () => {
    const { rt, mockFetch } = clock();
    mockFetch.mockImplementation(async (url) =>
      String(url) === KEV_URL ? new Response('Unavailable', { status: 503 }) : page([]),
    );
    await run(botEnv(), rt);
    expect(await env.DB.prepare('SELECT next_poll_at, last_error FROM kev_poll_state').first()).toEqual({
      next_poll_at: NOW + 5 * 60_000,
      last_error: 'CISA KEV HTTP 503',
    });
    expect(await env.DB.prepare('SELECT last_success_at, last_error FROM poll_state').first()).toEqual({
      last_success_at: NOW,
      last_error: null,
    });
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
