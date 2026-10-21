import { afterEach, describe, expect, it, vi } from 'vitest';
import { serviceRequest } from '../src/request';
import { type Runtime, readJson, safeError } from '../src/types';

afterEach(() => vi.restoreAllMocks());

describe('service request diagnostics', () => {
  it('reports the request stage and network cause without leaking credentials', async () => {
    const logs = vi.spyOn(console, 'error').mockImplementation(() => {});
    let now = 1000;
    const rt: Runtime = {
      now: () => now,
      sleep: async () => {},
      fetch: async () => {
        now += 123;
        throw new TypeError('Failed https://api.telegram.org/bot123:secret/sendMessage', {
          cause: { code: 'ECONNRESET', message: 'secret' },
        });
      },
    };
    await expect(
      serviceRequest(
        'telegram',
        'https://api.telegram.org/bot123:secret/sendMessage',
        { method: 'POST' },
        rt,
        10_000,
        async (r) => r,
      ),
    ).rejects.toThrow('telegram request failed');
    expect(JSON.parse(String(logs.mock.calls[0]![0]))).toMatchObject({
      event: 'service_request_failed',
      service: 'telegram',
      method: 'POST',
      stage: 'request',
      elapsedMs: 123,
      timeoutMs: 10_000,
      timedOut: false,
      errorType: 'TypeError',
      causeCode: 'ECONNRESET',
    });
    expect(JSON.stringify(logs.mock.calls)).not.toMatch(/secret|api\.telegram\.org/);
  });

  it('identifies malformed JSON without logging the response body', async () => {
    const logs = vi.spyOn(console, 'error').mockImplementation(() => {});
    const rt: Runtime = {
      now: () => 0,
      sleep: async () => {},
      fetch: async () => new Response('secret-response-body'),
    };
    await expect(serviceRequest('NVD', 'https://example.com', {}, rt, 1000, (r) => readJson(r, 1024))).rejects.toThrow(
      'NVD response failed: Invalid JSON response',
    );
    expect(JSON.parse(String(logs.mock.calls[0]![0]))).toMatchObject({
      stage: 'response',
      status: 200,
      errorType: 'SyntaxError',
    });
    expect(JSON.stringify(logs.mock.calls)).not.toContain('secret-response-body');
  });

  it('enforces the deadline while consuming a stalled body', async () => {
    const logs = vi.spyOn(console, 'error').mockImplementation(() => {});
    const rt: Runtime = {
      now: () => Date.now(),
      sleep: async () => {},
      fetch: async (_input, init) =>
        new Response(
          new ReadableStream({
            start(controller) {
              init!.signal!.addEventListener('abort', () => controller.error(init!.signal!.reason), { once: true });
            },
          }),
        ),
    };
    await expect(serviceRequest('NVD', 'https://example.com', {}, rt, 5, (r) => readJson(r, 1024))).rejects.toThrow(
      'Request timed out',
    );
    expect(JSON.parse(String(logs.mock.calls[0]![0]))).toMatchObject({
      stage: 'response',
      status: 200,
      timedOut: true,
      errorType: 'TimeoutError',
    });
  });

  it('clears the deadline after success', async () => {
    const clear = vi.spyOn(globalThis, 'clearTimeout');
    const rt: Runtime = { now: () => 0, sleep: async () => {}, fetch: async () => Response.json({ ok: true }) };
    await expect(serviceRequest('NVD', 'https://example.com', {}, rt, 1000, (r) => readJson(r, 1024))).resolves.toEqual(
      { ok: true },
    );
    expect(clear).toHaveBeenCalledTimes(1);
  });

  it('does not trust custom error names or cause codes', () => {
    const error = new Error('secret', { cause: { code: 'secret' } });
    error.name = 'secret';
    expect(safeError(error)).toBe('Request or processing failed (UnknownError)');
  });
});
