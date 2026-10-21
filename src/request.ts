import { type Runtime, errorDetails, safeError, ServiceError } from './types';

// Keep the deadline active through body consumption, and cancel its timer once done.
// Only log fixed service names and diagnostics: messaging URLs contain credentials.
export async function serviceRequest<T>(
  service: 'NVD' | 'CVE Search' | 'telegram' | 'discord',
  url: string | URL,
  init: RequestInit,
  rt: Runtime,
  timeoutMs: number,
  consume: (response: Response) => Promise<T>,
): Promise<T> {
  const started = rt.now();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(new DOMException('Request timed out', 'TimeoutError')), timeoutMs);
  let stage: 'request' | 'response' = 'request';
  let status: number | undefined;
  try {
    // Workers supports follow/manual only. Callers reject non-2xx responses,
    // so manual prevents redirects from forwarding credentials to another host.
    const response = await rt.fetch(url, { ...init, signal: controller.signal, redirect: 'manual' });
    status = response.status;
    stage = 'response';
    const result = await consume(response);
    console.log(JSON.stringify({ event: 'service_request_succeeded', service, status, elapsedMs: rt.now() - started }));
    return result;
  } catch (error) {
    console.error(
      JSON.stringify({
        event: 'service_request_failed',
        service,
        method: init.method ?? 'GET',
        stage,
        status,
        elapsedMs: rt.now() - started,
        timeoutMs,
        timedOut: controller.signal.aborted,
        error: safeError(error),
        ...errorDetails(error),
      }),
    );
    if (error instanceof ServiceError) throw error;
    throw new ServiceError(`${service} ${stage} failed: ${safeError(error)}`);
  } finally {
    clearTimeout(timer);
  }
}
