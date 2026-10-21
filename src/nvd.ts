import { type Cve, type Runtime, record, readJson, retryAfter, ServiceError } from './types';

export const PAGE_SIZE = 200;
export const NVD_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

function timestamp(value: unknown): string {
  if (typeof value !== 'string') throw new ServiceError('Invalid NVD timestamp');
  const utc = /(?:Z|[+-]\d{2}:\d{2})$/.test(value) ? value : `${value}Z`;
  if (!Number.isFinite(Date.parse(utc))) throw new ServiceError('Invalid NVD timestamp');
  return new Date(utc).toISOString();
}

export function parseCve(value: unknown): Cve | null {
  if (!record(value) || typeof value.id !== 'string' || !/^CVE-\d{4}-\d{4,}$/.test(value.id)) {
    throw new ServiceError('Invalid NVD CVE record');
  }
  if (value.vulnStatus === 'Rejected') return null;
  const published = timestamp(value.published);
  const descriptions = Array.isArray(value.descriptions) ? value.descriptions.filter(record) : [];
  const description = descriptions.find((d) => d.lang === 'en') ?? descriptions[0];
  let score: number | null = null;
  let severity = 'UNKNOWN';
  let cvssVersion: string | null = null;
  const metrics = record(value.metrics) ? value.metrics : {};
  for (const key of ['cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']) {
    const entries = metrics[key];
    if (!Array.isArray(entries)) continue;
    const candidates = entries
      .filter(record)
      .filter(
        (entry) =>
          record(entry.cvssData) &&
          typeof entry.cvssData.baseScore === 'number' &&
          entry.cvssData.baseScore >= 0 &&
          entry.cvssData.baseScore <= 10,
      );
    const entry = candidates.find((candidate) => candidate.type === 'Primary') ?? candidates[0];
    if (!entry || !record(entry.cvssData)) continue;
    score = entry.cvssData.baseScore as number;
    const label = entry.cvssData.baseSeverity ?? entry.baseSeverity;
    severity =
      typeof label === 'string'
        ? label.toUpperCase().slice(0, 16)
        : score >= 9
          ? 'CRITICAL'
          : score >= 7
            ? 'HIGH'
            : score >= 4
              ? 'MEDIUM'
              : score > 0
                ? 'LOW'
                : 'NONE';
    cvssVersion = typeof entry.cvssData.version === 'string' ? entry.cvssData.version.slice(0, 8) : null;
    break;
  }
  return {
    id: value.id,
    published,
    description:
      typeof description?.value === 'string'
        ? // Bounds a 200-record JSON batch below D1's 2 MB bound-value limit,
          // including descriptions consisting entirely of multi-byte characters.
          description.value.replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, 2000)
        : 'No description is available yet.',
    severity,
    score,
    cvssVersion,
    exploited: typeof value.cisaExploitAdd === 'string',
    source: 'NVD',
  };
}

export async function fetchPage(
  start: number,
  end: number,
  index: number,
  apiKey: string | undefined,
  rt: Runtime,
): Promise<{ cves: Cve[]; count: number; total: number }> {
  const url = new URL(NVD_URL);
  url.searchParams.set('lastModStartDate', new Date(start).toISOString());
  url.searchParams.set('lastModEndDate', new Date(end).toISOString());
  url.searchParams.set('startIndex', String(index));
  url.searchParams.set('resultsPerPage', String(PAGE_SIZE));
  const response = await rt.fetch(url, {
    headers: apiKey ? { apiKey, Accept: 'application/json' } : { Accept: 'application/json' },
    signal: AbortSignal.timeout(15_000),
    redirect: 'error',
  });
  if (!response.ok) {
    const delay = retryAfter(response, null, rt.now());
    await response.body?.cancel();
    throw new ServiceError(`NVD HTTP ${response.status}`, Math.max(delay, 300_000));
  }
  const body = await readJson(response, 12 * 1024 * 1024);
  if (
    !record(body) ||
    !Array.isArray(body.vulnerabilities) ||
    !Number.isSafeInteger(body.totalResults) ||
    (body.totalResults as number) < 0 ||
    body.startIndex !== index ||
    body.vulnerabilities.length > PAGE_SIZE
  ) {
    throw new ServiceError('Invalid NVD page');
  }
  const total = body.totalResults as number;
  if (body.vulnerabilities.length === 0 && index < total) {
    throw new ServiceError('NVD returned an incomplete page');
  }
  const cves = body.vulnerabilities
    .map((item: unknown) => {
      if (!record(item)) throw new ServiceError('Invalid NVD page item');
      return parseCve(item.cve);
    })
    .filter((cve): cve is Cve => cve !== null);
  return { cves, count: body.vulnerabilities.length, total };
}
