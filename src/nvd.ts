import { type Cve, type Runtime, record, readJson, retryAfter, ServiceError } from './types';
import { serviceRequest } from './request';

// NVD streams large pages slowly (200 records took ~20 seconds), and the run lease
// blocks live polls meanwhile. Smaller pages keep each request well inside its deadline.
export const PAGE_SIZE = 100;
export const NVD_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
export const NO_DESCRIPTION = 'No description is available yet.';

// Words that make up the placeholders CNAs publish for empty fields, such as "No
// description provided" or "None None None No publicly available exploits are known."
// A real description always names something outside this list.
const FILLER = new Set(
  `a added an and are available be description details exploits information is known later n/a na no none not
  null pending placeholder product provided publicly published reserved soon tba tbd to undefined unknown
  updated vendor will yet`.split(/\s+/),
);

export function informative(text: string): boolean {
  return text
    .toLowerCase()
    .split(/[^\p{L}\p{N}/]+/u)
    .some((word) => word && !FILLER.has(word));
}

// Keeps paragraph breaks, which some CNAs make with four line breaks, and list items.
// Other line breaks only wrap lines, as in Linux kernel descriptions, so they become
// spaces. Bounds a 200-record JSON batch below D1's 2 MB bound-value limit, including
// text consisting entirely of multi-byte characters.
export function plainText(text: string): string {
  return text
    .replace(/\r\n?/g, '\n')
    .replace(/[\u0000-\u0009\u000b-\u001f\u007f]/g, ' ')
    .replace(/ *\n */g, '\n')
    .replace(/\n{2,}/g, '\n\n')
    .replace(/(?<!\n)\n(?!\n|(?:[-*•]|\d+[.)]) )/g, ' ')
    .trim()
    .slice(0, 2000);
}

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
      typeof description?.value === 'string' && informative(description.value)
        ? plainText(description.value)
        : NO_DESCRIPTION,
    severity,
    score,
    cvssVersion,
    exploited: typeof value.cisaExploitAdd === 'string',
    source: 'NVD',
  };
}

function request(url: URL, apiKey: string | undefined, rt: Runtime, timeoutMs: number): Promise<unknown> {
  return serviceRequest(
    'NVD',
    url,
    { headers: apiKey ? { apiKey, Accept: 'application/json' } : { Accept: 'application/json' } },
    rt,
    timeoutMs,
    async (response) => {
      if (!response.ok) {
        const delay = retryAfter(response, null, rt.now());
        await response.body?.cancel();
        throw new ServiceError(`NVD HTTP ${response.status}`, Math.max(delay, 300_000));
      }
      return readJson(response, 12 * 1024 * 1024);
    },
  );
}

// Returns null when NVD has no record of the CVE yet, or has rejected it.
export async function fetchCve(id: string, apiKey: string | undefined, rt: Runtime): Promise<Cve | null> {
  const url = new URL(NVD_URL);
  url.searchParams.set('cveId', id);
  const body = await request(url, apiKey, rt, 15_000);
  if (!record(body) || !Array.isArray(body.vulnerabilities) || body.vulnerabilities.length > 1) {
    throw new ServiceError('Invalid NVD response');
  }
  const item: unknown = body.vulnerabilities[0];
  if (item === undefined) return null;
  if (!record(item)) throw new ServiceError('Invalid NVD page item');
  const cve = parseCve(item.cve);
  if (cve && cve.id !== id) throw new ServiceError('Invalid NVD CVE record');
  return cve;
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
  // Pages usually arrive in 2-12 seconds from Workers, but some stall past 30.
  const body = await request(url, apiKey, rt, 60_000);
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
