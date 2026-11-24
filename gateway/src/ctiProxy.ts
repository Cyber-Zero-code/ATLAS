/**
 * Project ATLAS — Gateway Threat-Intelligence Proxy Service
 *
 * Security & Isolation Rules:
 * - Each upstream source stays OFF unless its required environment variables are set.
 * - API keys/tokens are kept strictly server-side and redacted from every error, response, and log.
 * - Outbound requests enforce HTTPS, explicit allowed hostnames derived from config,
 *   pre-connection DNS resolution checks blocking private/loopback/link-local/metadata/ULA IPs,
 *   redirect blocking (manual redirect rejection), 10s request timeouts, and 5 MB max response body.
 * - Responses are cached per source in memory for 15 minutes and rate-limited per org (30 req/min).
 */

import dns from 'node:dns/promises';
import type http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import type { Readable } from 'node:stream';
import { isUnsafeInfrastructureTarget } from './policy.js';
import type {
  CtiConfig,
  CtiFailedSource,
  CtiSourceId,
  CtiSourceStatus,
  NormalizedCtiIndicator,
  NormalizedCtiIndicatorType,
} from './types.js';

export const CTI_CACHE_TTL_MS = 15 * 60 * 1000;
export const CTI_REQUEST_TIMEOUT_MS = 10_000;
export const CTI_MAX_RESPONSE_BYTES = 5 * 1024 * 1024;
export const CTI_ORG_RATE_LIMIT_PER_MIN = 30;

export const VALID_CTI_SOURCES: readonly CtiSourceId[] = [
  'ALIENVAULT_OTX',
  'ABUSE_CH',
  'MISP',
  'TAXII_2_1',
];

export const VALID_CTI_TYPES: readonly NormalizedCtiIndicatorType[] = [
  'ip',
  'cidr',
  'domain',
  'hostname',
  'url',
  'hash',
  'certificate',
  'malware',
  'threat_actor',
  'cve',
];

export function loadCtiConfigFromEnv(env = process.env): CtiConfig {
  return {
    otxApiKey: env.OTX_API_KEY?.trim() || undefined,
    abuseChAuthKey: env.ABUSECH_AUTH_KEY?.trim() || undefined,
    mispUrl: env.MISP_URL?.trim() || undefined,
    mispApiKey: env.MISP_API_KEY?.trim() || undefined,
    taxiiApiRoot: env.TAXII_API_ROOT?.trim() || undefined,
    taxiiCollectionId: env.TAXII_COLLECTION_ID?.trim() || undefined,
  };
}

export class CtiProxyError extends Error {
  constructor(
    public readonly statusCode: number,
    message: string
  ) {
    super(message);
    this.name = 'CtiProxyError';
  }
}

export function collectConfiguredSecrets(config: CtiConfig): string[] {
  return [config.otxApiKey, config.abuseChAuthKey, config.mispApiKey].filter(
    (s): s is string => Boolean(s && s.trim().length > 0)
  );
}

export function redactSecrets(input: string, secrets: string[]): string {
  let out = String(input || '');
  for (const secret of secrets) {
    if (!secret) continue;
    out = out.split(secret).join('[REDACTED]');
    const encoded = encodeURIComponent(secret);
    if (encoded !== secret) {
      out = out.split(encoded).join('[REDACTED]');
    }
  }
  out = out.replace(/((?:Bearer|Auth-Key|X-OTX-API-KEY|Authorization)\s*[:=]?\s*)[A-Za-z0-9._~+/=-]{8,}/gi, '$1[REDACTED]');
  return out;
}

function parseIpv4Octets(ip: string): [number, number, number, number] | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  const nums = parts.map((p) => (/^\d{1,3}$/.test(p) ? Number(p) : -1));
  if (nums.some((n) => n < 0 || n > 255)) return null;
  return [nums[0], nums[1], nums[2], nums[3]];
}

export function isPrivateOrReservedIp(rawIp: string): string | null {
  const ip = rawIp.trim().toLowerCase();
  const ipVer = net.isIP(ip);
  if (ipVer === 0) return `Unrecognized IP address "${rawIp}".`;

  if (ipVer === 4) {
    const octets = parseIpv4Octets(ip);
    if (!octets) return `Malformed IPv4 address "${rawIp}".`;
    const [o1, o2] = octets;
    if (o1 === 0) return 'Unspecified IPv4 range 0.0.0.0/8 is blocked.';
    if (o1 === 10) return 'Private RFC1918 IPv4 range 10.0.0.0/8 is blocked.';
    if (o1 === 100 && o2 >= 64 && o2 <= 127) return 'Shared CGNAT range 100.64.0.0/10 is blocked.';
    if (o1 === 127) return 'Loopback IPv4 range 127.0.0.0/8 is blocked.';
    if (o1 === 169 && o2 === 254) return 'Link-local / cloud metadata range 169.254.0.0/16 is blocked.';
    if (o1 === 172 && o2 >= 16 && o2 <= 31) return 'Private RFC1918 IPv4 range 172.16.0.0/12 is blocked.';
    if (o1 === 192 && o2 === 168) return 'Private RFC1918 IPv4 range 192.168.0.0/16 is blocked.';
    if (o1 >= 224) return 'Multicast or reserved IPv4 range 224.0.0.0+ is blocked.';
    return null;
  }

  // IPv6 checks
  const noZone = ip.split('%')[0];
  if (noZone === '::' || noZone === '::1') {
    return 'Loopback or unspecified IPv6 address is blocked.';
  }
  if (noZone.startsWith('fe80:') || noZone.startsWith('fe80') || /^fe[89ab][0-9a-f]:/i.test(noZone)) {
    return 'Link-local IPv6 address is blocked.';
  }
  if (/^f[cd][0-9a-f]{2}:/i.test(noZone) || /^f[cd][0-9a-f]{2}$/i.test(noZone)) {
    return 'Unique local IPv6 address (fc00::/7) is blocked.';
  }
  if (noZone.startsWith('ff')) {
    return 'Multicast IPv6 address is blocked.';
  }
  // Check IPv4-mapped IPv6 addresses (`::ffff:10.0.0.1` or `::ffff:0a00:0001`)
  if (noZone.startsWith('::ffff:')) {
    const tail = noZone.slice(7);
    if (net.isIPv4(tail)) {
      return isPrivateOrReservedIp(tail);
    }
    const hexParts = tail.split(':');
    if (hexParts.length === 2 && /^[0-9a-f]{1,4}$/.test(hexParts[0]) && /^[0-9a-f]{1,4}$/.test(hexParts[1])) {
      const hi = parseInt(hexParts[0], 16);
      const lo = parseInt(hexParts[1], 16);
      const mappedIpv4 = `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
      return isPrivateOrReservedIp(mappedIpv4);
    }
  }
  return null;
}

export interface DnsLookupEntry {
  address: string;
  family: number;
}

export type DnsLookupFn = (hostname: string) => Promise<DnsLookupEntry[]>;

export type UpstreamHttpTransport = (params: {
  url: URL;
  method: 'GET' | 'POST';
  headers: Record<string, string>;
  body?: string;
  resolvedAddress: string;
  resolvedFamily: number;
  timeoutMs: number;
  maxBytes: number;
}) => Promise<{ statusCode: number; bodyText: string }>;

const defaultDnsLookup: DnsLookupFn = async (hostname) => {
  const res = await dns.lookup(hostname, { all: true });
  return res.map((r) => ({ address: r.address, family: r.family }));
};

export function readBoundedHttpStream(
  stream: Readable,
  headers: http.IncomingHttpHeaders,
  statusCode: number,
  maxBytes: number
): Promise<{ statusCode: number; bodyText: string }> {
  return new Promise((resolve, reject) => {
    if (statusCode >= 300 && statusCode < 400) {
      stream.resume();
      reject(new Error(`Upstream redirect (HTTP ${statusCode}) blocked by proxy policy.`));
      return;
    }
    const contentLenHeader = headers['content-length'];
    if (contentLenHeader) {
      const declaredLen = Number(contentLenHeader);
      if (Number.isFinite(declaredLen) && declaredLen > maxBytes) {
        stream.destroy();
        reject(new Error(`Upstream response exceeds ${maxBytes} byte cap.`));
        return;
      }
    }

    const chunks: Buffer[] = [];
    let total = 0;
    let settled = false;
    stream.on('data', (chunk: Buffer) => {
      if (settled) return;
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      total += buf.length;
      if (total > maxBytes) {
        settled = true;
        stream.destroy();
        reject(new Error(`Upstream response exceeded ${maxBytes} byte cap.`));
        return;
      }
      chunks.push(buf);
    });
    stream.on('end', () => {
      if (settled) return;
      settled = true;
      resolve({ statusCode, bodyText: Buffer.concat(chunks).toString('utf8') });
    });
    stream.on('error', (err) => {
      if (settled) return;
      settled = true;
      reject(err);
    });
  });
}

const defaultHttpsTransport: UpstreamHttpTransport = async ({
  url,
  method,
  headers,
  body,
  resolvedAddress,
  resolvedFamily,
  timeoutMs,
  maxBytes,
}) => {
  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        protocol: url.protocol,
        hostname: url.hostname,
        port: url.port ? Number(url.port) : 443,
        path: `${url.pathname}${url.search}`,
        method,
        headers,
        servername: url.hostname,
        lookup: (_host, opts, cb) => {
          if (opts && (opts as { all?: boolean }).all) {
            (cb as unknown as (err: Error | null, res: Array<{ address: string; family: number }>) => void)(
              null,
              [{ address: resolvedAddress, family: resolvedFamily }]
            );
          } else {
            cb(null, resolvedAddress, resolvedFamily);
          }
        },
      },
      (res) => {
        readBoundedHttpStream(res, res.headers, res.statusCode ?? 0, maxBytes).then(resolve, reject);
      }
    );

    req.setTimeout(timeoutMs, () => {
      req.destroy(new Error(`Upstream request timed out after ${timeoutMs} ms.`));
    });
    req.on('error', (err) => reject(err));
    if (body) req.write(body);
    req.end();
  });
};

export async function validateAndResolveEgressUrl(
  rawUrl: string,
  allowedHostnames: Set<string>,
  dnsLookupFn: DnsLookupFn
): Promise<{ url: URL; resolvedAddress: string; resolvedFamily: number }> {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new Error('Malformed CTI endpoint URL.');
  }
  if (parsed.protocol !== 'https:') {
    throw new Error('Only HTTPS endpoints are permitted for outbound CTI proxy fetches.');
  }
  if (parsed.username || parsed.password) {
    throw new Error('Embedded credentials in CTI URL are prohibited.');
  }

  const host = parsed.hostname.toLowerCase();
  if (!allowedHostnames.has(host)) {
    throw new Error(`CTI hostname "${host}" is not in configured proxy allowlist.`);
  }

  const infraBlock = isUnsafeInfrastructureTarget(host);
  if (infraBlock) {
    throw new Error(infraBlock);
  }

  if (net.isIP(host) !== 0) {
    const ipReason = isPrivateOrReservedIp(host);
    if (ipReason) throw new Error(ipReason);
    return { url: parsed, resolvedAddress: host, resolvedFamily: net.isIPv6(host) ? 6 : 4 };
  }

  const addresses = await dnsLookupFn(host);
  if (!addresses || addresses.length === 0) {
    throw new Error(`DNS resolution failed for "${host}".`);
  }
  for (const entry of addresses) {
    const ipReason = isPrivateOrReservedIp(entry.address);
    if (ipReason) {
      throw new Error(`Egress blocked for "${host}": ${ipReason}`);
    }
  }
  return {
    url: parsed,
    resolvedAddress: addresses[0].address,
    resolvedFamily: addresses[0].family,
  };
}

function normalizeIsoTimestamp(value: unknown, fallbackIso: string): string {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return new Date(value > 1e12 ? value : value * 1000).toISOString();
  }
  if (typeof value === 'string' && value.trim()) {
    const ms = Date.parse(value.trim());
    if (!Number.isNaN(ms)) return new Date(ms).toISOString();
  }
  return fallbackIso;
}

function normalizeStixPatternValue(pattern: string): Array<{ type: NormalizedCtiIndicatorType; value: string }> {
  const out: Array<{ type: NormalizedCtiIndicatorType; value: string }> = [];
  const regex = /\[?\s*([a-z0-9_-]+):([a-z0-9_.'-]+)\s*=\s*'([^']+)'/gi;
  let match: RegExpExecArray | null;
  while ((match = regex.exec(pattern)) !== null) {
    const objType = match[1].toLowerCase();
    const attr = match[2].toLowerCase();
    const val = match[3].trim();
    if (!val) continue;
    if (objType === 'ipv4-addr' || objType === 'ipv6-addr') {
      out.push({ type: val.includes('/') ? 'cidr' : 'ip', value: val });
    } else if (objType === 'domain-name') {
      out.push({ type: 'domain', value: val });
    } else if (objType === 'url') {
      out.push({ type: 'url', value: val });
    } else if (objType === 'file' && attr.includes('hashes')) {
      out.push({ type: 'hash', value: val });
    } else if (objType === 'x509-certificate') {
      out.push({ type: 'certificate', value: val });
    }
  }
  return out;
}

function mapOtxType(otxType: string): NormalizedCtiIndicatorType | null {
  const lower = otxType.trim().toLowerCase();
  if (lower === 'ipv4' || lower === 'ipv6') return 'ip';
  if (lower === 'cidr') return 'cidr';
  if (lower === 'domain') return 'domain';
  if (lower === 'hostname') return 'hostname';
  if (lower === 'url' || lower === 'uri') return 'url';
  if (lower.startsWith('filehash')) return 'hash';
  if (lower === 'cve') return 'cve';
  return null;
}

function mapMispType(mispType: string): NormalizedCtiIndicatorType | null {
  const lower = mispType.trim().toLowerCase();
  if (lower === 'ip-src' || lower === 'ip-dst') return 'ip';
  if (lower === 'domain') return 'domain';
  if (lower === 'hostname') return 'hostname';
  if (lower === 'url' || lower === 'uri') return 'url';
  if (lower === 'md5' || lower === 'sha1' || lower === 'sha256' || lower === 'sha512') return 'hash';
  if (lower === 'vulnerability') return 'cve';
  return null;
}

function mapThreatFoxType(iocType: string): NormalizedCtiIndicatorType | null {
  const lower = iocType.trim().toLowerCase();
  if (lower === 'ip:port' || lower === 'ip') return 'ip';
  if (lower === 'domain') return 'domain';
  if (lower === 'url') return 'url';
  if (lower.includes('hash') || lower === 'md5' || lower === 'sha256') return 'hash';
  return null;
}

export function normalizeOtxPayload(payload: any, nowIso: string): NormalizedCtiIndicator[] {
  const pulses = Array.isArray(payload?.results) ? payload.results : [];
  const out: NormalizedCtiIndicator[] = [];
  for (const pulse of pulses) {
    if (!pulse || typeof pulse !== 'object') continue;
    const tags = Array.isArray(pulse.tags) ? pulse.tags.map(String).slice(0, 12) : [];
    const indicators = Array.isArray(pulse.indicators) ? pulse.indicators : [];
    for (const ind of indicators) {
      if (!ind?.indicator || !ind?.type) continue;
      const mappedType = mapOtxType(String(ind.type));
      if (!mappedType) continue;
      out.push({
        type: mappedType,
        value: String(ind.indicator).trim(),
        source: 'ALIENVAULT_OTX',
        source_ref: `otx:pulse:${pulse.id || 'unknown'}:${ind.id || ind.indicator}`,
        first_seen: normalizeIsoTimestamp(ind.created || pulse.created, nowIso),
        last_seen: pulse.modified ? normalizeIsoTimestamp(pulse.modified, nowIso) : null,
        confidence: 70,
        tags,
      });
    }
  }
  return out;
}

export function normalizeMispPayload(payload: any, nowIso: string): NormalizedCtiIndicator[] {
  const attrs = Array.isArray(payload?.response?.Attribute)
    ? payload.response.Attribute
    : Array.isArray(payload?.Attribute)
    ? payload.Attribute
    : [];
  const out: NormalizedCtiIndicator[] = [];
  for (const attr of attrs) {
    if (!attr?.value || !attr?.type) continue;
    const mappedType = mapMispType(String(attr.type));
    if (!mappedType) continue;
    const tags = Array.isArray(attr.Tag)
      ? attr.Tag.map((t: any) => (typeof t?.name === 'string' ? t.name : '')).filter(Boolean).slice(0, 12)
      : [];
    out.push({
      type: mappedType,
      value: String(attr.value).trim(),
      source: 'MISP',
      source_ref: `misp:attr:${attr.uuid || attr.id || attr.value}`,
      first_seen: normalizeIsoTimestamp(attr.timestamp, nowIso),
      last_seen: null,
      confidence: attr.to_ids ? 80 : 55,
      tags,
    });
  }
  return out;
}

export function normalizeTaxiiPayload(payload: any, collectionId: string, nowIso: string): NormalizedCtiIndicator[] {
  const objects = Array.isArray(payload?.objects) ? payload.objects : [];
  const out: NormalizedCtiIndicator[] = [];
  for (const obj of objects) {
    if (!obj || typeof obj !== 'object') continue;
    const objType = String(obj.type || '').toLowerCase();
    const confidence = typeof obj.confidence === 'number' ? Math.max(0, Math.min(100, Math.round(obj.confidence))) : 65;
    const firstSeen = normalizeIsoTimestamp(obj.valid_from || obj.created, nowIso);
    const lastSeen = obj.valid_until
      ? normalizeIsoTimestamp(obj.valid_until, nowIso)
      : obj.modified
      ? normalizeIsoTimestamp(obj.modified, nowIso)
      : null;
    const tags = Array.isArray(obj.labels) ? obj.labels.map(String).slice(0, 12) : [];

    if (objType === 'indicator' && typeof obj.pattern === 'string') {
      const items = normalizeStixPatternValue(obj.pattern);
      for (const item of items) {
        out.push({
          type: item.type,
          value: item.value,
          source: 'TAXII_2_1',
          source_ref: String(obj.id || `taxii:${collectionId}:${item.value}`),
          first_seen: firstSeen,
          last_seen: lastSeen,
          confidence,
          tags,
        });
      }
    } else if (objType === 'malware' && obj.name) {
      out.push({
        type: 'malware',
        value: String(obj.name).trim(),
        source: 'TAXII_2_1',
        source_ref: String(obj.id || `taxii:${collectionId}:${obj.name}`),
        first_seen: firstSeen,
        last_seen: lastSeen,
        confidence,
        tags,
      });
    } else if ((objType === 'threat-actor' || objType === 'intrusion-set') && obj.name) {
      out.push({
        type: 'threat_actor',
        value: String(obj.name).trim(),
        source: 'TAXII_2_1',
        source_ref: String(obj.id || `taxii:${collectionId}:${obj.name}`),
        first_seen: firstSeen,
        last_seen: lastSeen,
        confidence,
        tags,
      });
    } else if (objType === 'vulnerability' && obj.name) {
      out.push({
        type: 'cve',
        value: String(obj.name).trim(),
        source: 'TAXII_2_1',
        source_ref: String(obj.id || `taxii:${collectionId}:${obj.name}`),
        first_seen: firstSeen,
        last_seen: lastSeen,
        confidence,
        tags,
      });
    }
  }
  return out;
}

export function normalizeThreatFoxPayload(payload: any, nowIso: string): NormalizedCtiIndicator[] {
  const rows = Array.isArray(payload?.data) ? payload.data : [];
  const out: NormalizedCtiIndicator[] = [];
  for (const row of rows) {
    if (!row?.ioc || !row?.ioc_type) continue;
    const mapped = mapThreatFoxType(String(row.ioc_type));
    if (!mapped) continue;
    let value = String(row.ioc).trim();
    if (String(row.ioc_type).toLowerCase() === 'ip:port' && value.includes(':')) {
      value = value.split(':')[0];
    }
    const tags = [
      ...(Array.isArray(row.tags) ? row.tags.map(String) : []),
      ...(row.malware_printable ? [String(row.malware_printable)] : []),
    ].slice(0, 12);
    out.push({
      type: mapped,
      value,
      source: 'ABUSE_CH',
      source_ref: `threatfox:${row.id || value}`,
      first_seen: normalizeIsoTimestamp(row.first_seen, nowIso),
      last_seen: row.last_seen ? normalizeIsoTimestamp(row.last_seen, nowIso) : null,
      confidence: typeof row.confidence_level === 'number' ? Math.max(0, Math.min(100, row.confidence_level)) : 75,
      tags,
    });
  }
  return out;
}

export function normalizeUrlhausPayload(payload: any, nowIso: string): NormalizedCtiIndicator[] {
  const rows = Array.isArray(payload?.urls) ? payload.urls : [];
  const out: NormalizedCtiIndicator[] = [];
  for (const row of rows) {
    if (!row?.url) continue;
    const tags = Array.isArray(row.tags) ? row.tags.map(String).slice(0, 12) : [];
    out.push({
      type: 'url',
      value: String(row.url).trim(),
      source: 'ABUSE_CH',
      source_ref: `urlhaus:${row.id || row.url}`,
      first_seen: normalizeIsoTimestamp(row.date_added, nowIso),
      last_seen: row.last_online ? normalizeIsoTimestamp(row.last_online, nowIso) : null,
      confidence: 80,
      tags,
    });
  }
  return out;
}

export function normalizeFeodoPayload(payload: any, nowIso: string): NormalizedCtiIndicator[] {
  const rows = Array.isArray(payload) ? payload : [];
  const out: NormalizedCtiIndicator[] = [];
  for (const row of rows) {
    if (!row?.ip_address) continue;
    const tags = [row.malware, row.status].filter(Boolean).map(String).slice(0, 12);
    out.push({
      type: 'ip',
      value: String(row.ip_address).trim(),
      source: 'ABUSE_CH',
      source_ref: `feodo:${row.ip_address}:${row.port || ''}`,
      first_seen: normalizeIsoTimestamp(row.first_seen, nowIso),
      last_seen: row.last_online ? normalizeIsoTimestamp(row.last_online, nowIso) : null,
      confidence: 85,
      tags,
    });
  }
  return out;
}

interface CacheEntry {
  fetchedAtMs: number;
  indicators: NormalizedCtiIndicator[];
}

export interface CtiProxyOptions {
  dnsLookup?: DnsLookupFn;
  transport?: UpstreamHttpTransport;
  now?: () => number;
  logger?: (level: 'warn' | 'error', message: string) => void;
}

export class CtiProxyService {
  private readonly cache = new Map<CtiSourceId, CacheEntry>();
  private readonly rateWindows = new Map<string, number[]>();
  private readonly secrets: string[];
  private readonly dnsLookup: DnsLookupFn;
  private readonly transport: UpstreamHttpTransport;
  private readonly now: () => number;
  private readonly logger: (level: 'warn' | 'error', message: string) => void;

  constructor(
    private readonly config: CtiConfig,
    options: CtiProxyOptions = {}
  ) {
    this.secrets = collectConfiguredSecrets(config);
    this.dnsLookup = options.dnsLookup || defaultDnsLookup;
    this.transport = options.transport || defaultHttpsTransport;
    this.now = options.now || (() => Date.now());
    this.logger =
      options.logger ||
      ((level, msg) => {
        const clean = this.redact(msg);
        if (level === 'error') console.error(clean);
        else console.warn(clean);
      });
  }

  redact(text: string): string {
    return redactSecrets(text, this.secrets);
  }

  isSourceConfigured(source: CtiSourceId): boolean {
    switch (source) {
      case 'ALIENVAULT_OTX':
        return Boolean(this.config.otxApiKey);
      case 'ABUSE_CH':
        return Boolean(this.config.abuseChAuthKey);
      case 'MISP':
        return Boolean(this.config.mispUrl && this.config.mispApiKey);
      case 'TAXII_2_1':
        return Boolean(this.config.taxiiApiRoot);
    }
  }

  getConfiguredSummary(): Array<{ id: CtiSourceId; configured: boolean }> {
    return VALID_CTI_SOURCES.map((id) => ({
      id,
      configured: this.isSourceConfigured(id),
    }));
  }

  checkRateLimit(orgId: string): boolean {
    const nowMs = this.now();
    const cutoff = nowMs - 60_000;
    const prev = (this.rateWindows.get(orgId) || []).filter((ts) => ts > cutoff);
    if (prev.length >= CTI_ORG_RATE_LIMIT_PER_MIN) {
      this.rateWindows.set(orgId, prev);
      return false;
    }
    prev.push(nowMs);
    this.rateWindows.set(orgId, prev);
    return true;
  }

  private getAllowedHostnames(): Set<string> {
    const allowed = new Set<string>([
      'otx.alienvault.com',
      'threatfox-api.abuse.ch',
      'urlhaus-api.abuse.ch',
      'feodotracker.abuse.ch',
    ]);
    for (const rawUrl of [this.config.mispUrl, this.config.taxiiApiRoot]) {
      if (!rawUrl) continue;
      try {
        allowed.add(new URL(rawUrl).hostname.toLowerCase());
      } catch {
        // invalid URLs fail cleanly in validateAndResolveEgressUrl
      }
    }
    return allowed;
  }

  private async fetchJson(
    rawUrl: string,
    method: 'GET' | 'POST',
    headers: Record<string, string>,
    body?: string
  ): Promise<any> {
    const allowedHosts = this.getAllowedHostnames();
    const resolved = await validateAndResolveEgressUrl(rawUrl, allowedHosts, this.dnsLookup);
    const res = await this.transport({
      url: resolved.url,
      method,
      headers,
      body,
      resolvedAddress: resolved.resolvedAddress,
      resolvedFamily: resolved.resolvedFamily,
      timeoutMs: CTI_REQUEST_TIMEOUT_MS,
      maxBytes: CTI_MAX_RESPONSE_BYTES,
    });
    if (res.statusCode < 200 || res.statusCode >= 300) {
      throw new Error(`Upstream returned HTTP ${res.statusCode}`);
    }
    try {
      return JSON.parse(res.bodyText);
    } catch {
      throw new Error('Upstream returned invalid JSON payload.');
    }
  }

  private async fetchSourceFresh(source: CtiSourceId, nowIso: string): Promise<NormalizedCtiIndicator[]> {
    switch (source) {
      case 'ALIENVAULT_OTX': {
        const json = await this.fetchJson(
          'https://otx.alienvault.com/api/v1/pulses/subscribed?limit=25',
          'GET',
          {
            'X-OTX-API-KEY': this.config.otxApiKey!,
            Accept: 'application/json',
          }
        );
        return normalizeOtxPayload(json, nowIso);
      }

      case 'ABUSE_CH': {
        const authKey = this.config.abuseChAuthKey!;
        const results = await Promise.allSettled([
          this.fetchJson(
            'https://threatfox-api.abuse.ch/api/v1/',
            'POST',
            {
              'Auth-Key': authKey,
              'Content-Type': 'application/json',
              Accept: 'application/json',
            },
            JSON.stringify({ query: 'get_iocs', days: 7 })
          ).then((j) => normalizeThreatFoxPayload(j, nowIso)),
          this.fetchJson(
            'https://urlhaus-api.abuse.ch/v1/urls/recent/limit/50/',
            'GET',
            {
              'Auth-Key': authKey,
              Accept: 'application/json',
            }
          ).then((j) => normalizeUrlhausPayload(j, nowIso)),
          this.fetchJson(
            'https://feodotracker.abuse.ch/downloads/ipblocklist_recent.json',
            'GET',
            {
              'Auth-Key': authKey,
              Accept: 'application/json',
            }
          ).then((j) => normalizeFeodoPayload(j, nowIso)),
        ]);

        const collected: NormalizedCtiIndicator[] = [];
        let okCount = 0;
        let firstErr = '';
        for (const r of results) {
          if (r.status === 'fulfilled') {
            okCount++;
            collected.push(...r.value);
          } else if (!firstErr) {
            firstErr = r.reason instanceof Error ? r.reason.message : String(r.reason);
          }
        }
        if (okCount === 0) {
          throw new Error(firstErr || 'All Abuse.ch endpoints failed.');
        }
        return collected;
      }

      case 'MISP': {
        const base = this.config.mispUrl!.replace(/\/+$/, '');
        const json = await this.fetchJson(
          `${base}/attributes/restSearch`,
          'POST',
          {
            Authorization: this.config.mispApiKey!,
            Accept: 'application/json',
            'Content-Type': 'application/json',
          },
          JSON.stringify({ returnFormat: 'json', limit: 100 })
        );
        return normalizeMispPayload(json, nowIso);
      }

      case 'TAXII_2_1': {
        const root = this.config.taxiiApiRoot!.replace(/\/+$/, '');
        let collectionId = this.config.taxiiCollectionId;
        if (!collectionId) {
          const cols = await this.fetchJson(`${root}/collections/`, 'GET', {
            Accept: 'application/taxii+json;version=2.1, application/json',
          });
          const list = Array.isArray(cols?.collections) ? cols.collections : [];
          const readable = list.find((c: any) => c?.id && c?.can_read !== false);
          if (!readable?.id) {
            throw new Error('No readable TAXII 2.1 collection found.');
          }
          collectionId = String(readable.id);
        }
        const objs = await this.fetchJson(
          `${root}/collections/${encodeURIComponent(collectionId)}/objects/?limit=100`,
          'GET',
          {
            Accept: 'application/taxii+json;version=2.1, application/json',
          }
        );
        return normalizeTaxiiPayload(objs, collectionId, nowIso);
      }
    }
  }

  async getIndicators(params: {
    source?: CtiSourceId;
    type?: NormalizedCtiIndicatorType;
    limit?: number;
  }): Promise<{
    indicators: NormalizedCtiIndicator[];
    sources: CtiSourceStatus[];
    failedSources: CtiFailedSource[];
    cacheTtlSeconds: number;
  }> {
    const nowMs = this.now();
    const nowIso = new Date(nowMs).toISOString();
    const targetSources: readonly CtiSourceId[] = params.source ? [params.source] : VALID_CTI_SOURCES;

    const statuses: CtiSourceStatus[] = [];
    const failedSources: CtiFailedSource[] = [];
    const combined: NormalizedCtiIndicator[] = [];

    await Promise.all(
      targetSources.map(async (src) => {
        if (!this.isSourceConfigured(src)) {
          statuses.push({
            id: src,
            configured: false,
            state: 'unconfigured',
            cached: false,
            indicatorCount: 0,
          });
          return;
        }

        const cached = this.cache.get(src);
        if (cached && nowMs - cached.fetchedAtMs < CTI_CACHE_TTL_MS) {
          combined.push(...cached.indicators);
          statuses.push({
            id: src,
            configured: true,
            state: 'live',
            cached: true,
            indicatorCount: cached.indicators.length,
            checkedAtUtc: new Date(cached.fetchedAtMs).toISOString(),
          });
          return;
        }

        try {
          const fresh = await this.fetchSourceFresh(src, nowIso);
          this.cache.set(src, { fetchedAtMs: nowMs, indicators: fresh });
          combined.push(...fresh);
          statuses.push({
            id: src,
            configured: true,
            state: 'live',
            cached: false,
            indicatorCount: fresh.length,
            checkedAtUtc: nowIso,
          });
        } catch (err: unknown) {
          const rawReason = err instanceof Error ? err.message : 'Upstream fetch failed.';
          const safeReason = this.redact(rawReason).slice(0, 200);
          this.logger('warn', `[ATLAS-CTI-PROXY] Source ${src} failed: ${safeReason}`);
          failedSources.push({ source: src, reason: safeReason });
          statuses.push({
            id: src,
            configured: true,
            state: 'failing',
            cached: false,
            indicatorCount: 0,
            error: safeReason,
            checkedAtUtc: nowIso,
          });
        }
      })
    );

    const filteredByType = params.type
      ? combined.filter((i) => i.type === params.type)
      : combined;

    const limit = Math.max(1, Math.min(500, params.limit ?? 100));
    const orderedStatuses = targetSources.map(
      (id) => statuses.find((s) => s.id === id)!
    );

    return {
      indicators: filteredByType.slice(0, limit),
      sources: orderedStatuses,
      failedSources,
      cacheTtlSeconds: Math.round(CTI_CACHE_TTL_MS / 1000),
    };
  }
}
