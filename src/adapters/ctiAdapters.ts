/**
 * Project ATLAS — Module D: Threat Intelligence Feed Adapters & Proxy Client
 *
 * Security & Integrity Rules:
 * - Zero API keys or feed secrets are stored or injected in the browser.
 * - Authenticated threat-intelligence feeds (MISP, TAXII 2.1, AlienVault OTX, Abuse.ch)
 *   are queried strictly through the authenticated Linux Execution Gateway CTI proxy
 *   (`GET /api/v1/cti/indicators`) using the operator's AAL2 Supabase session JWT.
 * - Analysts can also ingest local STIX 2.1 JSON bundles or CISA KEV JSON snapshots directly
 *   in the browser; all extracted indicators are tagged `isExternalIntel: true` and
 *   strictly separated from verified ATLAS DB tables.
 */

import { supabase } from '../lib/supabase';
import { validateGatewayEndpointUrl } from './gatewayClient';
import type {
  Asset,
  CtiAdapterDescriptor,
  CtiProviderId,
  CtiProxySourceStatus,
  ExternalIocKind,
  ExternalThreatIndicator,
  Incident,
} from '../types/atlas';

export type ProxyCtiSourceId = 'ALIENVAULT_OTX' | 'ABUSE_CH' | 'MISP' | 'TAXII_2_1';

export interface GatewayNormalizedCtiRecord {
  type:
    | 'ip'
    | 'cidr'
    | 'domain'
    | 'hostname'
    | 'url'
    | 'hash'
    | 'certificate'
    | 'malware'
    | 'threat_actor'
    | 'cve';
  value: string;
  source: ProxyCtiSourceId;
  source_ref: string;
  first_seen: string;
  last_seen: string | null;
  confidence: number;
  tags: string[];
}

export const CTI_ADAPTER_CATALOG: CtiAdapterDescriptor[] = [
  {
    id: 'STIX_2_1',
    name: 'STIX 2.1 Bundle Ingestor',
    protocol: 'OASIS STIX 2.1 JSON',
    status: 'local_bundle_ready',
    requiresServerProxy: false,
    credentialRequirement: 'None for operator-supplied JSON bundles; TAXII transport uses gateway proxy.',
    description:
      'Parses and validates STIX 2.1 indicator, malware, threat-actor, and vulnerability objects locally against ATLAS assets and incidents.',
  },
  {
    id: 'CISA_KEV',
    name: 'CISA Known Exploited Vulnerabilities (KEV)',
    protocol: 'JSON Catalog / Operator Snapshot',
    status: 'local_bundle_ready',
    requiresServerProxy: false,
    credentialRequirement: 'Direct browser fetch disabled; local KEV JSON snapshot ingestion active.',
    description:
      'Ingests CISA KEV catalog JSON files (`vulnerabilities[]`) for vulnerability cross-referencing.',
  },
  {
    id: 'MISP',
    name: 'MISP Threat Sharing Instance',
    protocol: 'Gateway Proxy -> MISP REST (`/attributes/restSearch`)',
    status: 'unconfigured',
    requiresServerProxy: true,
    proxyEndpoint: '/api/v1/cti/indicators',
    credentialRequirement: 'Configured server-side on gateway via `MISP_URL` + `MISP_API_KEY`.',
    description:
      'Fetches IOC attributes via the authenticated gateway CTI proxy; credentials remain strictly server-side.',
  },
  {
    id: 'TAXII_2_1',
    name: 'TAXII 2.1 Discovery & Collections',
    protocol: 'Gateway Proxy -> OASIS TAXII 2.1 HTTPS',
    status: 'unconfigured',
    requiresServerProxy: true,
    proxyEndpoint: '/api/v1/cti/indicators',
    credentialRequirement: 'Configured server-side on gateway via `TAXII_API_ROOT` + optional `TAXII_COLLECTION_ID`.',
    description:
      'Polls approved TAXII 2.1 STIX object collections through the gateway proxy with 15-minute server caching.',
  },
  {
    id: 'ALIENVAULT_OTX',
    name: 'AlienVault OTX DirectConnect',
    protocol: 'Gateway Proxy -> OTX REST v1 (`/api/v1/pulses/subscribed`)',
    status: 'unconfigured',
    requiresServerProxy: true,
    proxyEndpoint: '/api/v1/cti/indicators',
    credentialRequirement: 'Configured server-side on gateway via `OTX_API_KEY`.',
    description:
      'Ingests subscribed OTX pulse indicators through the gateway proxy where `X-OTX-API-KEY` is injected.',
  },
  {
    id: 'ABUSE_CH',
    name: 'Abuse.ch Feeds (ThreatFox / URLhaus / Feodo)',
    protocol: 'Gateway Proxy -> HTTPS JSON API',
    status: 'unconfigured',
    requiresServerProxy: true,
    proxyEndpoint: '/api/v1/cti/indicators',
    credentialRequirement: 'Configured server-side on gateway via `ABUSECH_AUTH_KEY`.',
    description:
      'Aggregates ThreatFox, URLhaus, and Feodo Tracker IOC feeds via the gateway proxy with server-side `Auth-Key`.',
  },
];

/** Extract type & indicator value from STIX 2.1 pattern expression e.g. `[ipv4-addr:value = '203.0.113.5']` */
function extractFromStixPattern(pattern: string): Array<{ type: ExternalIocKind; value: string }> {
  const results: Array<{ type: ExternalIocKind; value: string }> = [];
  const regex = /\[?\s*([a-z0-9_-]+):([a-z0-9_.'-]+)\s*=\s*'([^']+)'/gi;
  let match: RegExpExecArray | null;
  while ((match = regex.exec(pattern)) !== null) {
    const objType = match[1].toLowerCase();
    const attr = match[2].toLowerCase();
    const val = match[3].trim();
    if (!val) continue;

    if (objType === 'ipv4-addr' || objType === 'ipv6-addr') {
      results.push({ type: val.includes('/') ? 'cidr' : 'ip', value: val });
    } else if (objType === 'domain-name') {
      results.push({ type: 'domain', value: val });
    } else if (objType === 'url') {
      try {
        const host = new URL(val).hostname;
        results.push({ type: 'hostname', value: host || val });
      } catch {
        results.push({ type: 'hostname', value: val });
      }
    } else if (objType === 'file' && attr.includes('hashes')) {
      results.push({ type: 'hash', value: val });
    } else if (objType === 'x509-certificate') {
      results.push({ type: 'certificate', value: val });
    }
  }
  return results;
}

function correlateAgainstAtlas(
  valLower: string,
  assets: Asset[],
  incidents: Incident[]
): { matchedAssetIds: string[]; matchedIncidentIds: string[] } {
  const matchedAssetIds: string[] = [];
  const matchedIncidentIds: string[] = [];

  for (const asset of assets) {
    const hay = [
      asset.site_code,
      ...(asset.identifiers?.ip_addresses || []),
      ...(asset.identifiers?.cidrs || []),
      ...(asset.identifiers?.hostnames || []),
      ...(asset.identifiers?.cloud_account_ids || []),
    ]
      .join(' ')
      .toLowerCase();
    if (hay.includes(valLower)) {
      matchedAssetIds.push(asset.id);
    }
  }

  for (const inc of incidents) {
    const sigStr = JSON.stringify(inc.signals || {}).toLowerCase();
    if (inc.event_id.toLowerCase().includes(valLower) || sigStr.includes(valLower)) {
      matchedIncidentIds.push(inc.id);
    }
  }

  return { matchedAssetIds, matchedIncidentIds };
}

function mapNormalizedTypeToIocKind(rawType: GatewayNormalizedCtiRecord['type']): ExternalIocKind {
  if (rawType === 'url') return 'hostname';
  return rawType;
}

function extractCorrelationNeedle(rawType: GatewayNormalizedCtiRecord['type'], value: string): string {
  if (rawType === 'url') {
    try {
      return new URL(value).hostname.toLowerCase() || value.toLowerCase();
    } catch {
      return value.toLowerCase();
    }
  }
  return value.toLowerCase();
}

export function mapProxyIndicatorsToExternal(
  records: GatewayNormalizedCtiRecord[],
  orgId: string,
  assets: Asset[],
  incidents: Incident[],
  existingIndicators: ExternalThreatIndicator[] = [],
  nowMs = Date.now()
): { indicators: ExternalThreatIndicator[]; skippedDuplicates: number } {
  const seenKeys = new Set(existingIndicators.map((i) => `${i.indicatorType}::${i.value.toLowerCase()}`));
  const out: ExternalThreatIndicator[] = [];
  let skippedDuplicates = 0;

  for (const rec of records) {
    const cleanVal = String(rec.value || '').trim();
    if (!cleanVal) continue;
    const indicatorType = mapNormalizedTypeToIocKind(rec.type);
    const key = `${indicatorType}::${cleanVal.toLowerCase()}`;
    if (seenKeys.has(key)) {
      skippedDuplicates++;
      continue;
    }
    seenKeys.add(key);

    const needle = extractCorrelationNeedle(rec.type, cleanVal);
    const { matchedAssetIds, matchedIncidentIds } = correlateAgainstAtlas(needle, assets, incidents);
    const tagsLabel = Array.isArray(rec.tags) && rec.tags.length > 0 ? `Tags: ${rec.tags.join(', ')}` : 'Gateway CTI Proxy';

    out.push({
      id: `ext-proxy-${rec.source.toLowerCase()}-${nowMs}-${out.length}`,
      orgId,
      providerId: rec.source,
      stixId: rec.source_ref,
      indicatorType,
      value: cleanVal,
      sourceName: `${rec.source} (${rec.source_ref})`,
      confidence: Math.max(0, Math.min(100, Math.round(rec.confidence ?? 65))),
      validFrom: rec.first_seen || new Date(nowMs).toISOString(),
      validUntil: rec.last_seen || undefined,
      isExpired: false,
      isExternalIntel: true,
      verificationStatus: 'unverified',
      matchedAssetIds,
      matchedIncidentIds,
      rawSummary: `${rec.source_ref} · ${tagsLabel}`,
      importedAt: new Date(nowMs).toISOString(),
    });
  }

  return { indicators: out, skippedDuplicates };
}

async function getSupabaseJwt(): Promise<string> {
  const { data } = await supabase.auth.getSession();
  const token = data?.session?.access_token;
  if (!token) {
    throw new Error('No active authenticated Supabase AAL2 session found.');
  }
  return token;
}

export async function probeCtiProxySources(
  endpointUrl: string,
  orgId: string
): Promise<CtiProxySourceStatus[]> {
  const check = validateGatewayEndpointUrl(endpointUrl);
  if (!check.valid || !check.normalized) {
    throw new Error(check.reason || 'Invalid gateway URL.');
  }
  const jwt = await getSupabaseJwt();
  const res = await fetch(`${check.normalized}/health`, {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${jwt}`,
      'x-atlas-org-id': orgId,
      Accept: 'application/json',
    },
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(data?.error || `Gateway probe failed (HTTP ${res.status}).`);
  }
  const list = Array.isArray(data?.ctiSources) ? data.ctiSources : [];
  return list.map((s: any) => ({
    id: s.id as ProxyCtiSourceId,
    configured: Boolean(s.configured),
    state: s.configured ? 'configured' : 'unconfigured',
    cached: false,
    indicatorCount: 0,
    checkedAtUtc: data.checkedAtUtc,
  }));
}

export async function fetchCtiProxyIndicators(params: {
  endpointUrl: string;
  orgId: string;
  source?: ProxyCtiSourceId;
  type?: ExternalIocKind;
  limit?: number;
  assets: Asset[];
  incidents: Incident[];
  existingIndicators?: ExternalThreatIndicator[];
}): Promise<{
  indicators: ExternalThreatIndicator[];
  skippedDuplicates: number;
  sources: CtiProxySourceStatus[];
  failedSources: Array<{ source: ProxyCtiSourceId; reason: string }>;
  cacheTtlSeconds: number;
}> {
  const check = validateGatewayEndpointUrl(params.endpointUrl);
  if (!check.valid || !check.normalized) {
    throw new Error(check.reason || 'Invalid gateway URL.');
  }

  const jwt = await getSupabaseJwt();
  const qs = new URLSearchParams();
  if (params.source) qs.set('source', params.source);
  if (params.type) qs.set('type', params.type);
  if (params.limit) qs.set('limit', String(params.limit));
  const queryStr = qs.toString() ? `?${qs.toString()}` : '';

  const res = await fetch(`${check.normalized}/api/v1/cti/indicators${queryStr}`, {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${jwt}`,
      'x-atlas-org-id': params.orgId,
      Accept: 'application/json',
    },
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(data?.error || `CTI proxy request failed (HTTP ${res.status}).`);
  }

  const rawRecords = Array.isArray(data?.indicators) ? (data.indicators as GatewayNormalizedCtiRecord[]) : [];
  const mapped = mapProxyIndicatorsToExternal(
    rawRecords,
    params.orgId,
    params.assets,
    params.incidents,
    params.existingIndicators || []
  );

  return {
    indicators: mapped.indicators,
    skippedDuplicates: mapped.skippedDuplicates,
    sources: Array.isArray(data?.sources) ? (data.sources as CtiProxySourceStatus[]) : [],
    failedSources: Array.isArray(data?.failedSources) ? data.failedSources : [],
    cacheTtlSeconds: Number(data?.cacheTtlSeconds || 900),
  };
}

export interface CtiParseReport {
  indicators: ExternalThreatIndicator[];
  skippedDuplicates: number;
  warnings: string[];
}

/**
 * Validates and ingests an operator-supplied STIX 2.1 bundle or CISA KEV JSON payload.
 */
export function parseCtiJsonBundle(
  rawJsonText: string,
  providerId: CtiProviderId,
  orgId: string,
  assets: Asset[],
  incidents: Incident[],
  existingIndicators: ExternalThreatIndicator[] = [],
  nowMs = Date.now()
): CtiParseReport {
  let parsed: any;
  try {
    parsed = JSON.parse(rawJsonText);
  } catch (err: any) {
    throw new Error(`Invalid JSON payload: ${err.message || 'syntax error'}`);
  }

  if (!parsed || typeof parsed !== 'object') {
    throw new Error('CTI bundle must be a JSON object.');
  }

  const seenKeys = new Set(existingIndicators.map((i) => `${i.indicatorType}::${i.value.toLowerCase()}`));
  const out: ExternalThreatIndicator[] = [];
  const warnings: string[] = [];
  let skippedDuplicates = 0;

  const pushIndicator = (draft: {
    stixId?: string;
    indicatorType: ExternalIocKind;
    value: string;
    sourceName: string;
    confidence: number;
    validFrom: string;
    validUntil?: string;
    rawSummary: string;
  }) => {
    const cleanVal = draft.value.trim();
    if (!cleanVal) return;
    const key = `${draft.indicatorType}::${cleanVal.toLowerCase()}`;
    if (seenKeys.has(key)) {
      skippedDuplicates++;
      return;
    }
    seenKeys.add(key);

    const validUntilMs = draft.validUntil ? Date.parse(draft.validUntil) : NaN;
    const isExpired = !Number.isNaN(validUntilMs) && validUntilMs < nowMs;
    const { matchedAssetIds, matchedIncidentIds } = correlateAgainstAtlas(
      cleanVal.toLowerCase(),
      assets,
      incidents
    );

    out.push({
      id: `ext-${providerId.toLowerCase()}-${nowMs}-${out.length}`,
      orgId,
      providerId,
      stixId: draft.stixId,
      indicatorType: draft.indicatorType,
      value: cleanVal,
      sourceName: draft.sourceName,
      confidence: Math.max(0, Math.min(100, Math.round(draft.confidence))),
      validFrom: draft.validFrom,
      validUntil: draft.validUntil,
      isExpired,
      isExternalIntel: true,
      verificationStatus: 'unverified',
      matchedAssetIds,
      matchedIncidentIds,
      rawSummary: draft.rawSummary,
      importedAt: new Date(nowMs).toISOString(),
    });
  };

  // Format 1: STIX 2.1 Bundle (`objects[]`)
  if (parsed.type === 'bundle' && Array.isArray(parsed.objects)) {
    for (const obj of parsed.objects) {
      if (!obj || typeof obj !== 'object') continue;
      const objType = String(obj.type || '').toLowerCase();
      const conf = typeof obj.confidence === 'number' ? obj.confidence : 65;
      const validFrom = typeof obj.valid_from === 'string' ? obj.valid_from : obj.created || new Date(nowMs).toISOString();
      const validUntil = typeof obj.valid_until === 'string' ? obj.valid_until : undefined;

      if (objType === 'indicator' && typeof obj.pattern === 'string') {
        const extracted = extractFromStixPattern(obj.pattern);
        if (extracted.length === 0) {
          warnings.push(`Skipped indicator ${obj.id || '(no id)'}: unsupported STIX pattern syntax.`);
        }
        for (const item of extracted) {
          pushIndicator({
            stixId: obj.id,
            indicatorType: item.type,
            value: item.value,
            sourceName: obj.name || `STIX 2.1 (${providerId})`,
            confidence: conf,
            validFrom,
            validUntil,
            rawSummary: obj.description || obj.pattern,
          });
        }
      } else if (objType === 'malware' && obj.name) {
        pushIndicator({
          stixId: obj.id,
          indicatorType: 'malware',
          value: String(obj.name),
          sourceName: `STIX Malware Object`,
          confidence: conf,
          validFrom,
          rawSummary: obj.description || `Malware family (${(obj.malware_types || []).join(', ') || 'unspecified'})`,
        });
      } else if ((objType === 'threat-actor' || objType === 'intrusion-set') && obj.name) {
        pushIndicator({
          stixId: obj.id,
          indicatorType: 'threat_actor',
          value: String(obj.name),
          sourceName: `STIX ${objType.toUpperCase()}`,
          confidence: conf,
          validFrom,
          rawSummary: obj.description || `External assessed threat actor record`,
        });
      } else if (objType === 'vulnerability' && obj.name) {
        pushIndicator({
          stixId: obj.id,
          indicatorType: 'cve',
          value: String(obj.name),
          sourceName: `STIX Vulnerability`,
          confidence: conf,
          validFrom,
          rawSummary: obj.description || String(obj.name),
        });
      }
    }
    return { indicators: out, skippedDuplicates, warnings };
  }

  // Format 2: CISA KEV Catalog (`vulnerabilities[]`)
  if (Array.isArray(parsed.vulnerabilities)) {
    for (const vuln of parsed.vulnerabilities.slice(0, 200)) {
      if (!vuln?.cveID) continue;
      pushIndicator({
        indicatorType: 'cve',
        value: String(vuln.cveID),
        sourceName: `CISA KEV (${vuln.vendorProject || 'Unknown Vendor'})`,
        confidence: 95,
        validFrom: vuln.dateAdded ? new Date(vuln.dateAdded).toISOString() : new Date(nowMs).toISOString(),
        validUntil: vuln.dueDate ? new Date(vuln.dueDate).toISOString() : undefined,
        rawSummary: `${vuln.vulnerabilityName || vuln.cveID} — ${vuln.shortDescription || 'Known Exploited Vulnerability'}`,
      });
    }
    return { indicators: out, skippedDuplicates, warnings };
  }

  throw new Error('Unrecognised bundle schema. Provide a valid STIX 2.1 `{"type":"bundle","objects":[...]}` or CISA KEV `{"vulnerabilities":[...]}` JSON object.');
}
