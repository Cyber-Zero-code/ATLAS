/**
 * Project ATLAS — Module D: Threat Intelligence Feed Adapters & Local STIX/KEV Parser
 *
 * Security & Integrity Rules:
 * - Zero hardcoded API keys, tokens, or silent background external polling.
 * - Live remote polling to authenticated feeds (MISP, TAXII 2.1, AlienVault OTX) requires
 *   an authorised server-side proxy/edge function (not permitted in locked backend).
 * - Analysts CAN ingest local STIX 2.1 JSON bundles or CISA KEV JSON snapshots directly
 *   in the browser; all extracted indicators are tagged `isExternalIntel: true` and
 *   strictly separated from verified ATLAS DB tables.
 */

import type {
  Asset,
  CtiAdapterDescriptor,
  CtiProviderId,
  ExternalIocKind,
  ExternalThreatIndicator,
  Incident,
} from '../types/atlas';

export const CTI_ADAPTER_CATALOG: CtiAdapterDescriptor[] = [
  {
    id: 'STIX_2_1',
    name: 'STIX 2.1 Bundle Ingestor',
    protocol: 'OASIS STIX 2.1 JSON',
    status: 'local_bundle_ready',
    requiresServerProxy: false,
    credentialRequirement: 'None for operator-supplied JSON bundles; TAXII transport requires authorised proxy.',
    description:
      'Parses and validates STIX 2.1 indicator, malware, threat-actor, and vulnerability objects locally against ATLAS assets and incidents.',
  },
  {
    id: 'CISA_KEV',
    name: 'CISA Known Exploited Vulnerabilities (KEV)',
    protocol: 'JSON Catalog / Operator Snapshot',
    status: 'local_bundle_ready',
    requiresServerProxy: false,
    credentialRequirement: 'Direct browser fetch blocked by origin CORS policy without proxy; local KEV JSON snapshot ingestion active.',
    description:
      'Ingests CISA KEV catalog JSON files (`vulnerabilities[]`) for vulnerability cross-referencing.',
  },
  {
    id: 'MISP',
    name: 'MISP Threat Sharing Instance',
    protocol: 'MISP REST API (`/attributes/restSearch`)',
    status: 'deferred_phase_2',
    requiresServerProxy: true,
    deferredExplanation:
      'Live MISP polling is deferred to Phase 2 because it requires a server-side proxy to hold credentials.',
    credentialRequirement: 'Requires `MISP_URL` + `MISP_API_KEY` provisioned inside a server-side Edge proxy.',
    description:
      'Bidirectional IOC & event attribute sync awaiting an authorised server-side credentialed connector.',
  },
  {
    id: 'TAXII_2_1',
    name: 'TAXII 2.1 Discovery & Collections',
    protocol: 'OASIS TAXII 2.1 HTTPS',
    status: 'deferred_phase_2',
    requiresServerProxy: true,
    deferredExplanation:
      'Live TAXII 2.1 collection polling is deferred to Phase 2 per Phase 1 scope and server-proxy requirements.',
    credentialRequirement: 'Requires collection URL, mTLS/Basic/Bearer credentials in a secure proxy.',
    description:
      'Automated polling of external TAXII collections awaiting server-side proxy configuration.',
  },
  {
    id: 'ALIENVAULT_OTX',
    name: 'AlienVault OTX DirectConnect',
    protocol: 'OTX REST v1 (`/api/v1/pulses/subscribed`)',
    status: 'deferred_phase_2',
    requiresServerProxy: true,
    deferredExplanation:
      'Live OTX pulse polling is deferred to Phase 2 because `X-OTX-API-KEY` must be injected by a server proxy.',
    credentialRequirement: 'Requires `X-OTX-API-KEY` header injected server-side.',
    description:
      'Subscribed OTX pulse ingestion disabled until API key proxy is provisioned.',
  },
  {
    id: 'ABUSE_CH',
    name: 'Abuse.ch Feeds (ThreatFox / URLhaus / Feodo)',
    protocol: 'HTTPS JSON API',
    status: 'deferred_phase_2',
    requiresServerProxy: true,
    deferredExplanation:
      'Live Abuse.ch feed polling is deferred to Phase 2 because it requires an authenticated server-side CORS relay.',
    credentialRequirement: 'Requires `Auth-Key` header & server-side CORS relay.',
    description:
      'C2 IP/domain/malware hash feed adapter awaiting authorised server relay.',
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
