/**
 * Project ATLAS — External Linux Execution Gateway Client
 *
 * Security & Honesty Rules:
 * - Connects ONLY to an explicitly validated operator-configured gateway URL
 *   (`https://` required for remote hosts; `http://127.0.0.1` / `http://localhost` allowed for local dev).
 * - Sends ONLY the live Supabase AAL2 user session JWT + `x-atlas-org-id`.
 * - Never sends `service_role` keys, never stores credentials or tokens in browser storage,
 *   and never reports `READY` until `/health` passes real authentication & tool probing.
 */

import { supabase } from '../lib/supabase';
import type {
  ExternalThreatIndicator,
  GatewayHealthSnapshot,
  GatewayJobRecord,
  LinuxToolDescriptor,
} from '../types/atlas';
import type { WorkspaceIntelligenceState } from '../hooks/useWorkspaceIntelligence';
import { correlateNmapWithAtlas, correlateTsharkWithAtlas } from './terminalAdapter';

export function validateGatewayEndpointUrl(rawUrl: string): { valid: boolean; normalized?: string; reason?: string } {
  const trimmed = (rawUrl || '').trim().replace(/\/+$/, '');
  if (!trimmed) return { valid: false, reason: 'Gateway URL is empty.' };
  if (/^https?:\/\/[^/?#]*@/i.test(trimmed)) {
    return { valid: false, reason: 'Embedded credentials (user:pass@) are prohibited in gateway URL.' };
  }
  if (/([?&]|#).*(token|key|secret|password|auth)=/i.test(trimmed)) {
    return { valid: false, reason: 'Credentials or tokens cannot be placed in gateway URL.' };
  }
  try {
    const parsed = new URL(trimmed);
    const isLoopback = parsed.hostname === '127.0.0.1' || parsed.hostname === 'localhost';
    if (parsed.protocol === 'https:') {
      return { valid: true, normalized: parsed.origin + parsed.pathname.replace(/\/+$/, '') };
    }
    if (parsed.protocol === 'http:' && isLoopback) {
      return { valid: true, normalized: parsed.origin + parsed.pathname.replace(/\/+$/, '') };
    }
    return {
      valid: false,
      reason: 'Remote execution gateways require HTTPS (`https://`). Plain HTTP is permitted only on localhost/127.0.0.1.',
    };
  } catch {
    return { valid: false, reason: 'Malformed gateway URL.' };
  }
}

async function getActiveSessionJwt(): Promise<string> {
  const { data } = await supabase.auth.getSession();
  const token = data?.session?.access_token;
  if (!token) {
    throw new Error('No active authenticated Supabase session JWT found.');
  }
  return token;
}

export async function checkGatewayHealth(
  endpointUrl: string | null,
  orgId: string
): Promise<GatewayHealthSnapshot> {
  if (!endpointUrl || !endpointUrl.trim()) {
    return {
      state: 'NOT_CONFIGURED',
      endpointUrl: null,
      authenticatedUserId: null,
      authenticatedOrgId: null,
      authenticatedRole: null,
      checkedAtUtc: new Date().toISOString(),
      tools: [],
    };
  }

  const check = validateGatewayEndpointUrl(endpointUrl);
  if (!check.valid || !check.normalized) {
    return {
      state: 'BLOCKED_BY_POLICY',
      endpointUrl,
      authenticatedUserId: null,
      authenticatedOrgId: null,
      authenticatedRole: null,
      checkedAtUtc: new Date().toISOString(),
      tools: [],
      errorMessage: check.reason,
    };
  }

  try {
    const jwt = await getActiveSessionJwt();
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
      return {
        state: res.status === 401 || res.status === 403 ? 'BLOCKED_BY_POLICY' : 'OFFLINE',
        endpointUrl: check.normalized,
        authenticatedUserId: null,
        authenticatedOrgId: null,
        authenticatedRole: null,
        checkedAtUtc: new Date().toISOString(),
        tools: [],
        errorMessage: data?.error || `Gateway authentication/health failed (HTTP ${res.status}).`,
      };
    }

    return {
      state: 'READY',
      endpointUrl: check.normalized,
      authenticatedUserId: data.authenticatedUserId || null,
      authenticatedOrgId: data.authenticatedOrgId || null,
      authenticatedRole: data.authenticatedRole || null,
      checkedAtUtc: data.checkedAtUtc || new Date().toISOString(),
      tools: Array.isArray(data.tools) ? (data.tools as LinuxToolDescriptor[]) : [],
    };
  } catch (err: any) {
    return {
      state: 'OFFLINE',
      endpointUrl: check.normalized,
      authenticatedUserId: null,
      authenticatedOrgId: null,
      authenticatedRole: null,
      checkedAtUtc: new Date().toISOString(),
      tools: [],
      errorMessage: err?.message || 'Unable to reach external Linux execution gateway.',
    };
  }
}

function attachAtlasCorrelation(
  job: GatewayJobRecord,
  intel: WorkspaceIntelligenceState,
  externalIndicators: ExternalThreatIndicator[]
): GatewayJobRecord {
  if (job.nmapParsed) {
    return { ...job, correlation: correlateNmapWithAtlas(job.nmapParsed, intel, externalIndicators) };
  }
  if (job.tsharkParsed) {
    return { ...job, correlation: correlateTsharkWithAtlas(job.tsharkParsed, intel, externalIndicators) };
  }
  return job;
}

export async function submitGatewayJob(params: {
  endpointUrl: string;
  orgId: string;
  tool: string;
  args: string[];
  target?: string;
  approvalConfirmed?: boolean;
  approvalJustification?: string;
  intel: WorkspaceIntelligenceState;
  externalIndicators?: ExternalThreatIndicator[];
}): Promise<GatewayJobRecord> {
  const check = validateGatewayEndpointUrl(params.endpointUrl);
  if (!check.valid || !check.normalized) {
    throw new Error(check.reason || 'Invalid gateway URL.');
  }

  const jwt = await getActiveSessionJwt();
  const res = await fetch(`${check.normalized}/api/v1/jobs`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${jwt}`,
      'x-atlas-org-id': params.orgId,
      'Content-Type': 'application/json',
      Accept: 'application/json',
    },
    body: JSON.stringify({
      tool: params.tool,
      args: params.args,
      target: params.target,
      orgId: params.orgId,
      approvalConfirmed: Boolean(params.approvalConfirmed),
      approvalJustification: params.approvalJustification,
    }),
  });

  const data = await res.json().catch(() => ({}));
  if (!res.ok || !data?.job) {
    throw new Error(data?.error || `Gateway rejected execution (HTTP ${res.status}).`);
  }

  return attachAtlasCorrelation(data.job as GatewayJobRecord, params.intel, params.externalIndicators || []);
}

export async function fetchGatewayJob(params: {
  endpointUrl: string;
  orgId: string;
  jobId: string;
  intel: WorkspaceIntelligenceState;
  externalIndicators?: ExternalThreatIndicator[];
}): Promise<GatewayJobRecord> {
  const check = validateGatewayEndpointUrl(params.endpointUrl);
  if (!check.valid || !check.normalized) {
    throw new Error(check.reason || 'Invalid gateway URL.');
  }
  const jwt = await getActiveSessionJwt();
  const res = await fetch(`${check.normalized}/api/v1/jobs/${encodeURIComponent(params.jobId)}`, {
    headers: {
      Authorization: `Bearer ${jwt}`,
      'x-atlas-org-id': params.orgId,
      Accept: 'application/json',
    },
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok || !data?.job) {
    throw new Error(data?.error || `Failed to query gateway job (HTTP ${res.status}).`);
  }
  return attachAtlasCorrelation(data.job as GatewayJobRecord, params.intel, params.externalIndicators || []);
}

export async function cancelGatewayJob(params: {
  endpointUrl: string;
  orgId: string;
  jobId: string;
}): Promise<GatewayJobRecord> {
  const check = validateGatewayEndpointUrl(params.endpointUrl);
  if (!check.valid || !check.normalized) {
    throw new Error(check.reason || 'Invalid gateway URL.');
  }
  const jwt = await getActiveSessionJwt();
  const res = await fetch(`${check.normalized}/api/v1/jobs/${encodeURIComponent(params.jobId)}/cancel`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${jwt}`,
      'x-atlas-org-id': params.orgId,
      Accept: 'application/json',
    },
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok || !data?.job) {
    throw new Error(data?.error || `Failed to cancel gateway job (HTTP ${res.status}).`);
  }
  return data.job as GatewayJobRecord;
}

export async function uploadGatewayPcap(params: {
  endpointUrl: string;
  orgId: string;
  file: File;
}): Promise<{ fileName: string; sizeBytes: number }> {
  const check = validateGatewayEndpointUrl(params.endpointUrl);
  if (!check.valid || !check.normalized) {
    throw new Error(check.reason || 'Invalid gateway URL.');
  }
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,95}\.(pcap|pcapng)$/i.test(params.file.name)) {
    throw new Error('PCAP filename must end with .pcap or .pcapng using safe alphanumeric characters.');
  }
  if (params.file.size > 10 * 1024 * 1024) {
    throw new Error('PCAP file exceeds 10 MB gateway upload limit.');
  }

  const jwt = await getActiveSessionJwt();
  const bytes = await params.file.arrayBuffer();
  const res = await fetch(`${check.normalized}/api/v1/pcap/upload`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${jwt}`,
      'x-atlas-org-id': params.orgId,
      'x-atlas-filename': params.file.name,
      'Content-Type': 'application/octet-stream',
    },
    body: bytes,
  });

  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(data?.error || `PCAP upload rejected (HTTP ${res.status}).`);
  }
  return { fileName: data.fileName, sizeBytes: data.sizeBytes };
}
