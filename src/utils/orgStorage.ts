/**
 * Project ATLAS: Organisation-Scoped Frontend Workspace Persistence Helper
 *
 * SECURITY & DATA HANDLING POLICY:
 * - Browser localStorage may ONLY hold non-sensitive UI preferences, temporary local
 *   working drafts, locally imported unverified CTI bundles, and defensive terminal
 *   command query logs.
 * - NEVER store API credentials, authentication tokens, session secrets, raw evidence
 *   blobs, or authoritative server attribution/incident findings in browser storage.
 * - Every key is strictly isolated by verified `orgId`, and array items containing an
 *   `orgId`/`org_id` field are validated against the active `orgId` on load to prevent
 *   cross-tenant leakage.
 */

export type OrgScopedDomain =
  | 'attributions'
  | 'cameras'
  | 'external_cti'
  | 'terminal_history'
  | 'mission_drafts'
  | 'ui_preferences'
  | 'gateway_preferences';

const SENSITIVE_KEY_PATTERN =
  /^(password|passwd|secret|api_?key|access_?token|refresh_?token|auth_?token|id_?token|bearer|private_?key|client_?secret|credential|session_?token|supabase_?key)$/i;

export function isValidOrgId(orgId: string): boolean {
  const trimmed = String(orgId || '').trim();
  if (!trimmed || trimmed === 'no-org') return false;
  return /^[a-zA-Z0-9_-]{4,128}$/.test(trimmed);
}

function buildKey(domain: OrgScopedDomain, orgId: string): string {
  const safeOrg = String(orgId).trim().replace(/[^a-zA-Z0-9_-]/g, '');
  return `atlas:${domain}:${safeOrg}`;
}

/**
 * Strips any accidental secret/token/credential keys before persisting to browser storage.
 */
export function sanitizeForBrowserStorage<T>(value: T): T {
  if (value === null || value === undefined || typeof value !== 'object') {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((item) => sanitizeForBrowserStorage(item)) as unknown as T;
  }
  const clean: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    if (SENSITIVE_KEY_PATTERN.test(k.trim())) {
      continue;
    }
    clean[k] = sanitizeForBrowserStorage(v);
  }
  return clean as T;
}

function getStorage(): Storage | null {
  if (typeof window === 'undefined') return null;
  try {
    return window.localStorage || null;
  } catch {
    return null;
  }
}

export function loadOrgScopedList<T>(domain: OrgScopedDomain, orgId: string): T[] {
  const storage = getStorage();
  if (!storage || !isValidOrgId(orgId)) {
    return [];
  }
  try {
    const raw = storage.getItem(buildKey(domain, orgId));
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    // Cross-tenant isolation check on every loaded record that carries orgId/org_id
    return parsed.filter((item) => {
      if (item && typeof item === 'object') {
        const rec = item as Record<string, unknown>;
        if (typeof rec.orgId === 'string' && rec.orgId !== orgId) return false;
        if (typeof rec.org_id === 'string' && rec.org_id !== orgId) return false;
      }
      return true;
    }) as T[];
  } catch {
    return [];
  }
}

export function saveOrgScopedList<T>(domain: OrgScopedDomain, orgId: string, items: T[]): void {
  const storage = getStorage();
  if (!storage || !isValidOrgId(orgId) || !Array.isArray(items)) {
    return;
  }
  try {
    // Enforce org isolation on write when objects carry orgId/org_id + strip sensitive fields
    const safeItems = items
      .filter((item) => {
        if (item && typeof item === 'object') {
          const rec = item as Record<string, unknown>;
          if (typeof rec.orgId === 'string' && rec.orgId !== orgId) return false;
          if (typeof rec.org_id === 'string' && rec.org_id !== orgId) return false;
        }
        return true;
      })
      .map((item) => sanitizeForBrowserStorage(item));
    storage.setItem(buildKey(domain, orgId), JSON.stringify(safeItems));
  } catch {
    // Ignore quota exceeded safely without disrupting workspace UI
  }
}

export function loadOrgScopedValue<T>(domain: OrgScopedDomain, orgId: string, fallback: T): T {
  const storage = getStorage();
  if (!storage || !isValidOrgId(orgId)) {
    return fallback;
  }
  try {
    const raw = storage.getItem(buildKey(domain, orgId));
    if (!raw) return fallback;
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      const rec = parsed as Record<string, unknown>;
      if (typeof rec.orgId === 'string' && rec.orgId !== orgId) return fallback;
      if (typeof rec.org_id === 'string' && rec.org_id !== orgId) return fallback;
    }
    return parsed as T;
  } catch {
    return fallback;
  }
}

export function saveOrgScopedValue<T>(domain: OrgScopedDomain, orgId: string, value: T): void {
  const storage = getStorage();
  if (!storage || !isValidOrgId(orgId)) {
    return;
  }
  try {
    const sanitized = sanitizeForBrowserStorage(value);
    storage.setItem(buildKey(domain, orgId), JSON.stringify(sanitized));
  } catch {
    // Ignore quota exceeded safely without disrupting workspace UI
  }
}

export function clearOrgScopedDomain(domain: OrgScopedDomain, orgId: string): void {
  const storage = getStorage();
  if (!storage || !isValidOrgId(orgId)) {
    return;
  }
  try {
    storage.removeItem(buildKey(domain, orgId));
  } catch {
    // Ignore storage removal errors safely
  }
}
