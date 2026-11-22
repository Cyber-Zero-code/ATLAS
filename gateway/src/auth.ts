/**
 * Project ATLAS External Gateway — Independent JWT Authentication & Org Isolation
 *
 * Security Guarantees:
 * - Verifies JWT cryptographic signature (RS256/ES256 via JWKS or HS256 via secret)
 *   plus `exp`, `nbf`, `iss`, `aud`, and MFA Assurance Level (`aal === 'aal2'`).
 * - Resolves organisation membership and role (`atlas:admin` | `atlas:analyst`) strictly
 *   from Supabase RLS using the caller's own verified Bearer JWT + public ANON key.
 * - NEVER uses `service_role`, NEVER trusts client-supplied roles or unverified org IDs,
 *   and fails closed if configuration or verification fails.
 */

import crypto from 'node:crypto';
import type { AppRole, AuthenticatedContext, GatewayConfig } from './types.js';

export class GatewayAuthError extends Error {
  public readonly statusCode: number;
  constructor(statusCode: number, message: string) {
    super(message);
    this.statusCode = statusCode;
  }
}

interface JwtHeader {
  alg?: string;
  kid?: string;
  typ?: string;
}

interface JwtClaims {
  sub?: string;
  email?: string;
  iss?: string;
  aud?: string | string[];
  exp?: number;
  nbf?: number;
  aal?: string;
  [k: string]: unknown;
}

export type MembershipResolver = (
  bearerJwt: string,
  userId: string,
  requestedOrgId: string
) => Promise<{ orgId: string; role: AppRole } | null>;

function base64UrlDecode(input: string): Buffer {
  const padded = input.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (input.length % 4)) % 4);
  return Buffer.from(padded, 'base64');
}

function parseJwtParts(token: string): { header: JwtHeader; claims: JwtClaims; signingInput: string; signature: Buffer } {
  const parts = token.split('.');
  if (parts.length !== 3 || parts.some((p) => !p)) {
    throw new GatewayAuthError(401, 'Malformed Bearer JWT structure.');
  }
  try {
    const header = JSON.parse(base64UrlDecode(parts[0]).toString('utf8')) as JwtHeader;
    const claims = JSON.parse(base64UrlDecode(parts[1]).toString('utf8')) as JwtClaims;
    const signature = base64UrlDecode(parts[2]);
    return { header, claims, signingInput: `${parts[0]}.${parts[1]}`, signature };
  } catch {
    throw new GatewayAuthError(401, 'Unreadable JWT header or payload.');
  }
}

/**
 * Converts a raw JOSE ES256 (r || s, 64 bytes) signature into ASN.1 DER for Node crypto.verify.
 */
function joseToDerEcdsa(sig: Buffer): Buffer {
  if (sig.length !== 64) {
    throw new GatewayAuthError(401, 'Invalid ES256 signature length.');
  }
  const encodeInt = (buf: Buffer): Buffer => {
    let i = 0;
    while (i < buf.length - 1 && buf[i] === 0) i++;
    let slice = buf.subarray(i);
    if (slice[0] & 0x80) {
      slice = Buffer.concat([Buffer.from([0x00]), slice]);
    }
    return Buffer.concat([Buffer.from([0x02, slice.length]), slice]);
  };
  const rDer = encodeInt(sig.subarray(0, 32));
  const sDer = encodeInt(sig.subarray(32, 64));
  const totalLen = rDer.length + sDer.length;
  return Buffer.concat([Buffer.from([0x30, totalLen]), rDer, sDer]);
}

export class GatewayAuthenticator {
  private jwksCache: { keys: JsonWebKey[]; fetchedAt: number } | null = null;
  private readonly config: GatewayConfig;
  private readonly customMembershipResolver?: MembershipResolver;

  constructor(config: GatewayConfig, customMembershipResolver?: MembershipResolver) {
    this.config = config;
    this.customMembershipResolver = customMembershipResolver;
  }

  private async getJwksKeys(): Promise<Array<JsonWebKey & { kid?: string; alg?: string }>> {
    if (this.config.jwksJson) {
      try {
        const parsed = JSON.parse(this.config.jwksJson);
        if (Array.isArray(parsed?.keys)) return parsed.keys;
      } catch {
        throw new GatewayAuthError(503, 'Gateway SUPABASE_JWKS_JSON configuration is malformed.');
      }
    }

    if (this.config.jwksUrl) {
      const now = Date.now();
      if (this.jwksCache && now - this.jwksCache.fetchedAt < 5 * 60 * 1000) {
        return this.jwksCache.keys as Array<JsonWebKey & { kid?: string; alg?: string }>;
      }
      const res = await fetch(this.config.jwksUrl, { headers: { Accept: 'application/json' } });
      if (!res.ok) {
        throw new GatewayAuthError(503, `Unable to retrieve JWKS signing keys (HTTP ${res.status}).`);
      }
      const data = (await res.json()) as { keys?: JsonWebKey[] };
      if (!Array.isArray(data?.keys) || data.keys.length === 0) {
        throw new GatewayAuthError(503, 'JWKS endpoint returned zero signing keys.');
      }
      this.jwksCache = { keys: data.keys, fetchedAt: now };
      return data.keys as Array<JsonWebKey & { kid?: string; alg?: string }>;
    }

    return [];
  }

  private async verifySignature(
    header: JwtHeader,
    signingInput: string,
    signature: Buffer
  ): Promise<void> {
    const alg = header.alg || '';

    if (alg === 'HS256') {
      if (!this.config.jwtHs256Secret) {
        throw new GatewayAuthError(
          401,
          'HS256 token rejected: gateway is not configured with HS256 verification secret.'
        );
      }
      const expected = crypto
        .createHmac('sha256', this.config.jwtHs256Secret)
        .update(signingInput)
        .digest();
      if (expected.length !== signature.length || !crypto.timingSafeEqual(expected, signature)) {
        throw new GatewayAuthError(401, 'JWT HMAC-SHA256 signature verification failed.');
      }
      return;
    }

    if (alg === 'RS256' || alg === 'ES256') {
      const keys = await this.getJwksKeys();
      if (keys.length === 0) {
        throw new GatewayAuthError(503, 'Gateway signing keys (JWKS) are not configured.');
      }
      const matchingKey =
        keys.find((k) => (!header.kid || k.kid === header.kid)) || keys[0];

      const keyObj = crypto.createPublicKey({ key: matchingKey as crypto.JsonWebKey, format: 'jwk' });
      const dataBuf = Buffer.from(signingInput, 'utf8');

      const sigToCheck = alg === 'ES256' ? joseToDerEcdsa(signature) : signature;
      const verified = crypto.verify('sha256', dataBuf, keyObj, sigToCheck);
      if (!verified) {
        throw new GatewayAuthError(401, `JWT ${alg} signature verification failed.`);
      }
      return;
    }

    throw new GatewayAuthError(401, `Unsupported JWT signing algorithm "${alg}".`);
  }

  private async resolveMembership(
    bearerJwt: string,
    userId: string,
    requestedOrgId: string
  ): Promise<{ orgId: string; role: AppRole }> {
    if (!/^[0-9a-f-]{36}$/i.test(requestedOrgId)) {
      throw new GatewayAuthError(400, 'Missing or malformed x-atlas-org-id workspace header.');
    }

    if (this.customMembershipResolver) {
      const hit = await this.customMembershipResolver(bearerJwt, userId, requestedOrgId);
      if (!hit) {
        throw new GatewayAuthError(403, `Access denied: user is not a member of organisation ${requestedOrgId}.`);
      }
      return hit;
    }

    if (!this.config.supabaseUrl || !this.config.supabaseAnonKey) {
      throw new GatewayAuthError(
        503,
        'Gateway authentication prerequisite missing: SUPABASE_URL and SUPABASE_ANON_KEY are required for RLS membership lookup.'
      );
    }

    const endpoint =
      `${this.config.supabaseUrl.replace(/\/+$/, '')}/rest/v1/memberships` +
      `?user_id=eq.${encodeURIComponent(userId)}&org_id=eq.${encodeURIComponent(requestedOrgId)}&select=org_id,role`;

    const res = await fetch(endpoint, {
      headers: {
        Authorization: `Bearer ${bearerJwt}`,
        apikey: this.config.supabaseAnonKey,
        Accept: 'application/json',
      },
    });

    if (!res.ok) {
      throw new GatewayAuthError(
        res.status === 401 ? 401 : 403,
        `Supabase RLS membership verification rejected request (HTTP ${res.status}).`
      );
    }

    const rows = (await res.json()) as Array<{ org_id: string; role: string }>;
    const row = Array.isArray(rows) ? rows.find((r) => r.org_id === requestedOrgId) : undefined;
    if (!row || (row.role !== 'atlas:admin' && row.role !== 'atlas:analyst')) {
      throw new GatewayAuthError(
        403,
        `Access denied: verified membership with valid ATLAS role not found for organisation ${requestedOrgId}.`
      );
    }

    return { orgId: row.org_id, role: row.role };
  }

  /**
   * Authenticates an incoming HTTP request strictly failing closed on any verification error.
   */
  public async authenticateRequest(
    authorizationHeader: string | undefined,
    orgHeader: string | undefined,
    nowSec = Math.floor(Date.now() / 1000)
  ): Promise<AuthenticatedContext> {
    if (!authorizationHeader || !authorizationHeader.startsWith('Bearer ')) {
      throw new GatewayAuthError(401, 'Missing Authorization: Bearer <JWT> header.');
    }
    const jwt = authorizationHeader.slice('Bearer '.length).trim();
    if (!jwt) {
      throw new GatewayAuthError(401, 'Empty Bearer token.');
    }

    const { header, claims, signingInput, signature } = parseJwtParts(jwt);
    await this.verifySignature(header, signingInput, signature);

    if (typeof claims.exp !== 'number' || claims.exp <= nowSec) {
      throw new GatewayAuthError(401, 'Session JWT has expired.');
    }
    if (typeof claims.nbf === 'number' && claims.nbf > nowSec + 5) {
      throw new GatewayAuthError(401, 'Session JWT is not yet valid (nbf).');
    }
    if (this.config.jwtIssuer && claims.iss !== this.config.jwtIssuer) {
      throw new GatewayAuthError(401, 'JWT issuer mismatch.');
    }
    if (this.config.jwtAudience) {
      const audList = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
      if (!audList.includes(this.config.jwtAudience)) {
        throw new GatewayAuthError(401, 'JWT audience mismatch.');
      }
    }
    if (claims.aal !== 'aal2') {
      throw new GatewayAuthError(403, 'MFA Assurance Level aal2 is mandatory for Linux Security Worker access.');
    }
    if (!claims.sub || typeof claims.sub !== 'string') {
      throw new GatewayAuthError(401, 'JWT missing subject (sub) user identifier.');
    }

    const requestedOrgId = (orgHeader || '').trim();
    const membership = await this.resolveMembership(jwt, claims.sub, requestedOrgId);

    return {
      userId: claims.sub,
      email: typeof claims.email === 'string' ? claims.email : undefined,
      orgId: membership.orgId,
      role: membership.role,
      aal: 'aal2',
      tokenExpiresAt: claims.exp,
    };
  }
}
