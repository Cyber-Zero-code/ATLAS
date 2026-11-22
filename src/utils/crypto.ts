/**
 * Project ATLAS: Cryptographic Utilities (Web Crypto Only)
 * 
 * HARD RULE 8: Browser hashing uses Web Crypto (crypto.subtle.digest) only.
 * Never hand-write a hash function. If Web Crypto is unavailable, block operations
 * with a clear message. Includes known SHA-256 test vector validation.
 */

function getCryptoInstance(): Crypto {
  if (typeof globalThis !== 'undefined' && globalThis.crypto && globalThis.crypto.subtle) {
    return globalThis.crypto;
  }
  if (typeof window !== 'undefined' && window.crypto && window.crypto.subtle) {
    return window.crypto;
  }
  throw new Error(
    'Web Crypto API (crypto.subtle) is unavailable in this environment. ' +
    'Evidence hashing and cryptographic verification are blocked by Project ATLAS security policy.'
  );
}

export function isWebCryptoAvailable(): boolean {
  try {
    const c = getCryptoInstance();
    return typeof c.subtle?.digest === 'function';
  } catch {
    return false;
  }
}

function assertWebCrypto(): Crypto {
  return getCryptoInstance();
}

/**
 * Computes standard SHA-256 hex digest using Web Crypto API exclusively.
 */
export async function computeSha256Hex(data: string | ArrayBuffer | Uint8Array): Promise<string> {
  const cryptoInstance = assertWebCrypto();

  let buffer: ArrayBuffer;
  if (typeof data === 'string') {
    buffer = new TextEncoder().encode(data).buffer as ArrayBuffer;
  } else if (data instanceof Uint8Array) {
    buffer = data.buffer as ArrayBuffer;
  } else {
    buffer = data;
  }

  const hashBuffer = await cryptoInstance.subtle.digest('SHA-256', buffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Computes SHA-256 for a File or Blob using Web Crypto
 */
export async function computeFileSha256(file: File | Blob): Promise<string> {
  assertWebCrypto();
  const arrayBuffer = await file.arrayBuffer();
  return computeSha256Hex(arrayBuffer);
}

/**
 * Standard NIST / RFC 6234 Test Vectors for SHA-256
 */
export const SHA256_TEST_VECTORS = [
  {
    input: '',
    expected: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    description: 'Empty string',
  },
  {
    input: 'abc',
    expected: 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    description: 'Short ASCII "abc"',
  },
  {
    input: 'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq',
    expected: '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1',
    description: 'Multi-block 448-bit string',
  },
];

/**
 * Validates the runtime Web Crypto implementation against standard SHA-256 test vectors.
 */
export async function verifyWebCryptoEngine(): Promise<{ passed: boolean; error?: string }> {
  try {
    assertWebCrypto();
    for (const vector of SHA256_TEST_VECTORS) {
      const actual = await computeSha256Hex(vector.input);
      if (actual !== vector.expected) {
        return {
          passed: false,
          error: `Vector "${vector.description}" failed: expected ${vector.expected}, got ${actual}`,
        };
      }
    }
    return { passed: true };
  } catch (err: any) {
    return { passed: false, error: err.message || 'Web Crypto validation failed.' };
  }
}

// ---------------------------------------------------------------------------
// Incident intake signing (migration 013). HMAC-SHA256 via Web Crypto only.
// Must produce byte-identical signing strings to public.ingest_signing_string() in the database.
// Every string value is JSON-quoted; signal lists are sorted by UTF-16 code unit (same as bytewise for ASCII).
// Known limits: a "confidence" written in exponent form (e.g. 1e-7) will not match the database's text
// form and is refused (fails closed). Sender payloads should use plain decimals such as 0.9.
// ---------------------------------------------------------------------------

const SIGNAL_KEYS = ['site_codes', 'hostnames', 'ips', 'cidrs', 'cloud_account_ids'] as const;

function asText(v: unknown): string {
  return v === undefined || v === null ? '' : String(v);
}

export function buildIngestSigningString(
  orgId: string,
  payload: Record<string, unknown>
): string {
  const q = (v: unknown) => JSON.stringify(asText(v));
  const lines: string[] = [
    'atlas-ingest-v1',
    `org_id=${q(orgId)}`,
    `key_id=${q(payload.key_id)}`,
  ];
  for (const k of ['schema_version', 'event_id', 'event_type', 'severity', 'observed_at', 'sent_at']) {
    lines.push(`${k}=${q(payload[k])}`);
  }
  lines.push(`confidence=${asText(payload.confidence)}`);
  lines.push(`correlation_id=${q(payload.correlation_id)}`);
  lines.push(`source=${q(payload.source)}`);

  const signals = (payload.signals ?? {}) as Record<string, unknown>;
  for (const k of SIGNAL_KEYS) {
    const raw = signals[k];
    if (raw !== undefined && !Array.isArray(raw)) {
      throw new Error(`Signal list "${k}" must be an array.`);
    }
    const values = ((raw as unknown[] | undefined) ?? []).map((x) => String(x)).sort();
    lines.push(`${k}=[${values.map((x) => JSON.stringify(x)).join(',')}]`);
  }
  return lines.join('\n');
}

export async function hmacSha256Hex(message: string, secret: string): Promise<string> {
  const c = getCryptoInstance();
  const enc = new TextEncoder();
  const key = await c.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await c.subtle.sign('HMAC', key, enc.encode(message));
  return Array.from(new Uint8Array(sig))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/** Returns a copy of the payload with key_id and signature set. Any old signature is replaced. */
export async function signIngestPayload(
  orgId: string,
  payload: Record<string, unknown>,
  keyId: string,
  secret: string
): Promise<Record<string, unknown>> {
  const unsigned: Record<string, unknown> = { ...payload, key_id: keyId };
  delete unsigned.signature;
  const signature = await hmacSha256Hex(buildIngestSigningString(orgId, unsigned), secret);
  return { ...unsigned, signature };
}

/** Reference vector, computed independently (Python hmac) and also asserted inside the database test suite. */
export const INGEST_SIGNING_TEST_VECTOR = {
  orgId: 'a0000000-0000-0000-0000-000000000001',
  secret: 'test-secret-0123456789abcdef',
  payload: {
    key_id: 'k_test0001',
    schema_version: '1.0',
    event_id: 'EVT-VEC-001',
    event_type: 'RANSOMWARE',
    severity: 'high',
    observed_at: '2026-01-01T00:00:00Z',
    sent_at: '2026-01-01T00:00:05Z',
    confidence: 0.9,
    correlation_id: 'cid-vec',
    signals: { hostnames: ['b.example.test', 'a.example.test'], ips: ['10.0.0.1'] },
  } as Record<string, unknown>,
  expectedSigningString:
    'atlas-ingest-v1\norg_id="a0000000-0000-0000-0000-000000000001"\nkey_id="k_test0001"\nschema_version="1.0"\nevent_id="EVT-VEC-001"\nevent_type="RANSOMWARE"\nseverity="high"\nobserved_at="2026-01-01T00:00:00Z"\nsent_at="2026-01-01T00:00:05Z"\nconfidence=0.9\ncorrelation_id="cid-vec"\nsource=""\nsite_codes=[]\nhostnames=["a.example.test","b.example.test"]\nips=["10.0.0.1"]\ncidrs=[]\ncloud_account_ids=[]',
  expectedSignature: '611621ffcbeafcf64cb6f5bf36523a27cd4a1564462a4e31f90bf08a99123c60',
};
