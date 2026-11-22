/**
 * Project ATLAS — External Linux Security Execution Gateway Server
 *
 * Security & Isolation Architecture:
 * - Zero Supabase `service_role` keys; validates incoming AAL2 user JWT + RLS memberships.
 * - Fails closed if auth or target allowlist policy checks fail.
 * - Enforces bounded request body sizes, CORS restrictions, and validated PCAP magic bytes.
 * - Never executes shell commands (`exec` / `shell: true` strictly prohibited).
 */

import fs from 'node:fs/promises';
import http from 'node:http';
import https from 'node:https';
import path from 'node:path';
import { GatewayAuthError, GatewayAuthenticator } from './auth.js';
import { GatewayJobManager, JobAccessError } from './jobManager.js';
import { validateGatewayJobRequest } from './policy.js';
import { runRealToolHealthChecks } from './tools/toolHealth.js';
import type { GatewayConfig, GatewayJobRequest, LinuxToolDescriptor } from './types.js';

export function loadConfigFromEnv(env = process.env): GatewayConfig {
  return {
    host: env.GATEWAY_HOST || '127.0.0.1',
    port: Number(env.GATEWAY_PORT || 8443),
    tlsCertPath: env.GATEWAY_TLS_CERT_PATH || undefined,
    tlsKeyPath: env.GATEWAY_TLS_KEY_PATH || undefined,
    corsOrigin: env.GATEWAY_CORS_ORIGIN || 'http://localhost:3000',
    supabaseUrl: env.SUPABASE_URL || '',
    supabaseAnonKey: env.SUPABASE_ANON_KEY || '',
    jwtIssuer: env.SUPABASE_JWT_ISSUER || undefined,
    jwtAudience: env.SUPABASE_JWT_AUDIENCE || 'authenticated',
    jwksUrl: env.SUPABASE_JWKS_URL || undefined,
    jwksJson: env.SUPABASE_JWKS_JSON || undefined,
    jwtHs256Secret: env.SUPABASE_JWT_HS256_SECRET || undefined,
    targetAllowlist: (env.GATEWAY_TARGET_ALLOWLIST || '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean),
    workDir: env.GATEWAY_WORK_DIR || '/tmp/atlas-worker-sandbox',
    maxConcurrentJobs: Math.max(1, Math.min(16, Number(env.GATEWAY_MAX_CONCURRENT_JOBS || 4))),
    maxPcapBytes: Math.max(65536, Number(env.GATEWAY_MAX_PCAP_BYTES || 10 * 1024 * 1024)),
  };
}

const VALID_PCAP_MAGICS = [
  0xa1b2c3d4, // classic libpcap BE
  0xd4c3b2a1, // classic libpcap LE
  0xa1b23c4d, // ns libpcap BE
  0x4d3cb2a1, // ns libpcap LE
  0x0a0d0d0a, // pcapng SHB
];

export function isValidPcapMagicBytes(buf: Buffer): boolean {
  if (buf.length < 24) return false;
  const magicBE = buf.readUInt32BE(0);
  return VALID_PCAP_MAGICS.includes(magicBE);
}

async function readBoundedBody(req: http.IncomingMessage, maxBytes: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    req.on('data', (chunk: Buffer) => {
      total += chunk.length;
      if (total > maxBytes) {
        reject(new JobAccessError(413, `Request payload exceeds limit (${maxBytes} bytes).`));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', (err) => reject(err));
  });
}

function sendJson(res: http.ServerResponse, status: number, payload: unknown, corsOrigin: string): void {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'X-Content-Type-Options': 'nosniff',
    'Cache-Control': 'no-store',
    'Access-Control-Allow-Origin': corsOrigin,
    'Access-Control-Allow-Headers': 'Authorization, Content-Type, x-atlas-org-id, x-atlas-filename',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  });
  res.end(JSON.stringify(payload));
}

export interface GatewayServerHandle {
  server: http.Server | https.Server;
  jobManager: GatewayJobManager;
  tools: LinuxToolDescriptor[];
  close: () => Promise<void>;
}

export async function createGatewayServer(
  config: GatewayConfig,
  authenticator: GatewayAuthenticator
): Promise<GatewayServerHandle> {
  await fs.mkdir(path.join(config.workDir, 'pcap'), { recursive: true });
  await fs.mkdir(path.join(config.workDir, 'datasets'), { recursive: true });

  const initialProbe = await runRealToolHealthChecks();
  const jobManager = new GatewayJobManager({
    workDir: config.workDir,
    maxConcurrentJobs: config.maxConcurrentJobs,
    resolvedPaths: initialProbe.resolvedPaths,
  });

  let cachedTools = initialProbe.tools;
  let lastToolProbeAt = initialProbe.checkedAtUtc;

  const handler = async (req: http.IncomingMessage, res: http.ServerResponse) => {
    const urlPath = (req.url || '/').split('?')[0];

    if (req.method === 'OPTIONS') {
      sendJson(res, 204, {}, config.corsOrigin);
      return;
    }

    try {
      // /health requires authenticated context too so unauthenticated callers cannot enumerate gateway topology
      const auth = await authenticator.authenticateRequest(
        req.headers.authorization,
        req.headers['x-atlas-org-id'] as string | undefined
      );

      if (req.method === 'GET' && urlPath === '/health') {
        const probe = await runRealToolHealthChecks();
        cachedTools = probe.tools;
        lastToolProbeAt = probe.checkedAtUtc;
        jobManager.updateResolvedPaths(probe.resolvedPaths);

        sendJson(
          res,
          200,
          {
            status: 'READY',
            service: 'atlas-linux-execution-gateway',
            authenticatedUserId: auth.userId,
            authenticatedOrgId: auth.orgId,
            authenticatedRole: auth.role,
            checkedAtUtc: lastToolProbeAt,
            tools: cachedTools,
          },
          config.corsOrigin
        );
        return;
      }

      if (req.method === 'GET' && urlPath === '/api/v1/tools') {
        sendJson(
          res,
          200,
          {
            checkedAtUtc: lastToolProbeAt,
            tools: cachedTools,
          },
          config.corsOrigin
        );
        return;
      }

      if (req.method === 'GET' && urlPath === '/api/v1/jobs') {
        sendJson(
          res,
          200,
          { jobs: jobManager.listJobsForOrg(auth.orgId) },
          config.corsOrigin
        );
        return;
      }

      if (req.method === 'POST' && urlPath === '/api/v1/jobs') {
        const rawBuf = await readBoundedBody(req, 65536);
        let body: GatewayJobRequest;
        try {
          body = JSON.parse(rawBuf.toString('utf8')) as GatewayJobRequest;
        } catch {
          sendJson(res, 400, { error: 'Invalid JSON body.' }, config.corsOrigin);
          return;
        }

        const spec = validateGatewayJobRequest(
          body,
          auth.role,
          auth.orgId,
          config.targetAllowlist,
          config.workDir
        );

        if (!spec.allowed) {
          sendJson(
            res,
            spec.requiresApproval ? 412 : 403,
            {
              status: 'BLOCKED_BY_POLICY',
              riskLevel: spec.riskLevel,
              requiresApproval: spec.requiresApproval,
              error: spec.rejectionReason || 'Command blocked by gateway policy.',
            },
            config.corsOrigin
          );
          return;
        }

        const job = await jobManager.startJob(auth, body, spec);
        sendJson(res, 200, { job }, config.corsOrigin);
        return;
      }

      const jobGetMatch = urlPath.match(/^\/api\/v1\/jobs\/([a-zA-Z0-9_-]{6,64})$/);
      if (req.method === 'GET' && jobGetMatch) {
        const job = jobManager.getJobForOrg(jobGetMatch[1], auth.orgId);
        sendJson(res, 200, { job }, config.corsOrigin);
        return;
      }

      const jobCancelMatch = urlPath.match(/^\/api\/v1\/jobs\/([a-zA-Z0-9_-]{6,64})\/cancel$/);
      if (req.method === 'POST' && jobCancelMatch) {
        const job = jobManager.cancelJob(jobCancelMatch[1], auth.orgId, auth.userId);
        sendJson(res, 200, { job }, config.corsOrigin);
        return;
      }

      if (req.method === 'POST' && urlPath === '/api/v1/pcap/upload') {
        const rawName = String(req.headers['x-atlas-filename'] || '').trim();
        if (
          rawName.includes('/') ||
          rawName.includes('\\') ||
          rawName.includes('..') ||
          !/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,95}\.(pcap|pcapng)$/i.test(rawName)
        ) {
          sendJson(res, 400, { error: 'Invalid x-atlas-filename header (.pcap/.pcapng required).' }, config.corsOrigin);
          return;
        }
        const buf = await readBoundedBody(req, config.maxPcapBytes);
        if (!isValidPcapMagicBytes(buf)) {
          sendJson(res, 400, { error: 'Invalid file header: uploaded file is not a recognised PCAP/PCAPNG capture.' }, config.corsOrigin);
          return;
        }
        const orgDir = path.resolve(config.workDir, 'pcap', auth.orgId);
        await fs.mkdir(orgDir, { recursive: true });
        const dest = path.resolve(orgDir, rawName);
        if (!dest.startsWith(orgDir + path.sep)) {
          sendJson(res, 403, { error: 'Path traversal blocked.' }, config.corsOrigin);
          return;
        }
        await fs.writeFile(dest, buf, { mode: 0o600 });
        sendJson(res, 201, { fileName: rawName, sizeBytes: buf.length, orgId: auth.orgId }, config.corsOrigin);
        return;
      }

      sendJson(res, 404, { error: 'Endpoint not found.' }, config.corsOrigin);
    } catch (err: any) {
      if (err instanceof GatewayAuthError || err instanceof JobAccessError) {
        sendJson(res, err.statusCode, { error: err.message }, config.corsOrigin);
        return;
      }
      sendJson(res, 500, { error: 'Internal gateway error.' }, config.corsOrigin);
    }
  };

  let server: http.Server | https.Server;
  if (config.tlsCertPath && config.tlsKeyPath) {
    const [cert, key] = await Promise.all([
      fs.readFile(config.tlsCertPath),
      fs.readFile(config.tlsKeyPath),
    ]);
    server = https.createServer({ cert, key }, handler);
  } else {
    server = http.createServer(handler);
  }

  return {
    server,
    jobManager,
    tools: cachedTools,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      }),
  };
}

// Start standalone HTTP/HTTPS gateway when executed directly
if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(new URL(import.meta.url).pathname)) {
  const cfg = loadConfigFromEnv();
  const auth = new GatewayAuthenticator(cfg);
  createGatewayServer(cfg, auth)
    .then(({ server }) => {
      server.listen(cfg.port, cfg.host, () => {
        console.log(
          `[ATLAS-LINUX-GATEWAY] Listening on ${cfg.tlsCertPath ? 'https' : 'http'}://${cfg.host}:${cfg.port}`
        );
      });
    })
    .catch((err) => {
      console.error('[ATLAS-LINUX-GATEWAY] Startup failed:', err);
      process.exit(1);
    });
}
