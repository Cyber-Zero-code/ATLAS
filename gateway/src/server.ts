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
import {
  CameraAnalyticsCoordinator,
  loadCameraAnalyticsConfigFromEnv,
} from './cameraAnalytics.js';
import {
  CAMERA_VIEW_ROLES,
  CameraAccessError,
  CameraStreamManager,
  MAX_CONCURRENT_STREAMS_PER_ORG,
} from './cameraManager.js';
import {
  CtiProxyService,
  loadCtiConfigFromEnv,
  VALID_CTI_SOURCES,
  VALID_CTI_TYPES,
} from './ctiProxy.js';
import { GatewayJobManager, JobAccessError } from './jobManager.js';
import { validateGatewayJobRequest } from './policy.js';
import { runRealToolHealthChecks } from './tools/toolHealth.js';
import type {
  CameraRegistrationInput,
  CtiSourceId,
  GatewayConfig,
  GatewayJobRequest,
  LinuxToolDescriptor,
  NormalizedCtiIndicatorType,
} from './types.js';

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
    cti: loadCtiConfigFromEnv(env),
    cameraAnalytics: loadCameraAnalyticsConfigFromEnv(env),
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

function sendJpeg(res: http.ServerResponse, status: number, frameBuffer: Buffer, corsOrigin: string): void {
  res.writeHead(status, {
    'Content-Type': 'image/jpeg',
    'Content-Length': frameBuffer.length,
    'X-Content-Type-Options': 'nosniff',
    'Cache-Control': 'no-store',
    'Access-Control-Allow-Origin': corsOrigin,
    'Access-Control-Allow-Headers': 'Authorization, Content-Type, x-atlas-org-id, x-atlas-filename',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  });
  res.end(frameBuffer);
}

export interface GatewayServerHandle {
  server: http.Server | https.Server;
  jobManager: GatewayJobManager;
  ctiService: CtiProxyService;
  analyticsCoordinator: CameraAnalyticsCoordinator;
  cameraManager: CameraStreamManager;
  tools: LinuxToolDescriptor[];
  close: () => Promise<void>;
}

export async function createGatewayServer(
  config: GatewayConfig,
  authenticator: GatewayAuthenticator,
  options?: {
    ctiService?: CtiProxyService;
    cameraAnalyticsCoordinator?: CameraAnalyticsCoordinator;
    cameraManager?: CameraStreamManager;
  }
): Promise<GatewayServerHandle> {
  await fs.mkdir(path.join(config.workDir, 'pcap'), { recursive: true });
  await fs.mkdir(path.join(config.workDir, 'datasets'), { recursive: true });

  const ctiService = options?.ctiService || new CtiProxyService(config.cti || {});

  const initialProbe = await runRealToolHealthChecks();
  const jobManager = new GatewayJobManager({
    workDir: config.workDir,
    maxConcurrentJobs: config.maxConcurrentJobs,
    resolvedPaths: initialProbe.resolvedPaths,
  });

  const analyticsCoordinator =
    options?.cameraAnalyticsCoordinator || new CameraAnalyticsCoordinator(config.cameraAnalytics || {});

  const cameraManager =
    options?.cameraManager ||
    new CameraStreamManager({
      workDir: config.workDir,
      jobManager,
      analyticsCoordinator,
      ffmpegPath: initialProbe.resolvedPaths.ffmpeg ?? '/usr/bin/ffmpeg',
      supabaseUrl: config.supabaseUrl,
      supabaseAnonKey: config.supabaseAnonKey,
    });

  const redactSensitive = (msg: string): string => {
    let out = cameraManager.redact(msg);
    for (const secret of analyticsCoordinator.getConfiguredSecret()) {
      if (secret) out = out.split(secret).join('[REDACTED]');
    }
    return out;
  };

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
      const bearerJwt = req.headers.authorization?.slice('Bearer '.length).trim();

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
            ctiSources: ctiService.getConfiguredSummary(),
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
            ctiSources: ctiService.getConfiguredSummary(),
          },
          config.corsOrigin
        );
        return;
      }

      if (req.method === 'GET' && urlPath === '/api/v1/cti/indicators') {
        if (!ctiService.checkRateLimit(auth.orgId)) {
          sendJson(
            res,
            429,
            { error: 'CTI proxy rate limit exceeded for organisation (max 30 requests/minute).' },
            config.corsOrigin
          );
          return;
        }

        const parsedUrl = new URL(req.url || '/', 'http://localhost');
        const rawSource = parsedUrl.searchParams.get('source')?.trim() || undefined;
        const rawType = parsedUrl.searchParams.get('type')?.trim() || undefined;
        const rawLimit = parsedUrl.searchParams.get('limit')?.trim() || undefined;

        if (rawSource && !VALID_CTI_SOURCES.includes(rawSource as CtiSourceId)) {
          sendJson(
            res,
            400,
            { error: `Invalid source parameter. Allowed: ${VALID_CTI_SOURCES.join(', ')}` },
            config.corsOrigin
          );
          return;
        }

        if (rawType && !VALID_CTI_TYPES.includes(rawType as NormalizedCtiIndicatorType)) {
          sendJson(
            res,
            400,
            { error: `Invalid type parameter. Allowed: ${VALID_CTI_TYPES.join(', ')}` },
            config.corsOrigin
          );
          return;
        }

        let limit = 100;
        if (rawLimit !== undefined) {
          const parsedLimit = Number(rawLimit);
          if (!Number.isInteger(parsedLimit) || parsedLimit < 1 || parsedLimit > 500) {
            sendJson(
              res,
              400,
              { error: 'Invalid limit parameter (must be an integer between 1 and 500).' },
              config.corsOrigin
            );
            return;
          }
          limit = parsedLimit;
        }

        const result = await ctiService.getIndicators({
          source: rawSource as CtiSourceId | undefined,
          type: rawType as NormalizedCtiIndicatorType | undefined,
          limit,
        });

        sendJson(
          res,
          200,
          {
            indicators: result.indicators,
            count: result.indicators.length,
            limit,
            cacheTtlSeconds: result.cacheTtlSeconds,
            sources: result.sources,
            failedSources: result.failedSources,
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

      // ---- Registered Camera Streams & Vision Analytics (ADR 010 Amended) ----
      if (req.method === 'GET' && urlPath === '/api/v1/cameras') {
        if (!CAMERA_VIEW_ROLES.has(auth.role)) {
          sendJson(res, 403, { error: 'Role not permitted to list registered cameras.' }, config.corsOrigin);
          return;
        }
        sendJson(
          res,
          200,
          {
            cameras: cameraManager.listCamerasForOrg(auth.orgId),
            maxConcurrentPerOrg: MAX_CONCURRENT_STREAMS_PER_ORG,
          },
          config.corsOrigin
        );
        return;
      }

      if (req.method === 'POST' && urlPath === '/api/v1/cameras') {
        if (!CAMERA_VIEW_ROLES.has(auth.role)) {
          sendJson(res, 403, { error: 'Role not permitted to register cameras.' }, config.corsOrigin);
          return;
        }
        const rawBuf = await readBoundedBody(req, 65536);
        let body: CameraRegistrationInput;
        try {
          body = JSON.parse(rawBuf.toString('utf8')) as CameraRegistrationInput;
        } catch {
          sendJson(res, 400, { error: 'Invalid JSON body.' }, config.corsOrigin);
          return;
        }
        const camera = await cameraManager.registerCamera(auth, body, bearerJwt);
        sendJson(res, 201, { camera }, config.corsOrigin);
        return;
      }

      if (req.method === 'GET' && urlPath === '/api/v1/cameras/audit') {
        if (!CAMERA_VIEW_ROLES.has(auth.role)) {
          sendJson(res, 403, { error: 'Role not permitted to view camera audit ledger.' }, config.corsOrigin);
          return;
        }
        sendJson(
          res,
          200,
          { auditRecords: cameraManager.getAuditRecordsForOrg(auth.orgId) },
          config.corsOrigin
        );
        return;
      }

      if (req.method === 'GET' && urlPath === '/api/v1/cameras/identities') {
        if (!CAMERA_VIEW_ROLES.has(auth.role)) {
          sendJson(res, 403, { error: 'Role not permitted to view biometric identities.' }, config.corsOrigin);
          return;
        }
        sendJson(
          res,
          200,
          { identities: analyticsCoordinator.listIdentitiesForOrg(auth.orgId) },
          config.corsOrigin
        );
        return;
      }

      if (req.method === 'POST' && urlPath === '/api/v1/cameras/identities') {
        if (!CAMERA_VIEW_ROLES.has(auth.role)) {
          sendJson(res, 403, { error: 'Role not permitted to enroll biometric identities.' }, config.corsOrigin);
          return;
        }
        const rawBuf = await readBoundedBody(req, 65536);
        let body: {
          personLabel?: string;
          personRef?: string;
          embedding?: number[];
          legalBasisRef?: string;
        };
        try {
          body = JSON.parse(rawBuf.toString('utf8')) as typeof body;
        } catch {
          sendJson(res, 400, { error: 'Invalid JSON body.' }, config.corsOrigin);
          return;
        }
        if (
          !body.personLabel?.trim() ||
          !body.personRef?.trim() ||
          !Array.isArray(body.embedding) ||
          body.embedding.length === 0 ||
          body.embedding.length > 2048 ||
          !body.embedding.every((n) => typeof n === 'number' && Number.isFinite(n))
        ) {
          sendJson(
            res,
            400,
            { error: 'personLabel, personRef, and numeric embedding vector (1..2048 dims) are required.' },
            config.corsOrigin
          );
          return;
        }
        const enrolled = analyticsCoordinator.enrollIdentity({
          orgId: auth.orgId,
          personLabel: body.personLabel,
          personRef: body.personRef,
          embedding: body.embedding,
          legalBasisRef: body.legalBasisRef,
        });
        sendJson(
          res,
          201,
          {
            identity: {
              id: enrolled.id,
              orgId: enrolled.orgId,
              personLabel: enrolled.personLabel,
              personRef: enrolled.personRef,
              legalBasisRef: enrolled.legalBasisRef,
              createdAtUtc: enrolled.createdAtUtc,
              embeddingDim: enrolled.embedding.length,
            },
          },
          config.corsOrigin
        );
        return;
      }

      const camStartMatch = urlPath.match(/^\/api\/v1\/cameras\/([a-zA-Z0-9_-]{3,64})\/start$/);
      if (req.method === 'POST' && camStartMatch) {
        if (!CAMERA_VIEW_ROLES.has(auth.role)) {
          sendJson(res, 403, { error: 'Role not permitted to start camera streams.' }, config.corsOrigin);
          return;
        }
        const rawBuf = await readBoundedBody(req, 16384);
        let body: { adminAcceptWithoutLegalBasis?: boolean } = {};
        if (rawBuf.length > 0) {
          try {
            body = JSON.parse(rawBuf.toString('utf8')) as { adminAcceptWithoutLegalBasis?: boolean };
          } catch {
            sendJson(res, 400, { error: 'Invalid JSON body.' }, config.corsOrigin);
            return;
          }
        }
        const camera = await cameraManager.startStream(
          auth,
          camStartMatch[1],
          { adminAcceptWithoutLegalBasis: Boolean(body?.adminAcceptWithoutLegalBasis) },
          bearerJwt
        );
        sendJson(res, 200, { camera }, config.corsOrigin);
        return;
      }

      const camStopMatch = urlPath.match(/^\/api\/v1\/cameras\/([a-zA-Z0-9_-]{3,64})\/stop$/);
      if (req.method === 'POST' && camStopMatch) {
        if (!CAMERA_VIEW_ROLES.has(auth.role)) {
          sendJson(res, 403, { error: 'Role not permitted to stop camera streams.' }, config.corsOrigin);
          return;
        }
        const camera = cameraManager.stopStream(auth, camStopMatch[1]);
        sendJson(res, 200, { camera }, config.corsOrigin);
        return;
      }

      const camFrameMatch = urlPath.match(/^\/api\/v1\/cameras\/([a-zA-Z0-9_-]{3,64})\/frame$/);
      if (req.method === 'GET' && camFrameMatch) {
        const { frame } = await cameraManager.getLatestFrame(auth, camFrameMatch[1], bearerJwt);
        sendJpeg(res, 200, frame, config.corsOrigin);
        return;
      }

      const camAnalyticsMatch = urlPath.match(/^\/api\/v1\/cameras\/([a-zA-Z0-9_-]{3,64})\/analytics$/);
      if (req.method === 'GET' && camAnalyticsMatch) {
        const camera = cameraManager.getCameraAnalytics(auth, camAnalyticsMatch[1]);
        sendJson(res, 200, { camera }, config.corsOrigin);
        return;
      }

      const camPruneMatch = urlPath.match(/^\/api\/v1\/cameras\/([a-zA-Z0-9_-]{3,64})\/retention\/prune$/);
      if (req.method === 'POST' && camPruneMatch) {
        cameraManager.getCameraAnalytics(auth, camPruneMatch[1]);
        const deletedCount = await cameraManager.pruneExpiredFrames(undefined, bearerJwt);
        sendJson(res, 200, { deletedCount }, config.corsOrigin);
        return;
      }

      sendJson(res, 404, { error: 'Endpoint not found.' }, config.corsOrigin);
    } catch (err: any) {
      if (
        err instanceof GatewayAuthError ||
        err instanceof JobAccessError ||
        err instanceof CameraAccessError
      ) {
        sendJson(res, err.statusCode, { error: redactSensitive(err.message) }, config.corsOrigin);
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
    ctiService,
    analyticsCoordinator,
    cameraManager,
    tools: cachedTools,
    close: async () => {
      await cameraManager.close();
      await new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      });
    },
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
