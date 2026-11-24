/**
 * Project ATLAS — Bounded Registered Camera RTSP Stream Manager
 *
 * Security & Governance Guarantees (ADR 010 Amended):
 * - Only cameras registered to the requesting organisation can be started or viewed (`403` cross-org).
 * - Decodes 1 JPEG frame every 5 seconds via `ffmpeg` child process using `GatewayJobManager` timeouts.
 * - Keeps only the latest frame in memory (`latestFrame`) and writes zero files to disk when retention === 'none'.
 * - Stream URLs and embedded credentials are never returned in HTTP responses or written to logs.
 * - Enforces max 4 concurrent streams per organisation (`429`) and stops after 3 consecutive failures (`offline`).
 * - Records every frame request (`user`, `camera`, `time`) and retention deletion in the audit ledger.
 */

import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import type { CameraAnalyticsCoordinator } from './cameraAnalytics.js';
import type { GatewayJobManager } from './jobManager.js';
import { isUnsafeInfrastructureTarget } from './policy.js';
import type {
  AuthenticatedContext,
  CameraAuditRecord,
  CameraProtocol,
  CameraRegistrationInput,
  CameraRetentionSetting,
  CameraStreamState,
  SanitizedCameraRecord,
} from './types.js';

export const MAX_CONCURRENT_STREAMS_PER_ORG = 4;
export const CAMERA_DECODE_INTERVAL_MS = 5_000;
export const MAX_CONSECUTIVE_STREAM_FAILURES = 3;

export const RETENTION_DURATION_MS: Record<CameraRetentionSetting, number | null> = {
  none: null,
  '1h': 60 * 60 * 1000,
  '24h': 24 * 60 * 60 * 1000,
  '7d': 7 * 24 * 60 * 60 * 1000,
  '30d': 30 * 24 * 60 * 60 * 1000,
};

export const CAMERA_VIEW_ROLES = new Set<string>(['atlas:admin', 'atlas:analyst', 'atlas:viewer']);

export class CameraAccessError extends Error {
  constructor(
    public readonly statusCode: number,
    message: string
  ) {
    super(message);
    this.name = 'CameraAccessError';
  }
}

interface InternalCameraRecord {
  cameraId: string;
  orgId: string;
  siteId?: string;
  siteCode?: string;
  cameraCode: string;
  name: string;
  protocol: CameraProtocol;
  streamUrl: string; // STRICTLY SERVER-SIDE ONLY
  retentionSetting: CameraRetentionSetting;
  legalBasisRef?: string;
  adminAcceptedWithoutLegalBasis: boolean;
  adminAcceptedBy?: string;
  status: CameraStreamState;
  consecutiveFailures: number;
  offlineReason?: string;
  lastFrameAtUtc?: string;
  latestFrame?: Buffer;
  latestAnalytics?: SanitizedCameraRecord['latestAnalytics'];
  storedFrameTimestamps: Array<{ fileName: string; timestampMs: number }>;
  timer?: ReturnType<typeof setInterval>;
  inFlight?: boolean;
}

export type FrameGrabberFn = (streamUrl: string) => Promise<Buffer>;
export type CameraAuditSink = (entry: CameraAuditRecord, bearerJwt?: string) => Promise<void> | void;

export function validateCameraStreamUrl(rawUrl: string): { valid: boolean; reason?: string } {
  const trimmed = String(rawUrl || '').trim();
  if (!trimmed || /\s/.test(trimmed)) {
    return { valid: false, reason: 'Camera stream URL must be non-empty without whitespace.' };
  }
  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    return { valid: false, reason: 'Malformed camera stream URL.' };
  }
  if (!['rtsp:', 'rtsps:', 'https:'].includes(parsed.protocol)) {
    return { valid: false, reason: 'Camera stream URL must use rtsp://, rtsps://, or https://.' };
  }
  const unsafe = isUnsafeInfrastructureTarget(parsed.hostname);
  if (unsafe) {
    return { valid: false, reason: unsafe };
  }
  return { valid: true };
}

export function isValidJpegBuffer(buf: Buffer): boolean {
  return Buffer.isBuffer(buf) && buf.length >= 4 && buf[0] === 0xff && buf[1] === 0xd8;
}

export function redactStreamSecrets(input: string, secretUrls: string[]): string {
  let out = String(input || '');
  for (const rawUrl of secretUrls) {
    if (!rawUrl) continue;
    out = out.split(rawUrl).join('[REDACTED_STREAM_URL]');
    try {
      const parsed = new URL(rawUrl);
      if (parsed.username) out = out.split(parsed.username).join('[REDACTED]');
      if (parsed.password) out = out.split(parsed.password).join('[REDACTED]');
      if (parsed.search) out = out.split(parsed.search).join('[REDACTED_QUERY]');
    } catch {
      // already replaced raw string
    }
  }
  out = out.replace(/(rtsps?|https?):\/\/[^\s"']+/gi, '[REDACTED_STREAM_URL]');
  return out;
}

export interface CameraStreamManagerOptions {
  workDir: string;
  jobManager: GatewayJobManager;
  analyticsCoordinator: CameraAnalyticsCoordinator;
  ffmpegPath?: string | null;
  frameGrabber?: FrameGrabberFn;
  auditSink?: CameraAuditSink;
  supabaseUrl?: string;
  supabaseAnonKey?: string;
  now?: () => number;
  decodeIntervalMs?: number;
  logger?: (level: 'warn' | 'error', msg: string) => void;
}

export class CameraStreamManager {
  private readonly cameras = new Map<string, InternalCameraRecord>();
  private readonly auditLog: CameraAuditRecord[] = [];
  private readonly workDir: string;
  private readonly jobManager: GatewayJobManager;
  private readonly analytics: CameraAnalyticsCoordinator;
  private readonly ffmpegPath: string | null;
  private readonly customFrameGrabber?: FrameGrabberFn;
  private readonly auditSink?: CameraAuditSink;
  private readonly supabaseUrl?: string;
  private readonly supabaseAnonKey?: string;
  private readonly now: () => number;
  private readonly decodeIntervalMs: number;
  private readonly logger: (level: 'warn' | 'error', msg: string) => void;
  private readonly retentionSweeper: ReturnType<typeof setInterval>;

  constructor(opts: CameraStreamManagerOptions) {
    this.workDir = opts.workDir;
    this.jobManager = opts.jobManager;
    this.analytics = opts.analyticsCoordinator;
    this.ffmpegPath = opts.ffmpegPath === undefined ? '/usr/bin/ffmpeg' : opts.ffmpegPath;
    this.customFrameGrabber = opts.frameGrabber;
    this.auditSink = opts.auditSink;
    this.supabaseUrl = opts.supabaseUrl;
    this.supabaseAnonKey = opts.supabaseAnonKey;
    this.now = opts.now || (() => Date.now());
    this.decodeIntervalMs = opts.decodeIntervalMs ?? CAMERA_DECODE_INTERVAL_MS;
    this.logger =
      opts.logger ||
      ((level, msg) => {
        const clean = this.redact(msg);
        if (level === 'error') console.error(clean);
        else console.warn(clean);
      });

    this.retentionSweeper = setInterval(() => {
      void this.pruneExpiredFrames();
    }, 30_000);
    this.retentionSweeper.unref?.();
  }

  public redact(text: string): string {
    const urls = Array.from(this.cameras.values()).map((c) => c.streamUrl);
    return redactStreamSecrets(text, urls);
  }

  private toSanitized(cam: InternalCameraRecord): SanitizedCameraRecord {
    return {
      cameraId: cam.cameraId,
      orgId: cam.orgId,
      siteId: cam.siteId,
      siteCode: cam.siteCode,
      cameraCode: cam.cameraCode,
      name: cam.name,
      protocol: cam.protocol,
      retentionSetting: cam.retentionSetting,
      legalBasisRef: cam.legalBasisRef,
      adminAcceptedWithoutLegalBasis: cam.adminAcceptedWithoutLegalBasis,
      adminAcceptedBy: cam.adminAcceptedBy,
      status: cam.status,
      consecutiveFailures: cam.consecutiveFailures,
      offlineReason: cam.offlineReason ? this.redact(cam.offlineReason) : undefined,
      lastFrameAtUtc: cam.lastFrameAtUtc,
      hasLatestFrame: Boolean(cam.latestFrame),
      storedFramesCount: cam.storedFrameTimestamps.length,
      latestAnalytics: cam.latestAnalytics,
    };
  }

  private async recordAudit(
    entry: Omit<CameraAuditRecord, 'id'>,
    bearerJwt?: string
  ): Promise<void> {
    const full: CameraAuditRecord = {
      id: `camaud-${crypto.randomUUID().slice(0, 12)}`,
      ...entry,
      details: JSON.parse(this.redact(JSON.stringify(entry.details))) as Record<string, unknown>,
    };
    this.auditLog.push(full);
    if (this.auditLog.length > 500) {
      this.auditLog.splice(0, this.auditLog.length - 500);
    }

    if (this.auditSink) {
      await this.auditSink(full, bearerJwt);
    }

    if (
      bearerJwt &&
      this.supabaseUrl &&
      this.supabaseAnonKey &&
      !this.supabaseUrl.includes('test.supabase.co')
    ) {
      const rpcUrl = `${this.supabaseUrl.replace(/\/+$/, '')}/rest/v1/rpc/log_event`;
      void fetch(rpcUrl, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${bearerJwt}`,
          apikey: this.supabaseAnonKey,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          p_org_id: full.orgId,
          p_action: full.action,
          p_target_type: 'camera_registry',
          p_target_id: full.cameraId,
          p_correlation_id: full.id,
          p_details: full.details,
        }),
      }).catch((err: unknown) => {
        this.logger('warn', `[ATLAS-CAMERA-AUDIT] Forward to Supabase log_event failed: ${err instanceof Error ? err.message : 'error'}`);
      });
    }
  }

  public getAuditRecordsForOrg(orgId: string): CameraAuditRecord[] {
    return this.auditLog.filter((a) => a.orgId === orgId);
  }

  private requireCameraInOrg(cameraId: string, orgId: string): InternalCameraRecord {
    const cam = this.cameras.get(cameraId);
    if (!cam) {
      throw new CameraAccessError(404, `Camera "${cameraId}" not found.`);
    }
    if (cam.orgId !== orgId) {
      throw new CameraAccessError(403, 'Access denied: camera belongs to another organisation.');
    }
    return cam;
  }

  private countActiveOrgStreams(orgId: string): number {
    let active = 0;
    for (const c of this.cameras.values()) {
      if (c.orgId === orgId && c.status === 'streaming') active++;
    }
    return active;
  }

  public listCamerasForOrg(orgId: string): SanitizedCameraRecord[] {
    return Array.from(this.cameras.values())
      .filter((c) => c.orgId === orgId)
      .map((c) => this.toSanitized(c));
  }

  public async registerCamera(
    auth: AuthenticatedContext,
    input: CameraRegistrationInput,
    bearerJwt?: string
  ): Promise<SanitizedCameraRecord> {
    if (!input?.cameraCode?.trim() || !input?.name?.trim()) {
      throw new CameraAccessError(400, 'cameraCode and name are required.');
    }
    const urlCheck = validateCameraStreamUrl(input.streamUrl);
    if (!urlCheck.valid) {
      throw new CameraAccessError(400, this.redact(urlCheck.reason || 'Invalid camera stream URL.'));
    }

    const retention: CameraRetentionSetting = input.retentionSetting || 'none';
    if (!(retention in RETENTION_DURATION_MS)) {
      throw new CameraAccessError(400, 'Invalid retentionSetting. Allowed: none, 1h, 24h, 7d, 30d.');
    }

    const cameraId = input.cameraId?.trim() || crypto.randomUUID();
    const record: InternalCameraRecord = {
      cameraId,
      orgId: auth.orgId,
      siteId: input.siteId?.trim() || undefined,
      siteCode: input.siteCode?.trim() || undefined,
      cameraCode: input.cameraCode.trim(),
      name: input.name.trim(),
      protocol: input.protocol || 'RTSP_HLS',
      streamUrl: input.streamUrl.trim(),
      retentionSetting: retention,
      legalBasisRef: input.legalBasisRef?.trim() || undefined,
      adminAcceptedWithoutLegalBasis: false,
      status: 'registered',
      consecutiveFailures: 0,
      storedFrameTimestamps: [],
    };
    this.cameras.set(cameraId, record);

    if (input.autoStart) {
      return this.startStream(
        auth,
        cameraId,
        { adminAcceptWithoutLegalBasis: input.adminAcceptWithoutLegalBasis },
        bearerJwt
      );
    }

    return this.toSanitized(record);
  }

  public async startStream(
    auth: AuthenticatedContext,
    cameraId: string,
    opts?: { adminAcceptWithoutLegalBasis?: boolean },
    bearerJwt?: string
  ): Promise<SanitizedCameraRecord> {
    const cam = this.requireCameraInOrg(cameraId, auth.orgId);

    const hasLegalBasis = Boolean(cam.legalBasisRef && cam.legalBasisRef.trim());
    if (!hasLegalBasis && !cam.adminAcceptedWithoutLegalBasis) {
      if (opts?.adminAcceptWithoutLegalBasis) {
        if (auth.role !== 'atlas:admin') {
          throw new CameraAccessError(
            403,
            'Only an atlas:admin operator may accept activating a camera without a legal_basis_ref.'
          );
        }
        cam.adminAcceptedWithoutLegalBasis = true;
        cam.adminAcceptedBy = auth.userId;
        await this.recordAudit(
          {
            orgId: auth.orgId,
            userId: auth.userId,
            actorRole: auth.role,
            action: 'CAMERA_LEGAL_OVERRIDE',
            cameraId: cam.cameraId,
            observedAtUtc: new Date(this.now()).toISOString(),
            details: {
              camera: cam.cameraId,
              cameraCode: cam.cameraCode,
              user: auth.userId,
              reason: 'Admin accepted stream activation without legal_basis_ref',
            },
          },
          bearerJwt
        );
      } else {
        throw new CameraAccessError(
          412,
          'Camera has no legal_basis_ref; record a legal basis reference or have an atlas:admin accept activation.'
        );
      }
    }

    if (cam.status !== 'streaming' && this.countActiveOrgStreams(auth.orgId) >= MAX_CONCURRENT_STREAMS_PER_ORG) {
      throw new CameraAccessError(
        429,
        `Concurrency limit reached: maximum ${MAX_CONCURRENT_STREAMS_PER_ORG} concurrent streams per organisation.`
      );
    }

    if (cam.timer) {
      clearInterval(cam.timer);
      cam.timer = undefined;
    }

    cam.consecutiveFailures = 0;
    cam.offlineReason = undefined;
    cam.status = 'streaming';

    await this.decodeOneFrame(cam, bearerJwt);

    if (cam.status === 'streaming') {
      cam.timer = setInterval(() => {
        void this.decodeOneFrame(cam, bearerJwt);
      }, this.decodeIntervalMs);
      cam.timer.unref?.();
    }

    return this.toSanitized(cam);
  }

  public stopStream(auth: AuthenticatedContext, cameraId: string): SanitizedCameraRecord {
    const cam = this.requireCameraInOrg(cameraId, auth.orgId);
    if (cam.timer) {
      clearInterval(cam.timer);
      cam.timer = undefined;
    }
    cam.status = 'stopped';
    return this.toSanitized(cam);
  }

  private async grabFrameFromFfmpeg(cam: InternalCameraRecord): Promise<Buffer> {
    if (this.customFrameGrabber) {
      return this.customFrameGrabber(cam.streamUrl);
    }
    if (!this.ffmpegPath) {
      throw new Error('ffmpeg binary is not available on this gateway worker.');
    }
    const args = [
      '-hide_banner',
      '-loglevel',
      'error',
      '-rtsp_transport',
      'tcp',
      '-i',
      cam.streamUrl,
      '-frames:v',
      '1',
      '-f',
      'image2pipe',
      '-vcodec',
      'mjpeg',
      '-q:v',
      '5',
      'pipe:1',
    ];
    const res = await this.jobManager.runCameraFrameCapture(
      this.ffmpegPath,
      args,
      this.jobManager.defaultCameraDecodeTimeoutMs,
      4 * 1024 * 1024
    );
    if (res.timedOut) {
      throw new Error(`ffmpeg decode timed out after ${this.jobManager.defaultCameraDecodeTimeoutMs} ms.`);
    }
    if (res.exitCode !== 0 || !isValidJpegBuffer(res.frameBuffer)) {
      const cleanErr = this.redact(res.stderr || `ffmpeg exited with code ${res.exitCode}`);
      throw new Error(cleanErr || 'ffmpeg did not produce a valid JPEG frame.');
    }
    return res.frameBuffer;
  }

  public async decodeOneFrame(cam: InternalCameraRecord, bearerJwt?: string): Promise<void> {
    if (cam.inFlight || cam.status !== 'streaming') return;
    cam.inFlight = true;
    try {
      const frame = await this.grabFrameFromFfmpeg(cam);
      if (!isValidJpegBuffer(frame)) {
        throw new Error('Decoded output was not a valid JPEG image.');
      }

      const nowMs = this.now();
      const nowIso = new Date(nowMs).toISOString();
      cam.consecutiveFailures = 0;
      cam.offlineReason = undefined;
      cam.latestFrame = frame;
      cam.lastFrameAtUtc = nowIso;

      // Write frame to disk ONLY when retentionSetting !== 'none'
      if (cam.retentionSetting !== 'none') {
        const orgCamDir = path.resolve(this.workDir, 'camera_frames', cam.orgId, cam.cameraId);
        const expectedBase = path.resolve(this.workDir, 'camera_frames', cam.orgId) + path.sep;
        if (!orgCamDir.startsWith(expectedBase)) {
          throw new Error('Invalid camera storage directory boundary.');
        }
        await fs.mkdir(orgCamDir, { recursive: true });
        const fileName = `${nowMs}-${crypto.randomUUID().slice(0, 6)}.jpg`;
        await fs.writeFile(path.join(orgCamDir, fileName), frame, { mode: 0o600 });
        cam.storedFrameTimestamps.push({ fileName, timestampMs: nowMs });
      }

      const analyticsResult = await this.analytics.analyzeFrame({
        orgId: cam.orgId,
        cameraId: cam.cameraId,
        cameraCode: cam.cameraCode,
        frameBuffer: frame,
      });
      cam.latestAnalytics = analyticsResult;

      for (const alert of analyticsResult.alerts) {
        await this.recordAudit(
          {
            orgId: cam.orgId,
            userId: 'atlas:system',
            actorRole: 'atlas:system',
            action: 'CAMERA_PERSON_ALERT',
            cameraId: cam.cameraId,
            observedAtUtc: alert.triggeredAtUtc,
            details: {
              camera: cam.cameraId,
              cameraCode: cam.cameraCode,
              personLabel: alert.personLabel,
              identityId: alert.identityId || null,
              trackId: alert.trackId || null,
              confidence: alert.confidence,
              reason: alert.reason,
              time: alert.triggeredAtUtc,
            },
          },
          bearerJwt
        );
      }
    } catch (err: unknown) {
      cam.consecutiveFailures += 1;
      const safeReason = this.redact(err instanceof Error ? err.message : 'Camera stream decode failure.');
      this.logger('warn', `[ATLAS-CAMERA] Decode failure (${cam.consecutiveFailures}/${MAX_CONSECUTIVE_STREAM_FAILURES}) for ${cam.cameraCode}: ${safeReason}`);
      if (cam.consecutiveFailures >= MAX_CONSECUTIVE_STREAM_FAILURES) {
        if (cam.timer) {
          clearInterval(cam.timer);
          cam.timer = undefined;
        }
        cam.status = 'offline';
        cam.offlineReason = safeReason || 'Stream stopped after 3 consecutive failures.';
      }
    } finally {
      cam.inFlight = false;
    }
  }

  public async getLatestFrame(
    auth: AuthenticatedContext,
    cameraId: string,
    bearerJwt?: string
  ): Promise<{ frame: Buffer; camera: SanitizedCameraRecord }> {
    if (!CAMERA_VIEW_ROLES.has(auth.role)) {
      throw new CameraAccessError(403, `Role "${auth.role}" is not permitted to view live camera frames.`);
    }
    const cam = this.requireCameraInOrg(cameraId, auth.orgId);

    const observedAtUtc = new Date(this.now()).toISOString();
    await this.recordAudit(
      {
        orgId: auth.orgId,
        userId: auth.userId,
        actorRole: auth.role,
        action: 'CAMERA_FRAME_VIEW',
        cameraId: cam.cameraId,
        observedAtUtc,
        details: {
          user: auth.userId,
          camera: cam.cameraId,
          cameraCode: cam.cameraCode,
          time: observedAtUtc,
        },
      },
      bearerJwt
    );

    if (!cam.latestFrame) {
      throw new CameraAccessError(
        cam.status === 'offline' ? 503 : 404,
        cam.status === 'offline'
          ? `Camera offline: ${this.redact(cam.offlineReason || 'stream unavailable')}`
          : 'No decoded JPEG frame available yet for this camera.'
      );
    }

    return { frame: cam.latestFrame, camera: this.toSanitized(cam) };
  }

  public getCameraAnalytics(auth: AuthenticatedContext, cameraId: string): SanitizedCameraRecord {
    if (!CAMERA_VIEW_ROLES.has(auth.role)) {
      throw new CameraAccessError(403, `Role "${auth.role}" is not permitted to view camera analytics.`);
    }
    const cam = this.requireCameraInOrg(cameraId, auth.orgId);
    return this.toSanitized(cam);
  }

  public async pruneExpiredFrames(nowMs = this.now(), bearerJwt?: string): Promise<number> {
    let totalDeleted = 0;
    for (const cam of this.cameras.values()) {
      const retentionMs = RETENTION_DURATION_MS[cam.retentionSetting];
      if (!retentionMs || cam.storedFrameTimestamps.length === 0) continue;

      const cutoff = nowMs - retentionMs;
      const keep: Array<{ fileName: string; timestampMs: number }> = [];
      let deletedForCam = 0;
      const orgCamDir = path.resolve(this.workDir, 'camera_frames', cam.orgId, cam.cameraId);

      for (const item of cam.storedFrameTimestamps) {
        if (item.timestampMs <= cutoff) {
          try {
            await fs.unlink(path.join(orgCamDir, item.fileName));
          } catch {
            // file may already be absent
          }
          deletedForCam++;
          totalDeleted++;
        } else {
          keep.push(item);
        }
      }
      cam.storedFrameTimestamps = keep;

      if (deletedForCam > 0) {
        const deletedAtUtc = new Date(nowMs).toISOString();
        await this.recordAudit(
          {
            orgId: cam.orgId,
            userId: 'atlas:system',
            actorRole: 'atlas:system',
            action: 'CAMERA_RETENTION_DELETE',
            cameraId: cam.cameraId,
            observedAtUtc: deletedAtUtc,
            details: {
              camera: cam.cameraId,
              cameraCode: cam.cameraCode,
              deletedCount: deletedForCam,
              retentionSetting: cam.retentionSetting,
              time: deletedAtUtc,
            },
          },
          bearerJwt
        );
      }
    }
    return totalDeleted;
  }

  public async close(): Promise<void> {
    clearInterval(this.retentionSweeper);
    for (const cam of this.cameras.values()) {
      if (cam.timer) {
        clearInterval(cam.timer);
        cam.timer = undefined;
      }
    }
  }
}
