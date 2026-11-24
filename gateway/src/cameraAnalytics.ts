/**
 * Project ATLAS — Authorised Site Camera Biometric & Person Analytics Coordinator
 *
 * Implements ADR 010 (Amended) & ADR 006 (Amended):
 * - Supports face detection, face recognition (cosine similarity against enrolled
 *   organisation identities), person detection/counting, cross-camera individual tracking,
 *   and automatic person-identifying alerts.
 * - Routes frame analysis to an operator-configured vision worker (`CAMERA_ANALYTICS_URL`)
 *   and never fabricates detections when no vision runtime is available.
 */

import crypto from 'node:crypto';
import { isUnsafeInfrastructureTarget } from './policy.js';
import type {
  CameraAnalyticsConfig,
  CameraAnalyticsResult,
  CameraFaceObservation,
  CameraPersonAlert,
  CameraPersonObservation,
} from './types.js';

export interface BiometricIdentityRecord {
  id: string;
  orgId: string;
  personLabel: string;
  personRef: string;
  embedding: number[];
  legalBasisRef?: string;
  createdAtUtc: string;
}

export interface VisionWorkerFaceRaw {
  confidence: number;
  box: { x: number; y: number; w: number; h: number };
  embedding?: number[];
  recognizedIdentityId?: string;
  recognizedLabel?: string;
  similarity?: number;
}

export interface VisionWorkerPersonRaw {
  trackId: string;
  confidence: number;
  box: { x: number; y: number; w: number; h: number };
  embedding?: number[];
  identityId?: string;
  personLabel?: string;
}

export interface VisionWorkerRawOutput {
  faces: VisionWorkerFaceRaw[];
  persons: VisionWorkerPersonRaw[];
}

export type VisionFrameAnalyzer = (params: {
  orgId: string;
  cameraId: string;
  cameraCode: string;
  observedAtUtc: string;
  frameBuffer: Buffer;
  enrolledIdentities: Array<{ id: string; personLabel: string; personRef: string; embedding: number[] }>;
}) => Promise<VisionWorkerRawOutput>;

interface CrossCameraTrackEntry {
  camerasSeen: Map<string, number>; // cameraCode -> lastSeenMs
  personLabel?: string;
  identityId?: string;
}

function cosineSimilarity(a: number[], b: number[]): number {
  if (!a.length || a.length !== b.length) return 0;
  let dot = 0;
  let normA = 0;
  let normB = 0;
  for (let i = 0; i < a.length; i++) {
    dot += a[i] * b[i];
    normA += a[i] * a[i];
    normB += b[i] * b[i];
  }
  const denom = Math.sqrt(normA) * Math.sqrt(normB);
  return denom > 0 ? dot / denom : 0;
}

export function loadCameraAnalyticsConfigFromEnv(env = process.env): CameraAnalyticsConfig {
  return {
    analyticsUrl: env.CAMERA_ANALYTICS_URL?.trim() || undefined,
    analyticsApiKey: env.CAMERA_ANALYTICS_API_KEY?.trim() || undefined,
  };
}

export function validateAnalyticsWorkerUrl(rawUrl: string): { valid: boolean; reason?: string } {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return { valid: false, reason: 'Malformed CAMERA_ANALYTICS_URL.' };
  }
  if (parsed.username || parsed.password) {
    return { valid: false, reason: 'Embedded URL credentials are prohibited in CAMERA_ANALYTICS_URL.' };
  }
  const host = parsed.hostname.toLowerCase();
  if (host === '169.254.169.254' || host === 'metadata.google.internal' || host === '100.100.100.200') {
    return { valid: false, reason: 'Cloud metadata targets are blocked for CAMERA_ANALYTICS_URL.' };
  }
  const isLoopback = host === '127.0.0.1' || host === 'localhost' || host === '::1';
  if (parsed.protocol === 'https:' || (parsed.protocol === 'http:' && isLoopback)) {
    return { valid: true };
  }
  const unsafe = isUnsafeInfrastructureTarget(host);
  if (unsafe && !isLoopback) {
    return { valid: false, reason: unsafe };
  }
  return { valid: false, reason: 'Remote CAMERA_ANALYTICS_URL requires HTTPS (plain HTTP allowed only on localhost/127.0.0.1).' };
}

export class CameraAnalyticsCoordinator {
  private readonly identities = new Map<string, BiometricIdentityRecord>();
  private readonly tracksByOrgKey = new Map<string, CrossCameraTrackEntry>();
  private readonly customAnalyzer?: VisionFrameAnalyzer;
  private readonly now: () => number;

  constructor(
    private readonly config: CameraAnalyticsConfig,
    opts?: { analyzer?: VisionFrameAnalyzer; now?: () => number }
  ) {
    this.customAnalyzer = opts?.analyzer;
    this.now = opts?.now || (() => Date.now());
  }

  public getConfiguredSecret(): string[] {
    return this.config.analyticsApiKey ? [this.config.analyticsApiKey] : [];
  }

  public enrollIdentity(params: {
    orgId: string;
    personLabel: string;
    personRef: string;
    embedding: number[];
    legalBasisRef?: string;
  }): BiometricIdentityRecord {
    const id = crypto.randomUUID();
    const record: BiometricIdentityRecord = {
      id,
      orgId: params.orgId,
      personLabel: params.personLabel.trim(),
      personRef: params.personRef.trim(),
      embedding: params.embedding,
      legalBasisRef: params.legalBasisRef?.trim() || undefined,
      createdAtUtc: new Date(this.now()).toISOString(),
    };
    this.identities.set(id, record);
    return record;
  }

  public listIdentitiesForOrg(orgId: string): Array<Omit<BiometricIdentityRecord, 'embedding'> & { embeddingDim: number }> {
    return Array.from(this.identities.values())
      .filter((i) => i.orgId === orgId)
      .map((i) => ({
        id: i.id,
        orgId: i.orgId,
        personLabel: i.personLabel,
        personRef: i.personRef,
        legalBasisRef: i.legalBasisRef,
        createdAtUtc: i.createdAtUtc,
        embeddingDim: i.embedding.length,
      }));
  }

  private async invokeWorker(params: {
    orgId: string;
    cameraId: string;
    cameraCode: string;
    observedAtUtc: string;
    frameBuffer: Buffer;
    enrolledIdentities: BiometricIdentityRecord[];
  }): Promise<VisionWorkerRawOutput> {
    if (this.customAnalyzer) {
      return this.customAnalyzer({
        orgId: params.orgId,
        cameraId: params.cameraId,
        cameraCode: params.cameraCode,
        observedAtUtc: params.observedAtUtc,
        frameBuffer: params.frameBuffer,
        enrolledIdentities: params.enrolledIdentities.map((i) => ({
          id: i.id,
          personLabel: i.personLabel,
          personRef: i.personRef,
          embedding: i.embedding,
        })),
      });
    }

    if (!this.config.analyticsUrl) {
      throw new Error(
        'Vision inference worker unavailable: CAMERA_ANALYTICS_URL is not configured and Python vision dependencies (cv2, onnxruntime, insightface) are not installed locally.'
      );
    }

    const urlCheck = validateAnalyticsWorkerUrl(this.config.analyticsUrl);
    if (!urlCheck.valid) {
      throw new Error(urlCheck.reason || 'Invalid CAMERA_ANALYTICS_URL.');
    }

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      Accept: 'application/json',
    };
    if (this.config.analyticsApiKey) {
      headers.Authorization = `Bearer ${this.config.analyticsApiKey}`;
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 8000);
    try {
      const res = await fetch(this.config.analyticsUrl, {
        method: 'POST',
        headers,
        signal: controller.signal,
        body: JSON.stringify({
          orgId: params.orgId,
          cameraId: params.cameraId,
          cameraCode: params.cameraCode,
          observedAtUtc: params.observedAtUtc,
          frameBase64: params.frameBuffer.toString('base64'),
          enrolledIdentities: params.enrolledIdentities.map((i) => ({
            id: i.id,
            personLabel: i.personLabel,
            personRef: i.personRef,
            embedding: i.embedding,
          })),
        }),
      });
      if (!res.ok) {
        throw new Error(`Vision worker returned HTTP ${res.status}.`);
      }
      const data = (await res.json()) as VisionWorkerRawOutput;
      return {
        faces: Array.isArray(data?.faces) ? data.faces : [],
        persons: Array.isArray(data?.persons) ? data.persons : [],
      };
    } finally {
      clearTimeout(timer);
    }
  }

  public async analyzeFrame(params: {
    orgId: string;
    cameraId: string;
    cameraCode: string;
    frameBuffer: Buffer;
  }): Promise<CameraAnalyticsResult> {
    const nowMs = this.now();
    const nowIso = new Date(nowMs).toISOString();
    const orgIdentities = Array.from(this.identities.values()).filter((i) => i.orgId === params.orgId);

    let raw: VisionWorkerRawOutput;
    try {
      raw = await this.invokeWorker({
        orgId: params.orgId,
        cameraId: params.cameraId,
        cameraCode: params.cameraCode,
        observedAtUtc: nowIso,
        frameBuffer: params.frameBuffer,
        enrolledIdentities: orgIdentities,
      });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Vision analytics worker unavailable.';
      return {
        status: 'ANALYTICS_UNAVAILABLE',
        unavailableReason: this.config.analyticsApiKey
          ? msg.split(this.config.analyticsApiKey).join('[REDACTED]')
          : msg,
        analyzedAtUtc: nowIso,
        faceCount: 0,
        personCount: 0,
        faces: [],
        persons: [],
        alerts: [],
      };
    }

    const alerts: CameraPersonAlert[] = [];
    const faces: CameraFaceObservation[] = [];

    for (const f of raw.faces) {
      let matchedId = f.recognizedIdentityId;
      let matchedLabel = f.recognizedLabel;
      let similarity = f.similarity;

      if (!matchedId && Array.isArray(f.embedding) && f.embedding.length > 0) {
        let bestScore = 0;
        let bestIdentity: BiometricIdentityRecord | null = null;
        for (const candidate of orgIdentities) {
          const sim = cosineSimilarity(f.embedding, candidate.embedding);
          if (sim > bestScore) {
            bestScore = sim;
            bestIdentity = candidate;
          }
        }
        if (bestIdentity && bestScore >= 0.72) {
          matchedId = bestIdentity.id;
          matchedLabel = bestIdentity.personLabel;
          similarity = Number(bestScore.toFixed(4));
        }
      }

      faces.push({
        confidence: f.confidence,
        box: f.box,
        recognizedIdentityId: matchedId,
        recognizedLabel: matchedLabel,
        biometricSimilarity: similarity,
      });

      if (matchedLabel) {
        alerts.push({
          alertId: `alert-${crypto.randomUUID().slice(0, 12)}`,
          cameraId: params.cameraId,
          cameraCode: params.cameraCode,
          personLabel: matchedLabel,
          identityId: matchedId,
          confidence: similarity ?? f.confidence,
          reason: `Biometric face recognition match for "${matchedLabel}" on ${params.cameraCode}.`,
          triggeredAtUtc: nowIso,
        });
      }
    }

    // Track persons & update cross-camera trajectory history (15m sliding window)
    const persons: CameraPersonObservation[] = [];
    const windowCutoffMs = nowMs - 15 * 60 * 1000;

    for (const p of raw.persons) {
      let matchedId = p.identityId;
      let matchedLabel = p.personLabel;

      if (!matchedId && Array.isArray(p.embedding) && p.embedding.length > 0) {
        let bestScore = 0;
        let bestIdentity: BiometricIdentityRecord | null = null;
        for (const candidate of orgIdentities) {
          const sim = cosineSimilarity(p.embedding, candidate.embedding);
          if (sim > bestScore) {
            bestScore = sim;
            bestIdentity = candidate;
          }
        }
        if (bestIdentity && bestScore >= 0.72) {
          matchedId = bestIdentity.id;
          matchedLabel = bestIdentity.personLabel;
        }
      }

      const trackKey = `${params.orgId}::${matchedId || p.trackId}`;
      const existingTrack = this.tracksByOrgKey.get(trackKey) || {
        camerasSeen: new Map<string, number>(),
      };
      for (const [cam, seenMs] of existingTrack.camerasSeen.entries()) {
        if (seenMs < windowCutoffMs) existingTrack.camerasSeen.delete(cam);
      }
      existingTrack.camerasSeen.set(params.cameraCode, nowMs);
      if (matchedId) existingTrack.identityId = matchedId;
      if (matchedLabel) existingTrack.personLabel = matchedLabel;
      this.tracksByOrgKey.set(trackKey, existingTrack);

      const crossCameraSeenIn = Array.from(existingTrack.camerasSeen.keys());

      persons.push({
        trackId: p.trackId,
        confidence: p.confidence,
        box: p.box,
        identityId: matchedId,
        personLabel: matchedLabel,
        crossCameraSeenIn,
      });

      if (matchedLabel && crossCameraSeenIn.length >= 2) {
        const alreadyAlerted = alerts.some(
          (a) => a.personLabel === matchedLabel && a.trackId === p.trackId
        );
        if (!alreadyAlerted) {
          alerts.push({
            alertId: `alert-${crypto.randomUUID().slice(0, 12)}`,
            cameraId: params.cameraId,
            cameraCode: params.cameraCode,
            personLabel: matchedLabel,
            identityId: matchedId,
            trackId: p.trackId,
            confidence: p.confidence,
            reason: `Cross-camera person alert: "${matchedLabel}" tracked across ${crossCameraSeenIn.join(' -> ')}.`,
            triggeredAtUtc: nowIso,
          });
        }
      }
    }

    return {
      status: 'ANALYZED',
      analyzedAtUtc: nowIso,
      faceCount: faces.length,
      personCount: persons.length,
      faces,
      persons,
      alerts,
    };
  }
}
