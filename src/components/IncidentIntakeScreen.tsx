/**
 * Project ATLAS: Incident Intake & Rule-Based Match Review (Stage 4)
 *
 * HARD RULES:
 * 1. Database-Authoritative: Every incident is ingested via ingest_incident() RPC.
 * 2. Contract: Validates schema_version "1.0", event_id, event_type allowlist,
 *    observed_at, sent_at (rejects >10m old), confidence, and signals.
 * 3. Idempotency: Duplicate event_id is a safe no-op returning the original record.
 * 4. Rule-based matching: exact site code, exact hostname, exact IP, CIDR containment,
 *    cloud account id, fuzzy hostname (pg_trgm).
 * 5. Score >= 0.90 is 'auto'; < 0.90 is 'proposed' requiring analyst confirmation.
 * 6. Store confirmations and rejections as labelled data.
 */

import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { atlasService } from '../data/api';
import { signIngestPayload } from '../utils/crypto';
import { Incident, AssetMatch, Asset, IngestKeyRecord } from '../types/atlas';
import {
  Radio,
  Send,
  RefreshCw,
  Repeat,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  ShieldCheck,
  ShieldAlert,
  Server,
  Zap,
  Cpu,
  Layers,
  ArrowRight,
  Database,
  FileCode,
  Tag,
  Clock,
  ExternalLink,
} from 'lucide-react';

interface IncidentIntakeScreenProps {
  activeOrgId: string;
  userRole?: string;
  onNavigateToBlastRadius?: (incidentId: string) => void;
}

export const IncidentIntakeScreen: React.FC<IncidentIntakeScreenProps> = ({
  activeOrgId,
  userRole,
  onNavigateToBlastRadius,
}) => {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string>('');
  const [matches, setMatches] = useState<AssetMatch[]>([]);
  const [assets, setAssets] = useState<Asset[]>([]);

  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Mock CSX Sender State
  const [payloadTemplate, setPayloadTemplate] = useState<string>('site_code');
  const [customJsonPayload, setCustomJsonPayload] = useState<string>('');
  const [isSending, setIsSending] = useState<boolean>(false);
  const [senderResult, setSenderResult] = useState<{
    success: boolean;
    idempotent: boolean;
    incident_id?: string;
    event_id?: string;
    matches_count?: number;
    message?: string;
  } | null>(null);
  const [senderError, setSenderError] = useState<string | null>(null);

  // Ingest signing (migrations 013 & 015). The secret lives only in this component's memory, never in storage.
  const isAdmin = userRole === 'atlas:admin';
  const [ingestKeys, setIngestKeys] = useState<IngestKeyRecord[]>([]);
  const [keyError, setKeyError] = useState<string | null>(null);
  const [isKeyBusy, setIsKeyBusy] = useState<boolean>(false);
  const [signingKeyId, setSigningKeyId] = useState<string>('');
  const [signingSecret, setSigningSecret] = useState<string>('');
  const [newSecretNotice, setNewSecretNotice] = useState<{ key_id: string; secret: string; rotatedFrom?: { old_key_id: string; old_key_expires_at: string } } | null>(null);
  const [pendingRotateKeyId, setPendingRotateKeyId] = useState<string | null>(null);
  const [rotateGraceMinutes, setRotateGraceMinutes] = useState<string>('60');

  const loadIngestKeys = useCallback(async () => {
    if (!activeOrgId) return;
    try {
      setKeyError(null);
      setIngestKeys(await atlasService.listIngestKeys(activeOrgId));
    } catch (err: any) {
      setKeyError(err.message || 'Could not load ingest keys.');
    }
  }, [activeOrgId]);

  useEffect(() => {
    // A secret belongs to one workspace: clear it when the workspace changes.
    setSigningKeyId('');
    setSigningSecret('');
    setNewSecretNotice(null);
    loadIngestKeys();
  }, [activeOrgId, loadIngestKeys]);

  const handleCreateKey = async () => {
    setIsKeyBusy(true);
    setKeyError(null);
    try {
      const created = await atlasService.createIngestKey(activeOrgId);
      setNewSecretNotice(created);
      setSigningKeyId(created.key_id);
      setSigningSecret(created.secret);
      await loadIngestKeys();
    } catch (err: any) {
      setKeyError(err.message || 'Could not create ingest key.');
    } finally {
      setIsKeyBusy(false);
    }
  };

  const handleRotateKey = async (oldKeyId: string) => {
    const mins = Number(rotateGraceMinutes);
    if (!Number.isInteger(mins) || mins < 0 || mins > 1440) {
      setKeyError('Grace period must be a whole number between 0 and 1440 minutes.');
      return;
    }
    setPendingRotateKeyId(null);
    setIsKeyBusy(true);
    setKeyError(null);
    try {
      const rotated = await atlasService.rotateIngestKey(activeOrgId, oldKeyId, mins);
      setNewSecretNotice({
        key_id: rotated.key_id,
        secret: rotated.secret,
        rotatedFrom: {
          old_key_id: rotated.old_key_id,
          old_key_expires_at: rotated.old_key_expires_at,
        },
      });
      setSigningKeyId(rotated.key_id);
      setSigningSecret(rotated.secret);
      await loadIngestKeys();
    } catch (err: any) {
      setKeyError(err.message || 'Could not rotate ingest key.');
    } finally {
      setIsKeyBusy(false);
    }
  };

  const handleRevokeKey = async (keyId: string) => {
    setPendingRevokeKeyId(null);
    setIsKeyBusy(true);
    setKeyError(null);
    try {
      await atlasService.revokeIngestKey(activeOrgId, keyId);
      if (signingKeyId === keyId) {
        setSigningKeyId('');
        setSigningSecret('');
      }
      await loadIngestKeys();
    } catch (err: any) {
      setKeyError(err.message || 'Could not revoke ingest key.');
    } finally {
      setIsKeyBusy(false);
    }
  };

  // Decision in progress
  const [decidingMatchId, setDecidingMatchId] = useState<string | null>(null);
  // Inline confirmations (browser dialogs such as confirm()/prompt()/alert() are blocked inside sandboxed previews)
  const [pendingRevokeKeyId, setPendingRevokeKeyId] = useState<string | null>(null);
  const [rejectingMatchId, setRejectingMatchId] = useState<string | null>(null);
  const [rejectReason, setRejectReason] = useState<string>('Telemetry false positive / non-correlated');
  const [decisionError, setDecisionError] = useState<string | null>(null);

  // Load existing incidents and assets
  const loadData = useCallback(async () => {
    if (!activeOrgId) return;

    setIsLoading(true);
    setError(null);

    try {
      const [fetchedIncidents, fetchedAssets] = await Promise.all([
        atlasService.fetchIncidents(activeOrgId),
        atlasService.fetchWorkspaceAssetsList(activeOrgId),
      ]);

      setIncidents(fetchedIncidents);
      setAssets(fetchedAssets);

      if (fetchedIncidents.length > 0 && !selectedIncidentId) {
        setSelectedIncidentId(fetchedIncidents[0].id);
      }
    } catch (err: any) {
      setError(err.message || 'Error loading incident intake data.');
    } finally {
      setIsLoading(false);
    }
  }, [activeOrgId]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  // Load matches for selected incident
  const loadMatches = useCallback(async () => {
    if (!selectedIncidentId || !activeOrgId) return;

    try {
      const fetchedMatches = await atlasService.fetchIncidentMatches(activeOrgId, selectedIncidentId);
      setMatches(fetchedMatches);
    } catch (err: any) {
      console.warn('Error fetching matches:', err);
    }
  }, [activeOrgId, selectedIncidentId]);

  useEffect(() => {
    loadMatches();
  }, [loadMatches]);

  // Generate synthetic sample payload based on template and active assets
  useEffect(() => {
    const now = new Date();
    const sentAtIso = now.toISOString();
    const observedAtIso = new Date(now.getTime() - 2 * 60 * 1000).toISOString();

    const sampleAsset = assets[0];
    const siteCodeSample = sampleAsset?.site_code || 'STE-A1';
    const hostnameSample = sampleAsset?.identifiers?.hostnames?.[0] || 'scada-node-01.grid.internal';
    const ipSample = sampleAsset?.identifiers?.ip_addresses?.[0] || '10.240.12.44';

    let sampleObj: Record<string, any>;

    switch (payloadTemplate) {
      case 'site_code':
        sampleObj = {
          schema_version: '1.0',
          event_id: `CSX-EVT-${Date.now().toString().slice(-6)}`,
          event_type: 'PHYSICAL_INTRUSION',
          severity: 'critical',
          observed_at: observedAtIso,
          sent_at: sentAtIso,
          confidence: 0.95,
          signals: {
            site_codes: [siteCodeSample],
            hostnames: [],
            ips: [],
            cidrs: [],
            cloud_account_ids: [],
          },
          org_id: activeOrgId,
          source: 'CyberShield X Perimeter Radar',
          correlation_id: `cid-csx-${Date.now()}`,
        };
        break;

      case 'hostname':
        sampleObj = {
          schema_version: '1.0',
          event_id: `CSX-EVT-${Date.now().toString().slice(-6)}`,
          event_type: 'OT_DISRUPTION',
          severity: 'high',
          observed_at: observedAtIso,
          sent_at: sentAtIso,
          confidence: 0.90,
          signals: {
            site_codes: [],
            hostnames: [hostnameSample],
            ips: [],
            cidrs: [],
            cloud_account_ids: [],
          },
          org_id: activeOrgId,
          source: 'CyberShield X Endpoint Agent',
          correlation_id: `cid-csx-${Date.now()}`,
        };
        break;

      case 'ip_and_cidr':
        sampleObj = {
          schema_version: '1.0',
          event_id: `CSX-EVT-${Date.now().toString().slice(-6)}`,
          event_type: 'TELEMETRY_ANOMALY',
          severity: 'medium',
          observed_at: observedAtIso,
          sent_at: sentAtIso,
          confidence: 0.85,
          signals: {
            site_codes: [],
            hostnames: [],
            ips: [ipSample],
            cidrs: ['10.240.0.0/16'],
            cloud_account_ids: [],
          },
          org_id: activeOrgId,
          source: 'CyberShield X NetFlow Monitor',
          correlation_id: `cid-csx-${Date.now()}`,
        };
        break;

      case 'fuzzy_hostname':
        // Deliberate typo in hostname to test pg_trgm fuzzy matching rule
        const typoHostname = hostnameSample.replace('scada', 'scda').replace('node', 'nod');
        sampleObj = {
          schema_version: '1.0',
          event_id: `CSX-EVT-${Date.now().toString().slice(-6)}`,
          event_type: 'SCADA_UNAUTHORIZED_COMMAND',
          severity: 'high',
          observed_at: observedAtIso,
          sent_at: sentAtIso,
          confidence: 0.78,
          signals: {
            site_codes: [],
            hostnames: [typoHostname],
            ips: [],
            cidrs: [],
            cloud_account_ids: [],
          },
          org_id: activeOrgId,
          source: 'CyberShield X Heuristic Parser',
          correlation_id: `cid-csx-${Date.now()}`,
        };
        break;

      case 'stale_replay':
        // Timestamp > 10 minutes ago to test replay rejection
        const staleSentAt = new Date(now.getTime() - 15 * 60 * 1000).toISOString();
        sampleObj = {
          schema_version: '1.0',
          event_id: `CSX-STALE-${Date.now().toString().slice(-6)}`,
          event_type: 'RANSOMWARE',
          severity: 'critical',
          observed_at: observedAtIso,
          sent_at: staleSentAt,
          confidence: 0.95,
          signals: {
            site_codes: [siteCodeSample],
            hostnames: [],
            ips: [],
            cidrs: [],
            cloud_account_ids: [],
          },
          org_id: activeOrgId,
          source: 'CyberShield X Replay Tester',
        };
        break;

      case 'unknown_field':
        sampleObj = {
          schema_version: '1.0',
          event_id: `CSX-ROGUE-${Date.now().toString().slice(-6)}`,
          event_type: 'OT_DISRUPTION',
          severity: 'low',
          observed_at: observedAtIso,
          sent_at: sentAtIso,
          confidence: 1.0,
          unauthorized_extra_field: 'malformed_contract_injection',
          signals: {
            site_codes: [siteCodeSample],
          },
          org_id: activeOrgId,
        };
        break;

      default:
        sampleObj = {};
    }

    setCustomJsonPayload(JSON.stringify(sampleObj, null, 2));
  }, [payloadTemplate, assets, activeOrgId]);

  // Send incident payload to database contract
  const handleSendPayload = async () => {
    setIsSending(true);
    setSenderResult(null);
    setSenderError(null);

    let parsedPayload: Record<string, unknown>;
    try {
      parsedPayload = JSON.parse(customJsonPayload);
    } catch (err: any) {
      setSenderError(`Malformed JSON syntax: ${err.message}`);
      setIsSending(false);
      return;
    }

    if (!signingKeyId.trim() || !signingSecret.trim()) {
      setSenderError('Signing key and secret are required: incident messages must be signed. Create a key (administrators) or paste an existing key id and secret above.');
      setIsSending(false);
      return;
    }

    try {
      // The database signs-checks against the organisation the message names; make that explicit.
      const orgForSigning = typeof parsedPayload.org_id === 'string' && parsedPayload.org_id ? parsedPayload.org_id : activeOrgId;
      const toSign = { ...parsedPayload, org_id: orgForSigning };
      const signed = await signIngestPayload(orgForSigning, toSign, signingKeyId.trim(), signingSecret.trim());
      const res = await atlasService.ingestIncident(signed);
      setSenderResult(res);

      if (res.incident_id) {
        await loadData();
        setSelectedIncidentId(res.incident_id);
      }
    } catch (err: any) {
      setSenderError(err.message || 'Incident ingest contract rejected payload.');
    } finally {
      setIsSending(false);
    }
  };

  // Confirm match decision
  const handleConfirmMatch = async (matchId: string) => {
    setDecidingMatchId(matchId);
    setDecisionError(null);
    try {
      await atlasService.confirmAssetMatch(matchId);
      await loadMatches();
    } catch (err: any) {
      setDecisionError(`Error confirming match: ${err.message}`);
    } finally {
      setDecidingMatchId(null);
    }
  };

  // Reject match decision (the reason is typed inline; no browser dialog)
  const handleRejectMatch = async (matchId: string) => {
    setDecidingMatchId(matchId);
    setDecisionError(null);
    try {
      await atlasService.rejectAssetMatch(matchId, rejectReason.trim() || 'Analyst rejected proposal');
      setRejectingMatchId(null);
      await loadMatches();
    } catch (err: any) {
      setDecisionError(`Error rejecting match: ${err.message}`);
    } finally {
      setDecidingMatchId(null);
    }
  };

  const selectedIncident = useMemo(() => {
    return incidents.find((i) => i.id === selectedIncidentId);
  }, [incidents, selectedIncidentId]);

  return (
    <div className="max-w-7xl mx-auto px-6 py-8 space-y-8 select-none text-slate-100 antialiased font-sans">
      {/* Page Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <div className="flex items-center gap-2 font-mono text-xs text-rose-400 font-bold uppercase tracking-wider mb-1">
            <Radio className="w-3.5 h-3.5" />
            Stage 4 Incident Intake & Match Engine
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-100">
            CyberShield X Ingest Contract & Asset Matching
          </h1>
          <p className="text-xs text-slate-400 mt-1 max-w-3xl leading-relaxed">
            Ingest real-time incident telemetry via SQL contract <code className="text-cyan-300 font-mono">ingest_incident()</code>. Replays and unknown fields are safely rejected. Rules run in strict priority order. Matches below 0.90 are proposals for analyst review; decisions are permanently stored as labelled ground-truth data.
          </p>
        </div>

        <div className="flex items-center gap-2 text-xs font-mono text-slate-400 bg-slate-900 px-3 py-1.5 rounded-lg border border-slate-800">
          <span>Incidents:</span>
          <strong className="text-rose-400">{incidents.length}</strong>
        </div>
      </div>

      {decisionError && (
        <div className="p-4 bg-rose-950/80 border border-rose-800 rounded-xl text-rose-200 text-xs flex items-start gap-2 shadow-lg">
          <AlertTriangle className="w-4 h-4 shrink-0 text-rose-400 mt-0.5" />
          <p className="font-mono">{decisionError}</p>
        </div>
      )}

      {error && (
        <div className="p-4 bg-rose-950/80 border border-rose-800 rounded-xl text-rose-200 text-xs flex items-start gap-2 shadow-lg">
          <AlertTriangle className="w-4 h-4 shrink-0 text-rose-400 mt-0.5" />
          <p className="font-mono">{error}</p>
        </div>
      )}

      {/* Main Grid: Mock CSX Sender & Match Review Screen */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Mock CSX Sender Panel */}
        <div className="lg:col-span-5 space-y-4">
          <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 space-y-4 shadow-xl">
            <div className="flex items-center justify-between">
              <h2 className="font-mono text-xs font-semibold uppercase tracking-wider text-slate-300 flex items-center gap-2">
                <FileCode className="w-3.5 h-3.5 text-rose-400" />
                Mock CSX Sender (Telemetry Ingest)
              </h2>
              <span className="text-[10px] font-mono text-cyan-400 bg-cyan-950/60 px-2 py-0.5 rounded border border-cyan-900/80">
                Contract v1.0
              </span>
            </div>

            {/* Ingest signing */}
            <div className="space-y-2 text-xs border border-slate-800 rounded-xl p-3 bg-slate-950/60">
              <div className="flex items-center justify-between">
                <span className="font-mono text-[11px] text-slate-300 uppercase tracking-wider">Message signing</span>
                {isAdmin && (
                  <button
                    onClick={handleCreateKey}
                    disabled={isKeyBusy}
                    className="px-2 py-1 bg-cyan-900/60 hover:bg-cyan-800 border border-cyan-800 text-cyan-200 rounded font-mono text-[10px] cursor-pointer disabled:opacity-50"
                  >
                    Create new key
                  </button>
                )}
              </div>
              <p className="text-[10px] text-slate-500 leading-snug">
                Every incident message must be signed with a key that belongs to this workspace. The secret is shown once and is kept only in this browser tab; reloading clears it.
              </p>
              {keyError && <p className="text-[11px] text-rose-300 font-mono">{keyError}</p>}
              {newSecretNotice && (
                <div className="p-2 rounded border border-amber-700 bg-amber-950/50 text-amber-200 font-mono text-[10px] break-all space-y-1">
                  <div>New key {newSecretNotice.key_id}. Copy the secret now; it cannot be shown again:</div>
                  <div className="select-all text-amber-100">{newSecretNotice.secret}</div>
                  {newSecretNotice.rotatedFrom && (
                    <div className="text-amber-300/90">
                      Previous key {newSecretNotice.rotatedFrom.old_key_id} expires at{' '}
                      {new Date(newSecretNotice.rotatedFrom.old_key_expires_at).toISOString().slice(0, 19).replace('T', ' ')} UTC.
                    </div>
                  )}
                  <button onClick={() => setNewSecretNotice(null)} className="underline cursor-pointer">I have saved it</button>
                </div>
              )}
              <div className="grid grid-cols-2 gap-2">
                <input
                  value={signingKeyId}
                  onChange={(e) => setSigningKeyId(e.target.value)}
                  placeholder="key id (k_xxxxxxxx)"
                  className="bg-slate-950 border border-slate-700 rounded px-2 py-1 text-slate-200 font-mono text-[11px] focus:outline-none focus:border-cyan-500"
                />
                <input
                  type="password"
                  value={signingSecret}
                  onChange={(e) => setSigningSecret(e.target.value)}
                  placeholder="secret"
                  autoComplete="off"
                  className="bg-slate-950 border border-slate-700 rounded px-2 py-1 text-slate-200 font-mono text-[11px] focus:outline-none focus:border-cyan-500"
                />
              </div>
              {ingestKeys.length > 0 && (
                <ul className="space-y-1.5">
                  {ingestKeys.map((k) => {
                    const isExpired = Boolean(k.expires_at && new Date(k.expires_at).getTime() <= Date.now());
                    return (
                      <li key={k.key_id} className="space-y-1 font-mono text-[10px] text-slate-400">
                        <div className="flex items-center justify-between gap-2">
                          <span className="truncate">
                            {k.key_id} · {isExpired ? 'expired' : k.status} · {new Date(k.created_at).toLocaleDateString()}
                            {k.expires_at && (
                              <span className="text-amber-300">
                                {' '}· exp {new Date(k.expires_at).toISOString().slice(0, 16).replace('T', ' ')}Z
                              </span>
                            )}
                          </span>
                          {isAdmin && k.status === 'active' && (
                            <span className="flex items-center gap-2 shrink-0">
                              <button
                                onClick={() => {
                                  setPendingRevokeKeyId(null);
                                  setPendingRotateKeyId(pendingRotateKeyId === k.key_id ? null : k.key_id);
                                }}
                                disabled={isKeyBusy}
                                className="text-cyan-300 hover:text-cyan-200 underline cursor-pointer disabled:opacity-50"
                              >
                                Rotate
                              </button>
                              <button
                                onClick={() => {
                                  setPendingRotateKeyId(null);
                                  setPendingRevokeKeyId(pendingRevokeKeyId === k.key_id ? null : k.key_id);
                                }}
                                disabled={isKeyBusy}
                                className="text-rose-300 hover:text-rose-200 underline cursor-pointer disabled:opacity-50"
                              >
                                Revoke
                              </button>
                            </span>
                          )}
                        </div>
                        {isAdmin && k.status === 'active' && pendingRotateKeyId === k.key_id && (
                          <div className="flex items-center gap-2 pl-2 border-l border-cyan-800">
                            <span className="text-slate-300">Grace (min):</span>
                            <input
                              type="number"
                              min={0}
                              max={1440}
                              value={rotateGraceMinutes}
                              onChange={(e) => setRotateGraceMinutes(e.target.value)}
                              className="w-16 bg-slate-950 border border-slate-700 rounded px-1.5 py-0.5 text-slate-200"
                            />
                            <button
                              onClick={() => handleRotateKey(k.key_id)}
                              disabled={isKeyBusy}
                              className="px-1.5 py-0.5 bg-cyan-700 hover:bg-cyan-600 text-white rounded cursor-pointer disabled:opacity-50"
                            >
                              Confirm rotate
                            </button>
                            <button
                              onClick={() => setPendingRotateKeyId(null)}
                              className="text-slate-400 hover:text-slate-200 underline cursor-pointer"
                            >
                              Cancel
                            </button>
                          </div>
                        )}
                        {isAdmin && k.status === 'active' && pendingRevokeKeyId === k.key_id && (
                          <div className="flex items-center gap-2 pl-2 border-l border-rose-800">
                            <span className="text-amber-300">Senders using it will be refused.</span>
                            <button
                              onClick={() => handleRevokeKey(k.key_id)}
                              disabled={isKeyBusy}
                              className="px-1.5 py-0.5 bg-rose-700 hover:bg-rose-600 text-white rounded cursor-pointer disabled:opacity-50"
                            >
                              Confirm revoke
                            </button>
                            <button
                              onClick={() => setPendingRevokeKeyId(null)}
                              className="text-slate-400 hover:text-slate-200 underline cursor-pointer"
                            >
                              Cancel
                            </button>
                          </div>
                        )}
                      </li>
                    );
                  })}
                </ul>
              )}
            </div>

            {/* Template Selector */}
            <div className="space-y-1.5 text-xs">
              <label className="block text-slate-400 font-mono text-[11px]">Select Scenario Payload:</label>
              <select
                value={payloadTemplate}
                onChange={(e) => setPayloadTemplate(e.target.value)}
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-2.5 py-1.5 text-slate-200 font-mono text-xs focus:outline-none focus:border-rose-500"
              >
                <option value="site_code">1. Exact Site Code Match (Score: 1.00 - Auto)</option>
                <option value="hostname">2. Exact Hostname Match (Score: 0.95 - Auto)</option>
                <option value="ip_and_cidr">3. IP & CIDR Containment Match (Score: 0.85 - Proposal)</option>
                <option value="fuzzy_hostname">4. Fuzzy Hostname Typo via pg_trgm (Proposal)</option>
                <option value="stale_replay">5. Stale Timestamp (&gt;10m old) [Replay Rejection]</option>
                <option value="unknown_field">6. Unknown Field Injection [Malformed Rejection]</option>
              </select>
            </div>

            {/* Live Editable JSON Payload */}
            <div className="space-y-1 text-xs font-mono">
              <div className="flex items-center justify-between text-slate-500 text-[10px]">
                <span>PAYLOAD JSON (EDITABLE)</span>
                <span>sent_at freshness: &lt;10 min</span>
              </div>
              <textarea
                value={customJsonPayload}
                onChange={(e) => setCustomJsonPayload(e.target.value)}
                rows={11}
                className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2.5 text-cyan-300 font-mono text-[11px] leading-snug focus:outline-none focus:border-cyan-500 resize-none"
              />
            </div>

            {/* Action Buttons: Send & Replay */}
            <div className="flex items-center gap-2 pt-1">
              <button
                onClick={handleSendPayload}
                disabled={isSending}
                className="flex-1 py-2 bg-rose-500 hover:bg-rose-400 disabled:bg-slate-800 text-slate-950 font-bold rounded-lg text-xs font-mono transition cursor-pointer flex items-center justify-center gap-1.5 shadow-lg"
              >
                {isSending ? (
                  <>
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    <span>Ingesting...</span>
                  </>
                ) : (
                  <>
                    <Send className="w-3.5 h-3.5" />
                    <span>Send CSX Intake</span>
                  </>
                )}
              </button>

              <button
                onClick={handleSendPayload}
                disabled={isSending}
                className="px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-mono transition cursor-pointer flex items-center gap-1.5 border border-slate-700"
                title="Send the exact same event_id again to test idempotent safe no-op"
              >
                <Repeat className="w-3.5 h-3.5 text-amber-400" />
                <span>Replay (Idempotency)</span>
              </button>
            </div>

            {/* Feedback Notifications */}
            {senderResult && (
              <div
                className={`p-3 rounded-xl border text-xs font-mono space-y-1 ${
                  senderResult.idempotent
                    ? 'bg-amber-950/60 border-amber-800 text-amber-200'
                    : 'bg-emerald-950/60 border-emerald-800 text-emerald-200'
                }`}
              >
                <div className="font-bold flex items-center gap-1.5">
                  <CheckCircle2 className="w-4 h-4" />
                  <span>
                    {senderResult.idempotent
                      ? 'Idempotent Replay Verified (Safe No-Op)'
                      : 'Incident Ingested & Matches Generated'}
                  </span>
                </div>
                <div className="text-[11px] text-slate-300">
                  Event ID: <span className="font-bold text-white">{senderResult.event_id}</span> • Matches: {senderResult.matches_count}
                </div>
              </div>
            )}

            {senderError && (
              <div className="p-3 bg-rose-950/80 border border-rose-800 rounded-xl text-rose-200 text-xs font-mono space-y-1">
                <div className="font-bold flex items-center gap-1.5">
                  <AlertTriangle className="w-4 h-4 text-rose-400" />
                  <span>Contract Rejection</span>
                </div>
                <p className="text-[11px] text-rose-300 leading-relaxed">{senderError}</p>
              </div>
            )}

            {/* Contract Documentation Footnote */}
            <div className="p-3 bg-slate-950/60 rounded-xl border border-slate-800 text-[10px] text-slate-400 space-y-1">
              <div className="font-semibold text-slate-300">CONFIDENCE DEFINITION:</div>
              <p className="leading-relaxed">
                Confidence represents the sender's estimate that the telemetry reflects a real event. It is not attribution of any actor. Messages require HMAC-SHA256 signing using an active workspace ingest key.
              </p>
            </div>
          </div>

          {/* Quick Incident Selector List */}
          <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-4 space-y-2">
            <div className="text-xs font-mono font-semibold text-slate-400 uppercase tracking-wider">
              Workspace Incidents ({incidents.length})
            </div>
            <div className="max-h-48 overflow-y-auto divide-y divide-slate-800">
              {incidents.map((inc) => (
                <div
                  key={inc.id}
                  onClick={() => setSelectedIncidentId(inc.id)}
                  className={`p-2 rounded-lg cursor-pointer transition flex items-center justify-between text-xs font-mono ${
                    selectedIncidentId === inc.id
                      ? 'bg-slate-800 text-cyan-300 border border-slate-700'
                      : 'hover:bg-slate-800/40 text-slate-400'
                  }`}
                >
                  <div className="truncate">
                    <span className="font-bold text-white">[{inc.event_id}]</span>{' '}
                    <span className="text-[11px]">{inc.event_type}</span>
                  </div>
                  <span className="text-[10px] uppercase text-rose-400 font-bold ml-2">
                    {inc.severity}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Right Column: Match Review & Analyst Confirmations */}
        <div className="lg:col-span-7 space-y-4">
          <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 space-y-4 shadow-xl">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
              <div>
                <h2 className="font-mono text-xs font-semibold uppercase tracking-wider text-slate-300 flex items-center gap-2">
                  <Tag className="w-3.5 h-3.5 text-cyan-400" />
                  Match Review & Labelled Data Engine
                </h2>
                {selectedIncident && (
                  <div className="text-[11px] text-slate-400 font-mono mt-0.5">
                    Incident: <span className="text-cyan-300 font-bold">{selectedIncident.event_id}</span> ({selectedIncident.event_type})
                  </div>
                )}
              </div>

              {selectedIncident && onNavigateToBlastRadius && (
                <button
                  onClick={() => onNavigateToBlastRadius(selectedIncident.id)}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-rose-300 hover:text-rose-200 rounded-lg text-xs font-mono transition flex items-center gap-1.5 cursor-pointer border border-rose-900/60"
                >
                  <span>View in Blast Radius</span>
                  <ArrowRight className="w-3 h-3" />
                </button>
              )}
            </div>

            {/* Matches List */}
            {matches.length === 0 ? (
              <div className="p-12 text-center text-slate-500 text-xs font-mono space-y-2">
                <Tag className="w-8 h-8 mx-auto text-slate-600 mb-2" />
                <div className="font-semibold text-slate-400">Zero Correlated Matches</div>
                <p className="max-w-xs mx-auto text-[11px] leading-relaxed text-slate-500">
                  No assets in this workspace matched the signals in the selected incident payload. Use the Mock CSX sender on the left to inject matching telemetry.
                </p>
              </div>
            ) : (
              <div className="space-y-3">
                {matches.map((match) => {
                  const isAuto = match.status === 'auto';
                  const isProposed = match.status === 'proposed';
                  const isConfirmed = match.status === 'confirmed';
                  const isRejected = match.status === 'rejected';

                  return (
                    <div
                      key={match.id}
                      className="p-4 bg-slate-950/80 border border-slate-800 rounded-xl space-y-3 hover:border-slate-700 transition"
                    >
                      {/* Top Row: Asset & Status */}
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                        <div className="flex items-center gap-2">
                          <span className="font-mono font-bold text-sm text-cyan-400">
                            {match.asset?.site_code || 'MATCHED ASSET'}
                          </span>
                          <span className="text-slate-300 text-xs font-semibold">
                            {match.asset?.name || match.asset_id}
                          </span>
                          <span className="text-[10px] font-mono text-slate-500 uppercase">
                            ({match.asset?.type || 'asset'})
                          </span>
                        </div>

                        {/* Status Badge */}
                        <div>
                          {isAuto && (
                            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-950 text-emerald-400 border border-emerald-800 flex items-center gap-1">
                              <CheckCircle2 className="w-3 h-3" />
                              AUTO MATCH (≥ 0.90)
                            </span>
                          )}
                          {isProposed && (
                            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-950 text-amber-400 border border-amber-800 flex items-center gap-1">
                              <AlertTriangle className="w-3 h-3" />
                              PROPOSAL (NEEDS CONFIRMATION)
                            </span>
                          )}
                          {isConfirmed && (
                            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-950 text-cyan-300 border border-cyan-800 flex items-center gap-1">
                              <CheckCircle2 className="w-3 h-3" />
                              CONFIRMED BY ANALYST
                            </span>
                          )}
                          {isRejected && (
                            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-950 text-rose-400 border border-rose-800 flex items-center gap-1">
                              <XCircle className="w-3 h-3" />
                              REJECTED
                            </span>
                          )}
                        </div>
                      </div>

                      {/* Rule & Confidence Metrics */}
                      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[11px] font-mono bg-slate-900/60 p-2.5 rounded-lg border border-slate-800">
                        <div>
                          <div className="text-slate-500 text-[10px]">RULE FIRED</div>
                          <div className="text-slate-200 font-semibold mt-0.5">{match.rule_fired}</div>
                        </div>
                        <div>
                          <div className="text-slate-500 text-[10px]">RULE SCORE</div>
                          <div className="text-cyan-300 font-bold mt-0.5">
                            {(Number(match.score) * 100).toFixed(0)}%
                          </div>
                        </div>
                        <div>
                          <div className="text-slate-500 text-[10px]">EVIDENCE CONFIDENCE</div>
                          <div className="text-slate-300 mt-0.5">
                            {(Number(match.confidence) * 100).toFixed(0)}%
                          </div>
                        </div>
                        <div>
                          <div className="text-slate-500 text-[10px]">DECIDED AT</div>
                          <div className="text-slate-400 mt-0.5 truncate">
                            {match.decided_at ? new Date(match.decided_at).toLocaleTimeString() : 'Pending'}
                          </div>
                        </div>
                      </div>

                      {/* Analyst Decision Actions */}
                      {isProposed && (
                        <div className="flex items-center justify-between pt-1 border-t border-slate-800/80">
                          <span className="text-[11px] text-slate-400 font-mono">
                            Review proposal and store analyst label:
                          </span>
                          <div className="flex items-center gap-2">
                            <button
                              onClick={() => handleConfirmMatch(match.id)}
                              disabled={decidingMatchId === match.id}
                              className="px-3 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold rounded-lg text-xs font-mono transition cursor-pointer flex items-center gap-1"
                            >
                              <CheckCircle2 className="w-3.5 h-3.5" />
                              <span>Confirm Match</span>
                            </button>
                            <button
                              onClick={() => setRejectingMatchId(rejectingMatchId === match.id ? null : match.id)}
                              disabled={decidingMatchId === match.id}
                              className="px-3 py-1.5 bg-rose-950/80 hover:bg-rose-900 text-rose-300 border border-rose-800 rounded-lg text-xs font-mono transition cursor-pointer flex items-center gap-1"
                            >
                              <XCircle className="w-3.5 h-3.5" />
                              <span>Reject</span>
                            </button>
                          </div>
                        </div>
                      )}
                      {isProposed && rejectingMatchId === match.id && (
                        <div className="flex items-center gap-2 pt-2">
                          <input
                            value={rejectReason}
                            onChange={(e) => setRejectReason(e.target.value)}
                            placeholder="Rejection reason (stored as a label)"
                            className="flex-1 bg-slate-950 border border-slate-700 rounded px-2 py-1 text-slate-200 font-mono text-[11px] focus:outline-none focus:border-rose-500"
                          />
                          <button
                            onClick={() => handleRejectMatch(match.id)}
                            disabled={decidingMatchId === match.id}
                            className="px-2.5 py-1 bg-rose-700 hover:bg-rose-600 text-white rounded text-[11px] font-mono cursor-pointer disabled:opacity-50"
                          >
                            Submit rejection
                          </button>
                          <button
                            onClick={() => setRejectingMatchId(null)}
                            className="text-slate-400 hover:text-slate-200 underline text-[11px] font-mono cursor-pointer"
                          >
                            Cancel
                          </button>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
