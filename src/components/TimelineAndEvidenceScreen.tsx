import React, { useState, useEffect } from 'react';
import { 
  ShieldCheck, 
  Upload, 
  FileCheck, 
  History, 
  FileText, 
  AlertTriangle, 
  CheckCircle2, 
  RefreshCw, 
  Clock, 
  Fingerprint, 
  Lock,
  ExternalLink,
  ChevronDown,
  ChevronRight
} from 'lucide-react';
import { atlasService } from '../data/api';
import { Evidence, Incident, TimelineEvent } from '../types/atlas';
import { computeFileSha256, verifyWebCryptoEngine } from '../utils/crypto';

interface TimelineAndEvidenceScreenProps {
  activeOrgId: string;
  activeRole: string;
}

export const TimelineAndEvidenceScreen: React.FC<TimelineAndEvidenceScreenProps> = ({
  activeOrgId,
  activeRole,
}) => {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string>('');
  const [timelineEvents, setTimelineEvents] = useState<TimelineEvent[]>([]);
  const [evidenceList, setEvidenceList] = useState<Evidence[]>([]);
  
  const [loadingIncidents, setLoadingIncidents] = useState(false);
  const [loadingTimeline, setLoadingTimeline] = useState(false);
  const [loadingEvidence, setLoadingEvidence] = useState(false);
  
  // Upload State
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [computedSha256, setComputedSha256] = useState<string>('');
  const [uploadTargetType, setUploadTargetType] = useState<'incident' | 'asset'>('incident');
  const [uploadTargetId, setUploadTargetId] = useState<string>('');
  const [isHashing, setIsHashing] = useState(false);
  const [isUploading, setIsUploading] = useState(false);
  
  // Verification State
  const [verifyingEvidenceId, setVerifyingEvidenceId] = useState<string | null>(null);
  const [verificationResults, setVerificationResults] = useState<Record<string, {
    is_intact: boolean;
    expected_hash: string;
    verified_hash: string;
    verified_at: string;
  }>>({});
  
  // Crypto Engine Check State
  const [cryptoStatus, setCryptoStatus] = useState<{ checked: boolean; passed: boolean; error?: string }>({
    checked: false,
    passed: false,
  });

  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const [expandedEvents, setExpandedEvents] = useState<Record<string, boolean>>({});
  const [activeTab, setActiveTab] = useState<'timeline' | 'evidence'>('timeline');

  // Load Incidents and Engine Validation on Mount
  useEffect(() => {
    runCryptoValidation();
    loadIncidents();
    loadEvidence();
  }, [activeOrgId]);

  // When selected incident changes, load its timeline
  useEffect(() => {
    if (selectedIncidentId) {
      loadTimeline(selectedIncidentId);
    } else {
      setTimelineEvents([]);
    }
  }, [selectedIncidentId]);

  const runCryptoValidation = async () => {
    const result = await verifyWebCryptoEngine();
    setCryptoStatus({
      checked: true,
      passed: result.passed,
      error: result.error,
    });
  };

  const loadIncidents = async () => {
    try {
      setLoadingIncidents(true);
      setErrorMessage(null);
      const data = await atlasService.fetchIncidents(activeOrgId);
      setIncidents(data);
      if (data.length > 0 && !selectedIncidentId) {
        setSelectedIncidentId(data[0].id);
        setUploadTargetId(data[0].id);
      }
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to load incidents.');
    } finally {
      setLoadingIncidents(false);
    }
  };

  const loadTimeline = async (incidentId: string) => {
    try {
      setLoadingTimeline(true);
      setErrorMessage(null);
      const events = await atlasService.fetchIncidentTimeline(incidentId);
      setTimelineEvents(events);
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to load incident timeline.');
    } finally {
      setLoadingTimeline(false);
    }
  };

  const loadEvidence = async () => {
    try {
      setLoadingEvidence(true);
      setErrorMessage(null);
      const list = await atlasService.fetchEvidenceList(activeOrgId);
      setEvidenceList(list);
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to load evidence records.');
    } finally {
      setLoadingEvidence(false);
    }
  };

  const handleFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) {
      setSelectedFile(null);
      setComputedSha256('');
      return;
    }

    if (file.size > 50 * 1024 * 1024) {
      setErrorMessage(`File size (${(file.size / 1024 / 1024).toFixed(2)} MB) exceeds strict 50 MB limit.`);
      setSelectedFile(null);
      setComputedSha256('');
      return;
    }

    setSelectedFile(file);
    setErrorMessage(null);
    setIsHashing(true);

    try {
      // Rule 8: Browser hashing uses Web Crypto (crypto.subtle.digest)
      const hash = await computeFileSha256(file);
      setComputedSha256(hash);
    } catch (err: any) {
      setErrorMessage(`Web Crypto hashing failed: ${err.message}`);
      setSelectedFile(null);
      setComputedSha256('');
    } finally {
      setIsHashing(false);
    }
  };

  const handleUploadSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedFile || !computedSha256) {
      setErrorMessage('Please select a file and ensure SHA-256 hash has been computed.');
      return;
    }

    const target = uploadTargetId || selectedIncidentId;
    if (!target) {
      setErrorMessage('Please select or specify a target incident or asset ID.');
      return;
    }

    try {
      setIsUploading(true);
      setErrorMessage(null);
      setSuccessMessage(null);

      const result = await atlasService.uploadEvidenceFile({
        orgId: activeOrgId,
        targetType: uploadTargetType,
        targetId: target,
        file: selectedFile,
      });

      setSuccessMessage(
        `Evidence file "${result.file_name}" uploaded and verified! Initial INTAKE custody event recorded with SHA-256: ${result.sha256}`
      );

      // Reset form and reload
      setSelectedFile(null);
      setComputedSha256('');
      await loadEvidence();
      if (uploadTargetType === 'incident') {
        await loadTimeline(target);
      }
    } catch (err: any) {
      setErrorMessage(err.message || 'Evidence upload failed.');
    } finally {
      setIsUploading(false);
    }
  };

  const handleVerifyEvidence = async (evidence: Evidence) => {
    try {
      setVerifyingEvidenceId(evidence.id);
      setErrorMessage(null);

      const result = await atlasService.verifyStoredEvidenceHash(evidence);

      setVerificationResults((prev) => ({
        ...prev,
        [evidence.id]: {
          is_intact: result.is_intact,
          expected_hash: result.expected_hash,
          verified_hash: result.verified_hash,
          verified_at: new Date().toLocaleTimeString(),
        },
      }));

      // Reload evidence list to update custody event log
      await loadEvidence();
    } catch (err: any) {
      setErrorMessage(`Custody verification failed: ${err.message}`);
    } finally {
      setVerifyingEvidenceId(null);
    }
  };

  const toggleEventDetails = (eventId: string) => {
    setExpandedEvents((prev) => ({
      ...prev,
      [eventId]: !prev[eventId],
    }));
  };

  return (
    <div className="space-y-6">
      {/* Header & Sub-navigation */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-zinc-800 pb-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold tracking-tight text-zinc-100">
              Audited Incident Timeline & Evidence Locker
            </h1>
            <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-mono bg-emerald-950 text-emerald-400 border border-emerald-800">
              MFA AAL2 Active
            </span>
          </div>
          <p className="text-xs text-zinc-400 mt-1">
            Read-only chronological incident audit trail derived from cryptographic hashes, paired with an append-only evidence custody log.
          </p>
        </div>

        {/* View Switcher */}
        <div className="flex items-center gap-2 bg-zinc-900 p-1 rounded-md border border-zinc-800">
          <button
            type="button"
            onClick={() => setActiveTab('timeline')}
            className={`px-3 py-1.5 text-xs font-medium rounded transition-colors flex items-center gap-1.5 ${
              activeTab === 'timeline'
                ? 'bg-zinc-800 text-zinc-100 shadow-sm'
                : 'text-zinc-400 hover:text-zinc-200'
            }`}
          >
            <History className="w-3.5 h-3.5" />
            Incident Timeline
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('evidence')}
            className={`px-3 py-1.5 text-xs font-medium rounded transition-colors flex items-center gap-1.5 ${
              activeTab === 'evidence'
                ? 'bg-zinc-800 text-zinc-100 shadow-sm'
                : 'text-zinc-400 hover:text-zinc-200'
            }`}
          >
            <Lock className="w-3.5 h-3.5" />
            Evidence Locker & Custody
          </button>
        </div>
      </div>

      {/* Web Crypto Engine Validation Badge */}
      <div className="bg-zinc-900 border border-zinc-800 rounded p-3 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Fingerprint className="w-4 h-4 text-zinc-400" />
          <div>
            <div className="text-xs font-mono font-medium text-zinc-200">
              Web Crypto API Hashing Engine (crypto.subtle.digest SHA-256)
            </div>
            <div className="text-[11px] text-zinc-400">
              {cryptoStatus.checked ? (
                cryptoStatus.passed ? (
                  <span className="text-emerald-400 font-mono">
                    ✓ Verified compliant with NIST / RFC 6234 standard test vectors
                  </span>
                ) : (
                  <span className="text-red-400 font-mono">
                    ✗ Engine check failed: {cryptoStatus.error}
                  </span>
                )
              ) : (
                'Validating browser cryptography engine...'
              )}
            </div>
          </div>
        </div>
        <button
          type="button"
          onClick={runCryptoValidation}
          className="px-2 py-1 text-[11px] font-mono text-zinc-300 bg-zinc-800 hover:bg-zinc-700 rounded border border-zinc-700 flex items-center gap-1"
        >
          <RefreshCw className="w-3 h-3" />
          Re-test Vectors
        </button>
      </div>

      {/* Error & Success Banners */}
      {errorMessage && (
        <div className="p-3 bg-red-950/80 border border-red-800 rounded text-xs text-red-200 flex items-start gap-2">
          <AlertTriangle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
          <div className="flex-1 font-mono">{errorMessage}</div>
          <button
            type="button"
            onClick={() => setErrorMessage(null)}
            className="text-red-400 hover:text-red-300 text-xs"
          >
            ×
          </button>
        </div>
      )}

      {successMessage && (
        <div className="p-3 bg-emerald-950/80 border border-emerald-800 rounded text-xs text-emerald-200 flex items-start gap-2">
          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
          <div className="flex-1 font-mono">{successMessage}</div>
          <button
            type="button"
            onClick={() => setSuccessMessage(null)}
            className="text-emerald-400 hover:text-emerald-300 text-xs"
          >
            ×
          </button>
        </div>
      )}

      {/* Tab 1: Incident Timeline */}
      {activeTab === 'timeline' && (
        <div className="space-y-4">
          {/* Incident Selector */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-zinc-900 border border-zinc-800 p-3 rounded">
            <div className="flex items-center gap-3">
              <label htmlFor="timeline-incident-select" className="text-xs font-mono text-zinc-300 uppercase tracking-wider">
                Select Incident:
              </label>
              <select
                id="timeline-incident-select"
                value={selectedIncidentId}
                onChange={(e) => setSelectedIncidentId(e.target.value)}
                disabled={loadingIncidents || incidents.length === 0}
                className="bg-zinc-950 border border-zinc-700 rounded px-2.5 py-1 text-xs font-mono text-zinc-100 focus:outline-none focus:border-zinc-500"
              >
                {incidents.length === 0 ? (
                  <option value="">No incidents found in workspace</option>
                ) : (
                  incidents.map((inc) => (
                    <option key={inc.id} value={inc.id}>
                      [{inc.severity.toUpperCase()}] {inc.event_id} ({inc.event_type}) - {new Date(inc.observed_at).toLocaleString()}
                    </option>
                  ))
                )}
              </select>
            </div>

            <button
              type="button"
              onClick={() => selectedIncidentId && loadTimeline(selectedIncidentId)}
              disabled={loadingTimeline || !selectedIncidentId}
              className="px-3 py-1 text-xs font-mono bg-zinc-800 hover:bg-zinc-700 text-zinc-200 rounded border border-zinc-700 flex items-center gap-1.5 self-start sm:self-auto"
            >
              <RefreshCw className={`w-3 h-3 ${loadingTimeline ? 'animate-spin' : ''}`} />
              Refresh Timeline
            </button>
          </div>

          {/* Timeline Feed */}
          <div className="bg-zinc-900 border border-zinc-800 rounded p-4">
            <div className="flex items-center justify-between mb-4 border-b border-zinc-800 pb-2">
              <div className="text-xs font-mono font-medium text-zinc-300 uppercase tracking-wider flex items-center gap-2">
                <Clock className="w-3.5 h-3.5 text-zinc-400" />
                Chronological Audit Chain ({timelineEvents.length} Verified Events)
              </div>
              <div className="text-[11px] font-mono text-zinc-500">
                Ordered by seq asc • Cryptographically linked
              </div>
            </div>

            {loadingTimeline ? (
              <div className="py-8 text-center text-xs font-mono text-zinc-500">
                Loading cryptographic audit timeline...
              </div>
            ) : timelineEvents.length === 0 ? (
              <div className="py-8 text-center text-xs font-mono text-zinc-500">
                No audit events recorded for this incident yet. Run ingestion or confirm matches to populate.
              </div>
            ) : (
              <div className="space-y-3">
                {timelineEvents.map((evt) => {
                  const isExpanded = !!expandedEvents[evt.event_id];
                  return (
                    <div
                      key={evt.event_id}
                      className="border border-zinc-800 rounded bg-zinc-950 p-3 hover:border-zinc-700 transition-colors"
                    >
                      <div className="flex items-start justify-between gap-3">
                        <div className="flex items-start gap-2.5">
                          <button
                            type="button"
                            onClick={() => toggleEventDetails(evt.event_id)}
                            className="mt-0.5 text-zinc-400 hover:text-zinc-200"
                          >
                            {isExpanded ? (
                              <ChevronDown className="w-4 h-4" />
                            ) : (
                              <ChevronRight className="w-4 h-4" />
                            )}
                          </button>
                          <div>
                            <div className="flex items-center gap-2 flex-wrap">
                              <span className="font-mono text-xs text-zinc-400 font-bold">
                                #{evt.seq}
                              </span>
                              <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold uppercase bg-zinc-800 text-zinc-200 border border-zinc-700">
                                {evt.action}
                              </span>
                              <span className="text-xs font-mono text-zinc-300">
                                Target: {evt.target_type} / {evt.target_id.slice(0, 8)}...
                              </span>
                              <span className="text-[11px] font-mono text-zinc-500">
                                Actor: {evt.actor_role} ({evt.actor_id ? evt.actor_id.slice(0, 8) + '...' : 'System'})
                              </span>
                            </div>
                            <div className="text-[11px] font-mono text-zinc-500 mt-1">
                              Timestamp: {new Date(evt.timestamp).toISOString()}
                            </div>
                          </div>
                        </div>

                        {/* Hash Digest Badge */}
                        <div className="text-right shrink-0">
                          <div className="text-[10px] font-mono text-zinc-400">
                            Payload Hash:
                          </div>
                          <div className="text-[10px] font-mono text-emerald-400 bg-emerald-950/60 px-1.5 py-0.5 rounded border border-emerald-900">
                            {evt.payload_hash.slice(0, 16)}...
                          </div>
                        </div>
                      </div>

                      {/* Expanded Hash Chain and Details */}
                      {isExpanded && (
                        <div className="mt-3 pt-3 border-t border-zinc-850 space-y-2 text-xs font-mono">
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-2 bg-zinc-900 p-2.5 rounded border border-zinc-800 text-[11px]">
                            <div>
                              <span className="text-zinc-500">Previous Record Hash:</span>
                              <div className="text-zinc-300 break-all select-all">{evt.prev_hash}</div>
                            </div>
                            <div>
                              <span className="text-zinc-500">Record Hash (SHA-256):</span>
                              <div className="text-emerald-400 break-all select-all">{evt.record_hash}</div>
                            </div>
                          </div>

                          <div>
                            <span className="text-zinc-500 text-[11px]">Event Details JSON:</span>
                            <pre className="p-2 bg-zinc-900 rounded border border-zinc-800 text-[11px] text-zinc-300 overflow-x-auto">
                              {JSON.stringify(evt.details, null, 2)}
                            </pre>
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Tab 2: Evidence Locker & Custody */}
      {activeTab === 'evidence' && (
        <div className="space-y-6">
          {/* Upload Form */}
          <div className="bg-zinc-900 border border-zinc-800 rounded p-4">
            <div className="flex items-center gap-2 border-b border-zinc-800 pb-2 mb-4">
              <Upload className="w-4 h-4 text-zinc-300" />
              <h2 className="text-xs font-mono uppercase tracking-wider font-medium text-zinc-200">
                Upload & Register Evidence
              </h2>
            </div>

            <form onSubmit={handleUploadSubmit} className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {/* Target Type */}
                <div>
                  <label htmlFor="evidence-target-type-select" className="block text-xs font-mono text-zinc-400 mb-1">
                    Target Association:
                  </label>
                  <select
                    id="evidence-target-type-select"
                    value={uploadTargetType}
                    onChange={(e) => setUploadTargetType(e.target.value as any)}
                    className="w-full bg-zinc-950 border border-zinc-700 rounded px-2.5 py-1.5 text-xs font-mono text-zinc-100 focus:outline-none focus:border-zinc-500"
                  >
                    <option value="incident">Incident</option>
                    <option value="asset">Asset</option>
                  </select>
                </div>

                {/* Target Identifier */}
                <div>
                  <label htmlFor="evidence-target-id-input" className="block text-xs font-mono text-zinc-400 mb-1">
                    Target UUID:
                  </label>
                  <input
                    id="evidence-target-id-input"
                    type="text"
                    value={uploadTargetId}
                    onChange={(e) => setUploadTargetId(e.target.value)}
                    placeholder="Enter Incident or Asset UUID"
                    required
                    className="w-full bg-zinc-950 border border-zinc-700 rounded px-2.5 py-1.5 text-xs font-mono text-zinc-100 focus:outline-none focus:border-zinc-500"
                  />
                </div>

                {/* File Input */}
                <div>
                  <label htmlFor="evidence-file-input" className="block text-xs font-mono text-zinc-400 mb-1">
                    Evidence File (Max 50 MB):
                  </label>
                  <input
                    id="evidence-file-input"
                    type="file"
                    onChange={handleFileChange}
                    required
                    className="w-full text-xs font-mono text-zinc-400 file:mr-2 file:py-1 file:px-2 file:rounded file:border-0 file:text-xs file:font-mono file:bg-zinc-800 file:text-zinc-200 hover:file:bg-zinc-700"
                  />
                </div>
              </div>

              {/* Pre-upload Web Crypto SHA-256 Display */}
              {selectedFile && (
                <div className="bg-zinc-950 border border-zinc-800 p-3 rounded text-xs font-mono space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="text-zinc-400">Selected File: {selectedFile.name} ({(selectedFile.size / 1024).toFixed(1)} KB)</span>
                    <span className="text-zinc-500">{isHashing ? 'Hashing with Web Crypto...' : 'Hashed locally'}</span>
                  </div>
                  <div>
                    <span className="text-zinc-500">Client-computed SHA-256: </span>
                    <span className="text-emerald-400 select-all break-all">{computedSha256 || 'Computing...'}</span>
                  </div>
                </div>
              )}

              <div className="flex justify-end">
                <button
                  type="submit"
                  disabled={!selectedFile || isHashing || isUploading || !computedSha256}
                  className="px-4 py-2 bg-zinc-100 hover:bg-white text-zinc-900 font-mono text-xs font-semibold rounded disabled:opacity-50 flex items-center gap-2"
                >
                  {isUploading ? (
                    <>
                      <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                      Uploading & Verifying...
                    </>
                  ) : (
                    <>
                      <FileCheck className="w-3.5 h-3.5" />
                      Upload to Secure Locker
                    </>
                  )}
                </button>
              </div>
            </form>
          </div>

          {/* Evidence Records & Custody Log */}
          <div className="bg-zinc-900 border border-zinc-800 rounded p-4">
            <div className="flex items-center justify-between border-b border-zinc-800 pb-2 mb-4">
              <div className="text-xs font-mono uppercase tracking-wider font-medium text-zinc-200 flex items-center gap-2">
                <FileText className="w-4 h-4 text-zinc-400" />
                Workspace Evidence Locker ({evidenceList.length} Objects)
              </div>
              <button
                type="button"
                onClick={loadEvidence}
                disabled={loadingEvidence}
                className="px-2.5 py-1 text-xs font-mono bg-zinc-800 hover:bg-zinc-700 text-zinc-200 rounded border border-zinc-700 flex items-center gap-1"
              >
                <RefreshCw className={`w-3 h-3 ${loadingEvidence ? 'animate-spin' : ''}`} />
                Refresh
              </button>
            </div>

            {loadingEvidence ? (
              <div className="py-8 text-center text-xs font-mono text-zinc-500">
                Loading evidence registry...
              </div>
            ) : evidenceList.length === 0 ? (
              <div className="py-8 text-center text-xs font-mono text-zinc-500">
                No evidence items uploaded to this workspace yet.
              </div>
            ) : (
              <div className="space-y-4">
                {evidenceList.map((item) => {
                  const verifyResult = verificationResults[item.id];
                  return (
                    <div
                      key={item.id}
                      className="bg-zinc-950 border border-zinc-800 rounded p-3 space-y-3"
                    >
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                        <div>
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className="font-mono text-xs font-bold text-zinc-100">
                              {item.file_name}
                            </span>
                            <span className="text-[11px] font-mono text-zinc-400">
                              ({(item.file_size_bytes / 1024).toFixed(1)} KB)
                            </span>
                            <span className="px-1.5 py-0.5 rounded text-[10px] font-mono uppercase bg-zinc-800 text-zinc-300 border border-zinc-700">
                              {item.target_type}: {item.target_id.slice(0, 8)}...
                            </span>
                          </div>
                          <div className="text-[11px] font-mono text-zinc-500 mt-0.5">
                            Uploaded: {new Date(item.created_at).toLocaleString()} by {item.uploader_id.slice(0, 8)}...
                          </div>
                        </div>

                        {/* Re-verify Button */}
                        <div className="flex items-center gap-2">
                          <button
                            type="button"
                            onClick={() => handleVerifyEvidence(item)}
                            disabled={verifyingEvidenceId === item.id}
                            className="px-3 py-1.5 text-xs font-mono bg-zinc-800 hover:bg-zinc-700 text-zinc-200 rounded border border-zinc-700 flex items-center gap-1.5"
                          >
                            <ShieldCheck className={`w-3.5 h-3.5 ${verifyingEvidenceId === item.id ? 'animate-spin text-amber-400' : 'text-emerald-400'}`} />
                            {verifyingEvidenceId === item.id ? 'Re-hashing...' : 'Verify'}
                          </button>
                        </div>
                      </div>

                      {/* Recorded Digest */}
                      <div className="text-xs font-mono bg-zinc-900 p-2 rounded border border-zinc-850">
                        <span className="text-zinc-500">Authoritative SHA-256 Digest: </span>
                        <span className="text-emerald-400 select-all break-all">{item.sha256}</span>
                      </div>

                      {/* Verification Status Banner if tested */}
                      {verifyResult && (
                        <div
                          className={`p-2.5 rounded border text-xs font-mono flex items-start gap-2 ${
                            verifyResult.is_intact
                              ? 'bg-emerald-950/70 border-emerald-800 text-emerald-200'
                              : 'bg-red-950/70 border-red-800 text-red-200'
                          }`}
                        >
                          {verifyResult.is_intact ? (
                            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                          ) : (
                            <AlertTriangle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                          )}
                          <div className="space-y-0.5">
                            <div className="font-bold">
                              {verifyResult.is_intact
                                ? 'INTEGRITY VERIFIED: Stored object SHA-256 matches recorded hash.'
                                : 'TAMPER DETECTED: Stored object hash does NOT match recorded hash!'}
                            </div>
                            <div className="text-[11px] opacity-80">
                              Verified at: {verifyResult.verified_at} • Downloaded from storage and re-hashed with Web Crypto.
                            </div>
                          </div>
                        </div>
                      )}

                      {/* Append-only Custody Trail */}
                      <div className="border-t border-zinc-850 pt-2">
                        <div className="text-[11px] font-mono text-zinc-400 uppercase tracking-wider mb-1.5">
                          Custody History ({item.custody_events?.length || 0} Events - Append-Only)
                        </div>
                        {(!item.custody_events || item.custody_events.length === 0) ? (
                          <div className="text-[11px] font-mono text-zinc-500">
                            No custody events logged.
                          </div>
                        ) : (
                          <div className="space-y-1">
                            {item.custody_events.map((cust) => (
                              <div
                                key={cust.id}
                                className="flex items-center justify-between text-[11px] font-mono bg-zinc-900/60 px-2 py-1 rounded border border-zinc-850"
                              >
                                <div className="flex items-center gap-2">
                                  <span className="px-1 py-0.2 rounded text-[9px] font-bold bg-zinc-800 text-zinc-300">
                                    {cust.event_type}
                                  </span>
                                  <span className="text-zinc-400">
                                    Actor: {cust.actor_id.slice(0, 8)}...
                                  </span>
                                  <span className="text-zinc-500">
                                    {new Date(cust.created_at).toLocaleTimeString()}
                                  </span>
                                </div>
                                <div className="text-zinc-400 select-all">
                                  SHA: {cust.sha256_verified.slice(0, 12)}...
                                </div>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
