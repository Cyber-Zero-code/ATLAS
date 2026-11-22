import React, { useState, useEffect } from 'react';
import { atlasService } from '../data/api';
import { AuditCheckpointRecord, AuditEvent, AuditVerificationResult } from '../types/atlas';
import { 
  ShieldCheck, 
  ShieldAlert, 
  RefreshCw, 
  Layers, 
  Clock, 
  FileCode, 
  CheckCircle2, 
  AlertOctagon,
  ChevronRight,
  ChevronDown,
  BookmarkCheck
} from 'lucide-react';

interface AuditLogViewerProps {
  activeOrgId: string;
  userRole?: string;
}

export const AuditLogViewer: React.FC<AuditLogViewerProps> = ({ activeOrgId, userRole }) => {
  const isAdmin = userRole === 'atlas:admin';
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [totalCount, setTotalCount] = useState<number>(0);
  const [isLoading, setIsLoading] = useState(false);
  const [isLoadingMore, setIsLoadingMore] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);

  const [verificationResult, setVerificationResult] = useState<AuditVerificationResult | null>(null);
  const [isVerifying, setIsVerifying] = useState(false);
  const [expandedSeq, setExpandedSeq] = useState<number | null>(null);

  // Migration 016: External audit checkpoints (detects tail truncation)
  const [checkpoint, setCheckpoint] = useState<AuditCheckpointRecord | null>(null);
  const [isRecordingCheckpoint, setIsRecordingCheckpoint] = useState(false);
  const [checkpointError, setCheckpointError] = useState<string | null>(null);
  const [anchorSeqInput, setAnchorSeqInput] = useState('');
  const [anchorHashInput, setAnchorHashInput] = useState('');

  const loadAuditEvents = async () => {
    if (!activeOrgId) return;
    setIsLoading(true);
    setLoadError(null);
    try {
      const { events: fetched, total } = await atlasService.fetchAuditEvents(activeOrgId);
      setEvents(fetched);
      setTotalCount(total);
    } catch (err: any) {
      setLoadError(err.message || 'Failed to fetch audit events from Supabase.');
    } finally {
      setIsLoading(false);
    }
  };

  const loadOlderEvents = async () => {
    if (!activeOrgId || events.length === 0) return;
    const oldestSeq = events[events.length - 1].seq;
    setIsLoadingMore(true);
    setLoadError(null);
    try {
      const { events: older } = await atlasService.fetchAuditEvents(activeOrgId, {
        beforeSeq: oldestSeq,
      });
      if (older.length > 0) {
        setEvents((prev) => [...prev, ...older]);
      }
    } catch (err: any) {
      setLoadError(err.message || 'Failed to load older audit events from Supabase.');
    } finally {
      setIsLoadingMore(false);
    }
  };

  const handleVerifyChain = async () => {
    if (!activeOrgId) return;
    setIsVerifying(true);
    try {
      const result = await atlasService.verifyAuditChain(activeOrgId);
      setVerificationResult(result);
    } catch (err: any) {
      setVerificationResult({
        is_valid: false,
        first_bad_seq: null,
        reason: err.message || 'Verification RPC call failed.',
        total_verified: 0,
      });
    } finally {
      setIsVerifying(false);
    }
  };

  const handleRecordCheckpoint = async () => {
    if (!activeOrgId) return;
    setIsRecordingCheckpoint(true);
    setCheckpointError(null);
    try {
      const cp = await atlasService.createAuditCheckpoint(activeOrgId);
      setCheckpoint(cp);
      setAnchorSeqInput(String(cp.seq));
      setAnchorHashInput(cp.record_hash);
      await loadAuditEvents();
    } catch (err: any) {
      setCheckpointError(err.message || 'Failed to record audit checkpoint.');
    } finally {
      setIsRecordingCheckpoint(false);
    }
  };

  const handleVerifyAgainstCheckpoint = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!activeOrgId) return;
    const seq = Number(anchorSeqInput);
    setIsVerifying(true);
    setCheckpointError(null);
    try {
      const result = await atlasService.verifyAuditChainAgainst(activeOrgId, seq, anchorHashInput);
      setVerificationResult(result);
    } catch (err: any) {
      setVerificationResult({
        is_valid: false,
        first_bad_seq: Number.isInteger(seq) && seq >= 1 ? seq : null,
        reason: err.message || 'Checkpoint verification RPC call failed.',
        total_verified: 0,
      });
    } finally {
      setIsVerifying(false);
    }
  };

  useEffect(() => {
    loadAuditEvents();
    setVerificationResult(null);
    setCheckpoint(null);
    setCheckpointError(null);
  }, [activeOrgId]);

  return (
    <div className="w-full max-w-7xl mx-auto p-6 space-y-6">
      {/* Header & Verification Bar */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between pb-4 border-b border-slate-800 gap-4">
        <div>
          <div className="flex items-center gap-2 text-cyan-400 font-mono text-xs uppercase tracking-wider font-semibold">
            <Layers className="w-4 h-4" />
            Append-Only Cryptographic Ledger
          </div>
          <h1 className="text-xl font-bold text-slate-100 mt-1">
            Audit Events & Integrity Chain
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Database-trigger generated SHA-256 hash chain per organisation. Clients have zero write permissions.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={loadAuditEvents}
            disabled={isLoading}
            className="px-3 py-1.5 bg-slate-900 hover:bg-slate-800 active:bg-slate-950 border border-slate-700 text-slate-200 text-xs rounded-lg transition cursor-pointer flex items-center gap-1.5 disabled:opacity-50"
            title="Refresh from database"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin text-cyan-400' : ''}`} />
            Refresh
          </button>

          {isAdmin && (
            <button
              onClick={handleRecordCheckpoint}
              disabled={isRecordingCheckpoint}
              className="px-3 py-1.5 bg-slate-900 hover:bg-slate-800 border border-amber-800/70 text-amber-300 text-xs rounded-lg transition cursor-pointer flex items-center gap-1.5 disabled:opacity-50"
              title="Append an AUDIT_CHECKPOINT block and output seq + hash to save outside ATLAS"
            >
              <BookmarkCheck className="w-3.5 h-3.5" />
              <span>{isRecordingCheckpoint ? 'Checkpointing...' : 'Record Checkpoint'}</span>
            </button>
          )}

          <button
            onClick={handleVerifyChain}
            disabled={isVerifying || events.length === 0}
            className="px-4 py-1.5 bg-cyan-600 hover:bg-cyan-500 active:bg-cyan-700 text-slate-950 font-bold text-xs rounded-lg transition cursor-pointer flex items-center gap-2 shadow-md shadow-cyan-950 disabled:opacity-50"
          >
            {isVerifying ? (
              <>
                <RefreshCw className="w-3.5 h-3.5 animate-spin text-slate-950" />
                <span>Verifying Proofs...</span>
              </>
            ) : (
              <>
                <ShieldCheck className="w-4 h-4" />
                <span>Verify Chain</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Audit Checkpoint Controls (Migration 016) */}
      <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-4 space-y-3 text-xs">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-2">
          <div>
            <div className="font-mono text-[11px] font-semibold text-slate-200">
              External Checkpoint Verification (Tail-Truncation Guard)
            </div>
            <p className="text-[11px] text-slate-400 mt-0.5">
              Verify the live hash chain against a previously recorded <code className="font-mono text-cyan-300">(seq, record_hash)</code> anchor to detect deletion of the newest ledger blocks.
            </p>
          </div>
        </div>

        {checkpoint && (
          <div className="p-3 rounded-lg border border-amber-700/70 bg-amber-950/40 font-mono text-[11px] text-amber-200 space-y-1">
            <div className="font-semibold text-amber-300">
              Checkpoint recorded at seq #{checkpoint.seq} ({new Date(checkpoint.recorded_at).toISOString().slice(0, 19).replace('T', ' ')} UTC). Save these values outside ATLAS:
            </div>
            <div className="select-all break-all text-slate-100">
              seq: {checkpoint.seq} | record_hash: {checkpoint.record_hash}
            </div>
          </div>
        )}

        {checkpointError && (
          <div className="p-2.5 rounded-lg border border-rose-800 bg-rose-950/60 font-mono text-[11px] text-rose-300">
            {checkpointError}
          </div>
        )}

        <form onSubmit={handleVerifyAgainstCheckpoint} className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2 font-mono text-[11px]">
          <input
            type="number"
            min={1}
            value={anchorSeqInput}
            onChange={(e) => setAnchorSeqInput(e.target.value)}
            placeholder="Anchor seq (e.g. 42)"
            className="sm:w-36 bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 text-slate-200 focus:outline-none focus:border-cyan-500"
          />
          <input
            type="text"
            value={anchorHashInput}
            onChange={(e) => setAnchorHashInput(e.target.value)}
            placeholder="64-character SHA-256 record_hash from external vault"
            className="flex-1 bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 text-slate-200 focus:outline-none focus:border-cyan-500"
          />
          <button
            type="submit"
            disabled={isVerifying || !anchorSeqInput.trim() || !anchorHashInput.trim()}
            className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 border border-slate-600 text-slate-100 rounded transition cursor-pointer disabled:opacity-50"
          >
            Verify Against Checkpoint
          </button>
        </form>
      </div>

      {/* Verification Status Banner */}
      {verificationResult && (
        <div
          className={`p-4 rounded-xl border flex items-start justify-between gap-3 text-xs ${
            verificationResult.is_valid
              ? 'bg-emerald-950/70 border-emerald-800 text-emerald-200'
              : 'bg-rose-950/70 border-rose-800 text-rose-200'
          }`}
        >
          <div className="flex items-start gap-3">
            {verificationResult.is_valid ? (
              <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
            ) : (
              <ShieldAlert className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
            )}
            <div>
              <div className="font-bold text-sm">
                {verificationResult.is_valid
                  ? 'Cryptographic Chain Integrity Verified'
                  : 'Audit Chain Compromise Detected'}
              </div>
              <div className="mt-1 font-mono text-[11px] opacity-90">
                {verificationResult.reason}
              </div>
              <div className="mt-1 text-[11px] text-slate-400">
                Total blocks verified from genesis (0^64): {verificationResult.total_verified}
              </div>
            </div>
          </div>

          <span
            className={`font-mono text-[10px] uppercase font-bold px-2 py-0.5 rounded border ${
              verificationResult.is_valid
                ? 'bg-emerald-900/60 border-emerald-700 text-emerald-300'
                : 'bg-rose-900/60 border-rose-700 text-rose-300'
            }`}
          >
            {verificationResult.is_valid ? 'PROOF VALID' : 'TAMPER DETECTED'}
          </span>
        </div>
      )}

      {/* Load Error */}
      {loadError && (
        <div className="p-4 bg-rose-950/80 border border-rose-800 text-rose-200 rounded-xl flex items-center justify-between text-xs">
          <div className="flex items-center gap-2">
            <AlertOctagon className="w-4 h-4 text-rose-400 shrink-0" />
            <span>Database Error: {loadError}</span>
          </div>
          <button
            onClick={loadAuditEvents}
            className="px-2.5 py-1 bg-rose-900 hover:bg-rose-800 rounded text-[11px] font-bold uppercase cursor-pointer"
          >
            Retry
          </button>
        </div>
      )}

      {/* Events Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950 text-slate-400 font-mono text-[11px] border-b border-slate-800">
              <tr>
                <th className="py-3 px-4 font-semibold w-16">Seq</th>
                <th className="py-3 px-4 font-semibold w-48">Timestamp (UTC)</th>
                <th className="py-3 px-4 font-semibold w-36">Action</th>
                <th className="py-3 px-4 font-semibold w-40">Target</th>
                <th className="py-3 px-4 font-semibold w-32">Role</th>
                <th className="py-3 px-4 font-semibold">Record Hash (SHA-256)</th>
                <th className="py-3 px-4 font-semibold w-20 text-right">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 font-mono text-[11px]">
              {events.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-slate-500 font-sans text-xs">
                    {isLoading ? 'Loading audit records...' : 'No audit records found in this workspace.'}
                  </td>
                </tr>
              ) : (
                events.map((evt) => {
                  const isExpanded = expandedSeq === evt.seq;
                  return (
                    <React.Fragment key={evt.id}>
                      <tr className="hover:bg-slate-800/40 transition">
                        <td className="py-3 px-4 font-bold text-cyan-400">
                          #{evt.seq}
                        </td>
                        <td className="py-3 px-4 text-slate-300 flex items-center gap-1.5">
                          <Clock className="w-3 h-3 text-slate-500 shrink-0" />
                          <span>{evt.timestamp_text || evt.timestamp}</span>
                        </td>
                        <td className="py-3 px-4">
                          <span className="px-2 py-0.5 rounded bg-slate-950 text-slate-200 border border-slate-700">
                            {evt.action}
                          </span>
                        </td>
                        <td className="py-3 px-4 text-slate-300">
                          <span className="text-slate-400">{evt.target_type}:</span> {evt.target_id.substring(0, 12)}
                        </td>
                        <td className="py-3 px-4 text-slate-300">
                          <span className="text-[10px] text-slate-400">{evt.actor_role}</span>
                        </td>
                        <td className="py-3 px-4 text-slate-400 truncate max-w-xs" title={evt.record_hash}>
                          <span className="text-emerald-400/90">{evt.record_hash.substring(0, 16)}...</span>
                          <span className="text-slate-600">{evt.record_hash.substring(evt.record_hash.length - 8)}</span>
                        </td>
                        <td className="py-3 px-4 text-right">
                          <button
                            onClick={() => setExpandedSeq(isExpanded ? null : evt.seq)}
                            className="p-1 hover:bg-slate-700 rounded text-slate-400 hover:text-slate-100 transition cursor-pointer"
                            title="Inspect Block Proof"
                          >
                            {isExpanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
                          </button>
                        </td>
                      </tr>

                      {/* Expanded Block Inspector */}
                      {isExpanded && (
                        <tr className="bg-slate-950/90 border-t border-b border-cyan-900/30">
                          <td colSpan={7} className="p-4 space-y-3 font-mono text-xs">
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-[11px]">
                              <div>
                                <span className="text-slate-500">Previous Block Hash (prev_hash):</span>
                                <div className="text-slate-300 bg-slate-900 p-1.5 rounded border border-slate-800 select-all break-all">
                                  {evt.prev_hash}
                                </div>
                              </div>
                              <div>
                                <span className="text-slate-500">Record Signature Hash (record_hash):</span>
                                <div className="text-emerald-300 bg-slate-900 p-1.5 rounded border border-slate-800 select-all break-all">
                                  {evt.record_hash}
                                </div>
                              </div>
                              <div>
                                <span className="text-slate-500">Payload SHA-256 (payload_hash):</span>
                                <div className="text-slate-300 bg-slate-900 p-1.5 rounded border border-slate-800 select-all break-all">
                                  {evt.payload_hash}
                                </div>
                              </div>
                              <div>
                                <span className="text-slate-500">Correlation ID:</span>
                                <div className="text-slate-300 bg-slate-900 p-1.5 rounded border border-slate-800">
                                  {evt.correlation_id}
                                </div>
                              </div>
                            </div>

                            <div>
                              <span className="text-slate-500 text-[11px] flex items-center gap-1">
                                <FileCode className="w-3 h-3 text-cyan-400" />
                                Details Payload (JSON):
                              </span>
                              <pre className="mt-1 p-2.5 bg-slate-900 border border-slate-800 rounded-lg text-[10px] text-cyan-200 overflow-x-auto max-h-40">
                                {JSON.stringify(evt.details, null, 2)}
                              </pre>
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
        {events.length > 0 && events.length < totalCount && (
          <div className="px-4 py-3 bg-slate-950/70 border-t border-slate-800 flex items-center justify-between text-xs">
            <span className="text-slate-400 font-mono text-[11px]">
              Showing {events.length} of {totalCount} audit events
            </span>
            <button
              onClick={loadOlderEvents}
              disabled={isLoadingMore}
              className="px-3 py-1 bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-200 text-xs font-mono rounded-lg transition cursor-pointer disabled:opacity-50"
            >
              {isLoadingMore ? 'Loading...' : 'Load older events'}
            </button>
          </div>
        )}
      </div>
    </div>
  );
};
