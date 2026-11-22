import React, { useEffect, useMemo, useState } from 'react';
import type {
  AppRole,
  AttributionClass,
  AttributionIndicatorKind,
  AttributionRecord,
  AttributionReviewStatus,
  SelectedEntity,
} from '../../types/atlas';
import type { WorkspaceIntelligenceState } from '../../hooks/useWorkspaceIntelligence';
import { atlasService } from '../../data/api';
import { loadOrgScopedList, saveOrgScopedList } from '../../utils/orgStorage';
import { ShieldAlert, Plus, CheckCircle2, AlertTriangle, Download, Trash2, Send } from 'lucide-react';

interface AttributionWorkbenchProps {
  intel: WorkspaceIntelligenceState;
  activeRole: AppRole;
  userEmail: string;
  onSelectEntity: (entity: SelectedEntity) => void;
  initialIndicator?: string;
  onRecordsChange?: (next: AttributionRecord[]) => void;
}

const CLASS_META: Record<
  AttributionClass,
  { label: string; color: string; rule: string }
> = {
  observed_technical: {
    label: '1. OBSERVED TECHNICAL INFRASTRUCTURE',
    color: '#4a9eb0',
    rule: 'Direct technical observable (IP, hostname, certificate, host artefact) logged in telemetry.',
  },
  suspected_relationship: {
    label: '2. SUSPECTED INFRASTRUCTURE RELATIONSHIP',
    color: '#c88b32',
    rule: 'Analytical link between technical nodes pending independent corroboration.',
  },
  assessed_threat_group: {
    label: '3. ASSESSED THREAT-GROUP ASSOCIATION',
    color: '#b0648b',
    rule: 'Analytical cluster/actor assessment grounded in multiple technical observables & TTPs.',
  },
  verified_identity: {
    label: '4. CANDIDATE VERIFIED IDENTITY (DRAFT — REQUIRES CUSTODY)',
    color: '#4f8f66',
    rule: 'STRICT POLICY: Browser draft only — cannot represent formally verified identity until exported and committed via authorised Evidence Custody / backend workflow.',
  },
};

export const AttributionWorkbench: React.FC<AttributionWorkbenchProps> = ({
  intel,
  activeRole,
  userEmail,
  onSelectEntity,
  initialIndicator = '',
  onRecordsChange,
}) => {
  const [records, setRecords] = useState<AttributionRecord[]>(() =>
    loadOrgScopedList<AttributionRecord>('attributions', intel.orgId)
  );
  const [classFilter, setClassFilter] = useState<'all' | AttributionClass>('all');
  const [search, setSearch] = useState('');

  // Form state
  const [indicatorValue, setIndicatorValue] = useState(initialIndicator);
  const [indicatorType, setIndicatorType] = useState<AttributionIndicatorKind>('ip_address');
  const [attributionClass, setAttributionClass] = useState<AttributionClass>('observed_technical');
  const [entityLabel, setEntityLabel] = useState('');
  const [relationshipType, setRelationshipType] = useState('HOSTED_BY_OR_ROUTED_VIA');
  const [source, setSource] = useState('SOC Technical Telemetry Review');
  const [evidenceRef, setEvidenceRef] = useState('');
  const [incidentId, setIncidentId] = useState('');
  const [assetId, setAssetId] = useState('');
  const [confidence, setConfidence] = useState('0.60');
  const [analystNotes, setAnalystNotes] = useState('');
  const [notice, setNotice] = useState<{ kind: 'ok' | 'err'; text: string } | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    setRecords(loadOrgScopedList<AttributionRecord>('attributions', intel.orgId));
    setSearch('');
    setClassFilter('all');
    setNotice(null);
    setEntityLabel('');
    setEvidenceRef('');
    setIncidentId('');
    setAssetId('');
    setAnalystNotes('');
    if (!initialIndicator) setIndicatorValue('');
  }, [intel.orgId]);

  useEffect(() => {
    if (initialIndicator) setIndicatorValue(initialIndicator);
  }, [initialIndicator]);

  const persist = (next: AttributionRecord[]) => {
    setRecords(next);
    saveOrgScopedList('attributions', intel.orgId, next);
    onRecordsChange?.(next);
  };

  // Strict epistemic guardrail: never identify an individual solely from an IP address
  const ipIdentityViolation =
    attributionClass === 'verified_identity' &&
    indicatorType === 'ip_address' &&
    (!evidenceRef.trim() || evidenceRef.trim().length < 10);

  const handleAddRecord = (e: React.FormEvent) => {
    e.preventDefault();
    setNotice(null);

    if (!indicatorValue.trim() || !entityLabel.trim()) {
      setNotice({ kind: 'err', text: 'Indicator value and attributed entity/infra label are required.' });
      return;
    }
    if (ipIdentityViolation) {
      setNotice({
        kind: 'err',
        text: 'GUARDRAIL BLOCKED: Verified Individual Identity cannot be asserted from an IP address alone. Downgrade to "Observed Technical" or provide independent documentary Evidence Ref.',
      });
      return;
    }

    const rec: AttributionRecord = {
      id: `attr-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
      orgId: intel.orgId,
      indicatorValue: indicatorValue.trim(),
      indicatorType,
      attributionClass,
      entityLabel: entityLabel.trim(),
      relationshipType: relationshipType.trim() || 'ASSOCIATED_WITH',
      observedTimestamp: new Date().toISOString(),
      source: source.trim() || 'Analyst Submission',
      evidenceRef: evidenceRef.trim() || 'No documentary reference supplied',
      incidentId: incidentId || undefined,
      assetId: assetId || undefined,
      confidence: Math.max(0.05, Math.min(1, Number(confidence) || 0.5)),
      status: 'active_review',
      analystNotes: analystNotes.trim(),
      createdBy: userEmail,
      createdAt: new Date().toISOString(),
    };

    persist([rec, ...records]);
    setIndicatorValue('');
    setEntityLabel('');
    setEvidenceRef('');
    setAnalystNotes('');
    setNotice({
      kind: 'ok',
      text: `Saved local attribution draft under [${CLASS_META[attributionClass].label}]. Local drafts are browser-scoped and NOT persisted in Supabase; export and upload via Evidence Custody for immutable DB archival.`,
    });
  };

  const updateStatus = (id: string, status: AttributionReviewStatus) => {
    persist(records.map((r) => (r.id === id ? { ...r, status } : r)));
  };

  const removeRecord = (id: string) => {
    persist(records.filter((r) => r.id !== id));
  };

  const handleMarkFindingDraft = (rec: AttributionRecord) => {
    const markedAt = new Date().toISOString();
    persist(
      records.map((r) =>
        r.id === rec.id
          ? { ...r, draftMarkedAt: markedAt }
          : r
      )
    );
    setNotice({
      kind: 'ok',
      text: `Prepared attribution draft (${rec.indicatorValue} -> ${rec.entityLabel}) for dossier export. Local drafts are not written to audit_events; use Export Dossier (logged as EXPORT) or upload as Evidence for DB custody.`,
    });
  };

  const handleExportDossier = async () => {
    setBusy(true);
    setNotice(null);
    const payload = {
      exported_at: new Date().toISOString(),
      org_id: intel.orgId,
      operator: userEmail,
      epistemic_warning:
        'Attribution entries strictly separate observed technical infrastructure from unverified assessments and verified identity.',
      records,
    };
    try {
      await atlasService.logEvent(intel.orgId, 'EXPORT', 'ATTRIBUTION_DOSSIER', intel.orgId, {
        records_count: records.length,
        exported_at: payload.exported_at,
      });
    } catch (err: any) {
      setNotice({ kind: 'err', text: `Export blocked by audit ledger: ${err.message}` });
      setBusy(false);
      return;
    }
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `atlas-attribution-dossier-${intel.orgId.slice(0, 8)}.json`;
    a.click();
    URL.revokeObjectURL(url);
    setBusy(false);
    setNotice({ kind: 'ok', text: 'Attribution dossier exported & logged to cryptographic audit chain.' });
  };

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return records.filter((r) => {
      if (classFilter !== 'all' && r.attributionClass !== classFilter) return false;
      if (!q) return true;
      return `${r.indicatorValue} ${r.entityLabel} ${r.source} ${r.analystNotes}`.toLowerCase().includes(q);
    });
  }, [records, classFilter, search]);

  return (
    <div className="flex-1 flex flex-col overflow-hidden bg-[#0b0d10]">
      {/* Header & Epistemic Separation Disclosure */}
      <div className="px-4 py-2.5 border-b border-[#252b36] bg-[#12151b] flex flex-wrap items-center justify-between gap-2 shrink-0">
        <div>
          <div className="font-mono text-[10px] tracking-[0.12em] text-[#8fa36d]">
            MODULE B // EVIDENCE-BASED THREAT ATTRIBUTION ENGINE
          </div>
          <h1 className="text-sm font-semibold text-[#e8ecf1] flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-[#c88b32]" />
            <span>Infrastructure Attribution & Corroboration Workbench</span>
          </h1>
        </div>
        <div className="flex items-center gap-2 font-mono text-[11px]">
          <span className="text-[10px] text-[#c88b32] border border-[#c88b32]/40 bg-[#c88b32]/10 px-2 py-0.5">
            BROWSER DRAFTS ONLY (NON-AUTHORITATIVE) · AUTHORITATIVE FINDINGS REQUIRE CUSTODY UPLOAD · ROLE: {activeRole}
          </span>
          <button
            disabled={busy || records.length === 0}
            onClick={handleExportDossier}
            className="px-2.5 py-1 bg-[#181c24] hover:bg-[#222834] border border-[#252b36] text-[#e8ecf1] flex items-center gap-1 cursor-pointer disabled:opacity-40"
          >
            <Download className="w-3 h-3 text-[#4a9eb0]" />
            <span>Export Dossier</span>
          </button>
        </div>
      </div>

      {/* Four-Tier Epistemic Strip */}
      <div className="grid grid-cols-1 md:grid-cols-4 border-b border-[#252b36] bg-[#0e1116] divide-y md:divide-y-0 md:divide-x divide-[#252b36] shrink-0">
        {(Object.keys(CLASS_META) as AttributionClass[]).map((cls) => {
          const meta = CLASS_META[cls];
          const count = records.filter((r) => r.attributionClass === cls).length;
          return (
            <button
              key={cls}
              onClick={() => setClassFilter(classFilter === cls ? 'all' : cls)}
              className={`p-2.5 text-left transition-colors cursor-pointer ${
                classFilter === cls ? 'bg-[#181c24]' : 'hover:bg-[#12151b]'
              }`}
            >
              <div className="flex items-center justify-between font-mono text-[10px] font-semibold" style={{ color: meta.color }}>
                <span className="truncate">{meta.label}</span>
                <span className="tabular-nums text-[#e8ecf1]">{count}</span>
              </div>
              <div className="text-[10px] text-[#8c97a8] mt-1 line-clamp-2">{meta.rule}</div>
            </button>
          );
        })}
      </div>

      {notice && (
        <div
          className={`px-4 py-1.5 border-b font-mono text-xs flex items-center justify-between shrink-0 ${
            notice.kind === 'ok'
              ? 'bg-[#4f8f66]/10 border-[#4f8f66]/40 text-[#4f8f66]'
              : 'bg-[#c94a4a]/10 border-[#c94a4a]/40 text-[#c94a4a]'
          }`}
        >
          <span>{notice.text}</span>
          <button onClick={() => setNotice(null)} className="underline cursor-pointer">
            Dismiss
          </button>
        </div>
      )}

      {/* Main Split: Left Attribution Record Form + Right Records Ledger */}
      <div className="flex-1 flex min-h-0 overflow-hidden">
        {/* Left Entry Form */}
        <aside className="w-80 xl:w-96 border-r border-[#252b36] bg-[#0e1116] p-3 overflow-y-auto shrink-0">
          <form onSubmit={handleAddRecord} className="space-y-2.5 font-mono text-[11px]">
            <div className="text-[10px] tracking-[0.12em] text-[#e8ecf1] font-semibold border-b border-[#252b36] pb-1.5">
              LOG TECHNICAL / ATTRIBUTION LINK
            </div>

            <div>
              <label className="block text-[10px] text-[#8c97a8] mb-1">EPISTEMIC CLASSIFICATION</label>
              <select
                value={attributionClass}
                onChange={(e) => setAttributionClass(e.target.value as AttributionClass)}
                className="w-full bg-[#0b0d10] border border-[#252b36] px-2 py-1 text-[#e8ecf1]"
              >
                <option value="observed_technical">1. Observed Technical Infrastructure (Local Draft)</option>
                <option value="suspected_relationship">2. Suspected Infrastructure Relationship (Local Draft)</option>
                <option value="assessed_threat_group">3. Assessed Threat-Group Association (Local Draft)</option>
                <option value="verified_identity">4. Candidate Verified Identity (Draft — Requires Custody)</option>
              </select>
            </div>

            <div className="grid grid-cols-2 gap-2">
              <div>
                <label className="block text-[10px] text-[#8c97a8] mb-1">INDICATOR KIND</label>
                <select
                  value={indicatorType}
                  onChange={(e) => setIndicatorType(e.target.value as AttributionIndicatorKind)}
                  className="w-full bg-[#0b0d10] border border-[#252b36] px-2 py-1 text-[#e8ecf1]"
                >
                  <option value="ip_address">IP Address</option>
                  <option value="domain">Domain</option>
                  <option value="hostname">Hostname</option>
                  <option value="network_infra">Network Infra / ASN</option>
                  <option value="malware_indicator">Malware Indicator</option>
                  <option value="certificate">TLS Certificate</option>
                  <option value="threat_group">Threat Actor Cluster</option>
                </select>
              </div>
              <div>
                <label className="block text-[10px] text-[#8c97a8] mb-1">CONFIDENCE (0.05–1.0)</label>
                <input
                  type="number"
                  step="0.05"
                  min="0.05"
                  max="1"
                  value={confidence}
                  onChange={(e) => setConfidence(e.target.value)}
                  className="w-full bg-[#0b0d10] border border-[#252b36] px-2 py-1 text-[#e8ecf1] tabular-nums"
                />
              </div>
            </div>

            <div>
              <label className="block text-[10px] text-[#8c97a8] mb-1">OBSERVABLE INDICATOR VALUE *</label>
              <input
                type="text"
                required
                value={indicatorValue}
                onChange={(e) => setIndicatorValue(e.target.value)}
                placeholder="e.g., 198.51.100.42 or c2-relay.example"
                className="w-full bg-[#0b0d10] border border-[#252b36] px-2 py-1 text-[#e8ecf1]"
              />
            </div>

            <div>
              <label className="block text-[10px] text-[#8c97a8] mb-1">ATTRIBUTED INFRA / CLUSTER LABEL *</label>
              <input
                type="text"
                required
                value={entityLabel}
                onChange={(e) => setEntityLabel(e.target.value)}
                placeholder="e.g., AS64512 Transit Relay / Cluster-G7"
                className="w-full bg-[#0b0d10] border border-[#252b36] px-2 py-1 text-[#e8ecf1]"
              />
            </div>

            <div className="grid grid-cols-2 gap-2">
              <div>
                <label className="block text-[10px] text-[#8c97a8] mb-1">LINK INCIDENT (OPTIONAL)</label>
                <select
                  value={incidentId}
                  onChange={(e) => setIncidentId(e.target.value)}
                  className="w-full bg-[#0b0d10] border border-[#252b36] px-2 py-1 text-[#e8ecf1]"
                >
                  <option value="">None</option>
                  {intel.incidents.map((i) => (
                    <option key={i.id} value={i.id}>
                      {i.event_id}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="block text-[10px] text-[#8c97a8] mb-1">LINK ASSET (OPTIONAL)</label>
                <select
                  value={assetId}
                  onChange={(e) => setAssetId(e.target.value)}
                  className="w-full bg-[#0b0d10] border border-[#252b36] px-2 py-1 text-[#e8ecf1]"
                >
                  <option value="">None</option>
                  {intel.assets.map((a) => (
                    <option key={a.id} value={a.id}>
                      {a.site_code}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            <div>
              <label className="block text-[10px] text-[#8c97a8] mb-1">RELATIONSHIP TYPE</label>
              <input
                type="text"
                value={relationshipType}
                onChange={(e) => setRelationshipType(e.target.value)}
                className="w-full bg-[#0b0d10] border border-[#252b36] px-2 py-1 text-[#e8ecf1]"
              />
            </div>

            <div>
              <label className="block text-[10px] text-[#8c97a8] mb-1">SOURCE & EVIDENCE REFERENCE *</label>
              <input
                type="text"
                value={source}
                onChange={(e) => setSource(e.target.value)}
                placeholder="Telemetry / Feed source"
                className="w-full bg-[#0b0d10] border border-[#252b36] px-2 py-1 text-[#e8ecf1] mb-1.5"
              />
              <input
                type="text"
                value={evidenceRef}
                onChange={(e) => setEvidenceRef(e.target.value)}
                placeholder="Evidence SHA-256 prefix, Warrant/Ticket ID, or PCAP ref"
                className="w-full bg-[#0b0d10] border border-[#252b36] px-2 py-1 text-[#e8ecf1]"
              />
            </div>

            <div>
              <label className="block text-[10px] text-[#8c97a8] mb-1">ANALYST CORROBORATION NOTES</label>
              <textarea
                rows={3}
                value={analystNotes}
                onChange={(e) => setAnalystNotes(e.target.value)}
                placeholder="Document technical overlap, alternative hypotheses, and limitations..."
                className="w-full bg-[#0b0d10] border border-[#252b36] p-2 text-[#e8ecf1] font-sans"
              />
            </div>

            {ipIdentityViolation && (
              <div className="p-2 bg-[#c94a4a]/15 border border-[#c94a4a]/40 text-[#c94a4a] text-[10px] flex items-start gap-1.5">
                <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-0.5" />
                <span>
                  IP address alone cannot establish Verified Individual Identity. Provide corroborating documentary evidence reference (≥10 chars) or select Technical/Suspected tier.
                </span>
              </div>
            )}

            <button
              type="submit"
              disabled={ipIdentityViolation}
              className="w-full py-1.5 bg-[#6f8054] hover:bg-[#7d905f] text-[#0b0d10] font-semibold flex items-center justify-center gap-1.5 cursor-pointer disabled:opacity-40"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Record Attribution Link</span>
            </button>
          </form>
        </aside>

        {/* Right Attribution Records Table */}
        <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
          <div className="px-3 py-2 border-b border-[#252b36] bg-[#12151b] flex flex-wrap items-center justify-between gap-2 font-mono text-[11px] shrink-0">
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Filter indicator, attributed entity, source..."
              className="bg-[#0b0d10] border border-[#252b36] px-2.5 py-1 text-[#e8ecf1] w-64 focus:outline-none focus:border-[#6f8054]"
            />
            <span className="text-[#8c97a8] tabular-nums">
              DISPLAYING {filtered.length} OF {records.length} RECORD(S)
            </span>
          </div>

          <div className="flex-1 overflow-y-auto p-3 space-y-2.5">
            {filtered.length === 0 ? (
              <div className="p-6 bg-[#12151b] border border-[#252b36] font-mono text-xs text-[#8c97a8] space-y-1">
                <div className="text-[#e8ecf1] font-semibold">No attribution records logged for this filter.</div>
                <p className="font-sans text-xs">
                  Use the attribution entry panel to document technical infrastructure links, suspected relationships, or assessed threat-group associations grounded in workspace evidence.
                </p>
              </div>
            ) : (
              filtered.map((rec) => {
                const meta = CLASS_META[rec.attributionClass];
                return (
                  <div key={rec.id} className="bg-[#12151b] border border-[#252b36] p-3 space-y-2">
                    <div className="flex flex-wrap items-center justify-between gap-2 font-mono text-[11px]">
                      <div className="flex items-center gap-2 min-w-0">
                        <span
                          className="text-[10px] font-semibold px-1.5 py-0.5 border"
                          style={{
                            color: meta.color,
                            borderColor: `${meta.color}66`,
                            backgroundColor: `${meta.color}1a`,
                          }}
                        >
                          {meta.label}
                        </span>
                        <span className="text-[#e8ecf1] font-semibold">{rec.indicatorValue}</span>
                        <span className="text-[#5d6778]">({rec.indicatorType})</span>
                        <span className="text-[#8c97a8]">→</span>
                        <span className="text-[#4a9eb0] font-semibold">{rec.entityLabel}</span>
                      </div>
                      <div className="flex items-center gap-2 tabular-nums">
                        <span className="text-[#e8ecf1]">CONF: {(rec.confidence * 100).toFixed(0)}%</span>
                        <select
                          value={rec.status}
                          onChange={(e) => updateStatus(rec.id, e.target.value as AttributionReviewStatus)}
                          className="bg-[#0b0d10] border border-[#252b36] px-1.5 py-0.5 text-[10px] text-[#e8ecf1]"
                        >
                          <option value="active_review">LOCAL REVIEW (DRAFT)</option>
                          <option value="corroborated">LOCAL CORROBORATED DRAFT (UNCOMMITTED)</option>
                          <option value="contested">CONTESTED (DRAFT)</option>
                          <option value="archived">ARCHIVED (DRAFT)</option>
                        </select>
                      </div>
                    </div>

                    <div className="text-xs text-[#e8ecf1]/90">
                      {rec.analystNotes || 'No additional analyst notes documented.'}
                    </div>

                    <div className="flex flex-wrap items-center justify-between gap-2 pt-1.5 border-t border-[#1e242e] font-mono text-[10px] text-[#8c97a8]">
                      <div className="flex flex-wrap items-center gap-3">
                        <span>REL: {rec.relationshipType}</span>
                        <span>SRC: {rec.source}</span>
                        <span>EV-REF (REFERENCE ONLY): {rec.evidenceRef}</span>
                        {rec.incidentId && (
                          <button
                            onClick={() => onSelectEntity({ kind: 'incident', id: rec.incidentId! })}
                            className="text-[#4a9eb0] hover:underline cursor-pointer"
                          >
                            Incident Pivot
                          </button>
                        )}
                        {rec.assetId && (
                          <button
                            onClick={() => onSelectEntity({ kind: 'asset', id: rec.assetId! })}
                            className="text-[#4a9eb0] hover:underline cursor-pointer"
                          >
                            Asset Pivot
                          </button>
                        )}
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-[10px] text-[#c88b32] border border-[#c88b32]/40 bg-[#c88b32]/10 px-1.5 py-0.5">
                          {rec.draftMarkedAt ? 'STAGED DRAFT (NOT DB-COMMITTED)' : 'UNVERIFIED LOCAL DRAFT'}
                        </span>
                        <button
                          disabled={busy}
                          onClick={() => handleMarkFindingDraft(rec)}
                          className="px-2 py-0.5 bg-[#4a9eb0]/15 hover:bg-[#4a9eb0]/25 border border-[#4a9eb0]/40 text-[#4a9eb0] flex items-center gap-1 cursor-pointer disabled:opacity-40"
                          title="Mark local attribution draft ready for dossier export or Evidence Custody upload"
                        >
                          <CheckCircle2 className="w-2.5 h-2.5" />
                          <span>Stage Draft</span>
                        </button>
                        <button
                          onClick={() => removeRecord(rec.id)}
                          className="text-[#8c97a8] hover:text-[#c94a4a] p-0.5 cursor-pointer"
                          title="Delete draft attribution"
                        >
                          <Trash2 className="w-3 h-3" />
                        </button>
                      </div>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
