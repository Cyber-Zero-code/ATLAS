import React, { useMemo, useState } from 'react';
import { BlastRadiusNode, ModuleId, SelectedEntity } from '../../types/atlas';
import { WorkspaceIntelligenceState } from '../../hooks/useWorkspaceIntelligence';
import { atlasService } from '../../data/api';
import { ResilienceModulePanel } from '../analysis/ResilienceModulePanel';
import {
  Cpu,
  TrendingUp,
  AlertTriangle,
  BarChart3,
  Bot,
  Send,
  Info,
  RefreshCw,
  Activity,
} from 'lucide-react';

interface AiMlWorkspaceProps {
  mode:
    | 'predictive_risk'
    | 'anomaly_detection'
    | 'behavioural_analysis'
    | 'ai_assistant'
    | 'model_performance';
  intel: WorkspaceIntelligenceState;
  onSelectEntity: (entity: SelectedEntity) => void;
  onNavigateModule: (module: ModuleId) => void;
}

interface AssistantTurn {
  id: string;
  query: string;
  facts: string[];
  limitations: string;
  timestamp: string;
}

export const AiMlWorkspace: React.FC<AiMlWorkspaceProps> = ({
  mode,
  intel,
  onSelectEntity,
  onNavigateModule,
}) => {
  // Predictive Risk State (executes real blast_radius RPC + Module F Resilience)
  const [riskSubTab, setRiskSubTab] = useState<'blast' | 'resilience'>('blast');
  const [selectedIncId, setSelectedIncId] = useState<string>('');
  const [blastNodes, setBlastNodes] = useState<BlastRadiusNode[]>([]);
  const [blastLoading, setBlastLoading] = useState(false);
  const [blastErr, setBlastErr] = useState<string | null>(null);

  // Assistant Query State
  const [prompt, setPrompt] = useState('');
  const [history, setHistory] = useState<AssistantTurn[]>([]);

  const activeIncidentId = selectedIncId || intel.incidents[0]?.id || '';

  const runDeterministicRiskModel = async () => {
    if (!activeIncidentId) return;
    setBlastLoading(true);
    setBlastErr(null);
    try {
      const res = await atlasService.fetchBlastRadius(activeIncidentId);
      setBlastNodes(res);
    } catch (err: any) {
      setBlastErr(err.message || 'Blast radius computation failed.');
    } finally {
      setBlastLoading(false);
    }
  };

  // =========================================================================
  // 1. MODEL PERFORMANCE (RULE-ENGINE METRICS ON LABELLED MATCHES)
  // =========================================================================
  if (mode === 'model_performance') {
    const rules = Array.from(new Set(intel.matches.map((m) => m.rule_fired))).sort();
    const ruleMetrics = rules.map((rule) => {
      const rows = intel.matches.filter((m) => m.rule_fired === rule);
      const confirmed = rows.filter((r) => r.status === 'confirmed').length;
      const rejected = rows.filter((r) => r.status === 'rejected').length;
      const autoCount = rows.filter((r) => r.status === 'auto').length;
      const proposed = rows.filter((r) => r.status === 'proposed').length;
      const labelled = confirmed + rejected;
      const precision = labelled > 0 ? confirmed / labelled : null;
      const meanScore =
        rows.length > 0 ? rows.reduce((acc, r) => acc + Number(r.score), 0) / rows.length : 0;

      return { rule, total: rows.length, autoCount, proposed, confirmed, rejected, precision, meanScore };
    });

    return (
      <div className="flex-1 overflow-y-auto bg-[#0b0d10] p-4 space-y-4">
        <div className="bg-[#12151b] border border-[#252b36] p-4 flex flex-wrap items-center justify-between gap-3">
          <div>
            <div className="font-mono text-[10px] tracking-[0.12em] text-[#8fa36d]">
              AI & MACHINE LEARNING // RULE ENGINE & PARAMETER TELEMETRY
            </div>
            <h1 className="text-base font-semibold text-[#e8ecf1] mt-0.5 flex items-center gap-2">
              <Cpu className="w-4 h-4 text-[#8fa36d]" />
              <span>Model Performance & Calibration</span>
            </h1>
          </div>
          <span className="font-mono text-[10px] text-[#c88b32] border border-[#c88b32]/40 bg-[#c88b32]/10 px-2 py-1">
            LOCAL RULE ENGINE ACTIVE · EXTERNAL NEURAL MODELS UNAVAILABLE
          </span>
        </div>

        {/* Rule Precision Table */}
        <div className="bg-[#12151b] border border-[#252b36]">
          <div className="px-3 py-2 border-b border-[#252b36] flex items-center justify-between font-mono text-[11px]">
            <span className="font-semibold text-[#e8ecf1]">
              DETERMINISTIC MATCHING RULES — PERFORMANCE ON LABELLED SAMPLES
            </span>
            <span className="text-[#8c97a8] text-[10px]">
              Precision = Confirmed / (Confirmed + Rejected)
            </span>
          </div>
          <table className="w-full text-left font-mono text-[11px] border-collapse">
            <thead className="bg-[#0e1116] border-b border-[#252b36] text-[#8c97a8] text-[10px]">
              <tr>
                <th className="py-2 px-3">RULE IDENTIFIER</th>
                <th className="py-2 px-2 text-right">TOTAL</th>
                <th className="py-2 px-2 text-right">AUTO (≥90%)</th>
                <th className="py-2 px-2 text-right">PROPOSED</th>
                <th className="py-2 px-2 text-right">CONFIRMED</th>
                <th className="py-2 px-2 text-right">REJECTED</th>
                <th className="py-2 px-2 text-right">MEAN SCORE</th>
                <th className="py-2 px-3 text-right">LABELLED PRECISION</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#181c24]">
              {ruleMetrics.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-6 text-center text-[#8c97a8] font-sans">
                    No asset matches recorded yet. Ingest incidents and confirm/reject proposals to populate rule precision metrics.
                  </td>
                </tr>
              ) : (
                ruleMetrics.map((rm) => (
                  <tr key={rm.rule} className="hover:bg-[#181c24]">
                    <td className="py-1.5 px-3 text-[#4a9eb0] font-semibold">{rm.rule}</td>
                    <td className="py-1.5 px-2 text-right tabular-nums text-[#e8ecf1]">{rm.total}</td>
                    <td className="py-1.5 px-2 text-right tabular-nums text-[#4f8f66]">{rm.autoCount}</td>
                    <td className="py-1.5 px-2 text-right tabular-nums text-[#c88b32]">{rm.proposed}</td>
                    <td className="py-1.5 px-2 text-right tabular-nums text-[#4f8f66]">{rm.confirmed}</td>
                    <td className="py-1.5 px-2 text-right tabular-nums text-[#c94a4a]">{rm.rejected}</td>
                    <td className="py-1.5 px-2 text-right tabular-nums text-[#e8ecf1]">
                      {(rm.meanScore * 100).toFixed(1)}%
                    </td>
                    <td className="py-1.5 px-3 text-right tabular-nums font-semibold">
                      {rm.precision === null ? (
                        <span className="text-[#5d6778]">UNLABELLED (0 reviews)</span>
                      ) : (
                        <span className="text-[#4f8f66]">{(rm.precision * 100).toFixed(1)}%</span>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Stored Scoring Configuration (Uncalibrated Disclosure) */}
        <div className="bg-[#12151b] border border-[#252b36]">
          <div className="px-3 py-2 border-b border-[#252b36] font-mono text-[11px] font-semibold text-[#e8ecf1]">
            SCORING PARAMETERS (public.scoring_config)
          </div>
          <table className="w-full text-left font-mono text-[11px] border-collapse">
            <thead className="bg-[#0e1116] border-b border-[#252b36] text-[#8c97a8] text-[10px]">
              <tr>
                <th className="py-1.5 px-3">PARAMETER KEY</th>
                <th className="py-1.5 px-2 text-right">WEIGHT</th>
                <th className="py-1.5 px-2 text-right">SCALE</th>
                <th className="py-1.5 px-2">CALIBRATION STATUS</th>
                <th className="py-1.5 px-3">DESCRIPTION</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#181c24]">
              {intel.scoringConfig.map((cfg) => (
                <tr key={cfg.id} className="hover:bg-[#181c24]">
                  <td className="py-1.5 px-3 text-[#e8ecf1] font-semibold">{cfg.config_key}</td>
                  <td className="py-1.5 px-2 text-right tabular-nums text-[#4a9eb0]">{cfg.weight}</td>
                  <td className="py-1.5 px-2 text-right tabular-nums text-[#e8ecf1]">{cfg.scale}</td>
                  <td className="py-1.5 px-2 text-[#c88b32]">{cfg.calibration_status.toUpperCase()}</td>
                  <td className="py-1.5 px-3 text-[#8c97a8] font-sans">{cfg.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    );
  }

  // =========================================================================
  // 2. PREDICTIVE RISK ANALYSIS & MODULE F INFRASTRUCTURE RESILIENCE
  // =========================================================================
  if (mode === 'predictive_risk') {
    return (
      <div className="flex-1 flex flex-col overflow-hidden bg-[#0b0d10]">
        <div className="px-4 py-2.5 border-b border-[#252b36] bg-[#12151b] flex flex-wrap items-center justify-between gap-3 shrink-0">
          <div>
            <div className="font-mono text-[10px] tracking-[0.12em] text-[#8fa36d]">
              AI & MACHINE LEARNING // DETERMINISTIC EXPOSURE &amp; RESILIENCE MODELLING
            </div>
            <h1 className="text-base font-semibold text-[#e8ecf1] mt-0.5 flex items-center gap-2">
              <TrendingUp className="w-4 h-4 text-[#c88b32]" />
              <span>Blast Consequence &amp; Infrastructure Resilience (Module F)</span>
            </h1>
          </div>
          <div className="flex items-center gap-1.5 font-mono text-[11px]">
            <button
              onClick={() => setRiskSubTab('blast')}
              className={`px-2.5 py-1 border rounded-[2px] flex items-center gap-1.5 cursor-pointer ${
                riskSubTab === 'blast'
                  ? 'bg-[#6f8054]/25 border-[#6f8054] text-[#e8ecf1]'
                  : 'bg-[#0b0d10] border-[#252b36] text-[#8c97a8] hover:text-[#e8ecf1]'
              }`}
            >
              <TrendingUp className="w-3 h-3" />
              <span>Blast Exposure Model (SQL)</span>
            </button>
            <button
              onClick={() => setRiskSubTab('resilience')}
              className={`px-2.5 py-1 border rounded-[2px] flex items-center gap-1.5 cursor-pointer ${
                riskSubTab === 'resilience'
                  ? 'bg-[#6f8054]/25 border-[#6f8054] text-[#e8ecf1]'
                  : 'bg-[#0b0d10] border-[#252b36] text-[#8c97a8] hover:text-[#e8ecf1]'
              }`}
            >
              <Activity className="w-3 h-3 text-[#c88b32]" />
              <span>Resilience &amp; Cascade Simulator (Module F)</span>
            </button>
          </div>
        </div>

        <div className="flex-1 overflow-y-auto">
          {riskSubTab === 'resilience' ? (
            <ResilienceModulePanel intel={intel} onSelectEntity={onSelectEntity} />
          ) : (
            <div className="p-4 space-y-4">
              <div className="bg-[#12151b] border border-[#252b36] p-4 flex flex-wrap items-center justify-between gap-3">
                <p className="text-xs text-[#8c97a8]">
                  Computes <code className="font-mono text-[#e8ecf1]">Priority = (c × r) × E × L</code> with uncertainty bounds widened by match score &amp; spatial accuracy. Marked <strong>uncalibrated</strong>.
                </p>
                <div className="flex items-center gap-2 font-mono text-xs">
                  <select
                    value={activeIncidentId}
                    onChange={(e) => setSelectedIncId(e.target.value)}
                    className="bg-[#0b0d10] border border-[#252b36] px-2.5 py-1.5 text-[#e8ecf1]"
                  >
                    {intel.incidents.length === 0 ? (
                      <option value="">No incidents available</option>
                    ) : (
                      intel.incidents.map((inc) => (
                        <option key={inc.id} value={inc.id}>
                          {inc.event_id} ({inc.severity.toUpperCase()})
                        </option>
                      ))
                    )}
                  </select>
                  <button
                    onClick={runDeterministicRiskModel}
                    disabled={!activeIncidentId || blastLoading}
                    className="px-3 py-1.5 bg-[#6f8054] hover:bg-[#7d905f] text-[#0b0d10] font-semibold flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
                  >
                    <RefreshCw className={`w-3.5 h-3.5 ${blastLoading ? 'animate-spin' : ''}`} />
                    <span>Run SQL Model</span>
                  </button>
                </div>
              </div>

              {blastErr && (
                <div className="p-3 bg-[#c94a4a]/10 border border-[#c94a4a]/40 font-mono text-xs text-[#c94a4a]">
                  {blastErr}
                </div>
              )}

              <div className="bg-[#12151b] border border-[#252b36]">
                <div className="px-3 py-2 border-b border-[#252b36] font-mono text-[11px] font-semibold text-[#e8ecf1] flex justify-between">
                  <span>PREDICTED DOWNSTREAM EXPOSURE INTERVALS (UNCALIBRATED)</span>
                  <span className="text-[#8c97a8]">{blastNodes.length} REACHABLE ASSETS</span>
                </div>
                <table className="w-full text-left font-mono text-[11px] border-collapse">
                  <thead className="bg-[#0e1116] border-b border-[#252b36] text-[#8c97a8] text-[10px]">
                    <tr>
                      <th className="py-2 px-3">ASSET</th>
                      <th className="py-2 px-2 text-right">HOPS</th>
                      <th className="py-2 px-2 text-right">IMPACT (I = c×r)</th>
                      <th className="py-2 px-2 text-right">POINT PRIORITY</th>
                      <th className="py-2 px-2 text-right">UNCERTAINTY INTERVAL</th>
                      <th className="py-2 px-3 text-right">ACCURACY / MATCH</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#181c24]">
                    {blastNodes.length === 0 ? (
                      <tr>
                        <td colSpan={6} className="py-8 text-center text-[#8c97a8] font-sans">
                          Select an incident and click "Run SQL Model" to compute deterministic downstream exposure intervals.
                        </td>
                      </tr>
                    ) : (
                      blastNodes.map((n) => (
                        <tr
                          key={`${n.root_asset_id}-${n.asset_id}`}
                          onClick={() => onSelectEntity({ kind: 'asset', id: n.asset_id })}
                          className="hover:bg-[#181c24] cursor-pointer"
                        >
                          <td className="py-1.5 px-3">
                            <span className="text-[#4a9eb0] font-semibold">{n.site_code}</span>{' '}
                            <span className="text-[#e8ecf1] font-sans">{n.name}</span>
                          </td>
                          <td className="py-1.5 px-2 text-right tabular-nums text-[#8c97a8]">{n.hop_depth}</td>
                          <td className="py-1.5 px-2 text-right tabular-nums text-[#e8ecf1]">{Number(n.i_factor).toFixed(3)}</td>
                          <td className="py-1.5 px-2 text-right tabular-nums font-semibold text-[#c88b32]">
                            {Number(n.priority).toFixed(3)}
                          </td>
                          <td className="py-1.5 px-2 text-right tabular-nums text-[#e8ecf1]">
                            [{Number(n.range_low).toFixed(3)}, {Number(n.range_high).toFixed(3)}]
                          </td>
                          <td className="py-1.5 px-3 text-right text-[#8c97a8]">
                            {n.accuracy_class} · {(Number(n.match_confidence) * 100).toFixed(0)}%
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      </div>
    );
  }

  // =========================================================================
  // 3. ANOMALY DETECTION (STRUCTURAL & DATA INTEGRITY SCANNER)
  // =========================================================================
  if (mode === 'anomaly_detection') {
    const anomalies: Array<{
      id: string;
      severity: 'critical' | 'high' | 'medium';
      category: string;
      title: string;
      explanation: string;
      entity: SelectedEntity;
    }> = [];

    for (const a of intel.assets) {
      if (a.criticality >= 4 && a.accuracy_class !== 'exact_survey') {
        anomalies.push({
          id: `anom-acc-${a.id}`,
          severity: 'high',
          category: 'SPATIAL_UNCERTAINTY',
          title: `${a.site_code} (${a.name}) has approximate coordinates on Tier-${a.criticality} asset`,
          explanation: `Accuracy class "${a.accuracy_class}" widens geospatial impact uncertainty.`,
          entity: { kind: 'asset', id: a.id },
        });
      }
      const hasIocs =
        (a.identifiers?.hostnames?.length || 0) +
          (a.identifiers?.ip_addresses?.length || 0) +
          (a.identifiers?.cidrs?.length || 0) +
          (a.identifiers?.cloud_account_ids?.length || 0) >
        0;
      if (a.criticality >= 4 && !hasIocs) {
        anomalies.push({
          id: `anom-blind-${a.id}`,
          severity: 'medium',
          category: 'CYBER_BLIND_SPOT',
          title: `${a.site_code} lacks cyber identifiers (hostname / IP / CIDR / cloud ID)`,
          explanation: 'Rule engine can only correlate this site via exact site_code telemetry.',
          entity: { kind: 'asset', id: a.id },
        });
      }
    }

    for (const m of intel.matches) {
      if (m.status === 'proposed') {
        const inc = intel.incidents.find((i) => i.id === m.incident_id);
        if (inc?.severity === 'critical') {
          anomalies.push({
            id: `anom-unver-${m.id}`,
            severity: 'critical',
            category: 'UNCONFIRMED_CRITICAL_CORRELATION',
            title: `Critical incident ${inc.event_id} has unverified match (${(Number(m.score) * 100).toFixed(0)}%)`,
            explanation: `Rule ${m.rule_fired} requires human analyst confirmation or rejection.`,
            entity: { kind: 'incident', id: inc.id },
          });
        }
      }
    }

    for (const ev of intel.evidence) {
      const verifiedCount = (ev.custody_events || []).filter((c) => c.event_type === 'VERIFY_HASH').length;
      if (verifiedCount === 0) {
        anomalies.push({
          id: `anom-ev-${ev.id}`,
          severity: 'medium',
          category: 'EVIDENCE_UNREVERIFIED',
          title: `Evidence "${ev.file_name}" has no post-intake VERIFY_HASH check`,
          explanation: 'Run Web Crypto storage integrity verification in Evidence Custody.',
          entity: { kind: 'evidence', id: ev.id },
        });
      }
    }

    return (
      <div className="flex-1 overflow-y-auto bg-[#0b0d10] p-4 space-y-4">
        <div className="bg-[#12151b] border border-[#252b36] p-4 flex flex-wrap items-center justify-between gap-2">
          <div>
            <div className="font-mono text-[10px] tracking-[0.12em] text-[#8fa36d]">
              AI & MACHINE LEARNING // DETERMINISTIC STRUCTURAL ANOMALY SCANNER
            </div>
            <h1 className="text-base font-semibold text-[#e8ecf1] mt-0.5 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-[#c88b32]" />
              <span>Workspace Anomaly Detection ({anomalies.length} Findings)</span>
            </h1>
          </div>
          <span className="font-mono text-[10px] text-[#8c97a8]">
            RULE-BASED HEURISTIC AUDIT OVER LIVE SUPABASE TABLES
          </span>
        </div>

        <div className="bg-[#12151b] border border-[#252b36] divide-y divide-[#1e242e]">
          {anomalies.length === 0 ? (
            <div className="p-6 font-mono text-xs text-[#4f8f66]">
              Zero structural, spatial-precision, or telemetry-coverage anomalies detected.
            </div>
          ) : (
            anomalies.map((anom) => (
              <button
                key={anom.id}
                onClick={() => {
                  onSelectEntity(anom.entity);
                  if (anom.entity?.kind === 'incident') onNavigateModule('cyber_incidents');
                  else if (anom.entity?.kind === 'asset') onNavigateModule('asset_tracking');
                }}
                className="w-full p-3 text-left hover:bg-[#181c24] flex items-start justify-between gap-3 cursor-pointer"
              >
                <div className="space-y-0.5">
                  <div className="flex items-center gap-2 font-mono text-xs">
                    <span
                      className={
                        anom.severity === 'critical'
                          ? 'text-[#c94a4a] font-semibold'
                          : anom.severity === 'high'
                          ? 'text-[#c88b32] font-semibold'
                          : 'text-[#4a9eb0]'
                      }
                    >
                      [{anom.severity.toUpperCase()}]
                    </span>
                    <span className="text-[#8c97a8]">{anom.category}</span>
                  </div>
                  <div className="text-xs font-medium text-[#e8ecf1]">{anom.title}</div>
                  <div className="text-[11px] text-[#8c97a8]">{anom.explanation}</div>
                </div>
                <span className="font-mono text-[10px] text-[#8fa36d] shrink-0">Inspect →</span>
              </button>
            ))
          )}
        </div>
      </div>
    );
  }

  // =========================================================================
  // 4. BEHAVIOURAL ANALYSIS (OPERATOR & DECISION TELEMETRY)
  // =========================================================================
  if (mode === 'behavioural_analysis') {
    const actionCounts = new Map<string, number>();
    for (const evt of intel.auditEvents) {
      actionCounts.set(evt.action, (actionCounts.get(evt.action) || 0) + 1);
    }

    const decisionStats = {
      confirmed: intel.matches.filter((m) => m.status === 'confirmed').length,
      rejected: intel.matches.filter((m) => m.status === 'rejected').length,
      pending: intel.matches.filter((m) => m.status === 'proposed').length,
    };

    return (
      <div className="flex-1 overflow-y-auto bg-[#0b0d10] p-4 space-y-4">
        <div className="bg-[#12151b] border border-[#252b36] p-4 flex items-center justify-between">
          <div>
            <div className="font-mono text-[10px] tracking-[0.12em] text-[#8fa36d]">
              AI & MACHINE LEARNING // OPERATOR & SYSTEM BEHAVIOUR
            </div>
            <h1 className="text-base font-semibold text-[#e8ecf1] mt-0.5 flex items-center gap-2">
              <BarChart3 className="w-4 h-4 text-[#4a9eb0]" />
              <span>Behavioural & Decision Pattern Analysis</span>
            </h1>
          </div>
          <span className="font-mono text-[10px] text-[#8c97a8]">DERIVED FROM AUDIT_EVENTS & ASSET_MATCHES</span>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <div className="bg-[#12151b] border border-[#252b36] p-4 space-y-3">
            <div className="font-mono text-xs font-semibold text-[#e8ecf1]">
              AUDIT LEDGER ACTION DISTRIBUTION (RECENT {intel.auditEvents.length} EVENTS)
            </div>
            <div className="space-y-2 font-mono text-[11px]">
              {Array.from(actionCounts.entries()).map(([action, count]) => (
                <div key={action} className="space-y-1">
                  <div className="flex justify-between">
                    <span className="text-[#e8ecf1]">{action}</span>
                    <span className="text-[#8fa36d] tabular-nums">{count}</span>
                  </div>
                  <div className="h-1.5 bg-[#0b0d10] border border-[#252b36]">
                    <div
                      className="h-full bg-[#6f8054]"
                      style={{
                        width: `${Math.min(100, (count / Math.max(intel.auditEvents.length, 1)) * 100)}%`,
                      }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="bg-[#12151b] border border-[#252b36] p-4 space-y-3">
            <div className="font-mono text-xs font-semibold text-[#e8ecf1]">
              ANALYST MATCH TRIAGE RATIO
            </div>
            <div className="grid grid-cols-3 gap-2 font-mono text-center">
              <div className="p-3 bg-[#0b0d10] border border-[#252b36]">
                <div className="text-[10px] text-[#8c97a8]">CONFIRMED</div>
                <div className="text-lg font-semibold text-[#4f8f66] tabular-nums">{decisionStats.confirmed}</div>
              </div>
              <div className="p-3 bg-[#0b0d10] border border-[#252b36]">
                <div className="text-[10px] text-[#8c97a8]">REJECTED</div>
                <div className="text-lg font-semibold text-[#c94a4a] tabular-nums">{decisionStats.rejected}</div>
              </div>
              <div className="p-3 bg-[#0b0d10] border border-[#252b36]">
                <div className="text-[10px] text-[#8c97a8]">PENDING</div>
                <div className="text-lg font-semibold text-[#c88b32] tabular-nums">{decisionStats.pending}</div>
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  // =========================================================================
  // 5. AI INTELLIGENCE ASSISTANT (GROUNDED DETERMINISTIC QUERY CONSOLE)
  // =========================================================================
  const handleAsk = (e: React.FormEvent) => {
    e.preventDefault();
    const q = prompt.trim();
    if (!q) return;
    const lower = q.toLowerCase();
    const facts: string[] = [];

    if (lower.includes('critical') || lower.includes('incident')) {
      const crits = intel.incidents.filter((i) => i.severity === 'critical' || i.severity === 'high');
      facts.push(
        `Database records ${intel.incidents.length} total incidents (${crits.length} critical/high).`
      );
      crits.slice(0, 5).forEach((i) => {
        facts.push(`• ${i.event_id} [${i.severity.toUpperCase()}]: ${i.event_type} (confidence ${(Number(i.confidence) * 100).toFixed(0)}%)`);
      });
    }

    if (lower.includes('match') || lower.includes('proposed') || lower.includes('review')) {
      const prop = intel.matches.filter((m) => m.status === 'proposed');
      facts.push(`There are ${prop.length} proposed asset matches awaiting analyst confirmation.`);
      prop.slice(0, 5).forEach((m) => {
        facts.push(`• Match ${m.id.slice(0, 8)} via ${m.rule_fired} (${(Number(m.score) * 100).toFixed(0)}%) -> ${m.asset?.site_code || m.asset_id}`);
      });
    }

    if (lower.includes('asset') || lower.includes('site') || lower.includes('approx') || lower.includes('tier')) {
      const t5 = intel.assets.filter((a) => a.criticality === 5);
      const approx = intel.assets.filter((a) => a.accuracy_class !== 'exact_survey');
      facts.push(
        `Workspace holds ${intel.assets.length} infrastructure assets (${t5.length} Tier-5; ${approx.length} with approximate spatial geometry).`
      );
    }

    if (lower.includes('evidence') || lower.includes('audit') || lower.includes('hash')) {
      facts.push(
        `Evidence vault holds ${intel.evidence.length} files. Cryptographic audit ledger contains ${intel.auditTotal} chained events.`
      );
    }

    // Direct token search across assets & incidents
    const tokens = lower.split(/\s+/).filter((t) => t.length >= 3);
    for (const tok of tokens) {
      const assetHit = intel.assets.find(
        (a) =>
          a.site_code.toLowerCase().includes(tok) ||
          a.name.toLowerCase().includes(tok) ||
          JSON.stringify(a.identifiers || {}).toLowerCase().includes(tok)
      );
      if (assetHit) {
        facts.push(
          `Matched asset "${assetHit.site_code} (${assetHit.name})": Tier ${assetHit.criticality}, ${assetHit.type}, accuracy=${assetHit.accuracy_class}.`
        );
      }
    }

    if (facts.length === 0) {
      facts.push(
        `Workspace summary: ${intel.assets.length} assets, ${intel.edges.length} dependency edges, ${intel.incidents.length} incidents, ${intel.matches.length} matches, ${intel.evidence.length} evidence items.`
      );
    }

    setHistory((prev) => [
      {
        id: `q-${Date.now()}`,
        query: q,
        facts,
        limitations:
          'Deterministic query engine over authorised Supabase workspace records. No external LLM/generative API is called; outputs reflect exact stored rows only.',
        timestamp: new Date().toISOString().slice(11, 19) + ' UTC',
      },
      ...prev,
    ]);
    setPrompt('');
  };

  return (
    <div className="flex-1 flex flex-col overflow-hidden bg-[#0b0d10]">
      <div className="px-4 py-2.5 border-b border-[#252b36] bg-[#12151b] flex items-center justify-between shrink-0">
        <div>
          <div className="font-mono text-[10px] tracking-[0.12em] text-[#8fa36d]">
            AI & MACHINE LEARNING // DETERMINISTIC DATA INTERROGATION
          </div>
          <h1 className="text-sm font-semibold text-[#e8ecf1] flex items-center gap-2">
            <Bot className="w-4 h-4 text-[#8fa36d]" />
            <span>AI Intelligence Assistant (Grounded Local Query Engine)</span>
          </h1>
        </div>
        <span className="font-mono text-[10px] text-[#4f8f66] border border-[#4f8f66]/40 bg-[#4f8f66]/10 px-2 py-0.5">
          ZERO EXTERNAL LLM CALLS · AUTHORISED RLS SCOPE ONLY
        </span>
      </div>

      <div className="p-4 border-b border-[#252b36] bg-[#0e1116] shrink-0">
        <form onSubmit={handleAsk} className="max-w-4xl flex gap-2">
          <input
            type="text"
            value={prompt}
            onChange={(e) => setPrompt(e.target.value)}
            placeholder="Query critical incidents, proposed matches, site codes, approximate assets, evidence..."
            className="flex-1 bg-[#0b0d10] border border-[#252b36] px-3 py-2 text-xs font-mono text-[#e8ecf1] focus:outline-none focus:border-[#6f8054]"
          />
          <button
            type="submit"
            className="px-4 py-2 bg-[#6f8054] hover:bg-[#7d905f] text-[#0b0d10] font-mono text-xs font-semibold flex items-center gap-1.5 cursor-pointer"
          >
            <Send className="w-3.5 h-3.5" />
            <span>Query DB</span>
          </button>
        </form>
        <div className="mt-2 flex flex-wrap gap-1.5 font-mono text-[10px]">
          {[
            'Summarize critical incidents',
            'Show proposed matches needing review',
            'Check Tier-5 and approximate assets',
            'Report evidence & audit chain status',
          ].map((preset) => (
            <button
              key={preset}
              onClick={() => setPrompt(preset)}
              className="px-2 py-0.5 bg-[#12151b] hover:bg-[#181c24] border border-[#252b36] text-[#8c97a8] hover:text-[#e8ecf1] cursor-pointer"
            >
              {preset}
            </button>
          ))}
        </div>
      </div>

      <div className="flex-1 overflow-y-auto p-4 space-y-3 max-w-4xl">
        {history.length === 0 ? (
          <div className="p-4 bg-[#12151b] border border-[#252b36] font-mono text-xs text-[#8c97a8] flex items-start gap-2">
            <Info className="w-4 h-4 text-[#4a9eb0] shrink-0 mt-0.5" />
            <span>
              Submit a query above to interrogate live workspace tables deterministically with exact record counts and explicit scope boundaries.
            </span>
          </div>
        ) : (
          history.map((turn) => (
            <div key={turn.id} className="bg-[#12151b] border border-[#252b36] p-3 space-y-2">
              <div className="flex items-center justify-between font-mono text-[11px]">
                <span className="text-[#8fa36d] font-semibold">QUERY: {turn.query}</span>
                <span className="text-[#5d6778]">{turn.timestamp}</span>
              </div>
              <div className="space-y-1 font-mono text-xs text-[#e8ecf1]">
                {turn.facts.map((f, i) => (
                  <div key={i}>{f}</div>
                ))}
              </div>
              <div className="border-t border-[#252b36] pt-1.5 font-mono text-[10px] text-[#8c97a8]">
                BOUNDARY: {turn.limitations}
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};
