/**
 * Project ATLAS: Blast Radius Screen (Stage 3)
 *
 * HARD RULES:
 * 1. Database-Authoritative: Calculates blast radius strictly via SQL function blast_radius(incident_id).
 * 2. Factors displayed:
 *    - c = criticality / 5.0
 *    - r = share of workspace's service assets reachable downstream
 *    - I = c * r
 *    - E (exposure) and L (likelihood) from scoring_config, labelled 'uncalibrated'
 *    - Priority = I * E * L
 *    - Displayed range [low, high] widened by match confidence and accuracy class
 *    - Point estimate is NEVER changed by uncertainty
 * 3. NO SINGLE HEADLINE NUMBER (Rule 59).
 * 4. Every row links to its evidence.
 */

import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { atlasService } from '../data/api';
import { Incident, BlastRadiusNode, AssetMatch } from '../types/atlas';
import {
  Flame,
  AlertTriangle,
  RefreshCw,
  GitCommit,
  Shield,
  ShieldAlert,
  ShieldCheck,
  ChevronRight,
  ExternalLink,
  HelpCircle,
  FileText,
  Activity,
  Layers,
  Search,
  X,
} from 'lucide-react';

interface BlastRadiusScreenProps {
  activeOrgId: string;
}

export const BlastRadiusScreen: React.FC<BlastRadiusScreenProps> = ({ activeOrgId }) => {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string>('');
  const [blastNodes, setBlastNodes] = useState<BlastRadiusNode[]>([]);
  const [matches, setMatches] = useState<AssetMatch[]>([]);

  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isCalculating, setIsCalculating] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  // Evidence Modal state
  const [selectedEvidenceNode, setSelectedEvidenceNode] = useState<BlastRadiusNode | null>(null);

  // 1. Fetch Incidents for the active workspace
  const loadIncidents = useCallback(async () => {
    if (!activeOrgId) return;

    setIsLoading(true);
    setError(null);

    try {
      const fetchedIncidents = await atlasService.fetchIncidents(activeOrgId);
      setIncidents(fetchedIncidents);

      if (fetchedIncidents.length > 0 && !selectedIncidentId) {
        setSelectedIncidentId(fetchedIncidents[0].id);
      }
    } catch (err: any) {
      setError(err.message || 'Error querying incidents.');
    } finally {
      setIsLoading(false);
    }
  }, [activeOrgId]);

  useEffect(() => {
    loadIncidents();
  }, [loadIncidents]);

  // 2. Fetch Blast Radius & Matches whenever an incident is selected
  const calculateBlastRadius = useCallback(async () => {
    if (!selectedIncidentId) return;

    setIsCalculating(true);
    setError(null);

    try {
      const [nodes, incidentMatches] = await Promise.all([
        atlasService.fetchBlastRadius(selectedIncidentId),
        atlasService.fetchIncidentMatches(activeOrgId, selectedIncidentId),
      ]);

      setBlastNodes(nodes);
      setMatches(incidentMatches);
    } catch (err: any) {
      setError(err.message || 'Failed to compute blast radius.');
    } finally {
      setIsCalculating(false);
    }
  }, [activeOrgId, selectedIncidentId]);

  useEffect(() => {
    calculateBlastRadius();
  }, [calculateBlastRadius]);

  const selectedIncident = useMemo(() => {
    return incidents.find((inc) => inc.id === selectedIncidentId);
  }, [incidents, selectedIncidentId]);

  return (
    <div className="max-w-7xl mx-auto px-6 py-8 space-y-8 select-none text-slate-100 antialiased font-sans">
      {/* Page Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <div className="flex items-center gap-2 font-mono text-xs text-rose-400 font-bold uppercase tracking-wider mb-1">
            <Flame className="w-3.5 h-3.5" />
            Stage 3 Deterministic Blast Radius
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-100">
            Consequence Propagation & Risk Factors
          </h1>
          <p className="text-xs text-slate-400 mt-1 max-w-3xl leading-relaxed">
            Deterministic blast radius computed by recursive traversal along directed dependency edges up to 6 hops deep. Impact propagates from provider to consumer. Weights and factors are labelled uncalibrated. Every affected asset links directly to intake evidence and match criteria.
          </p>
        </div>

        {/* Incident Selector */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-xs">
            <Activity className="w-3.5 h-3.5 text-rose-400" />
            <span className="font-mono text-slate-400">Incident:</span>
            <select
              value={selectedIncidentId}
              onChange={(e) => setSelectedIncidentId(e.target.value)}
              className="bg-slate-950 border border-slate-700 rounded px-2 py-1 text-slate-200 font-mono text-xs focus:outline-none focus:border-rose-500"
            >
              {incidents.length === 0 ? (
                <option value="">No incidents in workspace</option>
              ) : (
                incidents.map((inc) => (
                  <option key={inc.id} value={inc.id}>
                    [{inc.event_id}] {inc.event_type} ({inc.severity.toUpperCase()})
                  </option>
                ))
              )}
            </select>
          </div>

          <button
            onClick={calculateBlastRadius}
            disabled={isCalculating || !selectedIncidentId}
            className="p-2.5 bg-slate-900 hover:bg-slate-800 text-slate-300 rounded-xl border border-slate-800 transition cursor-pointer"
            title="Re-run deterministic blast radius query"
          >
            <RefreshCw className={`w-4 h-4 ${isCalculating ? 'animate-spin text-rose-400' : ''}`} />
          </button>
        </div>
      </div>

      {error && (
        <div className="p-4 bg-rose-950/80 border border-rose-800 rounded-xl text-rose-200 text-xs flex items-start gap-2 shadow-lg">
          <AlertTriangle className="w-4 h-4 shrink-0 text-rose-400 mt-0.5" />
          <div className="space-y-1">
            <div className="font-semibold">Blast Radius Computation Error</div>
            <p className="text-[11px] leading-relaxed font-mono">{error}</p>
          </div>
        </div>
      )}

      {/* Incident Intake Context & Root Matches Banner */}
      {selectedIncident && (
        <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-4 text-xs font-mono grid grid-cols-1 sm:grid-cols-4 gap-4 shadow-xl">
          <div>
            <div className="text-slate-500 text-[10px]">EVENT ID</div>
            <div className="font-bold text-slate-200 mt-0.5">{selectedIncident.event_id}</div>
          </div>
          <div>
            <div className="text-slate-500 text-[10px]">EVENT TYPE</div>
            <div className="text-slate-200 mt-0.5">{selectedIncident.event_type}</div>
          </div>
          <div>
            <div className="text-slate-500 text-[10px]">SEVERITY</div>
            <div className="mt-0.5">
              <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-rose-950 text-rose-300 border border-rose-800/80">
                {selectedIncident.severity}
              </span>
            </div>
          </div>
          <div>
            <div className="text-slate-500 text-[10px]">ACTIVE ROOT MATCHES</div>
            <div className="text-emerald-400 font-bold mt-0.5">
              {matches.filter((m) => m.status === 'auto' || m.status === 'confirmed').length} verified seeds
            </div>
          </div>
        </div>
      )}

      {/* Blast Radius Ranked Factor List (NO HEADLINE NUMBER) */}
      <div className="space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 px-1 text-xs font-mono">
          <div className="text-slate-300 font-semibold uppercase tracking-wider flex items-center gap-2">
            <span>AFFECTED ASSETS RANKED BY CONSEQUENCE FACTORS</span>
            <span className="text-[11px] font-normal text-slate-500">
              ({blastNodes.length} assets reached)
            </span>
          </div>

          <div className="flex items-center gap-2 text-[11px] text-amber-400 bg-amber-950/40 px-2.5 py-1 rounded border border-amber-900/50">
            <HelpCircle className="w-3.5 h-3.5" />
            <span>Weights & Scales: UNCALIBRATED (Multi-factor range analysis)</span>
          </div>
        </div>

        {blastNodes.length === 0 ? (
          <div className="p-12 text-center text-slate-500 bg-slate-900/40 border border-slate-800 rounded-2xl text-xs font-mono space-y-2">
            <GitCommit className="w-8 h-8 mx-auto text-slate-600 mb-2" />
            <div className="font-semibold text-slate-400">Zero Reachable Downstream Assets</div>
            <p className="max-w-md mx-auto text-[11px] leading-relaxed text-slate-500">
              Either this incident has no confirmed asset matches, or the matched root assets have no downstream dependency edges defined in this workspace.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto rounded-2xl border border-slate-800 bg-slate-900/50 shadow-2xl">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-950 text-slate-400 border-b border-slate-800 text-[11px]">
                <tr>
                  <th className="py-3 px-3">Rank</th>
                  <th className="py-3 px-3">Asset</th>
                  <th className="py-3 px-3">Hop</th>
                  <th className="py-3 px-3 text-center" title="Criticality factor (tier / 5.0)">
                    c
                  </th>
                  <th className="py-3 px-3 text-center" title="Share of workspace services reachable downstream">
                    r
                  </th>
                  <th className="py-3 px-3 text-center" title="Impact factor I = c * r">
                    I (c×r)
                  </th>
                  <th className="py-3 px-3 text-center text-amber-400" title="Exposure factor from scoring_config (uncalibrated)">
                    E <span className="text-[9px] text-amber-500/80">*</span>
                  </th>
                  <th className="py-3 px-3 text-center text-amber-400" title="Likelihood factor from scoring_config (uncalibrated)">
                    L <span className="text-[9px] text-amber-500/80">*</span>
                  </th>
                  <th className="py-3 px-3 text-center font-bold text-rose-300" title="Priority Point Estimate = I * E * L">
                    Priority
                  </th>
                  <th className="py-3 px-3 text-center" title="Uncertainty range [low, high] based on evidence confidence and accuracy class">
                    Range [Low, High]
                  </th>
                  <th className="py-3 px-3">Dependency Path</th>
                  <th className="py-3 px-3 text-right">Evidence</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800 text-slate-300">
                {blastNodes.map((node, index) => (
                  <tr key={node.asset_id} className="hover:bg-slate-800/40 transition">
                    {/* Rank */}
                    <td className="py-3 px-3 text-slate-500 font-bold">#{index + 1}</td>

                    {/* Asset Profile */}
                    <td className="py-3 px-3 min-w-[180px]">
                      <div className="font-bold text-slate-100 flex items-center gap-1.5">
                        <span className="text-cyan-400">{node.site_code}</span>
                        <span className="text-slate-400 font-normal truncate">{node.name}</span>
                      </div>
                      <div className="text-[10px] text-slate-500 flex items-center gap-1.5 mt-0.5">
                        <span className="uppercase">{node.type}</span>
                        <span>•</span>
                        {node.accuracy_class === 'exact_survey' ? (
                          <span className="text-emerald-400">exact</span>
                        ) : (
                          <span className="text-amber-400">approximate</span>
                        )}
                      </div>
                    </td>

                    {/* Hop Depth */}
                    <td className="py-3 px-3">
                      {node.hop_depth === 0 ? (
                        <span className="px-1.5 py-0.5 rounded text-[10px] bg-rose-950 text-rose-300 border border-rose-800 font-bold">
                          ROOT
                        </span>
                      ) : (
                        <span className="text-slate-400 font-mono">+{node.hop_depth} hops</span>
                      )}
                    </td>

                    {/* Factor c */}
                    <td className="py-3 px-3 text-center font-mono text-slate-300">
                      {node.c.toFixed(2)}
                    </td>

                    {/* Factor r */}
                    <td className="py-3 px-3 text-center font-mono text-slate-300">
                      {node.r.toFixed(2)}
                    </td>

                    {/* Impact I */}
                    <td className="py-3 px-3 text-center font-mono font-semibold text-cyan-300">
                      {node.i_factor.toFixed(3)}
                    </td>

                    {/* Exposure E */}
                    <td className="py-3 px-3 text-center font-mono text-amber-300">
                      {node.exposure.toFixed(2)}
                    </td>

                    {/* Likelihood L */}
                    <td className="py-3 px-3 text-center font-mono text-amber-300">
                      {node.likelihood.toFixed(2)}
                    </td>

                    {/* Priority Point Estimate */}
                    <td className="py-3 px-3 text-center font-mono font-bold text-rose-400 bg-rose-950/20">
                      {node.priority.toFixed(3)}
                    </td>

                    {/* Uncertainty Range */}
                    <td className="py-3 px-3 text-center min-w-[130px]">
                      <div className="font-mono text-[11px] text-slate-300">
                        [{node.range_low.toFixed(3)}, {node.range_high.toFixed(3)}]
                      </div>
                      <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden mt-1 flex">
                        <div
                          style={{
                            marginLeft: `${node.range_low * 100}%`,
                            width: `${Math.max(5, (node.range_high - node.range_low) * 100)}%`,
                          }}
                          className="bg-cyan-500 h-full rounded-full"
                        />
                      </div>
                    </td>

                    {/* Dependency Path */}
                    <td className="py-3 px-3 min-w-[220px]">
                      <div className="flex flex-wrap items-center gap-1 text-[10px]">
                        {node.path.map((p, i) => (
                          <React.Fragment key={i}>
                            {i > 0 && (
                              <span className="text-slate-500 font-bold">
                                → <span className="text-emerald-400">{p.relation_type}</span> →
                              </span>
                            )}
                            <span className="bg-slate-950 px-1.5 py-0.5 rounded border border-slate-800 text-slate-300">
                              {p.asset_id === node.root_asset_id ? 'root' : p.asset_id.slice(0, 8)}
                            </span>
                          </React.Fragment>
                        ))}
                      </div>
                    </td>

                    {/* Evidence Link */}
                    <td className="py-3 px-3 text-right">
                      <button
                        onClick={() => setSelectedEvidenceNode(node)}
                        className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-cyan-300 rounded text-[11px] transition cursor-pointer flex items-center gap-1 ml-auto"
                      >
                        <FileText className="w-3 h-3" />
                        <span>Evidence</span>
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Evidence Inspection Modal */}
      {selectedEvidenceNode && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-lg w-full p-6 shadow-2xl space-y-4 text-xs font-mono">
            <div className="flex items-start justify-between border-b border-slate-800 pb-3">
              <div>
                <div className="text-[10px] text-slate-500 uppercase">Intake Evidence Audit</div>
                <div className="text-sm font-bold text-slate-100 flex items-center gap-2 mt-0.5">
                  <span className="text-cyan-400">{selectedEvidenceNode.site_code}</span>
                  <span>{selectedEvidenceNode.name}</span>
                </div>
              </div>
              <button
                onClick={() => setSelectedEvidenceNode(null)}
                className="text-slate-400 hover:text-slate-100 p-1"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-3 bg-slate-950 p-4 rounded-xl border border-slate-800">
              <div className="text-slate-400 text-[11px] font-semibold">ROOT INCIDENT MATCH CRITERIA</div>

              <div className="grid grid-cols-2 gap-3 text-xs">
                <div>
                  <div className="text-slate-500 text-[10px]">MATCH STATUS</div>
                  <div className="text-emerald-400 font-bold uppercase mt-0.5">
                    {selectedEvidenceNode.match_status}
                  </div>
                </div>

                <div>
                  <div className="text-slate-500 text-[10px]">CONFIDENCE SCORE</div>
                  <div className="text-cyan-300 font-bold mt-0.5">
                    {(selectedEvidenceNode.match_confidence * 100).toFixed(1)}%
                  </div>
                </div>

                <div>
                  <div className="text-slate-500 text-[10px]">HOP DEPTH FROM ROOT</div>
                  <div className="text-slate-200 mt-0.5">
                    {selectedEvidenceNode.hop_depth} hops
                  </div>
                </div>

                <div>
                  <div className="text-slate-500 text-[10px]">ACCURACY CLASS</div>
                  <div className="text-slate-200 mt-0.5">
                    {selectedEvidenceNode.accuracy_class}
                  </div>
                </div>
              </div>
            </div>

            <div className="p-3 bg-slate-950/60 rounded-xl border border-slate-800 text-[11px] text-slate-400 space-y-1">
              <div>
                <span className="text-slate-500">ROOT ASSET ID:</span>{' '}
                <span className="text-slate-300">{selectedEvidenceNode.root_asset_id}</span>
              </div>
              <div>
                <span className="text-slate-500">MATCH RECORD ID:</span>{' '}
                <span className="text-slate-300">{selectedEvidenceNode.match_id}</span>
              </div>
              <div>
                <span className="text-slate-500">TARGET ASSET ID:</span>{' '}
                <span className="text-slate-300">{selectedEvidenceNode.asset_id}</span>
              </div>
            </div>

            <div className="pt-2 flex justify-end">
              <button
                onClick={() => setSelectedEvidenceNode(null)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs cursor-pointer"
              >
                Close Audit View
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
