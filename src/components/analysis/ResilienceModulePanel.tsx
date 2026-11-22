import React, { useEffect, useMemo, useState } from 'react';
import { SelectedEntity } from '../../types/atlas';
import { WorkspaceIntelligenceState } from '../../hooks/useWorkspaceIntelligence';
import {
  analyzeInfrastructureResilience,
  simulateNodeFailureCascade,
} from '../../utils/resilience';
import { AlertTriangle, Info, ShieldAlert, Zap, Network } from 'lucide-react';

interface ResilienceModulePanelProps {
  intel: WorkspaceIntelligenceState;
  onSelectEntity: (entity: SelectedEntity) => void;
}

export const ResilienceModulePanel: React.FC<ResilienceModulePanelProps> = ({
  intel,
  onSelectEntity,
}) => {
  const [cascadeFailedIds, setCascadeFailedIds] = useState<string[]>([]);
  const [profileFilter, setProfileFilter] = useState<'all' | 'spof' | 'exposed'>('all');

  // Reset simulated root selection cleanly if active workspace changes
  useEffect(() => {
    setCascadeFailedIds([]);
  }, [intel.orgId]);

  const resilienceProfiles = useMemo(
    () =>
      analyzeInfrastructureResilience(
        intel.assets,
        intel.edges,
        intel.assetCoordsMap,
        intel.matches
      ),
    [intel.assets, intel.edges, intel.assetCoordsMap, intel.matches]
  );

  const cascadeScenario = useMemo(
    () =>
      simulateNodeFailureCascade(
        cascadeFailedIds,
        intel.assets,
        intel.edges,
        intel.matches
      ),
    [cascadeFailedIds, intel.assets, intel.edges, intel.matches]
  );

  const toggleCascadeNode = (assetId: string) => {
    setCascadeFailedIds((prev) =>
      prev.includes(assetId) ? prev.filter((id) => id !== assetId) : [...prev, assetId]
    );
  };

  const spofCount = resilienceProfiles.filter((r) => r.isSinglePointOfFailure).length;
  const incidentExposedCount = resilienceProfiles.filter(
    (r) => r.activeIncidentExposureCount > 0
  ).length;
  const coLocatedAssetsCount = resilienceProfiles.filter(
    (r) => r.coLocatedCriticalCount > 0
  ).length;
  const maxVulnScore = resilienceProfiles[0]?.structuralVulnerabilityScore ?? 0;

  const visibleProfiles = useMemo(() => {
    if (profileFilter === 'spof') {
      return resilienceProfiles.filter((p) => p.isSinglePointOfFailure);
    }
    if (profileFilter === 'exposed') {
      return resilienceProfiles.filter((p) => p.activeIncidentExposureCount > 0);
    }
    return resilienceProfiles;
  }, [resilienceProfiles, profileFilter]);

  return (
    <div className="p-4 max-w-7xl mx-auto space-y-4">
      {/* Top Resilience Summary Strip */}
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-3 font-mono">
        <div className="bg-[#12151b] border border-[#252b36] p-3">
          <div className="text-[10px] text-[#8c97a8]">SINGLE POINTS OF FAILURE</div>
          <div className="text-lg font-semibold text-[#c94a4a] tabular-nums mt-0.5">
            {spofCount}
          </div>
          <div className="text-[10px] text-[#5d6778] mt-0.5">of {intel.assets.length} assets</div>
        </div>
        <div className="bg-[#12151b] border border-[#252b36] p-3">
          <div className="text-[10px] text-[#8c97a8]">INCIDENT-EXPOSED ASSETS</div>
          <div className="text-lg font-semibold text-[#c88b32] tabular-nums mt-0.5">
            {incidentExposedCount}
          </div>
          <div className="text-[10px] text-[#5d6778] mt-0.5">non-rejected matches</div>
        </div>
        <div className="bg-[#12151b] border border-[#252b36] p-3">
          <div className="text-[10px] text-[#8c97a8]">CO-LOCATED NODES (≤2KM)</div>
          <div className="text-lg font-semibold text-[#4a9eb0] tabular-nums mt-0.5">
            {coLocatedAssetsCount}
          </div>
          <div className="text-[10px] text-[#5d6778] mt-0.5">shared geographic risk</div>
        </div>
        <div className="bg-[#12151b] border border-[#252b36] p-3">
          <div className="text-[10px] text-[#8c97a8]">PEAK HEURISTIC SCORE</div>
          <div className="text-lg font-semibold text-[#e8ecf1] tabular-nums mt-0.5">
            {maxVulnScore}/100
          </div>
          <div className="text-[10px] text-[#5d6778] mt-0.5">structural index only</div>
        </div>
        <div className="bg-[#12151b] border border-[#c88b32]/40 p-3">
          <div className="text-[10px] text-[#8c97a8]">BACKUP / RECOVERY DATA</div>
          <div className="text-xs font-semibold text-[#c88b32] mt-1">NO_VERIFIED_DATA</div>
          <div className="text-[10px] text-[#8c97a8] font-sans mt-0.5">
            Generators, UPS, RTO/RPO unrecorded
          </div>
        </div>
      </div>

      {/* Heuristic & Missing Recovery Data Integrity Notice */}
      <div className="bg-[#12151b] border border-[#252b36] p-3 flex items-start gap-2.5 text-xs">
        <Info className="w-4 h-4 text-[#c88b32] shrink-0 mt-0.5" />
        <div className="space-y-1 text-[#8c97a8] leading-relaxed">
          <div className="font-mono text-[10px] font-semibold text-[#e8ecf1]">
            HEURISTIC STRUCTURAL MODEL &amp; MISSING RECOVERY DATA DISCLOSURE
          </div>
          <p>
            Structural exposure scores (0–100) are deterministic heuristics combining declared asset criticality, outbound dependency fan-out, SPOF detection, and non-rejected incident matches — <strong>not</strong> calibrated actuarial probabilities. Because the authorised schema does not record backup generators, UPS autonomy, circuit failover SLAs, RTO, or RPO targets, all assets explicitly report{' '}
            <code className="font-mono text-[#c88b32]">NO_VERIFIED_DATA</code> for recovery capability and cascading failure propagation assumes zero unverified failover.
          </p>
        </div>
      </div>

      {/* Multi-Node Cascading Failure Simulator */}
      <div className="bg-[#12151b] border border-[#252b36] p-4 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[#252b36] pb-2">
          <div>
            <div className="font-mono text-xs font-semibold text-[#e8ecf1] flex items-center gap-1.5">
              <AlertTriangle className="w-3.5 h-3.5 text-[#c88b32]" />
              <span>DETERMINISTIC CASCADING FAILURE SIMULATOR (DIRECTED BFS)</span>
            </div>
            <div className="text-[11px] text-[#8c97a8] mt-0.5">
              {cascadeScenario.methodologyNote}
            </div>
          </div>
          {cascadeFailedIds.length > 0 && (
            <button
              onClick={() => setCascadeFailedIds([])}
              className="px-2.5 py-1 bg-[#0b0d10] hover:bg-[#181c24] border border-[#252b36] font-mono text-[10px] text-[#c94a4a] cursor-pointer"
            >
              Clear Scenario ({cascadeFailedIds.length})
            </button>
          )}
        </div>

        {/* Root Node Selector */}
        <div className="flex flex-wrap gap-1.5 font-mono text-[10px]">
          <span className="text-[#8c97a8] py-1 mr-1">SELECT FAILED ROOT NODES:</span>
          {intel.assets.length === 0 ? (
            <span className="text-[#5d6778] py-1">No infrastructure assets imported in this workspace.</span>
          ) : (
            intel.assets.map((a) => {
              const active = cascadeFailedIds.includes(a.id);
              return (
                <button
                  key={a.id}
                  onClick={() => toggleCascadeNode(a.id)}
                  className={`px-2 py-1 border cursor-pointer ${
                    active
                      ? 'bg-[#c94a4a]/25 border-[#c94a4a] text-[#e8ecf1] font-semibold'
                      : 'bg-[#0b0d10] border-[#252b36] text-[#8c97a8] hover:text-[#e8ecf1]'
                  }`}
                >
                  {a.site_code} (T{a.criticality})
                </button>
              );
            })
          )}
        </div>

        {cascadeFailedIds.length > 0 && (
          <div className="space-y-3 pt-2 border-t border-[#1e242e]">
            <div className="grid grid-cols-2 md:grid-cols-5 gap-2 font-mono text-center">
              <div className="p-2 bg-[#0b0d10] border border-[#252b36]">
                <div className="text-[10px] text-[#8c97a8]">DIRECT DEPENDENTS</div>
                <div className="text-sm font-semibold text-[#e8ecf1] tabular-nums">
                  {cascadeScenario.directDependentsCount}
                </div>
              </div>
              <div className="p-2 bg-[#0b0d10] border border-[#252b36]">
                <div className="text-[10px] text-[#8c97a8]">TOTAL DOWNSTREAM OUTAGES</div>
                <div className="text-sm font-semibold text-[#c94a4a] tabular-nums">
                  {cascadeScenario.totalCascadingOutageCount}
                </div>
              </div>
              <div className="p-2 bg-[#0b0d10] border border-[#252b36]">
                <div className="text-[10px] text-[#8c97a8] flex items-center justify-center gap-1">
                  <Zap className="w-3 h-3 text-[#c88b32]" />
                  <span>POWER CASCADE</span>
                </div>
                <div className="text-sm font-semibold text-[#c88b32] tabular-nums">
                  {cascadeScenario.powerCascadeCount}
                </div>
              </div>
              <div className="p-2 bg-[#0b0d10] border border-[#252b36]">
                <div className="text-[10px] text-[#8c97a8] flex items-center justify-center gap-1">
                  <Network className="w-3 h-3 text-[#4a9eb0]" />
                  <span>TELECOM CASCADE</span>
                </div>
                <div className="text-sm font-semibold text-[#4a9eb0] tabular-nums">
                  {cascadeScenario.telecomCascadeCount}
                </div>
              </div>
              <div className="p-2 bg-[#0b0d10] border border-[#252b36]">
                <div className="text-[10px] text-[#8c97a8]">TIER 4–5 AFFECTED</div>
                <div className="text-sm font-semibold text-[#c94a4a] tabular-nums">
                  {cascadeScenario.tier4PlusAffectedCount}
                </div>
              </div>
            </div>

            {cascadeScenario.affectedAssets.length === 0 ? (
              <div className="p-3 bg-[#0b0d10] border border-[#252b36] font-mono text-xs text-[#4f8f66]">
                Selected root asset(s) have zero documented downstream dependents in public.dependency_edges.
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left font-mono text-[11px] border-collapse">
                  <thead className="bg-[#0e1116] border-b border-[#252b36] text-[#8c97a8] text-[10px]">
                    <tr>
                      <th className="py-1.5 px-3">HOP</th>
                      <th className="py-1.5 px-2">IMPACTED ASSET</th>
                      <th className="py-1.5 px-2">TYPE</th>
                      <th className="py-1.5 px-2">PROPAGATION EDGE</th>
                      <th className="py-1.5 px-2 text-right">TIER</th>
                      <th className="py-1.5 px-2 text-right">LINKED INCIDENTS</th>
                      <th className="py-1.5 px-3 text-right">RECOVERY DATA</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#181c24]">
                    {cascadeScenario.affectedAssets.map((imp) => (
                      <tr
                        key={imp.assetId}
                        onClick={() => onSelectEntity({ kind: 'asset', id: imp.assetId })}
                        className="hover:bg-[#181c24] cursor-pointer"
                      >
                        <td className="py-1.5 px-3 text-[#c88b32] tabular-nums">H+{imp.hopDepth}</td>
                        <td className="py-1.5 px-2 text-[#e8ecf1]">
                          <span className="text-[#4a9eb0] font-semibold">{imp.siteCode}</span> · {imp.name}
                        </td>
                        <td className="py-1.5 px-2 text-[#8c97a8]">{imp.type}</td>
                        <td className="py-1.5 px-2 text-[#5682b0]">{imp.viaRelation.toUpperCase()}</td>
                        <td className="py-1.5 px-2 text-right tabular-nums text-[#e8ecf1]">T{imp.criticality}</td>
                        <td className="py-1.5 px-2 text-right tabular-nums text-[#c94a4a]">{imp.activeIncidents}</td>
                        <td className="py-1.5 px-3 text-right text-[#c88b32]">NO_VERIFIED_DATA</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Infrastructure Resilience & SPOF Audit Table */}
      <div className="bg-[#12151b] border border-[#252b36]">
        <div className="px-3 py-2 border-b border-[#252b36] font-mono text-[11px] font-semibold text-[#e8ecf1] flex flex-wrap items-center justify-between gap-2">
          <span className="flex items-center gap-1.5">
            <ShieldAlert className="w-3.5 h-3.5 text-[#c88b32]" />
            <span>
              INFRASTRUCTURE RESILIENCE &amp; SPOF AUDIT MATRIX ({visibleProfiles.length} OF {resilienceProfiles.length} ASSETS)
            </span>
          </span>
          <div className="flex items-center gap-1 text-[10px]">
            {(
              [
                ['all', `All (${resilienceProfiles.length})`],
                ['spof', `SPOF Only (${spofCount})`],
                ['exposed', `Incident Exposed (${incidentExposedCount})`],
              ] as const
            ).map(([fid, label]) => (
              <button
                key={fid}
                onClick={() => setProfileFilter(fid)}
                className={`px-2 py-0.5 border cursor-pointer ${
                  profileFilter === fid
                    ? 'bg-[#6f8054]/25 border-[#6f8054] text-[#e8ecf1]'
                    : 'bg-[#0b0d10] border-[#252b36] text-[#8c97a8] hover:text-[#e8ecf1]'
                }`}
              >
                {label}
              </button>
            ))}
          </div>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono text-[11px] border-collapse">
            <thead className="bg-[#0e1116] border-b border-[#252b36] text-[#8c97a8] text-[10px]">
              <tr>
                <th className="py-1.5 px-3">SITE CODE</th>
                <th className="py-1.5 px-2">ASSET</th>
                <th className="py-1.5 px-2 text-right" title="Upstream Power / Telecom / Other dependencies">
                  UP (PWR/TEL/OTH)
                </th>
                <th className="py-1.5 px-2 text-right">DOWNSTREAM</th>
                <th className="py-1.5 px-2 text-right">CO-LOC (≤2KM)</th>
                <th className="py-1.5 px-2 text-right">INCIDENTS</th>
                <th className="py-1.5 px-2">SPOF FINDING</th>
                <th className="py-1.5 px-2">BACKUP / RTO</th>
                <th className="py-1.5 px-2 text-right" title="Heuristic Structural Exposure Index (0-100)">
                  HEURISTIC
                </th>
                <th className="py-1.5 px-3 text-right">SCENARIO</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#181c24]">
              {visibleProfiles.length === 0 ? (
                <tr>
                  <td colSpan={10} className="py-6 text-center text-[#8c97a8] font-sans">
                    No assets match the selected resilience audit filter.
                  </td>
                </tr>
              ) : (
                visibleProfiles.map((prof) => {
                  const inScenario = cascadeFailedIds.includes(prof.assetId);
                  return (
                    <tr key={prof.assetId} className="hover:bg-[#181c24]">
                      <td className="py-1.5 px-3">
                        <button
                          onClick={() => onSelectEntity({ kind: 'asset', id: prof.assetId })}
                          className="text-[#4a9eb0] font-semibold hover:underline cursor-pointer"
                        >
                          {prof.siteCode}
                        </button>
                      </td>
                      <td className="py-1.5 px-2 text-[#e8ecf1] font-sans">
                        <div>{prof.name}</div>
                        <div className="font-mono text-[10px] text-[#8c97a8]">
                          T{prof.criticality} · {prof.type} · {prof.accuracyClass}
                        </div>
                      </td>
                      <td className="py-1.5 px-2 text-right tabular-nums text-[#8c97a8]">
                        {prof.powerUpstreamCount}/{prof.telecomUpstreamCount}/{prof.otherUpstreamCount}
                      </td>
                      <td className="py-1.5 px-2 text-right tabular-nums text-[#c88b32]">
                        {prof.downstreamDependentCount}
                      </td>
                      <td className="py-1.5 px-2 text-right tabular-nums text-[#e8ecf1]">
                        {prof.coLocatedCriticalCount}
                      </td>
                      <td className="py-1.5 px-2 text-right tabular-nums">
                        <span
                          className={
                            prof.activeIncidentExposureCount > 0
                              ? 'text-[#c94a4a] font-semibold'
                              : 'text-[#5d6778]'
                          }
                        >
                          {prof.activeIncidentExposureCount}
                        </span>
                      </td>
                      <td className="py-1.5 px-2 max-w-[240px]">
                        {prof.isSinglePointOfFailure ? (
                          <div className="text-[#c94a4a] text-[10px]">
                            <strong>SPOF:</strong> {prof.spofReason}
                          </div>
                        ) : (
                          <span className="text-[#4f8f66] text-[10px]">No structural SPOF flagged</span>
                        )}
                      </td>
                      <td className="py-1.5 px-2 text-[10px] text-[#c88b32]">
                        {prof.backupRecoveryStatus}
                      </td>
                      <td className="py-1.5 px-2 text-right tabular-nums font-semibold text-[#e8ecf1]">
                        {prof.structuralVulnerabilityScore}
                      </td>
                      <td className="py-1.5 px-3 text-right">
                        <button
                          onClick={() => toggleCascadeNode(prof.assetId)}
                          className={`px-2 py-0.5 border text-[10px] cursor-pointer ${
                            inScenario
                              ? 'bg-[#c94a4a]/25 border-[#c94a4a] text-[#e8ecf1]'
                              : 'bg-[#0b0d10] border-[#252b36] text-[#8c97a8] hover:text-[#e8ecf1]'
                          }`}
                        >
                          {inScenario ? 'Remove Root' : 'Simulate Fail'}
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
