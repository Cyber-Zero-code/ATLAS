import React, { useMemo } from 'react';
import { ModuleId, SelectedEntity } from '../../types/atlas';
import { WorkspaceIntelligenceState } from '../../hooks/useWorkspaceIntelligence';
import {
  X,
  MapPin,
  ShieldAlert,
  CheckCircle2,
  GitFork,
  Radio,
  FileCheck,
  Share2,
  Flame,
  Crosshair,
  Server,
  Clock,
  ExternalLink,
} from 'lucide-react';

interface IntelligenceDossierPanelProps {
  selectedEntity: SelectedEntity;
  intel: WorkspaceIntelligenceState;
  onSelectEntity: (entity: SelectedEntity) => void;
  onNavigateModule: (module: ModuleId) => void;
  onClose?: () => void;
  onCenterCoordinate?: (lngLat: [number, number]) => void;
}

export const IntelligenceDossierPanel: React.FC<IntelligenceDossierPanelProps> = ({
  selectedEntity,
  intel,
  onSelectEntity,
  onNavigateModule,
  onClose,
  onCenterCoordinate,
}) => {
  const asset = useMemo(() => {
    if (selectedEntity?.kind !== 'asset') return null;
    return intel.assets.find((a) => a.id === selectedEntity.id) || null;
  }, [selectedEntity, intel.assets]);

  const incident = useMemo(() => {
    if (selectedEntity?.kind !== 'incident') return null;
    return intel.incidents.find((i) => i.id === selectedEntity.id) || null;
  }, [selectedEntity, intel.incidents]);

  const evidenceItem = useMemo(() => {
    if (selectedEntity?.kind !== 'evidence') return null;
    return intel.evidence.find((e) => e.id === selectedEntity.id) || null;
  }, [selectedEntity, intel.evidence]);

  // Empty state when nothing is selected
  if (!selectedEntity || (!asset && !incident && !evidenceItem && selectedEntity.kind !== 'indicator')) {
    return (
      <div className="h-full flex flex-col bg-[#12151b] text-[#e8ecf1] select-none">
        <div className="px-3 py-2 border-b border-[#252b36] flex items-center justify-between">
          <span className="font-mono text-[10px] tracking-[0.12em] text-[#8c97a8] font-semibold">
            INTELLIGENCE PROFILE
          </span>
          {onClose && (
            <button
              onClick={onClose}
              className="text-[#8c97a8] hover:text-[#e8ecf1] p-0.5 cursor-pointer"
              aria-label="Collapse profile panel"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
        <div className="p-4 text-xs text-[#8c97a8] space-y-3">
          <p className="leading-relaxed">
            Select an infrastructure asset on the map, an incident event, or a graph node to inspect its full cyber-physical intelligence dossier.
          </p>
          <div className="border-t border-[#252b36] pt-3 space-y-1.5 font-mono text-[11px]">
            <div className="text-[#e8ecf1] font-semibold">Quick Select</div>
            {intel.incidents.slice(0, 3).map((inc) => (
              <button
                key={inc.id}
                onClick={() => onSelectEntity({ kind: 'incident', id: inc.id })}
                className="w-full text-left px-2 py-1.5 bg-[#0b0d10] hover:bg-[#181c24] border border-[#252b36] rounded-[2px] flex items-center justify-between cursor-pointer"
              >
                <span className="truncate text-[#e8ecf1]">{inc.event_id}</span>
                <span
                  className={
                    inc.severity === 'critical'
                      ? 'text-[#c94a4a]'
                      : inc.severity === 'high'
                      ? 'text-[#c88b32]'
                      : 'text-[#8c97a8]'
                  }
                >
                  {inc.severity.toUpperCase()}
                </span>
              </button>
            ))}
            {intel.assets.slice(0, 3).map((a) => (
              <button
                key={a.id}
                onClick={() => onSelectEntity({ kind: 'asset', id: a.id })}
                className="w-full text-left px-2 py-1.5 bg-[#0b0d10] hover:bg-[#181c24] border border-[#252b36] rounded-[2px] flex items-center justify-between cursor-pointer"
              >
                <span className="truncate text-[#e8ecf1]">{a.site_code} · {a.name}</span>
                <span className="text-[#4a9eb0]">T{a.criticality}</span>
              </button>
            ))}
          </div>
        </div>
      </div>
    );
  }

  // Render ASSET dossier
  if (asset) {
    const coord = intel.assetCoordsMap.get(asset.id);
    const isApprox = asset.accuracy_class !== 'exact_survey';
    const upstream = intel.edges.filter((e) => e.to_asset_id === asset.id);
    const downstream = intel.edges.filter((e) => e.from_asset_id === asset.id);
    const relatedMatches = intel.matches.filter((m) => m.asset_id === asset.id);
    const relatedAudit = intel.auditEvents.filter(
      (evt) => evt.target_id === asset.id || JSON.stringify(evt.details || {}).includes(asset.id)
    );
    const relatedEvidence = intel.evidence.filter((ev) => ev.target_id === asset.id);

    const riskLabel =
      relatedMatches.some((m) => m.status === 'confirmed' || m.status === 'auto')
        ? 'EXPOSED — ACTIVE INCIDENT LINK'
        : asset.criticality >= 4
        ? 'HIGH CRITICALITY INFRASTRUCTURE'
        : 'MONITORED INFRASTRUCTURE';

    return (
      <div className="h-full flex flex-col bg-[#12151b] text-[#e8ecf1] overflow-hidden">
        <div className="px-3 py-2 border-b border-[#252b36] flex items-center justify-between shrink-0 bg-[#0e1116]">
          <div className="flex items-center gap-1.5 min-w-0">
            <Server className="w-3.5 h-3.5 text-[#4a9eb0] shrink-0" />
            <span className="font-mono text-[10px] tracking-[0.12em] text-[#8c97a8] truncate">
              ASSET DOSSIER · {asset.site_code}
            </span>
          </div>
          {onClose && (
            <button
              onClick={onClose}
              className="text-[#8c97a8] hover:text-[#e8ecf1] p-0.5 cursor-pointer"
              aria-label="Close dossier"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          )}
        </div>

        <div className="flex-1 overflow-y-auto p-3 space-y-3 text-xs">
          {/* Primary Identity */}
          <div>
            <h3 className="text-sm font-semibold text-[#e8ecf1] leading-snug">{asset.name}</h3>
            <div className="mt-1 flex flex-wrap items-center gap-1.5 font-mono text-[11px] text-[#8c97a8]">
              <span>{asset.type.replace('_', ' ')}</span>
              <span>·</span>
              <span>Owner: {asset.owner}</span>
              <span>·</span>
              <span className="text-[#c94a4a] font-semibold">Tier {asset.criticality}/5</span>
            </div>
          </div>

          {/* Action Bar */}
          <div className="grid grid-cols-2 gap-1.5 font-mono text-[11px]">
            {coord && onCenterCoordinate && (
              <button
                onClick={() => onCenterCoordinate(coord)}
                className="px-2 py-1 bg-[#181c24] hover:bg-[#222834] border border-[#252b36] text-[#e8ecf1] rounded-[2px] flex items-center justify-center gap-1 cursor-pointer"
              >
                <Crosshair className="w-3 h-3 text-[#4a9eb0]" />
                <span>Locate Map</span>
              </button>
            )}
            <button
              onClick={() => onNavigateModule('relationship_graph')}
              className="px-2 py-1 bg-[#181c24] hover:bg-[#222834] border border-[#252b36] text-[#e8ecf1] rounded-[2px] flex items-center justify-center gap-1 cursor-pointer"
            >
              <Share2 className="w-3 h-3 text-[#8fa36d]" />
              <span>Open Graph</span>
            </button>
          </div>

          {/* Coordinates & Spatial Confidence */}
          <div className="border-t border-[#252b36] pt-2.5 space-y-1.5">
            <div className="font-mono text-[10px] tracking-[0.1em] text-[#8c97a8]">
              GEOSPATIAL & ACCURACY
            </div>
            <div className="grid grid-cols-2 gap-2 font-mono text-[11px]">
              <div>
                <div className="text-[#5d6778] text-[10px]">COORDINATES (WGS84)</div>
                <div className="text-[#e8ecf1] tabular-nums">
                  {coord ? `${coord[1].toFixed(5)}, ${coord[0].toFixed(5)}` : 'Geometry unavailable'}
                </div>
              </div>
              <div>
                <div className="text-[#5d6778] text-[10px]">CONFIDENCE</div>
                <div className="text-[#4f8f66] font-semibold tabular-nums">
                  {(Number(asset.confidence) * 100).toFixed(0)}%
                </div>
              </div>
            </div>
            <div
              className={`px-2 py-1.5 border rounded-[2px] text-[11px] font-mono flex items-start gap-1.5 ${
                isApprox
                  ? 'bg-[#c88b32]/10 border-[#c88b32]/40 text-[#c88b32]'
                  : 'bg-[#4f8f66]/10 border-[#4f8f66]/40 text-[#4f8f66]'
              }`}
            >
              {isApprox ? (
                <ShieldAlert className="w-3.5 h-3.5 shrink-0 mt-0.5" />
              ) : (
                <CheckCircle2 className="w-3.5 h-3.5 shrink-0 mt-0.5" />
              )}
              <div>
                <div className="font-semibold">
                  {isApprox ? `APPROXIMATE (${asset.accuracy_class})` : 'EXACT SURVEY'}
                </div>
                {asset.positional_accuracy_m && (
                  <div className="text-[10px] opacity-90">
                    Uncertainty radius: ±{asset.positional_accuracy_m} m
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Risk Classification */}
          <div className="border-t border-[#252b36] pt-2.5 space-y-1">
            <div className="font-mono text-[10px] tracking-[0.1em] text-[#8c97a8]">
              RISK CLASSIFICATION
            </div>
            <div className="font-mono text-[11px] text-[#c88b32] font-medium">{riskLabel}</div>
          </div>

          {/* Cybersecurity Exposure / Identifiers */}
          <div className="border-t border-[#252b36] pt-2.5 space-y-1.5">
            <div className="font-mono text-[10px] tracking-[0.1em] text-[#8c97a8]">
              CYBERSECURITY EXPOSURE & IDENTIFIERS
            </div>
            {!asset.identifiers?.hostnames?.length &&
            !asset.identifiers?.ip_addresses?.length &&
            !asset.identifiers?.cidrs?.length &&
            !asset.identifiers?.cloud_account_ids?.length ? (
              <div className="text-[11px] text-[#5d6778] italic">No cyber identifiers linked.</div>
            ) : (
              <div className="space-y-1 font-mono text-[11px]">
                {asset.identifiers?.hostnames?.map((h) => (
                  <div key={h} className="text-[#4a9eb0] truncate">
                    HOST: {h}
                  </div>
                ))}
                {asset.identifiers?.ip_addresses?.map((ip) => (
                  <div key={ip} className="text-[#4f8f66] truncate">
                    IP: {ip}
                  </div>
                ))}
                {asset.identifiers?.cidrs?.map((c) => (
                  <div key={c} className="text-[#c88b32] truncate">
                    CIDR: {c}
                  </div>
                ))}
                {asset.identifiers?.cloud_account_ids?.map((cid) => (
                  <div key={cid} className="text-[#5682b0] truncate">
                    CLOUD: {cid}
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Connected Infrastructure */}
          <div className="border-t border-[#252b36] pt-2.5 space-y-1.5">
            <div className="font-mono text-[10px] tracking-[0.1em] text-[#8c97a8] flex items-center justify-between">
              <span>ASSOCIATED INFRASTRUCTURE ({upstream.length + downstream.length})</span>
              <button
                onClick={() => onNavigateModule('network_analysis')}
                className="text-[#8fa36d] hover:underline cursor-pointer"
              >
                Edit
              </button>
            </div>
            {upstream.length === 0 && downstream.length === 0 ? (
              <div className="text-[11px] text-[#5d6778]">No recorded dependency edges.</div>
            ) : (
              <div className="space-y-1 font-mono text-[11px]">
                {upstream.map((edge) => {
                  const prov = intel.assets.find((a) => a.id === edge.from_asset_id);
                  return (
                    <button
                      key={edge.id}
                      onClick={() => onSelectEntity({ kind: 'asset', id: edge.from_asset_id })}
                      className="w-full text-left px-2 py-1 bg-[#0b0d10] hover:bg-[#181c24] border border-[#252b36] flex items-center justify-between cursor-pointer"
                    >
                      <span className="truncate text-[#8c97a8]">
                        ← {edge.relation_type} from <strong className="text-[#e8ecf1]">{prov?.site_code || edge.from_asset_id.slice(0, 6)}</strong>
                      </span>
                      <span className="text-[#5d6778]">T{edge.criticality}</span>
                    </button>
                  );
                })}
                {downstream.map((edge) => {
                  const cons = intel.assets.find((a) => a.id === edge.to_asset_id);
                  return (
                    <button
                      key={edge.id}
                      onClick={() => onSelectEntity({ kind: 'asset', id: edge.to_asset_id })}
                      className="w-full text-left px-2 py-1 bg-[#0b0d10] hover:bg-[#181c24] border border-[#252b36] flex items-center justify-between cursor-pointer"
                    >
                      <span className="truncate text-[#8c97a8]">
                        → {edge.relation_type} <strong className="text-[#e8ecf1]">{cons?.site_code || edge.to_asset_id.slice(0, 6)}</strong>
                      </span>
                      <span className="text-[#5d6778]">T{edge.criticality}</span>
                    </button>
                  );
                })}
              </div>
            )}
          </div>

          {/* Related Incidents */}
          <div className="border-t border-[#252b36] pt-2.5 space-y-1.5">
            <div className="font-mono text-[10px] tracking-[0.1em] text-[#8c97a8]">
              RELATED INCIDENTS & MATCHES ({relatedMatches.length})
            </div>
            {relatedMatches.length === 0 ? (
              <div className="text-[11px] text-[#5d6778]">No correlated cyber incidents.</div>
            ) : (
              <div className="space-y-1 font-mono text-[11px]">
                {relatedMatches.map((m) => {
                  const inc = intel.incidents.find((i) => i.id === m.incident_id);
                  return (
                    <button
                      key={m.id}
                      onClick={() => onSelectEntity({ kind: 'incident', id: m.incident_id })}
                      className="w-full text-left px-2 py-1 bg-[#0b0d10] hover:bg-[#181c24] border border-[#252b36] flex items-center justify-between cursor-pointer"
                    >
                      <span className="truncate text-[#e8ecf1]">
                        {inc?.event_id || m.incident_id.slice(0, 8)} · {m.rule_fired}
                      </span>
                      <span
                        className={
                          m.status === 'confirmed' || m.status === 'auto'
                            ? 'text-[#4f8f66]'
                            : m.status === 'proposed'
                            ? 'text-[#c88b32]'
                            : 'text-[#8c97a8]'
                        }
                      >
                        {m.status.toUpperCase()} ({(Number(m.score) * 100).toFixed(0)}%)
                      </span>
                    </button>
                  );
                })}
              </div>
            )}
          </div>

          {/* Historical Activity & Evidence */}
          <div className="border-t border-[#252b36] pt-2.5 space-y-1.5">
            <div className="font-mono text-[10px] tracking-[0.1em] text-[#8c97a8]">
              HISTORICAL ACTIVITY & EVIDENCE ({relatedAudit.length + relatedEvidence.length})
            </div>
            <div className="space-y-1 font-mono text-[10px] text-[#8c97a8]">
              <div>Source: {asset.source}</div>
              <div>Registered: {new Date(asset.created_at).toISOString().slice(0, 19).replace('T', ' ')} UTC</div>
              {relatedAudit.slice(0, 4).map((evt) => (
                <div key={evt.id} className="truncate text-[#8c97a8]">
                  #{evt.seq} {evt.action} · {evt.timestamp_text?.slice(0, 19) || evt.timestamp.slice(0, 19)}
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    );
  }

  // Render INCIDENT dossier
  if (incident) {
    const incMatches = intel.matches.filter((m) => m.incident_id === incident.id);
    const incEvidence = intel.evidence.filter((e) => e.target_id === incident.id);
    const incAudit = intel.auditEvents.filter(
      (evt) => evt.target_id === incident.id || JSON.stringify(evt.details || {}).includes(incident.id)
    );

    return (
      <div className="h-full flex flex-col bg-[#12151b] text-[#e8ecf1] overflow-hidden">
        <div className="px-3 py-2 border-b border-[#252b36] flex items-center justify-between shrink-0 bg-[#0e1116]">
          <div className="flex items-center gap-1.5 min-w-0">
            <Radio className="w-3.5 h-3.5 text-[#c94a4a] shrink-0" />
            <span className="font-mono text-[10px] tracking-[0.12em] text-[#8c97a8] truncate">
              INCIDENT DOSSIER · {incident.event_id}
            </span>
          </div>
          {onClose && (
            <button
              onClick={onClose}
              className="text-[#8c97a8] hover:text-[#e8ecf1] p-0.5 cursor-pointer"
              aria-label="Close dossier"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          )}
        </div>

        <div className="flex-1 overflow-y-auto p-3 space-y-3 text-xs">
          <div>
            <h3 className="text-sm font-semibold text-[#e8ecf1]">{incident.event_type}</h3>
            <div className="mt-1 flex flex-wrap items-center gap-1.5 font-mono text-[11px] text-[#8c97a8]">
              <span
                className={
                  incident.severity === 'critical'
                    ? 'text-[#c94a4a] font-semibold'
                    : incident.severity === 'high'
                    ? 'text-[#c88b32] font-semibold'
                    : 'text-[#e8ecf1]'
                }
              >
                {incident.severity.toUpperCase()}
              </span>
              <span>·</span>
              <span>Confidence {(Number(incident.confidence) * 100).toFixed(0)}%</span>
              <span>·</span>
              <span>{incident.source}</span>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-1.5 font-mono text-[11px]">
            <button
              onClick={() => onNavigateModule('geospatial_correlation')}
              className="px-2 py-1 bg-[#181c24] hover:bg-[#222834] border border-[#252b36] text-[#e8ecf1] rounded-[2px] flex items-center justify-center gap-1 cursor-pointer"
            >
              <Flame className="w-3 h-3 text-[#c88b32]" />
              <span>Blast Radius</span>
            </button>
            <button
              onClick={() => onNavigateModule('cyber_incidents')}
              className="px-2 py-1 bg-[#181c24] hover:bg-[#222834] border border-[#252b36] text-[#e8ecf1] rounded-[2px] flex items-center justify-center gap-1 cursor-pointer"
            >
              <ExternalLink className="w-3 h-3 text-[#8fa36d]" />
              <span>SOC Case</span>
            </button>
          </div>

          {/* Connected Assets */}
          <div className="border-t border-[#252b36] pt-2.5 space-y-1.5">
            <div className="font-mono text-[10px] tracking-[0.1em] text-[#8c97a8]">
              CORRELATED PHYSICAL ASSETS ({incMatches.length})
            </div>
            {incMatches.length === 0 ? (
              <div className="text-[11px] text-[#5d6778]">No matched assets recorded.</div>
            ) : (
              <div className="space-y-1 font-mono text-[11px]">
                {incMatches.map((m) => (
                  <button
                    key={m.id}
                    onClick={() => onSelectEntity({ kind: 'asset', id: m.asset_id })}
                    className="w-full text-left px-2 py-1 bg-[#0b0d10] hover:bg-[#181c24] border border-[#252b36] flex items-center justify-between cursor-pointer"
                  >
                    <span className="truncate text-[#e8ecf1]">
                      {m.asset?.site_code || m.asset_id.slice(0, 8)} · {m.asset?.name || m.rule_fired}
                    </span>
                    <span
                      className={
                        m.status === 'confirmed' || m.status === 'auto'
                          ? 'text-[#4f8f66]'
                          : m.status === 'proposed'
                          ? 'text-[#c88b32]'
                          : 'text-[#8c97a8]'
                      }
                    >
                      {m.status.toUpperCase()}
                    </span>
                  </button>
                ))}
              </div>
            )}
          </div>

          {/* Telemetry Signals */}
          <div className="border-t border-[#252b36] pt-2.5 space-y-1.5">
            <div className="font-mono text-[10px] tracking-[0.1em] text-[#8c97a8]">
              OBSERVED TELEMETRY SIGNALS
            </div>
            <pre className="p-2 bg-[#0b0d10] border border-[#252b36] font-mono text-[10px] text-[#8c97a8] overflow-x-auto">
              {JSON.stringify(incident.signals || {}, null, 2)}
            </pre>
          </div>

          {/* Evidence & Audit */}
          <div className="border-t border-[#252b36] pt-2.5 space-y-1 font-mono text-[10px] text-[#8c97a8]">
            <div>Observed: {new Date(incident.observed_at).toISOString().replace('T', ' ').slice(0, 19)} UTC</div>
            <div>Evidence Files: {incEvidence.length}</div>
            <div>Audit Events Linked: {incAudit.length}</div>
          </div>
        </div>
      </div>
    );
  }

  // Render EVIDENCE dossier
  if (evidenceItem) {
    return (
      <div className="h-full flex flex-col bg-[#12151b] text-[#e8ecf1] overflow-hidden">
        <div className="px-3 py-2 border-b border-[#252b36] flex items-center justify-between shrink-0 bg-[#0e1116]">
          <div className="flex items-center gap-1.5 min-w-0">
            <FileCheck className="w-3.5 h-3.5 text-[#8fa36d] shrink-0" />
            <span className="font-mono text-[10px] tracking-[0.12em] text-[#8c97a8] truncate">
              EVIDENCE CUSTODY DOSSIER
            </span>
          </div>
          {onClose && (
            <button onClick={onClose} className="text-[#8c97a8] hover:text-[#e8ecf1] p-0.5 cursor-pointer">
              <X className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
        <div className="flex-1 overflow-y-auto p-3 space-y-3 text-xs font-mono">
          <div className="text-sm font-sans font-semibold text-[#e8ecf1] break-all">{evidenceItem.file_name}</div>
          <div className="text-[11px] text-[#8c97a8]">
            Target: {evidenceItem.target_type} · {evidenceItem.target_id.slice(0, 8)}
          </div>
          <div className="p-2 bg-[#0b0d10] border border-[#252b36] text-[10px] break-all text-[#4f8f66]">
            SHA-256: {evidenceItem.sha256}
          </div>
          <div className="text-[11px] text-[#8c97a8]">
            Custody Events: {evidenceItem.custody_events?.length || 0}
          </div>
          <button
            onClick={() => onNavigateModule('cyber_incidents')}
            className="w-full px-2 py-1.5 bg-[#181c24] hover:bg-[#222834] border border-[#252b36] text-[#e8ecf1] rounded-[2px] cursor-pointer"
          >
            Open Evidence & Custody Manager
          </button>
        </div>
      </div>
    );
  }

  return null;
};
