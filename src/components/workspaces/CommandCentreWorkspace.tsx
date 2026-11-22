import React, { useMemo, useState } from 'react';
import { AppRole, ModuleId, SelectedEntity, GisCustomSource } from '../../types/atlas';
import { WorkspaceIntelligenceState } from '../../hooks/useWorkspaceIntelligence';
import { TacticalAtlasMap, MapLayerVisibility } from '../map/TacticalAtlasMap';
import { IntelligenceDossierPanel } from '../common/IntelligenceDossierPanel';
import { OperationalTimelineDrawer } from '../common/OperationalTimelineDrawer';
import { BlastRadiusScreen } from '../BlastRadiusScreen';
import { TimelineAndEvidenceScreen } from '../TimelineAndEvidenceScreen';
import { atlasService } from '../../data/api';
import {
  AlertTriangle,
  CheckCircle2,
  XCircle,
  PanelRightClose,
  PanelRightOpen,
  ShieldAlert,
  Database,
  Layers,
  GitFork,
  Radio,
  Server,
  FileText,
  Save,
  Trash2,
  RefreshCw,
} from 'lucide-react';
import { loadOrgScopedList, saveOrgScopedList } from '../../utils/orgStorage';

interface MissionFindingDraft {
  id: string;
  incidentId: string;
  eventId: string;
  confidence: number;
  summary: string;
  createdAt: string;
  role: AppRole;
}

interface CommandCentreWorkspaceProps {
  mode: 'command_centre' | 'operational_overview' | 'mission_workspace';
  intel: WorkspaceIntelligenceState;
  activeRole: AppRole;
  selectedEntity: SelectedEntity;
  onSelectEntity: (entity: SelectedEntity) => void;
  onNavigateModule: (module: ModuleId) => void;
  customGisSources: GisCustomSource[];
}

export const CommandCentreWorkspace: React.FC<CommandCentreWorkspaceProps> = ({
  mode,
  intel,
  activeRole,
  selectedEntity,
  onSelectEntity,
  onNavigateModule,
  customGisSources,
}) => {
  // Command Centre Map & Panel states
  const [dossierOpen, setDossierOpen] = useState(true);
  const [timelineCollapsed, setTimelineCollapsed] = useState(false);
  const [typeFilter, setTypeFilter] = useState('all');
  const [minCriticality, setMinCriticality] = useState(1);
  const [centerTarget, setCenterTarget] = useState<[number, number] | null>(null);
  const [layerVisibility, setLayerVisibility] = useState<MapLayerVisibility>({
    assets: true,
    approxHalos: true,
    dependencies: true,
    incidents: true,
    riskZones: true,
    graticule: true,
  });

  // Mission Workspace states
  const [missionIncidentId, setMissionIncidentId] = useState<string>('');
  const [missionStage, setMissionStage] = useState<'matches' | 'blast' | 'custody' | 'finding'>('matches');
  const [findingSummary, setFindingSummary] = useState('');
  const [findingConfidence, setFindingConfidence] = useState('0.85');
  const [findingDrafts, setFindingDrafts] = useState<MissionFindingDraft[]>(() =>
    loadOrgScopedList<MissionFindingDraft>('mission_drafts', intel.orgId)
  );
  const [missionBusy, setMissionBusy] = useState(false);
  const [missionNotice, setMissionNotice] = useState<{ kind: 'ok' | 'err'; text: string } | null>(null);

  React.useEffect(() => {
    setFindingDrafts(loadOrgScopedList<MissionFindingDraft>('mission_drafts', intel.orgId));
    setMissionIncidentId('');
    setFindingSummary('');
    setMissionNotice(null);
  }, [intel.orgId]);

  const toggleLayer = (layer: keyof MapLayerVisibility) => {
    setLayerVisibility((prev) => ({ ...prev, [layer]: !prev[layer] }));
  };

  // Real metrics derived strictly from Supabase data
  const metrics = useMemo(() => {
    const exposedAssetIds = new Set(
      intel.matches.filter((m) => m.status === 'confirmed' || m.status === 'auto').map((m) => m.asset_id)
    );
    const criticalAssets = intel.assets.filter((a) => a.criticality >= 4);
    const criticalOrExposed = new Set([
      ...exposedAssetIds,
      ...criticalAssets.map((a) => a.id),
    ]);
    const proposedMatches = intel.matches.filter((m) => m.status === 'proposed').length;

    return {
      activeIncidents: intel.incidents.length,
      criticalIncidents: intel.incidents.filter((i) => i.severity === 'critical').length,
      criticalOrExposedCount: criticalOrExposed.size,
      exposedCount: exposedAssetIds.size,
      monitoredAssets: intel.assets.length,
      proposedMatches,
      dependencyEdges: intel.edges.length,
      verifiedSources: intel.datasets.length + customGisSources.filter((s) => s.enabled).length,
    };
  }, [intel.incidents, intel.matches, intel.assets, intel.edges, intel.datasets, customGisSources]);

  const activeMissionIncident = useMemo(() => {
    if (missionIncidentId) {
      return intel.incidents.find((i) => i.id === missionIncidentId) || intel.incidents[0] || null;
    }
    if (selectedEntity?.kind === 'incident') {
      return intel.incidents.find((i) => i.id === selectedEntity.id) || intel.incidents[0] || null;
    }
    return intel.incidents[0] || null;
  }, [missionIncidentId, selectedEntity, intel.incidents]);

  const activeMissionMatches = useMemo(() => {
    if (!activeMissionIncident) return [];
    return intel.matches.filter((m) => m.incident_id === activeMissionIncident.id);
  }, [intel.matches, activeMissionIncident]);

  const handleMatchDecision = async (matchId: string, decision: 'confirm' | 'reject') => {
    setMissionBusy(true);
    setMissionNotice(null);
    try {
      if (decision === 'confirm') {
        await atlasService.confirmAssetMatch(matchId);
        setMissionNotice({ kind: 'ok', text: `Confirmed match ${matchId.slice(0, 8)} and recorded labelled sample.` });
      } else {
        await atlasService.rejectAssetMatch(matchId, 'Rejected during Mission Workspace review');
        setMissionNotice({ kind: 'ok', text: `Rejected match ${matchId.slice(0, 8)} and recorded labelled sample.` });
      }
      await intel.refreshAll();
    } catch (err: any) {
      setMissionNotice({ kind: 'err', text: err.message || 'Decision write failed.' });
    } finally {
      setMissionBusy(false);
    }
  };

  const handleSaveFindingDraft = (e: React.FormEvent) => {
    e.preventDefault();
    if (!activeMissionIncident || !findingSummary.trim()) return;
    const draft: MissionFindingDraft = {
      id: `draft-${Date.now()}`,
      incidentId: activeMissionIncident.id,
      eventId: activeMissionIncident.event_id,
      confidence: Math.max(0.1, Math.min(1, Number(findingConfidence) || 0.5)),
      summary: findingSummary.trim(),
      createdAt: new Date().toISOString(),
      role: activeRole,
    };
    const next = [draft, ...findingDrafts];
    setFindingDrafts(next);
    saveOrgScopedList('mission_drafts', intel.orgId, next);
    setFindingSummary('');
    setMissionNotice({
      kind: 'ok',
      text: 'Saved assessment draft locally in browser storage. Upload an exported report under Evidence & Custody to seal it in PostgreSQL.',
    });
  };

  const handleDeleteFindingDraft = (draftId: string) => {
    const next = findingDrafts.filter((d) => d.id !== draftId);
    setFindingDrafts(next);
    saveOrgScopedList('mission_drafts', intel.orgId, next);
  };

  // =========================================================================
  // VIEW 1: COMMAND CENTRE
  // =========================================================================
  if (mode === 'command_centre') {
    return (
      <div className="flex-1 flex flex-col overflow-hidden bg-(--atlas-bg-primary)">
        {/* Top Intelligence Summary Strip (Compact, Hairline Borders, Real DB Metrics) */}
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 border-b border-(--atlas-border) bg-(--atlas-bg-secondary) shrink-0 divide-x divide-(--atlas-border)">
          <button
            onClick={() => onNavigateModule('cyber_incidents')}
            className="px-3 py-2 text-left hover:bg-(--atlas-bg-elevated) transition-colors cursor-pointer"
          >
            <div className="text-[10px] font-mono text-(--atlas-text-secondary) tracking-[0.08em] flex items-center justify-between gap-1.5">
              <span className="flex items-center gap-1.5 min-w-0">
                <span
                  className={`atlas-led ${
                    metrics.criticalIncidents > 0
                      ? 'text-(--atlas-red)'
                      : metrics.activeIncidents > 0
                      ? 'text-(--atlas-amber)'
                      : 'text-(--atlas-text-muted)'
                  }`}
                  data-state={
                    metrics.criticalIncidents > 0
                      ? 'critical'
                      : metrics.activeIncidents > 0
                      ? 'nominal'
                      : 'idle'
                  }
                  aria-hidden="true"
                />
                <span className="truncate">ACTIVE INCIDENTS</span>
              </span>
              <Radio className="w-3 h-3 text-(--atlas-red) shrink-0" />
            </div>
            <div className="mt-0.5 flex items-baseline justify-between gap-2">
              <span className="text-base font-mono font-semibold text-(--atlas-text-primary) tabular-nums">
                {metrics.activeIncidents}
              </span>
              <span className="w-24 shrink-0 text-right truncate text-[10px] font-mono text-(--atlas-red) tabular-nums">
                {metrics.criticalIncidents} CRIT
              </span>
            </div>
          </button>

          <button
            onClick={() => onNavigateModule('geographic_risk')}
            className="px-3 py-2 text-left hover:bg-(--atlas-bg-elevated) transition-colors cursor-pointer"
          >
            <div className="text-[10px] font-mono text-(--atlas-text-secondary) tracking-[0.08em] flex items-center justify-between gap-1.5">
              <span className="flex items-center gap-1.5 min-w-0">
                <span
                  className={`atlas-led ${
                    metrics.exposedCount > 0
                      ? 'text-(--atlas-red)'
                      : metrics.criticalOrExposedCount > 0
                      ? 'text-(--atlas-amber)'
                      : 'text-(--atlas-text-muted)'
                  }`}
                  data-state={
                    metrics.exposedCount > 0
                      ? 'critical'
                      : metrics.criticalOrExposedCount > 0
                      ? 'nominal'
                      : 'idle'
                  }
                  aria-hidden="true"
                />
                <span className="truncate">CRITICAL / EXPOSED</span>
              </span>
              <ShieldAlert className="w-3 h-3 text-(--atlas-amber) shrink-0" />
            </div>
            <div className="mt-0.5 flex items-baseline justify-between gap-2">
              <span className="text-base font-mono font-semibold text-(--atlas-text-primary) tabular-nums">
                {metrics.criticalOrExposedCount}
              </span>
              <span className="w-24 shrink-0 text-right truncate text-[10px] font-mono text-(--atlas-amber) tabular-nums">
                {metrics.exposedCount} LINKED
              </span>
            </div>
          </button>

          <button
            onClick={() => onNavigateModule('asset_tracking')}
            className="px-3 py-2 text-left hover:bg-(--atlas-bg-elevated) transition-colors cursor-pointer"
          >
            <div className="text-[10px] font-mono text-(--atlas-text-secondary) tracking-[0.08em] flex items-center justify-between gap-1.5">
              <span className="flex items-center gap-1.5 min-w-0">
                <span
                  className={`atlas-led ${
                    metrics.monitoredAssets > 0 ? 'text-(--atlas-cyan)' : 'text-(--atlas-text-muted)'
                  }`}
                  data-state={metrics.monitoredAssets > 0 ? 'nominal' : 'idle'}
                  aria-hidden="true"
                />
                <span className="truncate">MONITORED ASSETS</span>
              </span>
              <Server className="w-3 h-3 text-(--atlas-cyan) shrink-0" />
            </div>
            <div className="mt-0.5 flex items-baseline justify-between gap-2">
              <span className="text-base font-mono font-semibold text-(--atlas-text-primary) tabular-nums">
                {metrics.monitoredAssets}
              </span>
              <span className="w-24 shrink-0 text-right truncate text-[10px] font-mono text-(--atlas-text-secondary) tabular-nums">
                EPSG:4326
              </span>
            </div>
          </button>

          <button
            onClick={() => onNavigateModule('cyber_incidents')}
            className="px-3 py-2 text-left hover:bg-(--atlas-bg-elevated) transition-colors cursor-pointer"
          >
            <div className="text-[10px] font-mono text-(--atlas-text-secondary) tracking-[0.08em] flex items-center justify-between gap-1.5">
              <span className="flex items-center gap-1.5 min-w-0">
                <span
                  className={`atlas-led ${
                    metrics.proposedMatches > 0 ? 'text-(--atlas-amber)' : 'text-(--atlas-text-muted)'
                  }`}
                  data-state={metrics.proposedMatches > 0 ? 'nominal' : 'idle'}
                  aria-hidden="true"
                />
                <span className="truncate">MATCH ALERTS</span>
              </span>
              <AlertTriangle className="w-3 h-3 text-(--atlas-amber) shrink-0" />
            </div>
            <div className="mt-0.5 flex items-baseline justify-between gap-2">
              <span className="text-base font-mono font-semibold text-(--atlas-text-primary) tabular-nums">
                {metrics.proposedMatches}
              </span>
              <span className="w-24 shrink-0 text-right truncate text-[10px] font-mono text-(--atlas-text-secondary)">
                PROPOSED REVIEW
              </span>
            </div>
          </button>

          <button
            onClick={() => onNavigateModule('network_analysis')}
            className="px-3 py-2 text-left hover:bg-(--atlas-bg-elevated) transition-colors cursor-pointer"
          >
            <div className="text-[10px] font-mono text-(--atlas-text-secondary) tracking-[0.08em] flex items-center justify-between gap-1.5">
              <span className="flex items-center gap-1.5 min-w-0">
                <span
                  className={`atlas-led ${
                    metrics.dependencyEdges > 0 ? 'text-(--atlas-blue)' : 'text-(--atlas-text-muted)'
                  }`}
                  data-state={metrics.dependencyEdges > 0 ? 'nominal' : 'idle'}
                  aria-hidden="true"
                />
                <span className="truncate">DEPENDENCY EDGES</span>
              </span>
              <GitFork className="w-3 h-3 text-(--atlas-blue) shrink-0" />
            </div>
            <div className="mt-0.5 flex items-baseline justify-between gap-2">
              <span className="text-base font-mono font-semibold text-(--atlas-text-primary) tabular-nums">
                {metrics.dependencyEdges}
              </span>
              <span className="w-24 shrink-0 text-right truncate text-[10px] font-mono text-(--atlas-text-secondary)">
                DIRECTED TOPOLOGY
              </span>
            </div>
          </button>

          <button
            onClick={() => onNavigateModule('data_sources')}
            className="px-3 py-2 text-left hover:bg-(--atlas-bg-elevated) transition-colors cursor-pointer"
          >
            <div className="text-[10px] font-mono text-(--atlas-text-secondary) tracking-[0.08em] flex items-center justify-between gap-1.5">
              <span className="flex items-center gap-1.5 min-w-0">
                <span
                  className={`atlas-led ${
                    intel.error ? 'text-(--atlas-red)' : 'text-(--atlas-green)'
                  }`}
                  data-state={intel.error ? 'error' : 'live'}
                  aria-hidden="true"
                />
                <span className="truncate">DATA SOURCES</span>
              </span>
              <Database className="w-3 h-3 text-(--atlas-green) shrink-0" />
            </div>
            <div className="mt-0.5 flex items-baseline justify-between gap-2">
              <span className="text-base font-mono font-semibold text-(--atlas-text-primary) tabular-nums">
                {metrics.verifiedSources}
              </span>
              <span className={`w-24 shrink-0 text-right truncate text-[10px] font-mono ${intel.error ? 'text-(--atlas-red)' : 'text-(--atlas-green)'}`}>
                {intel.error ? 'SYNC ERR' : 'LIVE DB'}
              </span>
            </div>
          </button>
        </div>

        {/* Center Multi-Panel Workspace: Map + Right Dossier */}
        <div className="flex-1 flex min-h-0 overflow-hidden relative">
          <div className="flex-1 relative min-w-0">
            <TacticalAtlasMap
              intel={intel}
              selectedEntity={selectedEntity}
              onSelectEntity={(ent) => {
                onSelectEntity(ent);
                setDossierOpen(true);
              }}
              layerVisibility={layerVisibility}
              onToggleLayer={toggleLayer}
              typeFilter={typeFilter}
              onChangeTypeFilter={setTypeFilter}
              minCriticality={minCriticality}
              onChangeMinCriticality={setMinCriticality}
              customSources={customGisSources}
              centerTarget={centerTarget}
            />

            {!dossierOpen && (
              <button
                onClick={() => setDossierOpen(true)}
                className="absolute top-2.5 right-2.5 z-10 px-2.5 py-1 atlas-raised hover:bg-(--atlas-bg-elevated) text-(--atlas-text-primary) text-[11px] font-mono flex items-center gap-1.5 cursor-pointer"
              >
                <PanelRightOpen className="w-3.5 h-3.5 text-(--atlas-olive-bright)" />
                <span>Intelligence Profile</span>
              </button>
            )}
          </div>

          {dossierOpen && (
            <div className="w-80 xl:w-96 border-l border-(--atlas-border) shrink-0 h-full overflow-hidden">
              <IntelligenceDossierPanel
                selectedEntity={selectedEntity}
                intel={intel}
                onSelectEntity={onSelectEntity}
                onNavigateModule={onNavigateModule}
                onClose={() => setDossierOpen(false)}
                onCenterCoordinate={(lngLat) => setCenterTarget([...lngLat])}
              />
            </div>
          )}
        </div>

        {/* Bottom Collapsible Operational Timeline */}
        <OperationalTimelineDrawer
          intel={intel}
          collapsed={timelineCollapsed}
          onToggleCollapse={() => setTimelineCollapsed((v) => !v)}
          onSelectEntity={(ent) => {
            onSelectEntity(ent);
            setDossierOpen(true);
          }}
        />
      </div>
    );
  }

  // =========================================================================
  // VIEW 2: OPERATIONAL OVERVIEW
  // =========================================================================
  if (mode === 'operational_overview') {
    const assetTypes = ['site', 'power_feed', 'fibre_route', 'cloud_region', 'service'] as const;
    const severities = ['critical', 'high', 'medium', 'low'] as const;
    const approxCount = intel.assets.filter((a) => a.accuracy_class !== 'exact_survey').length;

    return (
      <div className="flex-1 overflow-y-auto bg-(--atlas-bg-primary) p-4 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-(--atlas-border) pb-3">
          <div>
            <div className="font-mono text-[10px] tracking-[0.14em] text-(--atlas-olive-bright)">
              COMMAND // CROSS-DOMAIN READINESS
            </div>
            <h1 className="text-base font-semibold text-(--atlas-text-primary) mt-0.5">
              Operational Overview
            </h1>
            <p className="text-xs text-(--atlas-text-secondary)">
              Authoritative counts and structural readiness across geospatial assets, dependencies, cyber telemetry, and evidence custody.
            </p>
          </div>
          <div className="flex items-center gap-2 font-mono text-[11px]">
            <button
              onClick={() => onNavigateModule('command_centre')}
              className="px-2.5 py-1 bg-(--atlas-bg-secondary) hover:bg-(--atlas-bg-elevated) border border-(--atlas-border) text-(--atlas-text-primary) cursor-pointer"
            >
              Open Tactical Map
            </button>
            <button
              onClick={() => intel.refreshAll()}
              className="px-2.5 py-1 bg-(--atlas-accent-olive)/20 hover:bg-(--atlas-accent-olive)/30 border border-(--atlas-accent-olive)/50 text-(--atlas-text-primary) flex items-center gap-1.5 cursor-pointer"
            >
              <RefreshCw className={`w-3 h-3 ${intel.isLoading ? 'animate-spin' : ''}`} />
              <span>Sync DB</span>
            </button>
          </div>
        </div>

        {/* Asset Type x Criticality Matrix */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <div className="atlas-raised">
            <div className="px-3 py-2 border-b border-(--atlas-border) flex items-center justify-between">
              <span className="font-mono text-[11px] font-semibold text-(--atlas-text-primary)">
                INFRASTRUCTURE DISTRIBUTION BY TYPE & TIER
              </span>
              <span className="font-mono text-[10px] text-(--atlas-text-secondary) tabular-nums">
                TOTAL: {intel.assets.length}
              </span>
            </div>
            <table className="w-full text-left font-mono text-[11px] border-collapse">
              <thead className="border-b border-(--atlas-border) text-(--atlas-text-secondary) text-[10px] bg-(--atlas-bg-inset)">
                <tr>
                  <th className="py-1.5 px-3">ASSET CLASS</th>
                  <th className="py-1.5 px-2 text-right">T5</th>
                  <th className="py-1.5 px-2 text-right">T4</th>
                  <th className="py-1.5 px-2 text-right">T1–T3</th>
                  <th className="py-1.5 px-3 text-right">TOTAL</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-(--atlas-border-subtle)">
                {assetTypes.map((t) => {
                  const list = intel.assets.filter((a) => a.type === t);
                  const t5 = list.filter((a) => a.criticality === 5).length;
                  const t4 = list.filter((a) => a.criticality === 4).length;
                  const tLow = list.filter((a) => a.criticality <= 3).length;
                  return (
                    <tr key={t} className="hover:bg-(--atlas-bg-elevated)">
                      <td className="py-1.5 px-3 text-(--atlas-text-primary)">{t.toUpperCase()}</td>
                      <td className="py-1.5 px-2 text-right tabular-nums text-(--atlas-red)">{t5}</td>
                      <td className="py-1.5 px-2 text-right tabular-nums text-(--atlas-amber)">{t4}</td>
                      <td className="py-1.5 px-2 text-right tabular-nums text-(--atlas-text-secondary)">{tLow}</td>
                      <td className="py-1.5 px-3 text-right tabular-nums font-semibold text-(--atlas-text-primary)">
                        {list.length}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          {/* Incident & Match Queue Summary */}
          <div className="atlas-raised">
            <div className="px-3 py-2 border-b border-(--atlas-border) flex items-center justify-between">
              <span className="font-mono text-[11px] font-semibold text-(--atlas-text-primary)">
                CYBER INCIDENTS & RULE-MATCH QUEUE
              </span>
              <span className="font-mono text-[10px] text-(--atlas-text-secondary) tabular-nums">
                INCIDENTS: {intel.incidents.length} · MATCHES: {intel.matches.length}
              </span>
            </div>
            <div className="p-3 space-y-3">
              <div className="grid grid-cols-4 gap-2 font-mono text-center">
                {severities.map((sev) => {
                  const count = intel.incidents.filter((i) => i.severity === sev).length;
                  return (
                    <div key={sev} className="bg-(--atlas-bg-primary) border border-(--atlas-border) p-2">
                      <div className="text-[10px] text-(--atlas-text-secondary)">{sev.toUpperCase()}</div>
                      <div
                        className={`text-lg font-semibold tabular-nums mt-0.5 ${
                          sev === 'critical'
                            ? 'text-(--atlas-red)'
                            : sev === 'high'
                            ? 'text-(--atlas-amber)'
                            : sev === 'medium'
                            ? 'text-(--atlas-cyan)'
                            : 'text-(--atlas-text-secondary)'
                        }`}
                      >
                        {count}
                      </div>
                    </div>
                  );
                })}
              </div>

              <div className="border-t border-(--atlas-border) pt-2.5 grid grid-cols-4 gap-2 font-mono text-[11px]">
                {(['auto', 'confirmed', 'proposed', 'rejected'] as const).map((status) => (
                  <div key={status} className="flex items-center justify-between bg-(--atlas-bg-primary) border border-(--atlas-border) px-2 py-1.5">
                    <span className="text-(--atlas-text-secondary) text-[10px]">{status.toUpperCase()}</span>
                    <span className="text-(--atlas-text-primary) font-semibold tabular-nums">
                      {intel.matches.filter((m) => m.status === status).length}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* Spatial Confidence, Scoring Calibration & Evidence Integrity */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <div className="atlas-raised p-3 space-y-2">
            <div className="font-mono text-[11px] font-semibold text-(--atlas-text-primary) flex items-center justify-between">
              <span>SPATIAL GEOMETRY QUALITY</span>
              <Layers className="w-3.5 h-3.5 text-(--atlas-cyan)" />
            </div>
            <div className="font-mono text-xs space-y-1">
              <div className="flex justify-between">
                <span className="text-(--atlas-text-secondary)">Exact Survey (EPSG:4326):</span>
                <span className="text-(--atlas-green) tabular-nums">{intel.assets.length - approxCount}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-(--atlas-text-secondary)">Facility / Regional Approximate:</span>
                <span className="text-(--atlas-amber) tabular-nums">{approxCount}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-(--atlas-text-secondary)">Active Custom GIS Layers:</span>
                <span className="text-(--atlas-text-primary) tabular-nums">
                  {customGisSources.filter((s) => s.enabled).length}
                </span>
              </div>
            </div>
          </div>

          <div className="atlas-raised p-3 space-y-2">
            <div className="font-mono text-[11px] font-semibold text-(--atlas-text-primary) flex items-center justify-between">
              <span>RISK PARAMETER CALIBRATION</span>
              <AlertTriangle className="w-3.5 h-3.5 text-(--atlas-amber)" />
            </div>
            <div className="font-mono text-[11px] text-(--atlas-amber)">
              STATUS: {intel.scoringConfig[0]?.calibration_status?.toUpperCase() || 'UNCALIBRATED'}
            </div>
            <p className="text-[11px] text-(--atlas-text-secondary) leading-relaxed">
              Blast radius priority scores use stored database weights (<span className="tabular-nums">{intel.scoringConfig.length}</span> entries) and widen displayed uncertainty ranges by match confidence and geometry precision.
            </p>
          </div>

          <div className="atlas-raised p-3 space-y-2">
            <div className="font-mono text-[11px] font-semibold text-(--atlas-text-primary) flex items-center justify-between">
              <span>EVIDENCE & CRYPTO LEDGER</span>
              <FileText className="w-3.5 h-3.5 text-(--atlas-olive-bright)" />
            </div>
            <div className="font-mono text-xs space-y-1">
              <div className="flex justify-between">
                <span className="text-(--atlas-text-secondary)">Registered Evidence Files:</span>
                <span className="text-(--atlas-text-primary) tabular-nums">{intel.evidence.length}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-(--atlas-text-secondary)">Audit Ledger Events:</span>
                <span className="text-(--atlas-text-primary) tabular-nums">{intel.auditTotal}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-(--atlas-text-secondary)">Latest Seq / Hash:</span>
                <span className="text-(--atlas-green) tabular-nums">
                  {intel.auditEvents[0] ? `#${intel.auditEvents[0].seq} · ${intel.auditEvents[0].record_hash.slice(0, 10)}` : 'None'}
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  // =========================================================================
  // VIEW 3: MISSION WORKSPACE
  // =========================================================================
  return (
    <div className="flex-1 flex overflow-hidden bg-(--atlas-bg-primary)">
      {/* Left Incident Mission Queue */}
      <aside className="w-72 border-r border-(--atlas-border) bg-(--atlas-bg-inset) flex flex-col shrink-0">
        <div className="px-3 py-2 border-b border-(--atlas-border) flex items-center justify-between">
          <span className="font-mono text-[10px] tracking-[0.12em] text-(--atlas-text-secondary) font-semibold tabular-nums">
            MISSION QUEUE ({intel.incidents.length})
          </span>
        </div>
        <div className="flex-1 overflow-y-auto divide-y divide-(--atlas-bg-elevated)">
          {intel.incidents.length === 0 ? (
            <div className="p-4 text-xs text-(--atlas-text-secondary)">
              No incidents ingested in this workspace. Ingest telemetry via Cyber Threat Monitoring.
            </div>
          ) : (
            intel.incidents.map((inc) => {
              const isSel = activeMissionIncident?.id === inc.id;
              const propCount = intel.matches.filter(
                (m) => m.incident_id === inc.id && m.status === 'proposed'
              ).length;
              return (
                <button
                  key={inc.id}
                  onClick={() => {
                    setMissionIncidentId(inc.id);
                    onSelectEntity({ kind: 'incident', id: inc.id });
                  }}
                  className={`w-full p-2.5 text-left transition-colors cursor-pointer ${
                    isSel ? 'bg-(--atlas-accent-olive)/15 border-r-2 border-(--atlas-olive-bright)' : 'hover:bg-(--atlas-bg-raised)'
                  }`}
                >
                  <div className="flex items-center justify-between font-mono text-[11px]">
                    <span className="text-(--atlas-text-primary) font-semibold truncate">{inc.event_id}</span>
                    <span
                      className={
                        inc.severity === 'critical'
                          ? 'text-(--atlas-red)'
                          : inc.severity === 'high'
                          ? 'text-(--atlas-amber)'
                          : 'text-(--atlas-text-secondary)'
                      }
                    >
                      {inc.severity.toUpperCase()}
                    </span>
                  </div>
                  <div className="text-xs text-(--atlas-text-secondary) truncate mt-0.5">{inc.event_type}</div>
                  <div className="mt-1 flex items-center justify-between font-mono text-[10px] text-(--atlas-text-muted) tabular-nums">
                    <span>{new Date(inc.observed_at).toISOString().slice(0, 16).replace('T', ' ')}</span>
                    {propCount > 0 && <span className="text-(--atlas-amber) tabular-nums">{propCount} PROPOSED</span>}
                  </div>
                </button>
              );
            })
          )}
        </div>
      </aside>

      {/* Center Investigation Case Stage */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Stage Header & Sub-tabs */}
        <div className="px-4 py-2 border-b border-(--atlas-border) bg-(--atlas-bg-secondary) flex flex-wrap items-center justify-between gap-2 shrink-0">
          <div className="flex items-center gap-2 min-w-0">
            <span className="font-mono text-[10px] tracking-[0.12em] text-(--atlas-olive-bright)">MISSION CASE:</span>
            <span className="font-mono text-xs font-semibold text-(--atlas-text-primary) truncate">
              {activeMissionIncident ? `${activeMissionIncident.event_id} — ${activeMissionIncident.event_type}` : 'No Active Case'}
            </span>
          </div>
          <div className="flex items-center gap-1 font-mono text-[11px]">
            {(
              [
                ['matches', '1. Match Triage'],
                ['blast', '2. Blast Radius'],
                ['custody', '3. Evidence & Custody'],
                ['finding', '4. Assessment Drafts'],
              ] as const
            ).map(([id, label]) => (
              <button
                key={id}
                onClick={() => setMissionStage(id)}
                className={`px-2.5 py-1 border rounded-[2px] cursor-pointer ${
                  missionStage === id
                    ? 'bg-(--atlas-accent-olive)/25 border-(--atlas-accent-olive) text-(--atlas-text-primary)'
                    : 'bg-(--atlas-bg-primary) border-(--atlas-border) text-(--atlas-text-secondary) hover:text-(--atlas-text-primary)'
                }`}
              >
                {label}
              </button>
            ))}
          </div>
        </div>

        {missionNotice && (
          <div
            className={`px-4 py-2 border-b text-xs font-mono flex items-center justify-between ${
              missionNotice.kind === 'ok'
                ? 'bg-(--atlas-green)/10 border-(--atlas-green)/40 text-(--atlas-green)'
                : 'bg-(--atlas-red)/10 border-(--atlas-red)/40 text-(--atlas-red)'
            }`}
          >
            <span>{missionNotice.text}</span>
            <button onClick={() => setMissionNotice(null)} className="underline cursor-pointer">
              Dismiss
            </button>
          </div>
        )}

        <div className="flex-1 overflow-y-auto">
          {missionStage === 'matches' && (
            <div className="p-4 space-y-3">
              <div className="text-xs text-(--atlas-text-secondary)">
                Review deterministic rule-engine matches between this incident and workspace infrastructure. Decisions are saved as labelled ground-truth data.
              </div>
              {activeMissionMatches.length === 0 ? (
                <div className="p-6 atlas-raised text-xs font-mono text-(--atlas-text-secondary)">
                  No asset matches recorded for the selected incident.
                </div>
              ) : (
                <div className="atlas-raised divide-y divide-(--atlas-border-subtle)">
                  {activeMissionMatches.map((m) => (
                    <div key={m.id} className="p-3 flex flex-wrap items-center justify-between gap-3">
                      <div className="space-y-0.5 min-w-0">
                        <div className="flex items-center gap-2 font-mono text-xs">
                          <button
                            onClick={() => onSelectEntity({ kind: 'asset', id: m.asset_id })}
                            className="text-(--atlas-cyan) hover:underline font-semibold cursor-pointer"
                          >
                            {m.asset?.site_code || m.asset_id.slice(0, 8)}
                          </button>
                          <span className="text-(--atlas-text-primary)">{m.asset?.name}</span>
                          <span className="text-(--atlas-text-secondary)">· Rule: {m.rule_fired}</span>
                        </div>
                        <div className="font-mono text-[11px] text-(--atlas-text-secondary) tabular-nums">
                          Score: {(Number(m.score) * 100).toFixed(0)}% · Status:{' '}
                          <span
                            className={
                              m.status === 'confirmed' || m.status === 'auto'
                                ? 'text-(--atlas-green)'
                                : m.status === 'proposed'
                                ? 'text-(--atlas-amber)'
                                : 'text-(--atlas-red)'
                            }
                          >
                            {m.status.toUpperCase()}
                          </span>
                        </div>
                      </div>

                      {m.status === 'proposed' && (
                        <div className="flex items-center gap-2 font-mono text-[11px]">
                          <button
                            disabled={missionBusy}
                            onClick={() => handleMatchDecision(m.id, 'confirm')}
                            className="px-2.5 py-1 bg-(--atlas-green)/20 hover:bg-(--atlas-green)/30 border border-(--atlas-green)/50 text-(--atlas-text-primary) flex items-center gap-1 cursor-pointer disabled:opacity-50"
                          >
                            <CheckCircle2 className="w-3 h-3 text-(--atlas-green)" />
                            <span>Confirm Match</span>
                          </button>
                          <button
                            disabled={missionBusy}
                            onClick={() => handleMatchDecision(m.id, 'reject')}
                            className="px-2.5 py-1 bg-(--atlas-red)/20 hover:bg-(--atlas-red)/30 border border-(--atlas-red)/50 text-(--atlas-text-primary) flex items-center gap-1 cursor-pointer disabled:opacity-50"
                          >
                            <XCircle className="w-3 h-3 text-(--atlas-red)" />
                            <span>Reject</span>
                          </button>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {missionStage === 'blast' && <BlastRadiusScreen activeOrgId={intel.orgId} />}

          {missionStage === 'custody' && (
            <div className="p-4">
              <TimelineAndEvidenceScreen activeOrgId={intel.orgId} activeRole={activeRole} />
            </div>
          )}

          {missionStage === 'finding' && (
            <div className="p-4 max-w-2xl space-y-4">
              <div className="atlas-raised p-4 space-y-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="font-mono text-xs font-semibold text-(--atlas-text-primary)">
                    ANALYST ASSESSMENT NOTES (LOCAL WORKSPACE DRAFT)
                  </div>
                  <span className="font-mono text-[10px] text-(--atlas-amber) border border-(--atlas-amber)/40 bg-(--atlas-amber)/10 px-1.5 py-0.5">
                    LOCAL DRAFT · NOT IN SUPABASE AUDIT LEDGER
                  </span>
                </div>
                <p className="text-xs text-(--atlas-text-secondary)">
                  Saves working assessment notes locally in browser storage per organisation. To persist an immutable record in PostgreSQL, triage asset matches in Stage 1 or upload signed report evidence in Stage 3.
                </p>
                <form onSubmit={handleSaveFindingDraft} className="space-y-3">
                  <div>
                    <label className="block font-mono text-[10px] text-(--atlas-text-secondary) mb-1">
                      ANALYST CONFIDENCE (0.10 – 1.00)
                    </label>
                    <input
                      type="number"
                      step="0.05"
                      min="0.1"
                      max="1"
                      value={findingConfidence}
                      onChange={(e) => setFindingConfidence(e.target.value)}
                      className="w-32 bg-(--atlas-bg-primary) border border-(--atlas-border) px-2.5 py-1.5 font-mono text-xs text-(--atlas-text-primary) tabular-nums"
                    />
                  </div>
                  <div>
                    <label className="block font-mono text-[10px] text-(--atlas-text-secondary) mb-1">
                      ASSESSMENT & RECOMMENDED CONTAINMENT ACTION
                    </label>
                    <textarea
                      rows={4}
                      required
                      value={findingSummary}
                      onChange={(e) => setFindingSummary(e.target.value)}
                      placeholder="Document corroborating evidence, physical dependency exposure, and containment steps..."
                      className="w-full bg-(--atlas-bg-primary) border border-(--atlas-border) p-2.5 text-xs text-(--atlas-text-primary) focus:outline-none focus:border-(--atlas-accent-olive)"
                    />
                  </div>
                  <button
                    type="submit"
                    disabled={!activeMissionIncident || !findingSummary.trim()}
                    className="px-3 py-1.5 bg-(--atlas-accent-olive) hover:bg-(--atlas-accent-olive-hover) text-(--atlas-bg-primary) font-mono text-xs font-semibold flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
                  >
                    <Save className="w-3.5 h-3.5" />
                    <span>Save Local Assessment Draft</span>
                  </button>
                </form>
              </div>

              {findingDrafts.filter((d) => !activeMissionIncident || d.incidentId === activeMissionIncident.id).length > 0 && (
                <div className="atlas-raised divide-y divide-(--atlas-border-subtle)">
                  <div className="px-3 py-2 font-mono text-[11px] font-semibold text-(--atlas-text-primary)">
                    SAVED LOCAL DRAFTS FOR THIS INCIDENT
                  </div>
                  {findingDrafts
                    .filter((d) => !activeMissionIncident || d.incidentId === activeMissionIncident.id)
                    .map((d) => (
                      <div key={d.id} className="p-3 space-y-1 text-xs">
                        <div className="flex items-center justify-between font-mono text-[10px] text-(--atlas-text-secondary) tabular-nums">
                          <span>
                            {d.eventId} · CONF {(d.confidence * 100).toFixed(0)}% · {d.role}
                          </span>
                          <div className="flex items-center gap-2">
                            <span>{new Date(d.createdAt).toISOString().slice(0, 19).replace('T', ' ')} UTC</span>
                            <button
                              onClick={() => handleDeleteFindingDraft(d.id)}
                              className="text-(--atlas-text-secondary) hover:text-(--atlas-red) cursor-pointer"
                              title="Delete draft"
                            >
                              <Trash2 className="w-3 h-3" />
                            </button>
                          </div>
                        </div>
                        <div className="text-(--atlas-text-primary)">{d.summary}</div>
                      </div>
                    ))}
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Right Intelligence Profile */}
      <div className="w-80 border-l border-(--atlas-border) shrink-0 hidden xl:block overflow-hidden">
        <IntelligenceDossierPanel
          selectedEntity={selectedEntity}
          intel={intel}
          onSelectEntity={onSelectEntity}
          onNavigateModule={onNavigateModule}
        />
      </div>
    </div>
  );
};
