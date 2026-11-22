import React, { useEffect, useMemo, useState } from 'react';
import {
  AppRole,
  AttributionRecord,
  ExternalThreatIndicator,
  ModuleId,
  SelectedEntity,
} from '../../types/atlas';
import { WorkspaceIntelligenceState } from '../../hooks/useWorkspaceIntelligence';
import { IntelligenceDossierPanel } from '../common/IntelligenceDossierPanel';
import { IncidentIntakeScreen } from '../IncidentIntakeScreen';
import { TimelineAndEvidenceScreen } from '../TimelineAndEvidenceScreen';
import { BlastRadiusScreen } from '../BlastRadiusScreen';
import { ThreatIntelAdaptersPanel } from '../cyber/ThreatIntelAdaptersPanel';
import { DefensiveTerminal } from '../cyber/DefensiveTerminal';
import { AttributionWorkbench } from '../cyber/AttributionWorkbench';
import { loadOrgScopedList } from '../../utils/orgStorage';
import { atlasService } from '../../data/api';
import {
  Search,
  Radio,
  SearchCode,
  ShieldAlert,
  FileCheck,
  Flame,
  Send,
  Rss,
  Terminal,
  PanelRightOpen,
  PanelRightClose,
} from 'lucide-react';

interface CyberSecurityWorkspaceProps {
  mode:
    | 'threat_intelligence'
    | 'cyber_monitoring'
    | 'vulnerability_intelligence'
    | 'attack_surface'
    | 'cyber_incidents'
    | 'ioc_investigation';
  intel: WorkspaceIntelligenceState;
  activeRole: AppRole;
  userEmail: string;
  selectedEntity: SelectedEntity;
  onSelectEntity: (entity: SelectedEntity) => void;
  onNavigateModule: (module: ModuleId) => void;
}

interface IocAggregate {
  value: string;
  indicatorType: 'hostname' | 'ip' | 'cidr' | 'cloud_account' | 'site_code';
  assetIds: string[];
  incidentIds: string[];
}

export const CyberSecurityWorkspace: React.FC<CyberSecurityWorkspaceProps> = ({
  mode,
  intel,
  activeRole,
  userEmail,
  selectedEntity,
  onSelectEntity,
  onNavigateModule,
}) => {
  const [socSubTab, setSocSubTab] = useState<
    'events' | 'intake' | 'custody' | 'blast' | 'cti' | 'terminal' | 'attribution'
  >('events');
  const [attributionSeedIndicator, setAttributionSeedIndicator] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [socQuery, setSocQuery] = useState('');
  const [dossierOpen, setDossierOpen] = useState(true);
  const [iocQuery, setIocQuery] = useState('');
  const [selectedIocKey, setSelectedIocKey] = useState<string>('');

  const [externalIndicators, setExternalIndicators] = useState<ExternalThreatIndicator[]>([]);
  const [attributionRecords, setAttributionRecords] = useState<AttributionRecord[]>(() =>
    loadOrgScopedList<AttributionRecord>('attributions', intel.orgId)
  );

  useEffect(() => {
    atlasService
      .fetchExternalIndicators(intel.orgId)
      .then(setExternalIndicators)
      .catch((err) => console.error('Could not load external threat indicators:', err));
    setAttributionRecords(loadOrgScopedList<AttributionRecord>('attributions', intel.orgId));
    setAttributionSeedIndicator('');
  }, [intel.orgId]);

  // Aggregate unique IOCs across assets and incidents.signals
  const iocDirectory = useMemo<IocAggregate[]>(() => {
    const map = new Map<string, IocAggregate>();

    const addEntry = (
      indicatorType: IocAggregate['indicatorType'],
      rawValue: string,
      assetId?: string,
      incidentId?: string
    ) => {
      const value = String(rawValue || '').trim();
      if (!value) return;
      const key = `${indicatorType}::${value}`;
      let entry = map.get(key);
      if (!entry) {
        entry = { value, indicatorType, assetIds: [], incidentIds: [] };
        map.set(key, entry);
      }
      if (assetId && !entry.assetIds.includes(assetId)) entry.assetIds.push(assetId);
      if (incidentId && !entry.incidentIds.includes(incidentId)) entry.incidentIds.push(incidentId);
    };

    for (const a of intel.assets) {
      addEntry('site_code', a.site_code, a.id);
      (a.identifiers?.hostnames || []).forEach((v) => addEntry('hostname', v, a.id));
      (a.identifiers?.ip_addresses || []).forEach((v) => addEntry('ip', v, a.id));
      (a.identifiers?.cidrs || []).forEach((v) => addEntry('cidr', v, a.id));
      (a.identifiers?.cloud_account_ids || []).forEach((v) => addEntry('cloud_account', v, a.id));
    }

    for (const inc of intel.incidents) {
      const sig = (inc.signals || {}) as Record<string, unknown>;
      const listKeys: Array<[string, IocAggregate['indicatorType']]> = [
        ['site_codes', 'site_code'],
        ['hostnames', 'hostname'],
        ['ips', 'ip'],
        ['cidrs', 'cidr'],
        ['cloud_account_ids', 'cloud_account'],
      ];
      for (const [sigKey, iocType] of listKeys) {
        const arr = sig[sigKey];
        if (Array.isArray(arr)) {
          arr.forEach((v) => addEntry(iocType, String(v), undefined, inc.id));
        }
      }
    }

    return Array.from(map.values()).sort(
      (a, b) => b.incidentIds.length + b.assetIds.length - (a.incidentIds.length + a.assetIds.length)
    );
  }, [intel.assets, intel.incidents]);

  const severityCounts = useMemo(() => {
    return {
      critical: intel.incidents.filter((i) => i.severity === 'critical').length,
      high: intel.incidents.filter((i) => i.severity === 'high').length,
      medium: intel.incidents.filter((i) => i.severity === 'medium').length,
      low: intel.incidents.filter((i) => i.severity === 'low').length,
      proposed: intel.matches.filter((m) => m.status === 'proposed').length,
    };
  }, [intel.incidents, intel.matches]);

  // =========================================================================
  // ATTACK SURFACE INTELLIGENCE
  // =========================================================================
  if (mode === 'attack_surface') {
    const surfaceRows = intel.assets.filter((a) => {
      if (!socQuery.trim()) return true;
      const q = socQuery.toLowerCase();
      return `${a.site_code} ${a.name} ${a.owner} ${JSON.stringify(a.identifiers || {})}`
        .toLowerCase()
        .includes(q);
    });

    return (
      <div className="flex-1 flex overflow-hidden bg-[#0b0d10]">
        <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
          <div className="px-4 py-2.5 border-b border-[#252b36] bg-[#12151b] flex flex-wrap items-center justify-between gap-2 shrink-0">
            <div>
              <div className="font-mono text-[10px] tracking-[0.12em] text-[#8fa36d]">
                CYBER INTELLIGENCE // ATTACK SURFACE
              </div>
              <h1 className="text-sm font-semibold text-[#e8ecf1]">
                Exposed Cyber-Physical Identifiers ({surfaceRows.length} Assets)
              </h1>
            </div>
            <div className="relative flex items-center font-mono">
              <Search className="w-3.5 h-3.5 text-[#5d6778] absolute left-2 pointer-events-none" />
              <input
                type="text"
                value={socQuery}
                onChange={(e) => setSocQuery(e.target.value)}
                placeholder="Search hostname, IP, CIDR, cloud ID..."
                className="bg-[#0b0d10] border border-[#252b36] text-[#e8ecf1] pl-7 pr-2.5 py-1 text-xs w-64 focus:outline-none focus:border-[#6f8054]"
              />
            </div>
          </div>

          <div className="flex-1 overflow-auto">
            <table className="w-full text-left font-mono text-[11px] border-collapse">
              <thead className="sticky top-0 bg-[#12151b] border-b border-[#252b36] text-[#8c97a8] text-[10px]">
                <tr>
                  <th className="py-2 px-3">SITE CODE</th>
                  <th className="py-2 px-2">INFRASTRUCTURE</th>
                  <th className="py-2 px-2">HOSTNAMES</th>
                  <th className="py-2 px-2">IP ADDRESSES</th>
                  <th className="py-2 px-2">CIDRS</th>
                  <th className="py-2 px-2">CLOUD ACCOUNTS</th>
                  <th className="py-2 px-3 text-right">INCIDENT MATCHES</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#181c24]">
                {surfaceRows.map((a) => {
                  const hits = intel.matches.filter((m) => m.asset_id === a.id && m.status !== 'rejected').length;
                  return (
                    <tr
                      key={a.id}
                      onClick={() => onSelectEntity({ kind: 'asset', id: a.id })}
                      className="hover:bg-[#151922] cursor-pointer"
                    >
                      <td className="py-2 px-3 text-[#4a9eb0] font-semibold align-top">{a.site_code}</td>
                      <td className="py-2 px-2 text-[#e8ecf1] font-sans align-top">
                        <div>{a.name}</div>
                        <div className="font-mono text-[10px] text-[#8c97a8]">
                          T{a.criticality} · {a.type}
                        </div>
                      </td>
                      <td className="py-2 px-2 text-[#4a9eb0] align-top">
                        {(a.identifiers?.hostnames || []).join(', ') || '—'}
                      </td>
                      <td className="py-2 px-2 text-[#4f8f66] align-top">
                        {(a.identifiers?.ip_addresses || []).join(', ') || '—'}
                      </td>
                      <td className="py-2 px-2 text-[#c88b32] align-top">
                        {(a.identifiers?.cidrs || []).join(', ') || '—'}
                      </td>
                      <td className="py-2 px-2 text-[#5682b0] align-top">
                        {(a.identifiers?.cloud_account_ids || []).join(', ') || '—'}
                      </td>
                      <td className="py-2 px-3 text-right align-top tabular-nums">
                        <span className={hits > 0 ? 'text-[#c94a4a] font-semibold' : 'text-[#8c97a8]'}>
                          {hits}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>

        <div className="w-80 border-l border-[#252b36] hidden xl:block overflow-hidden">
          <IntelligenceDossierPanel
            selectedEntity={selectedEntity}
            intel={intel}
            onSelectEntity={onSelectEntity}
            onNavigateModule={onNavigateModule}
          />
        </div>
      </div>
    );
  }

  // =========================================================================
  // IOC INVESTIGATION WORKBENCH
  // =========================================================================
  if (mode === 'ioc_investigation') {
    const filteredIocs = iocDirectory.filter((i) => {
      if (!iocQuery.trim()) return true;
      return `${i.indicatorType} ${i.value}`.toLowerCase().includes(iocQuery.toLowerCase());
    });

    const activeIoc =
      filteredIocs.find((i) => `${i.indicatorType}::${i.value}` === selectedIocKey) || filteredIocs[0] || null;

    return (
      <div className="flex-1 flex overflow-hidden bg-[#0b0d10]">
        <aside className="w-80 border-r border-[#252b36] bg-[#0e1116] flex flex-col shrink-0">
          <div className="p-2.5 border-b border-[#252b36] space-y-2">
            <div className="font-mono text-[10px] tracking-[0.12em] text-[#8c97a8] font-semibold">
              IOC INDICATOR INDEX ({filteredIocs.length})
            </div>
            <div className="relative flex items-center">
              <SearchCode className="w-3.5 h-3.5 text-[#5d6778] absolute left-2 pointer-events-none" />
              <input
                type="text"
                value={iocQuery}
                onChange={(e) => setIocQuery(e.target.value)}
                placeholder="Pivot IP, hostname, CIDR, site..."
                className="w-full bg-[#0b0d10] border border-[#252b36] pl-7 pr-2 py-1 text-xs font-mono text-[#e8ecf1] focus:outline-none focus:border-[#6f8054]"
              />
            </div>
          </div>
          <div className="flex-1 overflow-y-auto divide-y divide-[#181c24]">
            {filteredIocs.map((ioc) => {
              const key = `${ioc.indicatorType}::${ioc.value}`;
              const isSel = activeIoc && `${activeIoc.indicatorType}::${activeIoc.value}` === key;
              return (
                <button
                  key={key}
                  onClick={() => setSelectedIocKey(key)}
                  className={`w-full px-3 py-2 text-left font-mono text-[11px] cursor-pointer ${
                    isSel ? 'bg-[#6f8054]/20 border-r-2 border-[#8fa36d]' : 'hover:bg-[#151922]'
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-[#e8ecf1] truncate font-medium">{ioc.value}</span>
                    <span className="text-[10px] text-[#8c97a8] shrink-0">{ioc.indicatorType.toUpperCase()}</span>
                  </div>
                  <div className="text-[10px] text-[#5d6778] mt-0.5 tabular-nums">
                    {ioc.assetIds.length} asset(s) · {ioc.incidentIds.length} incident(s)
                  </div>
                </button>
              );
            })}
          </div>
        </aside>

        <div className="flex-1 overflow-y-auto p-4 space-y-4">
          {!activeIoc ? (
            <div className="p-6 bg-[#12151b] border border-[#252b36] font-mono text-xs text-[#8c97a8]">
              No indicators available to inspect. Import infrastructure identifiers or ingest incidents first.
            </div>
          ) : (
            <>
              <div className="bg-[#12151b] border border-[#252b36] p-4 flex flex-wrap items-center justify-between gap-2">
                <div>
                  <div className="font-mono text-[10px] text-[#8fa36d] tracking-[0.12em]">
                    INDICATOR TYPE: {activeIoc.indicatorType.toUpperCase()}
                  </div>
                  <h2 className="text-base font-mono font-semibold text-[#e8ecf1] mt-0.5">{activeIoc.value}</h2>
                </div>
                <div className="flex items-center gap-2 font-mono text-xs">
                  <button
                    onClick={() => {
                      setAttributionSeedIndicator(activeIoc.value);
                      setSocSubTab('attribution');
                      onNavigateModule('threat_intelligence');
                    }}
                    className="px-2.5 py-1 bg-[#6f8054]/20 hover:bg-[#6f8054]/30 border border-[#6f8054]/50 text-[#e8ecf1] cursor-pointer"
                  >
                    Pivot to Attribution
                  </button>
                  <button
                    onClick={() => onNavigateModule('relationship_graph')}
                    className="px-2.5 py-1 bg-[#181c24] hover:bg-[#222834] border border-[#252b36] text-[#e8ecf1] cursor-pointer"
                  >
                    View in Relationship Graph
                  </button>
                </div>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <div className="bg-[#12151b] border border-[#252b36]">
                  <div className="px-3 py-2 border-b border-[#252b36] font-mono text-[11px] font-semibold text-[#e8ecf1]">
                    LINKED INFRASTRUCTURE ASSETS ({activeIoc.assetIds.length})
                  </div>
                  <div className="divide-y divide-[#1e242e]">
                    {activeIoc.assetIds.length === 0 ? (
                      <div className="p-3 text-xs text-[#8c97a8]">No registered asset directly declares this indicator.</div>
                    ) : (
                      activeIoc.assetIds.map((aid) => {
                        const a = intel.assets.find((x) => x.id === aid);
                        if (!a) return null;
                        const coord = intel.assetCoordsMap.get(a.id);
                        return (
                          <button
                            key={a.id}
                            onClick={() => onSelectEntity({ kind: 'asset', id: a.id })}
                            className="w-full p-2.5 text-left hover:bg-[#181c24] flex items-center justify-between font-mono text-[11px] cursor-pointer"
                          >
                            <div>
                              <div className="text-[#4a9eb0] font-semibold">
                                {a.site_code} — {a.name}
                              </div>
                              <div className="text-[#8c97a8] text-[10px]">
                                {a.type} · Tier {a.criticality} · {coord ? `${coord[1].toFixed(4)}, ${coord[0].toFixed(4)}` : 'No coord'}
                              </div>
                            </div>
                          </button>
                        );
                      })
                    )}
                  </div>
                </div>

                <div className="bg-[#12151b] border border-[#252b36]">
                  <div className="px-3 py-2 border-b border-[#252b36] font-mono text-[11px] font-semibold text-[#e8ecf1]">
                    OBSERVED IN CYBER INCIDENTS ({activeIoc.incidentIds.length})
                  </div>
                  <div className="divide-y divide-[#1e242e]">
                    {activeIoc.incidentIds.length === 0 ? (
                      <div className="p-3 text-xs text-[#8c97a8]">Indicator has not appeared in ingested incidents.</div>
                    ) : (
                      activeIoc.incidentIds.map((iid) => {
                        const inc = intel.incidents.find((x) => x.id === iid);
                        if (!inc) return null;
                        return (
                          <button
                            key={inc.id}
                            onClick={() => onSelectEntity({ kind: 'incident', id: inc.id })}
                            className="w-full p-2.5 text-left hover:bg-[#181c24] flex items-center justify-between font-mono text-[11px] cursor-pointer"
                          >
                            <div>
                              <div className="text-[#e8ecf1] font-semibold">
                                {inc.event_id} · {inc.event_type}
                              </div>
                              <div className="text-[#8c97a8] text-[10px]">
                                {new Date(inc.observed_at).toISOString().slice(0, 19).replace('T', ' ')} UTC
                              </div>
                            </div>
                            <span className={inc.severity === 'critical' ? 'text-[#c94a4a]' : 'text-[#c88b32]'}>
                              {inc.severity.toUpperCase()}
                            </span>
                          </button>
                        );
                      })
                    )}
                  </div>
                </div>
              </div>
            </>
          )}
        </div>

        <div className="w-80 border-l border-[#252b36] hidden xl:block overflow-hidden">
          <IntelligenceDossierPanel
            selectedEntity={selectedEntity}
            intel={intel}
            onSelectEntity={onSelectEntity}
            onNavigateModule={onNavigateModule}
          />
        </div>
      </div>
    );
  }

  // =========================================================================
  // VULNERABILITY INTELLIGENCE
  // =========================================================================
  if (mode === 'vulnerability_intelligence') {
    return (
      <div className="flex-1 flex flex-col overflow-hidden bg-[#0b0d10]">
        <div className="px-4 py-2 border-b border-[#252b36] bg-[#12151b] flex items-center justify-between shrink-0">
          <div>
            <div className="font-mono text-[10px] tracking-[0.12em] text-[#8fa36d]">
              CYBER INTELLIGENCE // VULNERABILITY & CONSEQUENCE EXPOSURE
            </div>
            <h1 className="text-sm font-semibold text-[#e8ecf1]">
              Downstream Infrastructure Vulnerability & Blast Consequence
            </h1>
          </div>
          <span className="font-mono text-[10px] text-[#c88b32] border border-[#c88b32]/40 bg-[#c88b32]/10 px-2 py-0.5">
            NO CVE FEED ATTACHED — DETERMINISTIC EXPOSURE ACTIVE
          </span>
        </div>
        <div className="flex-1 overflow-y-auto">
          <BlastRadiusScreen activeOrgId={intel.orgId} />
        </div>
      </div>
    );
  }

  // =========================================================================
  // DEFAULT ENTERPRISE SOC WORKSTATION
  // (threat_intelligence | cyber_monitoring | cyber_incidents)
  // =========================================================================
  const filteredIncidents = intel.incidents.filter((inc) => {
    if (severityFilter !== 'all' && inc.severity !== severityFilter) return false;
    if (socQuery.trim()) {
      const q = socQuery.toLowerCase();
      const hay = `${inc.event_id} ${inc.event_type} ${inc.source} ${JSON.stringify(inc.signals || {})}`.toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });

  // Auto-select appropriate sub-tab when navigating specifically to intake vs incidents vs monitoring
  const activeTabView = socSubTab;

  return (
    <div className="flex-1 flex flex-col overflow-hidden bg-[#0b0d10]">
      {/* SOC Telemetry Header & Sub-Tab Strip */}
      <div className="px-3 py-2 border-b border-[#252b36] bg-[#12151b] flex flex-wrap items-center justify-between gap-2 shrink-0">
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-1.5">
            <Radio className="w-3.5 h-3.5 text-[#c94a4a]" />
            <span className="font-mono text-xs font-semibold text-[#e8ecf1]">
              {mode === 'threat_intelligence'
                ? 'THREAT INTELLIGENCE CENTER'
                : mode === 'cyber_monitoring'
                ? 'CYBER THREAT MONITORING'
                : 'CYBER INCIDENT MANAGEMENT'}
            </span>
          </div>
          <div className="hidden md:flex items-center gap-3 font-mono text-[11px] tabular-nums">
            <span className="text-[#c94a4a]">CRIT: {severityCounts.critical}</span>
            <span className="text-[#c88b32]">HIGH: {severityCounts.high}</span>
            <span className="text-[#4a9eb0]">MED: {severityCounts.medium}</span>
            <span className="text-[#8c97a8]">LOW: {severityCounts.low}</span>
            <span className="text-[#323a48]">|</span>
            <span className="text-[#c88b32]">PROPOSED MATCHES: {severityCounts.proposed}</span>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-1 font-mono text-[11px]">
          {(
            [
              ['events', 'Events', Radio],
              ['intake', 'Intake & Triage', Send],
              ['custody', 'Custody', FileCheck],
              ['blast', 'Blast Radius', Flame],
              ['cti', 'CTI Feeds', Rss],
              ['terminal', 'Terminal', Terminal],
              ['attribution', 'Attribution', ShieldAlert],
            ] as const
          ).map(([id, label, Icon]) => (
            <button
              key={id}
              onClick={() => setSocSubTab(id)}
              className={`px-2 py-1 border rounded-[2px] flex items-center gap-1 cursor-pointer ${
                activeTabView === id
                  ? 'bg-[#6f8054]/25 border-[#6f8054] text-[#e8ecf1]'
                  : 'bg-[#0b0d10] border-[#252b36] text-[#8c97a8] hover:text-[#e8ecf1]'
              }`}
            >
              <Icon className="w-3 h-3" />
              <span>{label}</span>
            </button>
          ))}
          <button
            onClick={() => setDossierOpen((v) => !v)}
            className="ml-1 p-1 bg-[#0b0d10] border border-[#252b36] text-[#8c97a8] hover:text-[#e8ecf1] cursor-pointer"
            title="Toggle Entity Dossier"
          >
            {dossierOpen ? <PanelRightClose className="w-3.5 h-3.5" /> : <PanelRightOpen className="w-3.5 h-3.5" />}
          </button>
        </div>
      </div>

      {/* Main SOC Content + Optional Dossier */}
      <div className="flex-1 flex min-h-0 overflow-hidden">
        <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
          {activeTabView === 'events' && (
            <>
              <div className="px-3 py-1.5 border-b border-[#252b36] bg-[#0e1116] flex flex-wrap items-center justify-between gap-2 shrink-0 font-mono text-[11px]">
                <div className="flex items-center gap-2">
                  <select
                    value={severityFilter}
                    onChange={(e) => setSeverityFilter(e.target.value)}
                    className="bg-[#0b0d10] border border-[#252b36] text-[#e8ecf1] px-2 py-0.5 text-[11px]"
                  >
                    <option value="all">All Severities ({intel.incidents.length})</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                  <input
                    type="text"
                    value={socQuery}
                    onChange={(e) => setSocQuery(e.target.value)}
                    placeholder="Filter Event ID, type, IP, site code..."
                    className="bg-[#0b0d10] border border-[#252b36] text-[#e8ecf1] px-2 py-0.5 text-[11px] w-60 focus:outline-none focus:border-[#6f8054]"
                  />
                </div>
                <button
                  onClick={() => setSocSubTab('intake')}
                  className="px-2.5 py-0.5 bg-[#6f8054]/20 hover:bg-[#6f8054]/30 border border-[#6f8054]/50 text-[#e8ecf1] cursor-pointer"
                >
                  Open Signed Intake / Review Matches →
                </button>
              </div>

              <div className="flex-1 overflow-auto">
                <table className="w-full text-left font-mono text-[11px] border-collapse">
                  <thead className="sticky top-0 bg-[#12151b] border-b border-[#252b36] text-[#8c97a8] text-[10px]">
                    <tr>
                      <th className="py-2 px-3">TIMESTAMP (UTC)</th>
                      <th className="py-2 px-2">EVENT ID</th>
                      <th className="py-2 px-2">SOURCE</th>
                      <th className="py-2 px-2">CATEGORY</th>
                      <th className="py-2 px-2">SEVERITY</th>
                      <th className="py-2 px-2">GEO / ASSET CONTEXT</th>
                      <th className="py-2 px-2 text-right">CONFIDENCE</th>
                      <th className="py-2 px-3 text-right">MATCH STATUS</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#181c24]">
                    {filteredIncidents.length === 0 ? (
                      <tr>
                        <td colSpan={8} className="py-8 text-center text-[#8c97a8] font-sans">
                          No security incidents match the current filter.
                        </td>
                      </tr>
                    ) : (
                      filteredIncidents.map((inc) => {
                        const incMatches = intel.matches.filter((m) => m.incident_id === inc.id);
                        const linkedSites = incMatches
                          .map((m) => m.asset?.site_code || m.asset_id.slice(0, 6))
                          .join(', ');
                        const hasProposed = incMatches.some((m) => m.status === 'proposed');
                        const hasConfirmed = incMatches.some((m) => m.status === 'confirmed' || m.status === 'auto');
                        const statusLabel = hasProposed
                          ? 'REVIEW REQUIRED'
                          : hasConfirmed
                          ? 'CORRELATED'
                          : incMatches.length > 0
                          ? 'REJECTED'
                          : 'TELEMETRY ONLY';

                        const isSelected = selectedEntity?.kind === 'incident' && selectedEntity.id === inc.id;

                        return (
                          <tr
                            key={inc.id}
                            onClick={() => {
                              onSelectEntity({ kind: 'incident', id: inc.id });
                              setDossierOpen(true);
                            }}
                            className={`cursor-pointer hover:bg-[#151922] ${
                              isSelected ? 'bg-[#6f8054]/15' : ''
                            }`}
                          >
                            <td className="py-1.5 px-3 text-[#8c97a8] tabular-nums whitespace-nowrap">
                              {new Date(inc.observed_at).toISOString().replace('T', ' ').slice(0, 19)}
                            </td>
                            <td className="py-1.5 px-2 text-[#e8ecf1] font-semibold">{inc.event_id}</td>
                            <td className="py-1.5 px-2 text-[#8c97a8]">{inc.source}</td>
                            <td className="py-1.5 px-2 text-[#e8ecf1]">{inc.event_type}</td>
                            <td className="py-1.5 px-2">
                              <span
                                className={
                                  inc.severity === 'critical'
                                    ? 'text-[#c94a4a] font-semibold'
                                    : inc.severity === 'high'
                                    ? 'text-[#c88b32] font-semibold'
                                    : inc.severity === 'medium'
                                    ? 'text-[#4a9eb0]'
                                    : 'text-[#8c97a8]'
                                }
                              >
                                {inc.severity.toUpperCase()}
                              </span>
                            </td>
                            <td className="py-1.5 px-2 text-[#4a9eb0] truncate max-w-[200px]">
                              {linkedSites || 'Unlinked'}
                            </td>
                            <td className="py-1.5 px-2 text-right tabular-nums text-[#e8ecf1]">
                              {(Number(inc.confidence) * 100).toFixed(0)}%
                            </td>
                            <td className="py-1.5 px-3 text-right">
                              <span
                                className={
                                  hasProposed
                                    ? 'text-[#c88b32]'
                                    : hasConfirmed
                                    ? 'text-[#4f8f66]'
                                    : 'text-[#8c97a8]'
                                }
                              >
                                {statusLabel}
                              </span>
                            </td>
                          </tr>
                        );
                      })
                    )}
                  </tbody>
                </table>
              </div>
            </>
          )}

          {activeTabView === 'intake' && (
            <div className="flex-1 overflow-y-auto">
              <IncidentIntakeScreen
                activeOrgId={intel.orgId}
                userRole={activeRole}
                onNavigateToBlastRadius={() => setSocSubTab('blast')}
              />
            </div>
          )}

          {activeTabView === 'custody' && (
            <div className="flex-1 overflow-y-auto p-4">
              <TimelineAndEvidenceScreen activeOrgId={intel.orgId} activeRole={activeRole} />
            </div>
          )}

          {activeTabView === 'blast' && (
            <div className="flex-1 overflow-y-auto">
              <BlastRadiusScreen activeOrgId={intel.orgId} />
            </div>
          )}

          {activeTabView === 'cti' && (
            <ThreatIntelAdaptersPanel
              intel={intel}
              onSelectEntity={onSelectEntity}
              onIndicatorsChange={setExternalIndicators}
              onSendToAttribution={(val) => {
                setAttributionSeedIndicator(val);
                setSocSubTab('attribution');
              }}
            />
          )}

          {activeTabView === 'terminal' && (
            <DefensiveTerminal
              intel={intel}
              activeRole={activeRole}
              userEmail={userEmail}
              onSelectEntity={onSelectEntity}
              externalIndicators={externalIndicators}
              attributionRecords={attributionRecords}
            />
          )}

          {activeTabView === 'attribution' && (
            <AttributionWorkbench
              intel={intel}
              activeRole={activeRole}
              userEmail={userEmail}
              onSelectEntity={onSelectEntity}
              initialIndicator={attributionSeedIndicator}
              onRecordsChange={setAttributionRecords}
            />
          )}
        </div>

        {dossierOpen && (
          <div className="w-80 xl:w-96 border-l border-[#252b36] shrink-0 overflow-hidden hidden lg:block">
            <IntelligenceDossierPanel
              selectedEntity={selectedEntity}
              intel={intel}
              onSelectEntity={onSelectEntity}
              onNavigateModule={onNavigateModule}
              onClose={() => setDossierOpen(false)}
            />
          </div>
        )}
      </div>
    </div>
  );
};
