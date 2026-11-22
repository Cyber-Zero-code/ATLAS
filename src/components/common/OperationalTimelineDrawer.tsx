import React, { useMemo, useState } from 'react';
import { SelectedEntity } from '../../types/atlas';
import { WorkspaceIntelligenceState } from '../../hooks/useWorkspaceIntelligence';
import { ChevronDown, ChevronUp, Clock, Filter, Search } from 'lucide-react';

interface OperationalTimelineDrawerProps {
  intel: WorkspaceIntelligenceState;
  collapsed: boolean;
  onToggleCollapse: () => void;
  onSelectEntity: (entity: SelectedEntity) => void;
}

interface UnifiedTimelineEntry {
  id: string;
  timestamp: string;
  category: 'INCIDENT' | 'MATCH' | 'TOPOLOGY' | 'CUSTODY' | 'LEDGER';
  severity: 'critical' | 'high' | 'medium' | 'info';
  title: string;
  detail: string;
  siteContext: string;
  targetEntity: SelectedEntity;
}

export const OperationalTimelineDrawer: React.FC<OperationalTimelineDrawerProps> = ({
  intel,
  collapsed,
  onToggleCollapse,
  onSelectEntity,
}) => {
  const [timeWindow, setTimeWindow] = useState<'all' | '24h' | '7d' | '30d'>('all');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [categoryFilter, setCategoryFilter] = useState<string>('all');
  const [areaQuery, setAreaQuery] = useState<string>('');

  const assetSiteMap = useMemo(() => {
    const map = new Map<string, string>();
    for (const a of intel.assets) {
      map.set(a.id, `${a.site_code} ${a.name}`);
    }
    return map;
  }, [intel.assets]);

  const entries = useMemo<UnifiedTimelineEntry[]>(() => {
    const list: UnifiedTimelineEntry[] = [];

    for (const inc of intel.incidents) {
      const linkedSites = intel.matches
        .filter((m) => m.incident_id === inc.id)
        .map((m) => assetSiteMap.get(m.asset_id) || '')
        .filter(Boolean)
        .join(', ');

      list.push({
        id: `tl-inc-${inc.id}`,
        timestamp: inc.observed_at,
        category: 'INCIDENT',
        severity: inc.severity === 'low' ? 'info' : inc.severity,
        title: `${inc.event_id} · ${inc.event_type}`,
        detail: `Source: ${inc.source} · Confidence ${(Number(inc.confidence) * 100).toFixed(0)}%`,
        siteContext: linkedSites || 'Unmapped / Telemetry Only',
        targetEntity: { kind: 'incident', id: inc.id },
      });
    }

    for (const m of intel.matches) {
      const inc = intel.incidents.find((i) => i.id === m.incident_id);
      const site = assetSiteMap.get(m.asset_id) || m.asset_id.slice(0, 8);
      list.push({
        id: `tl-match-${m.id}`,
        timestamp: m.decided_at || m.created_at,
        category: 'MATCH',
        severity: m.status === 'proposed' ? 'high' : 'info',
        title: `Match ${m.status.toUpperCase()} (${(Number(m.score) * 100).toFixed(0)}%) via ${m.rule_fired}`,
        detail: `${inc?.event_id || m.incident_id.slice(0, 8)} → ${site}`,
        siteContext: site,
        targetEntity: { kind: 'asset', id: m.asset_id },
      });
    }

    for (const ev of intel.evidence) {
      list.push({
        id: `tl-ev-${ev.id}`,
        timestamp: ev.created_at,
        category: 'CUSTODY',
        severity: 'info',
        title: `Evidence Registered: ${ev.file_name}`,
        detail: `SHA-256 ${ev.sha256.slice(0, 16)}... · Custody events: ${ev.custody_events?.length || 0}`,
        siteContext: ev.target_type,
        targetEntity: { kind: 'evidence', id: ev.id },
      });
    }

    for (const ae of intel.auditEvents.slice(0, 60)) {
      const cat: UnifiedTimelineEntry['category'] =
        ae.target_type === 'dependency_edges' || ae.target_type === 'assets'
          ? 'TOPOLOGY'
          : ae.target_type === 'evidence' || ae.target_type === 'custody_events'
          ? 'CUSTODY'
          : ae.target_type === 'incidents'
          ? 'INCIDENT'
          : 'LEDGER';

      list.push({
        id: `tl-ae-${ae.id}`,
        timestamp: ae.timestamp,
        category: cat,
        severity: 'info',
        title: `Ledger #${ae.seq} · ${ae.action}`,
        detail: `${ae.target_type}:${ae.target_id.slice(0, 12)} · ${ae.actor_role}`,
        siteContext: assetSiteMap.get(ae.target_id) || ae.target_type,
        targetEntity:
          ae.target_type === 'assets'
            ? { kind: 'asset', id: ae.target_id }
            : ae.target_type === 'incidents'
            ? { kind: 'incident', id: ae.target_id }
            : null,
      });
    }

    return list.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
  }, [intel.incidents, intel.matches, intel.evidence, intel.auditEvents, assetSiteMap]);

  const filteredEntries = useMemo(() => {
    const now = Date.now();
    const q = areaQuery.trim().toLowerCase();

    return entries.filter((e) => {
      if (severityFilter !== 'all' && e.severity !== severityFilter) return false;
      if (categoryFilter !== 'all' && e.category !== categoryFilter) return false;

      if (timeWindow !== 'all') {
        const ms = now - new Date(e.timestamp).getTime();
        const maxMs =
          timeWindow === '24h'
            ? 24 * 3600 * 1000
            : timeWindow === '7d'
            ? 7 * 24 * 3600 * 1000
            : 30 * 24 * 3600 * 1000;
        if (ms > maxMs) return false;
      }

      if (q) {
        const hay = `${e.title} ${e.detail} ${e.siteContext}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }

      return true;
    });
  }, [entries, severityFilter, categoryFilter, timeWindow, areaQuery]);

  return (
    <section className="bg-[#0e1116] border-t border-[#252b36] flex flex-col shrink-0 select-none">
      {/* Header / Filter Bar */}
      <div className="h-8 px-3 border-b border-[#252b36] flex items-center justify-between gap-3 bg-[#12151b]">
        <div className="flex items-center gap-3 min-w-0">
          <button
            onClick={onToggleCollapse}
            className="flex items-center gap-1.5 font-mono text-[10px] tracking-[0.12em] text-[#e8ecf1] font-semibold cursor-pointer hover:text-[#8fa36d]"
          >
            {collapsed ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
            <Clock className="w-3 h-3 text-[#8c97a8]" />
            <span>OPERATIONAL TIMELINE</span>
            <span className="text-[#8c97a8] font-normal tabular-nums">({filteredEntries.length})</span>
          </button>

          {!collapsed && (
            <div className="hidden md:flex items-center gap-2 text-[11px] font-mono">
              <Filter className="w-3 h-3 text-[#5d6778]" />
              <select
                aria-label="Timeline window"
                value={timeWindow}
                onChange={(e) => setTimeWindow(e.target.value as any)}
                className="bg-[#0b0d10] border border-[#252b36] text-[#e8ecf1] px-1.5 py-0.5 rounded-[2px] text-[10px]"
              >
                <option value="all">All Time</option>
                <option value="24h">Last 24h</option>
                <option value="7d">Last 7d</option>
                <option value="30d">Last 30d</option>
              </select>

              <select
                aria-label="Timeline severity"
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                className="bg-[#0b0d10] border border-[#252b36] text-[#e8ecf1] px-1.5 py-0.5 rounded-[2px] text-[10px]"
              >
                <option value="all">All Severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="info">Info / Routine</option>
              </select>

              <select
                aria-label="Timeline category"
                value={categoryFilter}
                onChange={(e) => setCategoryFilter(e.target.value)}
                className="bg-[#0b0d10] border border-[#252b36] text-[#e8ecf1] px-1.5 py-0.5 rounded-[2px] text-[10px]"
              >
                <option value="all">All Categories</option>
                <option value="INCIDENT">Cyber Incidents</option>
                <option value="MATCH">Threat Matches</option>
                <option value="TOPOLOGY">Infra / Topology</option>
                <option value="CUSTODY">Evidence Custody</option>
                <option value="LEDGER">Audit Ledger</option>
              </select>

              <div className="relative flex items-center">
                <Search className="w-3 h-3 text-[#5d6778] absolute left-1.5 pointer-events-none" />
                <input
                  type="text"
                  value={areaQuery}
                  onChange={(e) => setAreaQuery(e.target.value)}
                  placeholder="Site / geo / filter..."
                  className="bg-[#0b0d10] border border-[#252b36] text-[#e8ecf1] pl-5 pr-2 py-0.5 rounded-[2px] text-[10px] w-36 focus:outline-none focus:border-[#6f8054]"
                />
              </div>
            </div>
          )}
        </div>

        <button
          onClick={onToggleCollapse}
          className="text-[10px] font-mono text-[#8c97a8] hover:text-[#e8ecf1] cursor-pointer"
        >
          {collapsed ? 'EXPAND' : 'COLLAPSE'}
        </button>
      </div>

      {/* Table Body */}
      {!collapsed && (
        <div className="h-44 overflow-y-auto bg-[#0b0d10]">
          <table className="w-full text-left text-[11px] border-collapse">
            <thead className="sticky top-0 bg-[#12151b] border-b border-[#252b36] font-mono text-[10px] text-[#8c97a8]">
              <tr>
                <th className="py-1.5 px-3 font-medium w-40">UTC TIMESTAMP</th>
                <th className="py-1.5 px-2 font-medium w-24">CATEGORY</th>
                <th className="py-1.5 px-2 font-medium w-20">SEVERITY</th>
                <th className="py-1.5 px-2 font-medium">EVENT</th>
                <th className="py-1.5 px-2 font-medium">SITE / GEOGRAPHIC CONTEXT</th>
                <th className="py-1.5 px-3 font-medium text-right">DETAIL</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#181c24] font-mono">
              {filteredEntries.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-6 text-center text-[#5d6778] font-sans text-xs">
                    No operational events match the active filters.
                  </td>
                </tr>
              ) : (
                filteredEntries.slice(0, 80).map((item) => (
                  <tr
                    key={item.id}
                    onClick={() => item.targetEntity && onSelectEntity(item.targetEntity)}
                    className={`hover:bg-[#151922] transition-colors ${
                      item.targetEntity ? 'cursor-pointer' : ''
                    }`}
                  >
                    <td className="py-1 px-3 text-[#8c97a8] tabular-nums whitespace-nowrap">
                      {new Date(item.timestamp).toISOString().replace('T', ' ').slice(0, 19)}
                    </td>
                    <td className="py-1 px-2 text-[#8c97a8]">{item.category}</td>
                    <td className="py-1 px-2">
                      <span
                        className={
                          item.severity === 'critical'
                            ? 'text-[#c94a4a] font-semibold'
                            : item.severity === 'high'
                            ? 'text-[#c88b32] font-semibold'
                            : item.severity === 'medium'
                            ? 'text-[#4a9eb0]'
                            : 'text-[#8c97a8]'
                        }
                      >
                        {item.severity.toUpperCase()}
                      </span>
                    </td>
                    <td className="py-1 px-2 text-[#e8ecf1] font-sans font-medium truncate max-w-xs">
                      {item.title}
                    </td>
                    <td className="py-1 px-2 text-[#4a9eb0] truncate max-w-[200px]">
                      {item.siteContext}
                    </td>
                    <td className="py-1 px-3 text-[#8c97a8] text-right truncate max-w-xs">
                      {item.detail}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
};
