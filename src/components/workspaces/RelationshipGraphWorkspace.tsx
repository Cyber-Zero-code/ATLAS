import React, { useMemo, useState } from 'react';
import { AppRole, ModuleId, SelectedEntity } from '../../types/atlas';
import { WorkspaceIntelligenceState } from '../../hooks/useWorkspaceIntelligence';
import { shortestPathUndirected } from '../../utils/intelligence';
import { analyzeInfrastructureResilience } from '../../utils/resilience';
import { ResilienceModulePanel } from '../analysis/ResilienceModulePanel';
import { IntelligenceDossierPanel } from '../common/IntelligenceDossierPanel';
import { DependencyEditorScreen } from '../DependencyEditorScreen';
import { BlastRadiusScreen } from '../BlastRadiusScreen';
import { atlasService } from '../../data/api';
import {
  Share2,
  ZoomIn,
  ZoomOut,
  RotateCcw,
  ChevronDown,
  ChevronUp,
  PanelLeftClose,
  PanelLeftOpen,
  FileText,
  Download,
  Search,
  GitFork,
  Route,
  CheckCircle2,
  Activity,
} from 'lucide-react';

interface RelationshipGraphWorkspaceProps {
  mode:
    | 'entity_intelligence'
    | 'relationship_graph'
    | 'network_analysis'
    | 'geospatial_correlation'
    | 'intelligence_reports';
  intel: WorkspaceIntelligenceState;
  activeRole: AppRole;
  userEmail: string;
  selectedEntity: SelectedEntity;
  onSelectEntity: (entity: SelectedEntity) => void;
  onNavigateModule: (module: ModuleId) => void;
}

type GraphNodeKind = 'organisation' | 'incident' | 'asset' | 'indicator' | 'evidence';
type GraphEdgeCertainty = 'CONFIRMED' | 'PROBABLE' | 'UNVERIFIED' | 'TOPOLOGY' | 'SIGNAL';

interface GraphNode {
  id: string;
  label: string;
  sublabel: string;
  kind: GraphNodeKind;
  x: number;
  y: number;
  entityRef: SelectedEntity;
  criticality?: number;
  degree: number;
}

interface GraphEdge {
  id: string;
  source: string;
  target: string;
  relation: string;
  certainty: GraphEdgeCertainty;
  confidence: number;
  sourceRef: string;
}

const NODE_COLORS: Record<GraphNodeKind, { fill: string; stroke: string; text: string }> = {
  organisation: { fill: '#1c2319', stroke: '#8fa36d', text: '#8fa36d' },
  incident: { fill: '#2a1618', stroke: '#c94a4a', text: '#e8ecf1' },
  asset: { fill: '#122229', stroke: '#4a9eb0', text: '#e8ecf1' },
  indicator: { fill: '#261e13', stroke: '#c88b32', text: '#e8ecf1' },
  evidence: { fill: '#18241d', stroke: '#4f8f66', text: '#e8ecf1' },
};

const CERTAINTY_COLORS: Record<GraphEdgeCertainty, string> = {
  CONFIRMED: '#4f8f66',
  PROBABLE: '#4a9eb0',
  UNVERIFIED: '#c88b32',
  TOPOLOGY: '#5682b0',
  SIGNAL: '#5d6778',
};

export const RelationshipGraphWorkspace: React.FC<RelationshipGraphWorkspaceProps> = ({
  mode,
  intel,
  activeRole,
  userEmail,
  selectedEntity,
  onSelectEntity,
  onNavigateModule,
}) => {
  // Interactive Graph States
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [dragging, setDragging] = useState<{ startX: number; startY: number; origX: number; origY: number } | null>(null);
  const [leftFilterOpen, setLeftFilterOpen] = useState(true);
  const [edgeTableCollapsed, setEdgeTableCollapsed] = useState(false);

  const [kindVisibility, setKindVisibility] = useState<Record<GraphNodeKind, boolean>>({
    organisation: true,
    incident: true,
    asset: true,
    indicator: true,
    evidence: true,
  });
  const [certaintyFilter, setCertaintyFilter] = useState<'all' | GraphEdgeCertainty>('all');
  const [hopLimit, setHopLimit] = useState<'all' | 1 | 2>('all');
  const [focusNodeId, setFocusNodeId] = useState<string | null>(null);
  const [pathStartId, setPathStartId] = useState<string>('');
  const [pathEndId, setPathEndId] = useState<string>('');

  // Entity Explorer State
  const [entitySearch, setEntitySearch] = useState('');

  // Report Export State
  const [reportNote, setReportNote] = useState('');
  const [exportStatus, setExportStatus] = useState<string | null>(null);

  // Module F: Network Resilience & Cascade Simulation State
  const [networkSubTab, setNetworkSubTab] = useState<'topology' | 'resilience'>('topology');

  const spofCount = useMemo(
    () =>
      analyzeInfrastructureResilience(
        intel.assets,
        intel.edges,
        intel.assetCoordsMap,
        intel.matches
      ).filter((r) => r.isSinglePointOfFailure).length,
    [intel.assets, intel.edges, intel.assetCoordsMap, intel.matches]
  );

  // Build Full Knowledge Graph from Real Workspace Data
  const { allNodes, allEdges } = useMemo(() => {
    const nodes: GraphNode[] = [];
    const edges: GraphEdge[] = [];
    const nodeIds = new Set<string>();

    const addNode = (n: Omit<GraphNode, 'degree'>) => {
      if (nodeIds.has(n.id)) return;
      nodeIds.add(n.id);
      nodes.push({ ...n, degree: 0 });
    };

    // Column layout anchors for clean deterministic Gotham-like layering
    const orgNodeId = `org:${intel.orgId}`;
    addNode({
      id: orgNodeId,
      label: 'ACTIVE WORKSPACE',
      sublabel: intel.orgId.slice(0, 8),
      kind: 'organisation',
      x: 90,
      y: 260,
      entityRef: null,
    });

    // Incidents column
    intel.incidents.slice(0, 14).forEach((inc, idx) => {
      const nid = `incident:${inc.id}`;
      addNode({
        id: nid,
        label: inc.event_id,
        sublabel: `${inc.severity.toUpperCase()} · ${inc.event_type}`,
        kind: 'incident',
        x: 270,
        y: 80 + idx * 78,
        entityRef: { kind: 'incident', id: inc.id },
      });
      edges.push({
        id: `e-org-${inc.id}`,
        source: orgNodeId,
        target: nid,
        relation: 'OBSERVED_IN',
        certainty: 'SIGNAL',
        confidence: Number(inc.confidence) || 1,
        sourceRef: inc.source,
      });
    });

    // Assets column
    intel.assets.slice(0, 24).forEach((asset, idx) => {
      const nid = `asset:${asset.id}`;
      addNode({
        id: nid,
        label: asset.site_code,
        sublabel: `${asset.name} (T${asset.criticality})`,
        kind: 'asset',
        x: 540,
        y: 65 + idx * 66,
        entityRef: { kind: 'asset', id: asset.id },
        criticality: asset.criticality,
      });

      // Asset -> Indicators
      const iocs: Array<[string, 'hostname' | 'ip' | 'cidr' | 'cloud_account']> = [
        ...(asset.identifiers?.hostnames || []).slice(0, 2).map((v) => [v, 'hostname'] as [string, 'hostname']),
        ...(asset.identifiers?.ip_addresses || []).slice(0, 2).map((v) => [v, 'ip'] as [string, 'ip']),
        ...(asset.identifiers?.cidrs || []).slice(0, 1).map((v) => [v, 'cidr'] as [string, 'cidr']),
        ...(asset.identifiers?.cloud_account_ids || []).slice(0, 1).map((v) => [v, 'cloud_account'] as [string, 'cloud_account']),
      ];

      iocs.forEach(([val, iType], iIdx) => {
        const indId = `indicator:${iType}:${val}`;
        addNode({
          id: indId,
          label: val,
          sublabel: iType.toUpperCase(),
          kind: 'indicator',
          x: 820,
          y: 60 + idx * 66 + iIdx * 30,
          entityRef: { kind: 'indicator', value: val, indicatorType: iType },
        });
        edges.push({
          id: `e-ai-${asset.id}-${indId}`,
          source: nid,
          target: indId,
          relation: 'HAS_IDENTIFIER',
          certainty: 'SIGNAL',
          confidence: 1,
          sourceRef: asset.source,
        });
      });
    });

    // Incident -> Asset Matches
    for (const m of intel.matches) {
      if (m.status === 'rejected') continue;
      const srcId = `incident:${m.incident_id}`;
      const dstId = `asset:${m.asset_id}`;
      if (!nodeIds.has(srcId) || !nodeIds.has(dstId)) continue;

      const certainty: GraphEdgeCertainty =
        m.status === 'confirmed' ? 'CONFIRMED' : m.status === 'auto' ? 'PROBABLE' : 'UNVERIFIED';

      edges.push({
        id: `e-match-${m.id}`,
        source: srcId,
        target: dstId,
        relation: m.rule_fired.toUpperCase(),
        certainty,
        confidence: Number(m.score),
        sourceRef: m.source,
      });
    }

    // Asset -> Asset Dependency Edges
    for (const dep of intel.edges) {
      const srcId = `asset:${dep.from_asset_id}`;
      const dstId = `asset:${dep.to_asset_id}`;
      if (!nodeIds.has(srcId) || !nodeIds.has(dstId)) continue;
      edges.push({
        id: `e-dep-${dep.id}`,
        source: srcId,
        target: dstId,
        relation: dep.relation_type.toUpperCase(),
        certainty: 'TOPOLOGY',
        confidence: Number(dep.confidence) || 1,
        sourceRef: dep.source,
      });
    }

    // Evidence Nodes linked to Incident or Asset
    intel.evidence.slice(0, 12).forEach((ev, idx) => {
      const eid = `evidence:${ev.id}`;
      const targetNodeId =
        ev.target_type.toLowerCase() === 'incident'
          ? `incident:${ev.target_id}`
          : `asset:${ev.target_id}`;
      addNode({
        id: eid,
        label: ev.file_name,
        sublabel: `SHA256:${ev.sha256.slice(0, 10)}`,
        kind: 'evidence',
        x: 820,
        y: 420 + idx * 62,
        entityRef: { kind: 'evidence', id: ev.id },
      });
      if (nodeIds.has(targetNodeId)) {
        edges.push({
          id: `e-ev-${ev.id}`,
          source: targetNodeId,
          target: eid,
          relation: 'HAS_EVIDENCE',
          certainty: 'CONFIRMED',
          confidence: 1,
          sourceRef: ev.source,
        });
      }
    });

    // Compute node degrees
    const degMap = new Map<string, number>();
    for (const e of edges) {
      degMap.set(e.source, (degMap.get(e.source) || 0) + 1);
      degMap.set(e.target, (degMap.get(e.target) || 0) + 1);
    }
    for (const n of nodes) {
      n.degree = degMap.get(n.id) || 0;
    }

    return { allNodes: nodes, allEdges: edges };
  }, [intel.orgId, intel.incidents, intel.assets, intel.matches, intel.edges, intel.evidence]);

  // Apply Kind, Certainty, and Hop Filters
  const { visibleNodes, visibleEdges, shortestPathIds } = useMemo(() => {
    let edges = allEdges.filter((e) => certaintyFilter === 'all' || e.certainty === certaintyFilter);
    let allowedIds = new Set(allNodes.filter((n) => kindVisibility[n.kind]).map((n) => n.id));
    edges = edges.filter((e) => allowedIds.has(e.source) && allowedIds.has(e.target));

    if (focusNodeId && hopLimit !== 'all' && allowedIds.has(focusNodeId)) {
      const hopSet = new Set<string>([focusNodeId]);
      let frontier = new Set<string>([focusNodeId]);
      for (let h = 0; h < hopLimit; h++) {
        const nextFrontier = new Set<string>();
        for (const e of edges) {
          if (frontier.has(e.source) && !hopSet.has(e.target)) {
            hopSet.add(e.target);
            nextFrontier.add(e.target);
          }
          if (frontier.has(e.target) && !hopSet.has(e.source)) {
            hopSet.add(e.source);
            nextFrontier.add(e.source);
          }
        }
        frontier = nextFrontier;
      }
      allowedIds = hopSet;
      edges = edges.filter((e) => allowedIds.has(e.source) && allowedIds.has(e.target));
    }

    const shortest = shortestPathUndirected(edges, allowedIds, pathStartId, pathEndId);
    const pathNodes = shortest.nodes;
    const pathEdges = shortest.edges;

    const nodes = allNodes.filter((n) => allowedIds.has(n.id));
    return {
      visibleNodes: nodes,
      visibleEdges: edges,
      shortestPathIds: { nodes: pathNodes, edges: pathEdges },
    };
  }, [allNodes, allEdges, kindVisibility, certaintyFilter, focusNodeId, hopLimit, pathStartId, pathEndId]);

  const nodeLookup = useMemo(() => {
    const map = new Map<string, GraphNode>();
    for (const n of visibleNodes) map.set(n.id, n);
    return map;
  }, [visibleNodes]);

  // =========================================================================
  // 1. NETWORK ANALYSIS (DEPENDENCY EDITOR + CHOKEPOINT MATRIX + MODULE F)
  // =========================================================================
  if (mode === 'network_analysis') {
    const degreeStats = intel.assets
      .map((a) => ({
        asset: a,
        inDeg: intel.edges.filter((e) => e.to_asset_id === a.id).length,
        outDeg: intel.edges.filter((e) => e.from_asset_id === a.id).length,
      }))
      .filter((x) => x.inDeg + x.outDeg > 0)
      .sort((a, b) => b.outDeg + b.inDeg - (a.outDeg + a.inDeg));

    return (
      <div className="flex-1 flex flex-col overflow-hidden bg-[#0b0d10]">
        <div className="px-4 py-2 border-b border-[#252b36] bg-[#12151b] flex flex-wrap items-center justify-between gap-2 shrink-0">
          <div>
            <div className="font-mono text-[10px] tracking-[0.12em] text-[#8fa36d]">
              INTELLIGENCE ANALYSIS // NETWORK DEPENDENCY & RESILIENCE
            </div>
            <h1 className="text-sm font-semibold text-[#e8ecf1] flex items-center gap-2">
              <GitFork className="w-4 h-4 text-[#5682b0]" />
              <span>Infrastructure Dependencies, Chokepoints & Cascade Resilience</span>
            </h1>
          </div>

          <div className="flex items-center gap-1.5 font-mono text-[11px]">
            <button
              onClick={() => setNetworkSubTab('topology')}
              className={`px-2.5 py-1 border rounded-[2px] flex items-center gap-1.5 cursor-pointer ${
                networkSubTab === 'topology'
                  ? 'bg-[#6f8054]/25 border-[#6f8054] text-[#e8ecf1]'
                  : 'bg-[#0b0d10] border-[#252b36] text-[#8c97a8] hover:text-[#e8ecf1]'
              }`}
            >
              <GitFork className="w-3 h-3" />
              <span>Topology & Chokepoints</span>
            </button>
            <button
              onClick={() => setNetworkSubTab('resilience')}
              className={`px-2.5 py-1 border rounded-[2px] flex items-center gap-1.5 cursor-pointer ${
                networkSubTab === 'resilience'
                  ? 'bg-[#6f8054]/25 border-[#6f8054] text-[#e8ecf1]'
                  : 'bg-[#0b0d10] border-[#252b36] text-[#8c97a8] hover:text-[#e8ecf1]'
              }`}
            >
              <Activity className="w-3 h-3 text-[#c88b32]" />
              <span>Resilience & Cascade Simulator ({spofCount} SPOF)</span>
            </button>
          </div>
        </div>

        <div className="flex-1 overflow-y-auto">
          {networkSubTab === 'topology' ? (
            <>
              <DependencyEditorScreen activeOrgId={intel.orgId} userRole={activeRole} />
              <div className="px-6 pb-8 max-w-7xl mx-auto">
                <div className="bg-[#12151b] border border-[#252b36]">
                  <div className="px-3 py-2 border-b border-[#252b36] font-mono text-[11px] font-semibold text-[#e8ecf1] flex items-center justify-between">
                    <span className="flex items-center gap-1.5">
                      <GitFork className="w-3.5 h-3.5 text-[#5682b0]" />
                      <span>TOPOLOGICAL CHOKEPOINT ANALYSIS (IN/OUT DEGREE)</span>
                    </span>
                    <span className="text-[10px] text-[#8c97a8]">{degreeStats.length} CONNECTED NODES</span>
                  </div>
                  <table className="w-full text-left font-mono text-[11px] border-collapse">
                    <thead className="bg-[#0e1116] border-b border-[#252b36] text-[#8c97a8] text-[10px]">
                      <tr>
                        <th className="py-1.5 px-3">SITE CODE</th>
                        <th className="py-1.5 px-2">ASSET NAME</th>
                        <th className="py-1.5 px-2 text-right">OUT-DEGREE (PROVIDES TO)</th>
                        <th className="py-1.5 px-2 text-right">IN-DEGREE (DEPENDS ON)</th>
                        <th className="py-1.5 px-3 text-right">CRITICALITY</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#181c24]">
                      {degreeStats.map((d) => (
                        <tr key={d.asset.id} className="hover:bg-[#181c24]">
                          <td className="py-1.5 px-3 text-[#4a9eb0] font-semibold">{d.asset.site_code}</td>
                          <td className="py-1.5 px-2 text-[#e8ecf1] font-sans">{d.asset.name}</td>
                          <td className="py-1.5 px-2 text-right tabular-nums text-[#c88b32]">{d.outDeg}</td>
                          <td className="py-1.5 px-2 text-right tabular-nums text-[#4f8f66]">{d.inDeg}</td>
                          <td className="py-1.5 px-3 text-right tabular-nums text-[#e8ecf1]">T{d.asset.criticality}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </>
          ) : (
            <ResilienceModulePanel intel={intel} onSelectEntity={onSelectEntity} />
          )}
        </div>
      </div>
    );
  }

  // =========================================================================
  // 2. GEOSPATIAL CORRELATION
  // =========================================================================
  if (mode === 'geospatial_correlation') {
    return (
      <div className="flex-1 flex flex-col overflow-hidden bg-[#0b0d10]">
        <div className="px-4 py-2 border-b border-[#252b36] bg-[#12151b] flex items-center justify-between shrink-0">
          <div>
            <div className="font-mono text-[10px] tracking-[0.12em] text-[#8fa36d]">
              INTELLIGENCE ANALYSIS // GEOSPATIAL CORRELATION
            </div>
            <h1 className="text-sm font-semibold text-[#e8ecf1]">
              Cyber-to-Physical Blast Propagation & Coordinate Accuracy
            </h1>
          </div>
          <button
            onClick={() => onNavigateModule('global_map')}
            className="px-2.5 py-1 bg-[#181c24] hover:bg-[#222834] border border-[#252b36] font-mono text-xs text-[#e8ecf1] cursor-pointer"
          >
            Inspect on Global Map →
          </button>
        </div>
        <div className="flex-1 overflow-y-auto">
          <BlastRadiusScreen activeOrgId={intel.orgId} />
        </div>
      </div>
    );
  }

  // =========================================================================
  // 3. ENTITY INTELLIGENCE EXPLORER
  // =========================================================================
  if (mode === 'entity_intelligence') {
    const q = entitySearch.trim().toLowerCase();
    const matchedNodes = allNodes.filter(
      (n) => !q || `${n.label} ${n.sublabel} ${n.kind}`.toLowerCase().includes(q)
    );

    return (
      <div className="flex-1 flex overflow-hidden bg-[#0b0d10]">
        <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
          <div className="px-4 py-2.5 border-b border-[#252b36] bg-[#12151b] flex flex-wrap items-center justify-between gap-2 shrink-0">
            <div>
              <div className="font-mono text-[10px] tracking-[0.12em] text-[#8fa36d]">
                INTELLIGENCE ANALYSIS // UNIFIED ENTITY DIRECTORY
              </div>
              <h1 className="text-sm font-semibold text-[#e8ecf1]">
                Entity Intelligence ({matchedNodes.length} Graph Entities)
              </h1>
            </div>
            <div className="relative flex items-center">
              <Search className="w-3.5 h-3.5 text-[#5d6778] absolute left-2 pointer-events-none" />
              <input
                type="text"
                value={entitySearch}
                onChange={(e) => setEntitySearch(e.target.value)}
                placeholder="Search any entity..."
                className="bg-[#0b0d10] border border-[#252b36] pl-7 pr-2.5 py-1 text-xs font-mono text-[#e8ecf1] w-60 focus:outline-none focus:border-[#6f8054]"
              />
            </div>
          </div>

          <div className="flex-1 overflow-auto">
            <table className="w-full text-left font-mono text-[11px] border-collapse">
              <thead className="sticky top-0 bg-[#12151b] border-b border-[#252b36] text-[#8c97a8] text-[10px]">
                <tr>
                  <th className="py-2 px-3">TYPE</th>
                  <th className="py-2 px-2">PRIMARY IDENTIFIER</th>
                  <th className="py-2 px-2">METADATA SUMMARY</th>
                  <th className="py-2 px-3 text-right">LINKS (DEGREE)</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#181c24]">
                {matchedNodes.map((n) => (
                  <tr
                    key={n.id}
                    onClick={() => n.entityRef && onSelectEntity(n.entityRef)}
                    className={`hover:bg-[#151922] ${n.entityRef ? 'cursor-pointer' : ''}`}
                  >
                    <td className="py-1.5 px-3" style={{ color: NODE_COLORS[n.kind].stroke }}>
                      {n.kind.toUpperCase()}
                    </td>
                    <td className="py-1.5 px-2 text-[#e8ecf1] font-semibold">{n.label}</td>
                    <td className="py-1.5 px-2 text-[#8c97a8] font-sans">{n.sublabel}</td>
                    <td className="py-1.5 px-3 text-right tabular-nums text-[#e8ecf1]">{n.degree}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        <div className="w-80 xl:w-96 border-l border-[#252b36] hidden lg:block overflow-hidden">
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
  // 4. INTELLIGENCE REPORTS GENERATOR
  // =========================================================================
  if (mode === 'intelligence_reports') {
    const latestLedger = intel.auditEvents[0];
    const generatedAt = new Date().toISOString();
    const markdownBrief = [
      `# PROJECT ATLAS — CYBER-PHYSICAL INTELLIGENCE REPORT`,
      `Generated UTC: ${generatedAt}`,
      `Operator: ${userEmail} (${activeRole})`,
      `Workspace ID: ${intel.orgId}`,
      `Latest Ledger Seal: ${latestLedger ? `#${latestLedger.seq} / ${latestLedger.record_hash}` : 'N/A'}`,
      ``,
      `## 1. EXECUTIVE SUMMARY`,
      `- Monitored Physical Infrastructure Assets: ${intel.assets.length}`,
      `- Directed Dependency Edges: ${intel.edges.length}`,
      `- Active Cyber Incidents: ${intel.incidents.length} (${intel.incidents.filter((i) => i.severity === 'critical').length} Critical)`,
      `- Rule-Engine Asset Matches: ${intel.matches.length} (${intel.matches.filter((m) => m.status === 'proposed').length} Proposed / Unconfirmed)`,
      `- Registered Custody Evidence Files: ${intel.evidence.length}`,
      reportNote.trim() ? `\n## ANALYST ASSESSMENT NOTE\n${reportNote.trim()}\n` : '',
      `## 2. CRITICAL & EXPOSED INCIDENTS`,
      ...intel.incidents.slice(0, 15).map((inc) => {
        const ms = intel.matches.filter((m) => m.incident_id === inc.id);
        const sites = ms.map((m) => `${m.asset?.site_code || m.asset_id} [${m.status}]`).join(', ') || 'No asset matches';
        return `- **${inc.event_id}** (${inc.severity.toUpperCase()} / ${inc.event_type}) @ ${inc.observed_at} -> ${sites}`;
      }),
      ``,
      `## 3. INFRASTRUCTURE SPATIAL CONFIDENCE SUMMARY`,
      `- Exact Survey: ${intel.assets.filter((a) => a.accuracy_class === 'exact_survey').length}`,
      `- Approximate Geometry: ${intel.assets.filter((a) => a.accuracy_class !== 'exact_survey').length}`,
      `- Scoring Calibration Status: ${intel.scoringConfig[0]?.calibration_status || 'uncalibrated'}`,
    ]
      .filter(Boolean)
      .join('\n');

    const handleDownloadReport = async (format: 'md' | 'json') => {
      const content =
        format === 'md'
          ? markdownBrief
          : JSON.stringify(
              {
                generated_at: generatedAt,
                operator: userEmail,
                org_id: intel.orgId,
                latest_audit_hash: latestLedger?.record_hash || null,
                analyst_note: reportNote.trim() || null,
                counts: {
                  assets: intel.assets.length,
                  edges: intel.edges.length,
                  incidents: intel.incidents.length,
                  matches: intel.matches.length,
                  evidence: intel.evidence.length,
                },
                incidents: intel.incidents,
                matches: intel.matches,
              },
              null,
              2
            );

      // Fail closed: the audit entry is written first. If the ledger refuses it, nothing is downloaded.
      try {
        await atlasService.logEvent(intel.orgId, 'EXPORT', 'REPORT', intel.orgId, {
          format,
          incidents_count: intel.incidents.length,
          assets_count: intel.assets.length,
          generated_at: generatedAt,
        });
      } catch (err: any) {
        setExportStatus(`Export blocked: the audit ledger did not accept the entry (${err.message}). No file was downloaded.`);
        return;
      }

      const blob = new Blob([content], { type: format === 'md' ? 'text/markdown' : 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `atlas-intelligence-report-${intel.orgId.slice(0, 8)}.${format}`;
      a.click();
      URL.revokeObjectURL(url);

      setExportStatus(`Report (${format.toUpperCase()}) exported & logged to cryptographic audit ledger.`);
      intel.refreshAll();
    };

    return (
      <div className="flex-1 overflow-y-auto bg-[#0b0d10] p-4">
        <div className="max-w-5xl mx-auto space-y-4">
          <div className="bg-[#12151b] border border-[#252b36] p-4 flex flex-wrap items-center justify-between gap-3">
            <div>
              <div className="font-mono text-[10px] tracking-[0.12em] text-[#8fa36d]">
                INTELLIGENCE ANALYSIS // EVIDENCE-BACKED REPORTING
              </div>
              <h1 className="text-base font-semibold text-[#e8ecf1] mt-0.5 flex items-center gap-2">
                <FileText className="w-4 h-4 text-[#8fa36d]" />
                <span>Intelligence Reports Generator</span>
              </h1>
            </div>
            <div className="flex items-center gap-2 font-mono text-xs">
              <button
                onClick={() => handleDownloadReport('md')}
                className="px-3 py-1.5 bg-[#6f8054] hover:bg-[#7d905f] text-[#0b0d10] font-semibold flex items-center gap-1.5 cursor-pointer"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Export Markdown</span>
              </button>
              <button
                onClick={() => handleDownloadReport('json')}
                className="px-3 py-1.5 bg-[#181c24] hover:bg-[#222834] border border-[#252b36] text-[#e8ecf1] flex items-center gap-1.5 cursor-pointer"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Export JSON</span>
              </button>
            </div>
          </div>

          {exportStatus && (
            <div className="p-2.5 bg-[#4f8f66]/10 border border-[#4f8f66]/40 font-mono text-xs text-[#4f8f66] flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 shrink-0" />
              <span>{exportStatus}</span>
            </div>
          )}

          <div className="bg-[#12151b] border border-[#252b36] p-4 space-y-2">
            <label className="block font-mono text-[10px] tracking-[0.1em] text-[#8c97a8]">
              OPTIONAL ANALYST ASSESSMENT SUMMARY (INCLUDED IN EXPORT)
            </label>
            <textarea
              rows={3}
              value={reportNote}
              onChange={(e) => setReportNote(e.target.value)}
              placeholder="Enter operational commander context or containment status..."
              className="w-full bg-[#0b0d10] border border-[#252b36] p-2.5 text-xs text-[#e8ecf1] focus:outline-none focus:border-[#6f8054]"
            />
          </div>

          <div className="bg-[#12151b] border border-[#252b36]">
            <div className="px-3 py-2 border-b border-[#252b36] font-mono text-[10px] tracking-[0.1em] text-[#8c97a8]">
              LIVE REPORT PREVIEW (AUTHORITATIVE DATABASE SNAPSHOT)
            </div>
            <pre className="p-4 font-mono text-xs text-[#e8ecf1] whitespace-pre-wrap leading-relaxed overflow-x-auto bg-[#0b0d10]">
              {markdownBrief}
            </pre>
          </div>
        </div>
      </div>
    );
  }

  // =========================================================================
  // 5. RELATIONSHIP GRAPH (PALANTIR GOTHAM-INSPIRED SVG WORKBENCH)
  // =========================================================================
  return (
    <div className="flex-1 flex flex-col overflow-hidden bg-[#0b0d10]">
      {/* Graph Header Controls */}
      <div className="px-3 py-1.5 border-b border-[#252b36] bg-[#12151b] flex flex-wrap items-center justify-between gap-2 shrink-0 font-mono text-[11px]">
        <div className="flex items-center gap-2">
          <button
            onClick={() => setLeftFilterOpen((v) => !v)}
            className="px-2 py-1 bg-[#0b0d10] border border-[#252b36] text-[#8c97a8] hover:text-[#e8ecf1] flex items-center gap-1 cursor-pointer"
          >
            {leftFilterOpen ? <PanelLeftClose className="w-3 h-3" /> : <PanelLeftOpen className="w-3 h-3" />}
            <span>Filters</span>
          </button>
          <Share2 className="w-3.5 h-3.5 text-[#8fa36d]" />
          <span className="font-semibold text-[#e8ecf1]">RELATIONSHIP TOPOLOGY</span>
          <span className="text-[#8c97a8] tabular-nums">
            ({visibleNodes.length} nodes · {visibleEdges.length} links)
          </span>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {/* Path Finder Quick Select */}
          <div className="hidden xl:flex items-center gap-1 bg-[#0b0d10] border border-[#252b36] px-2 py-0.5">
            <Route className="w-3 h-3 text-[#c88b32]" />
            <select
              value={pathStartId}
              onChange={(e) => setPathStartId(e.target.value)}
              className="bg-transparent text-[10px] text-[#e8ecf1] max-w-[110px]"
            >
              <option value="">Path Origin...</option>
              {visibleNodes.map((n) => (
                <option key={n.id} value={n.id} className="bg-[#0b0d10]">
                  {n.label}
                </option>
              ))}
            </select>
            <span className="text-[#5d6778]">→</span>
            <select
              value={pathEndId}
              onChange={(e) => setPathEndId(e.target.value)}
              className="bg-transparent text-[10px] text-[#e8ecf1] max-w-[110px]"
            >
              <option value="">Path Target...</option>
              {visibleNodes.map((n) => (
                <option key={n.id} value={n.id} className="bg-[#0b0d10]">
                  {n.label}
                </option>
              ))}
            </select>
          </div>

          <div className="flex items-center border border-[#252b36] bg-[#0b0d10]">
            <button
              onClick={() => setZoom((z) => Math.min(2.4, z + 0.2))}
              className="p-1 text-[#8c97a8] hover:text-[#e8ecf1] cursor-pointer"
              title="Zoom In"
            >
              <ZoomIn className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={() => setZoom((z) => Math.max(0.45, z - 0.2))}
              className="p-1 border-l border-[#252b36] text-[#8c97a8] hover:text-[#e8ecf1] cursor-pointer"
              title="Zoom Out"
            >
              <ZoomOut className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={() => {
                setZoom(1);
                setPan({ x: 0, y: 0 });
                setFocusNodeId(null);
                setHopLimit('all');
              }}
              className="p-1 border-l border-[#252b36] text-[#8c97a8] hover:text-[#e8ecf1] cursor-pointer"
              title="Reset Canvas"
            >
              <RotateCcw className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>

      {/* Main Graph Row */}
      <div className="flex-1 flex min-h-0 overflow-hidden">
        {/* Left Collapsible Graph Filters */}
        {leftFilterOpen && (
          <aside className="w-60 border-r border-[#252b36] bg-[#0e1116] p-3 space-y-4 overflow-y-auto shrink-0 font-mono text-[11px]">
            <div className="space-y-1.5">
              <div className="text-[10px] tracking-[0.12em] text-[#8c97a8] font-semibold">ENTITY LAYERS</div>
              {(['organisation', 'incident', 'asset', 'indicator', 'evidence'] as GraphNodeKind[]).map((kind) => (
                <label
                  key={kind}
                  className="flex items-center justify-between px-2 py-1 bg-[#12151b] border border-[#252b36] cursor-pointer hover:bg-[#181c24]"
                >
                  <span className="flex items-center gap-1.5">
                    <span className="w-2 h-2 rounded-full" style={{ backgroundColor: NODE_COLORS[kind].stroke }} />
                    <span className="text-[#e8ecf1]">{kind.toUpperCase()}</span>
                  </span>
                  <input
                    type="checkbox"
                    checked={kindVisibility[kind]}
                    onChange={() => setKindVisibility((p) => ({ ...p, [kind]: !p[kind] }))}
                    className="accent-[#6f8054]"
                  />
                </label>
              ))}
            </div>

            <div className="border-t border-[#252b36] pt-3 space-y-1.5">
              <div className="text-[10px] tracking-[0.12em] text-[#8c97a8] font-semibold">EDGE CERTAINTY</div>
              <select
                value={certaintyFilter}
                onChange={(e) => setCertaintyFilter(e.target.value as any)}
                className="w-full bg-[#0b0d10] border border-[#252b36] px-2 py-1 text-[#e8ecf1]"
              >
                <option value="all">All Edge Types</option>
                <option value="CONFIRMED">Confirmed Links</option>
                <option value="PROBABLE">Probable (Auto ≥90%)</option>
                <option value="UNVERIFIED">Unverified Proposals</option>
                <option value="TOPOLOGY">Infra Dependencies</option>
                <option value="SIGNAL">Identifiers / Telemetry</option>
              </select>
            </div>

            <div className="border-t border-[#252b36] pt-3 space-y-1.5">
              <div className="text-[10px] tracking-[0.12em] text-[#8c97a8] font-semibold">HOP EXPANSION</div>
              <div className="text-[10px] text-[#8c97a8]">
                Focus: <span className="text-[#e8ecf1]">{focusNodeId ? nodeLookup.get(focusNodeId)?.label || 'Node' : 'All'}</span>
              </div>
              <div className="grid grid-cols-3 gap-1">
                {(['all', 1, 2] as const).map((h) => (
                  <button
                    key={String(h)}
                    onClick={() => setHopLimit(h)}
                    className={`py-1 border text-[10px] cursor-pointer ${
                      hopLimit === h
                        ? 'bg-[#6f8054]/25 border-[#6f8054] text-[#e8ecf1]'
                        : 'bg-[#0b0d10] border-[#252b36] text-[#8c97a8]'
                    }`}
                  >
                    {h === 'all' ? 'ALL' : `${h}-HOP`}
                  </button>
                ))}
              </div>
            </div>
          </aside>
        )}

        {/* Interactive SVG Graph Canvas */}
        <div
          className="flex-1 bg-[#090c10] relative overflow-hidden cursor-grab active:cursor-grabbing"
          onMouseDown={(e) => {
            if ((e.target as HTMLElement).closest('[data-graph-node]')) return;
            setDragging({ startX: e.clientX, startY: e.clientY, origX: pan.x, origY: pan.y });
          }}
          onMouseMove={(e) => {
            if (!dragging) return;
            setPan({
              x: dragging.origX + (e.clientX - dragging.startX),
              y: dragging.origY + (e.clientY - dragging.startY),
            });
          }}
          onMouseUp={() => setDragging(null)}
          onMouseLeave={() => setDragging(null)}
          onWheel={(e) => {
            e.preventDefault();
            setZoom((z) => Math.max(0.4, Math.min(2.5, z - e.deltaY * 0.001)));
          }}
        >
          {/* Subtle Graph Grid Background */}
          <svg className="w-full h-full select-none">
            <defs>
              <pattern id="atlas-grid" width="32" height="32" patternUnits="userSpaceOnUse">
                <path d="M 32 0 L 0 0 0 32" fill="none" stroke="#141820" strokeWidth="1" />
              </pattern>
            </defs>
            <rect width="100%" height="100%" fill="url(#atlas-grid)" />

            <g transform={`translate(${pan.x}, ${pan.y}) scale(${zoom})`}>
              {/* Relationship Edges */}
              {visibleEdges.map((edge) => {
                const src = nodeLookup.get(edge.source);
                const dst = nodeLookup.get(edge.target);
                if (!src || !dst) return null;
                const onPath = shortestPathIds.edges.has(edge.id);
                const color = onPath ? '#8fa36d' : CERTAINTY_COLORS[edge.certainty];
                const midX = (src.x + dst.x) / 2;
                const midY = (src.y + dst.y) / 2;
                return (
                  <g key={edge.id}>
                    <line
                      x1={src.x}
                      y1={src.y}
                      x2={dst.x}
                      y2={dst.y}
                      stroke={color}
                      strokeWidth={onPath ? 2.6 : 1.25}
                      strokeDasharray={edge.certainty === 'UNVERIFIED' ? '4 3' : undefined}
                      strokeOpacity={onPath ? 1 : 0.7}
                    />
                    <text
                      x={midX}
                      y={midY - 4}
                      textAnchor="middle"
                      fill="#8c97a8"
                      fontSize="8.5"
                      fontFamily="IBM Plex Mono, monospace"
                    >
                      {edge.relation}
                    </text>
                  </g>
                );
              })}

              {/* Entity Nodes */}
              {visibleNodes.map((node) => {
                const style = NODE_COLORS[node.kind];
                const isFocused = focusNodeId === node.id;
                const onPath = shortestPathIds.nodes.has(node.id);
                const isSharedIndicator = node.kind === 'indicator' && node.degree >= 2;
                return (
                  <g
                    key={node.id}
                    data-graph-node="true"
                    transform={`translate(${node.x}, ${node.y})`}
                    onClick={() => {
                      setFocusNodeId(node.id);
                      if (node.entityRef) onSelectEntity(node.entityRef);
                    }}
                    className="cursor-pointer"
                  >
                    <rect
                      x={-72}
                      y={-18}
                      width={144}
                      height={36}
                      rx={2}
                      fill={style.fill}
                      stroke={onPath ? '#8fa36d' : isSharedIndicator ? '#c88b32' : isFocused ? '#e8ecf1' : style.stroke}
                      strokeWidth={onPath || isFocused ? 2 : 1.25}
                    />
                    <text
                      x={0}
                      y={-3}
                      textAnchor="middle"
                      fill={style.text}
                      fontSize="10.5"
                      fontWeight="600"
                      fontFamily="IBM Plex Mono, monospace"
                    >
                      {node.label.length > 18 ? `${node.label.slice(0, 17)}…` : node.label}
                    </text>
                    <text
                      x={0}
                      y={11}
                      textAnchor="middle"
                      fill="#8c97a8"
                      fontSize="8.5"
                      fontFamily="IBM Plex Mono, monospace"
                    >
                      {node.sublabel.length > 22 ? `${node.sublabel.slice(0, 21)}…` : node.sublabel}
                    </text>
                  </g>
                );
              })}
            </g>
          </svg>

          {/* Column Header Legend */}
          <div className="absolute top-2.5 left-2.5 bg-[#12151b]/90 border border-[#252b36] px-2.5 py-1.5 font-mono text-[10px] text-[#8c97a8] flex flex-wrap items-center gap-3 pointer-events-none">
            <span>PAN: Drag canvas · ZOOM: Wheel · CLICK NODE: Focus & Dossier</span>
            {shortestPathIds.nodes.size > 0 && (
              <span className="text-[#8fa36d]">SHORTEST PATH HIGHLIGHTED ({shortestPathIds.nodes.size} nodes)</span>
            )}
          </div>
        </div>

        {/* Right Dossier Panel */}
        <div className="w-80 border-l border-[#252b36] hidden xl:block overflow-hidden">
          <IntelligenceDossierPanel
            selectedEntity={selectedEntity}
            intel={intel}
            onSelectEntity={onSelectEntity}
            onNavigateModule={onNavigateModule}
          />
        </div>
      </div>

      {/* Bottom Collapsible Relationship Edge Metadata Table */}
      <div className="border-t border-[#252b36] bg-[#0e1116] shrink-0">
        <div className="h-7 px-3 border-b border-[#252b36] bg-[#12151b] flex items-center justify-between font-mono text-[10px]">
          <button
            onClick={() => setEdgeTableCollapsed((v) => !v)}
            className="flex items-center gap-1.5 text-[#e8ecf1] font-semibold cursor-pointer"
          >
            {edgeTableCollapsed ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
            <span>RELATIONSHIP EDGE METADATA ({visibleEdges.length})</span>
          </button>
          <span className="text-[#8c97a8]">SOURCE & CERTAINTY PROVENANCE</span>
        </div>
        {!edgeTableCollapsed && (
          <div className="h-36 overflow-y-auto bg-[#0b0d10]">
            <table className="w-full text-left font-mono text-[11px] border-collapse">
              <thead className="sticky top-0 bg-[#12151b] border-b border-[#252b36] text-[#8c97a8] text-[10px]">
                <tr>
                  <th className="py-1 px-3">SOURCE NODE</th>
                  <th className="py-1 px-2">RELATION</th>
                  <th className="py-1 px-2">TARGET NODE</th>
                  <th className="py-1 px-2">CERTAINTY</th>
                  <th className="py-1 px-2 text-right">CONFIDENCE</th>
                  <th className="py-1 px-3 text-right">PROVENANCE</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#181c24]">
                {visibleEdges.slice(0, 80).map((e) => (
                  <tr key={e.id} className="hover:bg-[#151922]">
                    <td className="py-1 px-3 text-[#e8ecf1]">{nodeLookup.get(e.source)?.label || e.source}</td>
                    <td className="py-1 px-2 text-[#8c97a8]">{e.relation}</td>
                    <td className="py-1 px-2 text-[#4a9eb0]">{nodeLookup.get(e.target)?.label || e.target}</td>
                    <td className="py-1 px-2" style={{ color: CERTAINTY_COLORS[e.certainty] }}>
                      {e.certainty}
                    </td>
                    <td className="py-1 px-2 text-right tabular-nums text-[#e8ecf1]">
                      {(e.confidence * 100).toFixed(0)}%
                    </td>
                    <td className="py-1 px-3 text-right text-[#8c97a8] truncate max-w-[180px]">{e.sourceRef}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
