import { useState, useEffect, useCallback, useMemo } from 'react';
import { atlasService } from '../data/api';
import {
  Asset,
  AssetMatch,
  AuditEvent,
  DatasetRecord,
  DependencyEdge,
  Evidence,
  Incident,
  Membership,
  ScoringConfigRecord,
  WorkspaceGeoJsonCollection,
} from '../types/atlas';
import { computeAlerts, extractRepresentativeCoord } from '../utils/intelligence';
import type { IntelligenceAlert } from '../utils/intelligence';

export { extractRepresentativeCoord };
export type { IntelligenceAlert };

export interface WorkspaceIntelligenceState {
  orgId: string;
  assetsGeoJson: WorkspaceGeoJsonCollection;
  assets: Asset[];
  edges: Array<DependencyEdge & { from_asset?: Asset; to_asset?: Asset }>;
  incidents: Incident[];
  matches: AssetMatch[];
  evidence: Evidence[];
  auditEvents: AuditEvent[];
  auditTotal: number;
  datasets: DatasetRecord[];
  scoringConfig: ScoringConfigRecord[];
  orgMemberships: Membership[];
  isLoading: boolean;
  error: string | null;
  lastSyncedAt: string | null;
  alerts: IntelligenceAlert[];
  assetCoordsMap: Map<string, [number, number]>;
  refreshAll: () => Promise<void>;
}

export function useWorkspaceIntelligence(orgId: string): WorkspaceIntelligenceState {
  const [assetsGeoJson, setAssetsGeoJson] = useState<WorkspaceGeoJsonCollection>({
    type: 'FeatureCollection',
    features: [],
  });
  const [assets, setAssets] = useState<Asset[]>([]);
  const [edges, setEdges] = useState<Array<DependencyEdge & { from_asset?: Asset; to_asset?: Asset }>>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [matches, setMatches] = useState<AssetMatch[]>([]);
  const [evidence, setEvidence] = useState<Evidence[]>([]);
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [auditTotal, setAuditTotal] = useState<number>(0);
  const [datasets, setDatasets] = useState<DatasetRecord[]>([]);
  const [scoringConfig, setScoringConfig] = useState<ScoringConfigRecord[]>([]);
  const [orgMemberships, setOrgMemberships] = useState<Membership[]>([]);

  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [lastSyncedAt, setLastSyncedAt] = useState<string | null>(null);

  const refreshAll = useCallback(async () => {
    if (!orgId) return;
    setIsLoading(true);
    setError(null);

    try {
      const [
        geoRes,
        assetsRes,
        edgesRes,
        incidentsRes,
        matchesRes,
        evidenceRes,
        auditRes,
        datasetsRes,
        scoringRes,
        membersRes,
      ] = await Promise.all([
        atlasService.fetchWorkspaceAssetsGeoJson(orgId, 'all', 1),
        atlasService.fetchWorkspaceAssetsList(orgId),
        atlasService.fetchDependencyEdges(orgId),
        atlasService.fetchIncidents(orgId),
        atlasService.fetchWorkspaceMatches(orgId),
        atlasService.fetchEvidenceList(orgId),
        atlasService.fetchAuditEvents(orgId, { limit: 150 }),
        atlasService.fetchDatasets(orgId),
        atlasService.fetchScoringConfig(orgId),
        atlasService.fetchWorkspaceMemberships(orgId),
      ]);

      setAssetsGeoJson(geoRes);
      setAssets(assetsRes);
      setEdges(edgesRes);
      setIncidents(incidentsRes);
      setMatches(matchesRes);
      setEvidence(evidenceRes);
      setAuditEvents(auditRes.events);
      setAuditTotal(auditRes.total);
      setDatasets(datasetsRes);
      setScoringConfig(scoringRes);
      setOrgMemberships(membersRes);
      setLastSyncedAt(new Date().toISOString());
    } catch (err: any) {
      setError(err.message || 'Failed to synchronize workspace intelligence from Supabase.');
    } finally {
      setIsLoading(false);
    }
  }, [orgId]);

  useEffect(() => {
    refreshAll();
  }, [refreshAll]);

  const assetCoordsMap = useMemo(() => {
    const map = new Map<string, [number, number]>();
    for (const f of assetsGeoJson.features) {
      const coord = extractRepresentativeCoord(f.geometry);
      if (coord) {
        map.set(f.properties.id || f.id, coord);
      }
    }
    return map;
  }, [assetsGeoJson]);

  const alerts = useMemo<IntelligenceAlert[]>(() => computeAlerts(matches, incidents, assets), [matches, incidents, assets]);

  return {
    orgId,
    assetsGeoJson,
    assets,
    edges,
    incidents,
    matches,
    evidence,
    auditEvents,
    auditTotal,
    datasets,
    scoringConfig,
    orgMemberships,
    isLoading,
    error,
    lastSyncedAt,
    alerts,
    assetCoordsMap,
    refreshAll,
  };
}
