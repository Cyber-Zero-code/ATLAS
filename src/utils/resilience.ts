/**
 * Project ATLAS — Module F: Infrastructure Resilience & Cascading Failure Simulator
 *
 * Computes deterministic topological metrics over workspace `assets`,
 * `dependency_edges`, coordinates, and `asset_matches`.
 *
 * Integrity rules:
 * - Never fabricates backup generators, UPS autonomy, or RTO/RPO targets. Where
 *   the locked schema does not store backup/recovery telemetry, explicitly reports
 *   `NO_VERIFIED_DATA`.
 * - Clearly discloses transparent heuristic methodology.
 */

import type {
  Asset,
  AssetMatch,
  CascadeImpactedAsset,
  DependencyEdge,
  FailureScenarioResult,
  ResilienceAssetProfile,
} from '../types/atlas';
import { haversineKm } from './intelligence';

export function analyzeInfrastructureResilience(
  assets: Asset[],
  edges: DependencyEdge[],
  assetCoordsMap: Map<string, [number, number]>,
  matches: AssetMatch[]
): ResilienceAssetProfile[] {
  const incomingByTarget = new Map<string, DependencyEdge[]>();
  const outgoingBySource = new Map<string, DependencyEdge[]>();
  const activeIncidentsByAsset = new Map<string, Set<string>>();

  for (const e of edges) {
    const inList = incomingByTarget.get(e.to_asset_id) || [];
    inList.push(e);
    incomingByTarget.set(e.to_asset_id, inList);

    const outList = outgoingBySource.get(e.from_asset_id) || [];
    outList.push(e);
    outgoingBySource.set(e.from_asset_id, outList);
  }

  for (const m of matches) {
    if (m.status === 'rejected') continue;
    const set = activeIncidentsByAsset.get(m.asset_id) || new Set<string>();
    set.add(m.incident_id);
    activeIncidentsByAsset.set(m.asset_id, set);
  }

  return assets
    .map((asset) => {
      const incoming = incomingByTarget.get(asset.id) || [];
      const outgoing = outgoingBySource.get(asset.id) || [];

      const powerUpstreamCount = incoming.filter((e) => e.relation_type === 'powers').length;
      const telecomUpstreamCount = incoming.filter((e) => e.relation_type === 'connects_to').length;
      const otherUpstreamCount = incoming.length - powerUpstreamCount - telecomUpstreamCount;
      const uniqueProviders = new Set(incoming.map((e) => e.from_asset_id)).size;

      // Geographic co-location within 2 km of other Tier-3+ assets
      const myCoord = assetCoordsMap.get(asset.id);
      let coLocatedCriticalCount = 0;
      if (myCoord) {
        for (const other of assets) {
          if (other.id === asset.id || other.criticality < 3) continue;
          const oCoord = assetCoordsMap.get(other.id);
          if (oCoord && haversineKm(myCoord, oCoord) <= 2.0) {
            coLocatedCriticalCount++;
          }
        }
      }

      // Single Point of Failure check:
      // 1) Provides critical upstream feed to >= 2 dependents, OR
      // 2) Sole provider to a Tier-4/5 asset, OR
      // 3) Tier-4/5 asset with exactly 1 upstream provider and 0 alternates
      const criticalConsumersWithSingleFeed = outgoing.filter((outEdge) => {
        const consumerIncoming = incomingByTarget.get(outEdge.to_asset_id) || [];
        return consumerIncoming.length === 1;
      }).length;

      let isSinglePointOfFailure = false;
      let spofReason: string | undefined;

      if (criticalConsumersWithSingleFeed > 0 && outgoing.length >= 2) {
        isSinglePointOfFailure = true;
        spofReason = `Sole upstream provider for ${criticalConsumersWithSingleFeed} dependent(s) across ${outgoing.length} outbound links.`;
      } else if (criticalConsumersWithSingleFeed > 0) {
        const dep = assets.find((x) => x.id === outgoing.find((e) => (incomingByTarget.get(e.to_asset_id) || []).length === 1)?.to_asset_id);
        if (dep && dep.criticality >= 4) {
          isSinglePointOfFailure = true;
          spofReason = `Sole documented dependency for Tier-${dep.criticality} asset ${dep.site_code}.`;
        }
      } else if (asset.criticality >= 4 && uniqueProviders === 1) {
        isSinglePointOfFailure = true;
        spofReason = `Tier-${asset.criticality} node depends on a single upstream provider with zero alternate path.`;
      }

      const activeIncidentExposureCount = activeIncidentsByAsset.get(asset.id)?.size || 0;

      // Transparent structural exposure heuristic (NOT a calibrated empirical probability)
      const critWeight = asset.criticality * 10; // up to 50
      const fanOutWeight = Math.min(25, outgoing.length * 6);
      const spofWeight = isSinglePointOfFailure ? 15 : 0;
      const exposureWeight = Math.min(10, activeIncidentExposureCount * 5);
      const structuralVulnerabilityScore = Math.min(100, critWeight + fanOutWeight + spofWeight + exposureWeight);

      return {
        assetId: asset.id,
        siteCode: asset.site_code,
        name: asset.name,
        type: asset.type,
        criticality: asset.criticality,
        accuracyClass: asset.accuracy_class,
        powerUpstreamCount,
        telecomUpstreamCount,
        otherUpstreamCount,
        totalUpstreamCount: incoming.length,
        downstreamDependentCount: outgoing.length,
        uniqueProviderTypes: new Set(incoming.map((e) => e.relation_type)).size,
        isSinglePointOfFailure,
        spofReason,
        coLocatedCriticalCount,
        activeIncidentExposureCount,
        backupRecoveryStatus: 'NO_VERIFIED_DATA' as const,
        structuralVulnerabilityScore,
      };
    })
    .sort(
      (a, b) =>
        b.structuralVulnerabilityScore - a.structuralVulnerabilityScore ||
        b.downstreamDependentCount - a.downstreamDependentCount
    );
}

/**
 * Deterministic Client-Side Cascading Outage Simulator (directed BFS from failed node(s)).
 */
export function simulateNodeFailureCascade(
  failedAssetIds: string[],
  assets: Asset[],
  edges: DependencyEdge[],
  matches: AssetMatch[]
): FailureScenarioResult {
  const assetMap = new Map(assets.map((a) => [a.id, a]));
  const failedSet = new Set(failedAssetIds.filter((id) => assetMap.has(id)));
  const activeIncidentsByAsset = new Map<string, Set<string>>();

  for (const m of matches) {
    if (m.status === 'rejected') continue;
    const set = activeIncidentsByAsset.get(m.asset_id) || new Set<string>();
    set.add(m.incident_id);
    activeIncidentsByAsset.set(m.asset_id, set);
  }

  const visitedDepth = new Map<string, { depth: number; viaRelation: string }>();
  const queue: Array<{ id: string; depth: number }> = [];

  for (const rootId of failedSet) {
    visitedDepth.set(rootId, { depth: 0, viaRelation: 'ROOT_FAILURE' });
    queue.push({ id: rootId, depth: 0 });
  }

  let head = 0;
  let directDependentsCount = 0;

  while (head < queue.length) {
    const current = queue[head++];
    for (const edge of edges) {
      if (edge.from_asset_id !== current.id) continue;
      if (!assetMap.has(edge.to_asset_id)) continue;
      if (current.depth === 0 && !failedSet.has(edge.to_asset_id)) {
        directDependentsCount++;
      }
      if (!visitedDepth.has(edge.to_asset_id)) {
        const nextDepth = current.depth + 1;
        visitedDepth.set(edge.to_asset_id, { depth: nextDepth, viaRelation: edge.relation_type });
        queue.push({ id: edge.to_asset_id, depth: nextDepth });
      }
    }
  }

  const affectedAssets: CascadeImpactedAsset[] = [];
  let powerCascadeCount = 0;
  let telecomCascadeCount = 0;
  let tier4PlusAffectedCount = 0;

  for (const [assetId, info] of visitedDepth.entries()) {
    if (info.depth === 0) continue; // exclude initial failed root nodes from downstream count
    const asset = assetMap.get(assetId);
    if (!asset) continue;
    if (info.viaRelation === 'powers') powerCascadeCount++;
    if (info.viaRelation === 'connects_to') telecomCascadeCount++;
    if (asset.criticality >= 4) tier4PlusAffectedCount++;

    affectedAssets.push({
      assetId: asset.id,
      siteCode: asset.site_code,
      name: asset.name,
      type: asset.type,
      criticality: asset.criticality,
      hopDepth: info.depth,
      viaRelation: info.viaRelation,
      activeIncidents: activeIncidentsByAsset.get(asset.id)?.size || 0,
    });
  }

  affectedAssets.sort((a, b) => a.hopDepth - b.hopDepth || b.criticality - a.criticality);

  return {
    failedAssetIds: Array.from(failedSet),
    directDependentsCount,
    totalCascadingOutageCount: affectedAssets.length,
    powerCascadeCount,
    telecomCascadeCount,
    tier4PlusAffectedCount,
    affectedAssets,
    methodologyNote:
      'Deterministic directed-graph traversal (BFS) across documented `dependency_edges`. Assumes failure propagates unconditionally down undocumented failover paths because backup generators / redundant circuits are marked NO_VERIFIED_DATA in the locked schema.',
  };
}
