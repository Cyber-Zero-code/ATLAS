/**
 * Project ATLAS: pure helper logic used by several workspaces.
 * No React, no network. Kept in one file so it can be unit tested (npm test).
 */
import type { Asset, AssetMatch, Incident } from '../types/atlas';

export interface IntelligenceAlert {
  id: string;
  severity: 'critical' | 'high' | 'medium' | 'info';
  category: 'PROPOSED_MATCH' | 'CRITICAL_INCIDENT' | 'HIGH_INCIDENT' | 'APPROXIMATE_CRITICAL_ASSET';
  title: string;
  detail: string;
  timestamp: string;
  targetKind: 'incident' | 'asset';
  targetId: string;
}

/**
 * Computes centroid / representative [lng, lat] for a GeoJSON geometry
 */
export function extractRepresentativeCoord(geometry: { type: string; coordinates: any } | null): [number, number] | null {
  if (!geometry || !geometry.coordinates) return null;
  if (geometry.type === 'Point' && Array.isArray(geometry.coordinates) && geometry.coordinates.length >= 2) {
    return [Number(geometry.coordinates[0]), Number(geometry.coordinates[1])];
  }
  if (geometry.type === 'LineString' && Array.isArray(geometry.coordinates) && geometry.coordinates.length > 0) {
    const mid = geometry.coordinates[Math.floor(geometry.coordinates.length / 2)];
    if (Array.isArray(mid) && mid.length >= 2) return [Number(mid[0]), Number(mid[1])];
  }
  if (geometry.type === 'Polygon' && Array.isArray(geometry.coordinates) && Array.isArray(geometry.coordinates[0]) && geometry.coordinates[0].length > 0) {
    const ring = geometry.coordinates[0];
    let sumLng = 0;
    let sumLat = 0;
    let count = 0;
    for (const pt of ring) {
      if (Array.isArray(pt) && pt.length >= 2) {
        sumLng += Number(pt[0]);
        sumLat += Number(pt[1]);
        count++;
      }
    }
    if (count > 0) return [sumLng / count, sumLat / count];
  }
  return null;
}

export function computeAlerts(matches: AssetMatch[], incidents: Incident[], assets: Asset[]): IntelligenceAlert[] {
  const items: IntelligenceAlert[] = [];

  // 1. Unconfirmed proposed matches requiring analyst decision
  for (const m of matches) {
    if (m.status === 'proposed') {
      const inc = incidents.find((i) => i.id === m.incident_id);
      items.push({
        id: `alert-match-${m.id}`,
        severity: inc?.severity === 'critical' ? 'critical' : 'high',
        category: 'PROPOSED_MATCH',
        title: `Unverified Match Proposal (${(Number(m.score) * 100).toFixed(0)}%)`,
        detail: `${inc?.event_id || 'Incident'} -> ${m.asset?.site_code || m.asset_id.slice(0, 8)} via ${m.rule_fired}`,
        timestamp: m.created_at,
        targetKind: 'incident',
        targetId: m.incident_id,
      });
    }
  }

  // 2. Critical & High incidents
  for (const inc of incidents) {
    if (inc.severity === 'critical' || inc.severity === 'high') {
      items.push({
        id: `alert-inc-${inc.id}`,
        severity: inc.severity,
        category: inc.severity === 'critical' ? 'CRITICAL_INCIDENT' : 'HIGH_INCIDENT',
        title: `${inc.severity.toUpperCase()} Incident: ${inc.event_id}`,
        detail: `${inc.event_type} · Source: ${inc.source}`,
        timestamp: inc.observed_at,
        targetKind: 'incident',
        targetId: inc.id,
      });
    }
  }

  // 3. Tier-5 critical assets with approximate spatial accuracy
  for (const asset of assets) {
    if (asset.criticality >= 5 && asset.accuracy_class !== 'exact_survey') {
      items.push({
        id: `alert-approx-${asset.id}`,
        severity: 'medium',
        category: 'APPROXIMATE_CRITICAL_ASSET',
        title: `Approximate Location on Tier-${asset.criticality} Asset`,
        detail: `${asset.site_code} (${asset.name}) · ${asset.accuracy_class}`,
        timestamp: asset.created_at,
        targetKind: 'asset',
        targetId: asset.id,
      });
    }
  }

  return items.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
}

/** Haversine distance in kilometers */
export function haversineKm(a: [number, number], b: [number, number]): number {
  const toRad = (deg: number) => (deg * Math.PI) / 180;
  const R = 6371;
  const dLat = toRad(b[1] - a[1]);
  const dLon = toRad(b[0] - a[0]);
  const lat1 = toRad(a[1]);
  const lat2 = toRad(b[1]);
  const h =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(lat1) * Math.cos(lat2) * Math.sin(dLon / 2) * Math.sin(dLon / 2);
  return 2 * R * Math.asin(Math.sqrt(h));
}

/** Initial compass bearing in degrees */
export function computeBearingDeg(a: [number, number], b: [number, number]): number {
  const toRad = (d: number) => (d * Math.PI) / 180;
  const toDeg = (r: number) => ((r * 180) / Math.PI + 360) % 360;
  const lat1 = toRad(a[1]);
  const lat2 = toRad(b[1]);
  const dLon = toRad(b[0] - a[0]);
  const y = Math.sin(dLon) * Math.cos(lat2);
  const x = Math.cos(lat1) * Math.sin(lat2) - Math.sin(lat1) * Math.cos(lat2) * Math.cos(dLon);
  return toDeg(Math.atan2(y, x));
}


/**
 * Shortest path (fewest hops, edges followed in either direction) between two nodes.
 * Returns the node ids and edge ids on the path; both sets are empty when there is no path
 * or the start and end are the same, or either is not in allowedIds.
 */
export function shortestPathUndirected(
  edges: Array<{ id: string; source: string; target: string }>,
  allowedIds: Set<string>,
  pathStartId: string,
  pathEndId: string
): { nodes: Set<string>; edges: Set<string> } {
  const pathNodes = new Set<string>();
  const pathEdges = new Set<string>();
  if (pathStartId && pathEndId && pathStartId !== pathEndId && allowedIds.has(pathStartId) && allowedIds.has(pathEndId)) {
    const adj = new Map<string, Array<{ next: string; edgeId: string }>>();
    for (const e of edges) {
      if (!adj.has(e.source)) adj.set(e.source, []);
      if (!adj.has(e.target)) adj.set(e.target, []);
      adj.get(e.source)!.push({ next: e.target, edgeId: e.id });
      adj.get(e.target)!.push({ next: e.source, edgeId: e.id });
    }
    const prev = new Map<string, { node: string; edgeId: string }>();
    const visited = new Set<string>([pathStartId]);
    const queue: string[] = [pathStartId];
    let head = 0;
    while (head < queue.length) {
      const cur = queue[head++];
      if (cur === pathEndId) break;
      for (const step of adj.get(cur) || []) {
        if (!visited.has(step.next)) {
          visited.add(step.next);
          prev.set(step.next, { node: cur, edgeId: step.edgeId });
          queue.push(step.next);
        }
      }
    }
    if (visited.has(pathEndId)) {
      let cur: string | undefined = pathEndId;
      while (cur) {
        pathNodes.add(cur);
        const p = prev.get(cur);
        if (!p) break;
        pathEdges.add(p.edgeId);
        cur = p.node;
      }
    }
  }
  return { nodes: pathNodes, edges: pathEdges };
}

const ALLOWED_GIS_PROTOCOLS = new Set(['GeoJSON', 'WMS', 'WMTS', 'XYZ_RASTER']);

/**
 * Validates custom external GIS source inputs (https:// only, no embedded credentials).
 * Returns an error string or null when valid.
 */
export function validateGisSourceInput(input: {
  name: string;
  protocol: string;
  url: string;
}): string | null {
  const name = (input.name || '').trim();
  const protocol = (input.protocol || '').trim();
  const url = (input.url || '').trim();

  if (!name) return 'Feed label is required.';
  if (name.length > 120) return 'Feed label must be 120 characters or fewer.';
  if (!ALLOWED_GIS_PROTOCOLS.has(protocol)) {
    return 'Protocol must be one of GeoJSON, WMS, WMTS, or XYZ_RASTER.';
  }
  if (!url) return 'Feed URL is required.';
  if (url.length > 2048) return 'Feed URL must be 2048 characters or fewer.';
  if (!/^https:\/\/[^\s]+$/.test(url)) {
    return 'GIS feed URL must use https:// and contain no whitespace.';
  }
  if (/^https:\/\/[^/?#]*@/.test(url)) {
    return 'GIS feed URL must not contain embedded user credentials.';
  }
  if (/([?&])(api_?key|access_?token|auth_?token|auth|token|secret|password|passwd|session_?token|session_?id|bearer|sig|x-amz-signature|x-amz-credential)=/i.test(url)) {
    return 'GIS feed URL must not contain API keys or access tokens in query parameters.';
  }
  if (/#.*(token|key|secret|password|auth)=/i.test(url)) {
    return 'GIS feed URL must not contain credentials or tokens in fragment parameters.';
  }
  return null;
}
