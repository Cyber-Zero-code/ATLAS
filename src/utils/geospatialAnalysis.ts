/**
 * Project ATLAS — Module E: Computational Geospatial Analysis Engine
 *
 * Pure deterministic spatial computation over verified / declared asset coordinates.
 * Never mutates source database coordinates and explicitly propagates spatial
 * accuracy classes (exact_survey vs facility_approximate vs regional_approximate).
 */

import type {
  AccuracyClass,
  Asset,
  AssetMatch,
  BufferAnalysisResult,
  BufferIntersectAsset,
  ConcentrationCell,
  GisCustomSource,
  SpatialCluster,
} from '../types/atlas';
import { computeBearingDeg, haversineKm } from './intelligence';

export function createGeodesicCircleCoords(
  center: [number, number],
  radiusKm: number,
  sides = 40
): Array<[number, number]> {
  const safeRadius = Math.max(0.1, radiusKm);
  const coords: Array<[number, number]> = [];
  const latRad = (center[1] * Math.PI) / 180;
  const dLat = safeRadius / 111.32;
  const dLon = safeRadius / (111.32 * Math.max(Math.cos(latRad), 0.12));
  for (let i = 0; i <= sides; i++) {
    const theta = (i / sides) * Math.PI * 2;
    const lng = Math.max(-180, Math.min(180, center[0] + dLon * Math.cos(theta)));
    const lat = Math.max(-85, Math.min(85, center[1] + dLat * Math.sin(theta)));
    coords.push([lng, lat]);
  }
  return coords;
}

/**
 * Spatial Grid-Centroid Clustering over real workspace coordinates.
 */
export function computeSpatialClusters(
  assets: Asset[],
  assetCoordsMap: Map<string, [number, number]>,
  matches: AssetMatch[],
  cellSizeKm = 50
): SpatialCluster[] {
  const degStep = Math.max(0.05, cellSizeKm / 111.32);
  const activeIncidentsByAsset = new Map<string, Set<string>>();
  for (const m of matches) {
    if (m.status === 'rejected') continue;
    let set = activeIncidentsByAsset.get(m.asset_id);
    if (!set) {
      set = new Set<string>();
      activeIncidentsByAsset.set(m.asset_id, set);
    }
    set.add(m.incident_id);
  }

  const buckets = new Map<
    string,
    {
      assets: Asset[];
      coords: Array<[number, number]>;
    }
  >();

  for (const asset of assets) {
    const coord = assetCoordsMap.get(asset.id);
    if (!coord) continue;
    const gx = Math.floor(coord[0] / degStep);
    const gy = Math.floor(coord[1] / degStep);
    const key = `${gx}:${gy}`;
    let bucket = buckets.get(key);
    if (!bucket) {
      bucket = { assets: [], coords: [] };
      buckets.set(key, bucket);
    }
    bucket.assets.push(asset);
    bucket.coords.push(coord);
  }

  const clusters: SpatialCluster[] = [];
  for (const [cellKey, bucket] of buckets.entries()) {
    const count = bucket.coords.length;
    const sum = bucket.coords.reduce(
      (acc, c) => [acc[0] + c[0], acc[1] + c[1]],
      [0, 0] as [number, number]
    );
    const centroid: [number, number] = [sum[0] / count, sum[1] / count];

    const incIds = new Set<string>();
    let maxCrit = 1;
    let exact = 0;
    let facilityApprox = 0;
    let regionalApprox = 0;

    for (const a of bucket.assets) {
      if (a.criticality > maxCrit) maxCrit = a.criticality;
      if (a.accuracy_class === 'exact_survey') exact++;
      else if (a.accuracy_class === 'facility_approximate') facilityApprox++;
      else regionalApprox++;

      const linked = activeIncidentsByAsset.get(a.id);
      if (linked) linked.forEach((id) => incIds.add(id));
    }

    clusters.push({
      id: `cluster-${cellKey}`,
      centroid,
      cellLabel: `${centroid[1].toFixed(2)}°, ${centroid[0].toFixed(2)}° (~${cellSizeKm} km grid)`,
      assetIds: bucket.assets.map((a) => a.id),
      incidentCount: incIds.size,
      maxCriticality: maxCrit,
      accuracy: { exact, facilityApprox, regionalApprox },
    });
  }

  return clusters.sort((a, b) => b.assetIds.length - a.assetIds.length || b.incidentCount - a.incidentCount);
}

/**
 * Geodesic Buffer Zone intersection against real asset geometries & active incidents.
 */
export function analyzeBufferZone(
  center: [number, number],
  radiusKm: number,
  assets: Asset[],
  assetCoordsMap: Map<string, [number, number]>,
  matches: AssetMatch[]
): BufferAnalysisResult {
  const safeRadius = Math.max(0.5, radiusKm);
  const intersecting: BufferIntersectAsset[] = [];
  const linkedIncidentSet = new Set<string>();
  let hasApprox = false;

  for (const asset of assets) {
    const coord = assetCoordsMap.get(asset.id);
    if (!coord) continue;
    const dist = haversineKm(center, coord);
    if (dist <= safeRadius) {
      if (asset.accuracy_class !== 'exact_survey') hasApprox = true;
      intersecting.push({
        assetId: asset.id,
        siteCode: asset.site_code,
        name: asset.name,
        type: asset.type,
        criticality: asset.criticality,
        accuracyClass: asset.accuracy_class as AccuracyClass,
        distanceKm: dist,
        bearingDeg: computeBearingDeg(center, coord),
      });

      for (const m of matches) {
        if (m.asset_id === asset.id && m.status !== 'rejected') {
          linkedIncidentSet.add(m.incident_id);
        }
      }
    }
  }

  intersecting.sort((a, b) => a.distanceKm - b.distanceKm);

  return {
    center,
    radiusKm: safeRadius,
    ringPolygon: createGeodesicCircleCoords(center, safeRadius, 48),
    intersectingAssets: intersecting,
    linkedIncidentIds: Array.from(linkedIncidentSet),
    hasApproximateAssets: hasApprox,
  };
}

/**
 * Proximity Matrix sorted by Haversine distance & true bearing from origin coordinate.
 */
export function computeProximityRankings(
  origin: [number, number],
  radiusKm: number,
  assets: Asset[],
  assetCoordsMap: Map<string, [number, number]>,
  excludeAssetId?: string
): BufferIntersectAsset[] {
  const list: BufferIntersectAsset[] = [];
  for (const asset of assets) {
    if (excludeAssetId && asset.id === excludeAssetId) continue;
    const coord = assetCoordsMap.get(asset.id);
    if (!coord) continue;
    const dist = haversineKm(origin, coord);
    if (dist <= radiusKm) {
      list.push({
        assetId: asset.id,
        siteCode: asset.site_code,
        name: asset.name,
        type: asset.type,
        criticality: asset.criticality,
        accuracyClass: asset.accuracy_class,
        distanceKm: dist,
        bearingDeg: computeBearingDeg(origin, coord),
      });
    }
  }
  return list.sort((a, b) => a.distanceKm - b.distanceKm);
}

/**
 * Infrastructure Spatial Concentration & Co-Location Risk Grid
 */
export function computeInfrastructureConcentration(
  assets: Asset[],
  assetCoordsMap: Map<string, [number, number]>,
  matches: AssetMatch[],
  gridDeg = 0.5
): ConcentrationCell[] {
  const step = Math.max(0.05, gridDeg);
  const cells = new Map<string, { assets: Asset[]; coords: Array<[number, number]> }>();

  for (const asset of assets) {
    const coord = assetCoordsMap.get(asset.id);
    if (!coord) continue;
    const key = `${Math.floor(coord[0] / step)}:${Math.floor(coord[1] / step)}`;
    let c = cells.get(key);
    if (!c) {
      c = { assets: [], coords: [] };
      cells.set(key, c);
    }
    c.assets.push(asset);
    c.coords.push(coord);
  }

  const out: ConcentrationCell[] = [];
  for (const [cellId, group] of cells.entries()) {
    const n = group.coords.length;
    const sum = group.coords.reduce((acc, c) => [acc[0] + c[0], acc[1] + c[1]], [0, 0] as [number, number]);
    const tier4Plus = group.assets.filter((a) => a.criticality >= 4).length;

    let coLocatedPairs = 0;
    for (let i = 0; i < group.coords.length; i++) {
      for (let j = i + 1; j < group.coords.length; j++) {
        if (haversineKm(group.coords[i], group.coords[j]) <= 5) coLocatedPairs++;
      }
    }

    const assetIds = new Set(group.assets.map((a) => a.id));
    const incidentIds = new Set(
      matches.filter((m) => m.status !== 'rejected' && assetIds.has(m.asset_id)).map((m) => m.incident_id)
    );

    out.push({
      cellId,
      center: [sum[0] / n, sum[1] / n],
      assetCount: n,
      tier4PlusCount: tier4Plus,
      coLocatedPairs,
      incidentLinkCount: incidentIds.size,
      densityIndex: n + tier4Plus * 1.5 + coLocatedPairs * 2 + incidentIds.size * 2,
    });
  }

  return out.sort((a, b) => b.densityIndex - a.densityIndex);
}

/**
 * Checks whether any licensed DEM raster / elevation source is actively attached.
 */
export function inspectTerrainDemAvailability(customGisSources: GisCustomSource[]): {
  demAvailable: boolean;
  activeDemSourceName: string | null;
  statusMessage: string;
} {
  const demSource = customGisSources.find(
    (s) =>
      s.enabled &&
      /dem|srtm|copernicus|usgs|3dep|elev|terrain|contour/i.test(`${s.name} ${s.url} ${s.attribution}`)
  );

  if (demSource) {
    return {
      demAvailable: true,
      activeDemSourceName: demSource.name,
      statusMessage: `Operator DEM layer "${demSource.name}" is attached to the map canvas. Raster elevation tiles are rendered via MapLibre; pixel-level numerical DEM sampling requires server-side WCS/GeoTIFF extraction (not present in locked backend).`,
    };
  }

  return {
    demAvailable: false,
    activeDemSourceName: null,
    statusMessage:
      'DATA SOURCE UNAVAILABLE — No authorised DEM dataset (Copernicus DEM GLO-30 / USGS 3DEP / SRTM) is configured. Elevation profiles, slope gradients, and line-of-sight viewsheds cannot be fabricated without elevation raster samples.',
  };
}
