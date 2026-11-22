import React, { useEffect, useRef, useState, useMemo, useCallback } from 'react';
import * as maplibregl from 'maplibre-gl';
import maplibreWorkerUrl from 'maplibre-gl/dist/maplibre-gl-worker.mjs?worker&url';
import {
  GisCustomSource,
  SelectedEntity,
} from '../../types/atlas';
import { haversineKm, computeBearingDeg } from '../../utils/intelligence';
import { WorkspaceIntelligenceState } from '../../hooks/useWorkspaceIntelligence';
import {
  Crosshair,
  Ruler,
  Search,
  Layers,
  Trash2,
  Maximize2,
} from 'lucide-react';

maplibregl.setWorkerUrl(maplibreWorkerUrl);

export interface MapLayerVisibility {
  assets: boolean;
  approxHalos: boolean;
  dependencies: boolean;
  incidents: boolean;
  riskZones: boolean;
  graticule: boolean;
  cameras?: boolean;
}

interface TacticalAtlasMapProps {
  intel: WorkspaceIntelligenceState;
  selectedEntity: SelectedEntity;
  onSelectEntity: (entity: SelectedEntity) => void;
  layerVisibility: MapLayerVisibility;
  onToggleLayer?: (layer: keyof MapLayerVisibility) => void;
  typeFilter: string;
  onChangeTypeFilter?: (type: string) => void;
  minCriticality: number;
  onChangeMinCriticality?: (tier: number) => void;
  customSources?: GisCustomSource[];
  camerasGeoJson?: { type: 'FeatureCollection'; features: any[] };
  bufferGeoJson?: { type: 'FeatureCollection'; features: any[] };
  centerTarget?: [number, number] | null;
  measureMode?: 'none' | 'distance' | 'area';
  onChangeMeasureMode?: (mode: 'none' | 'distance' | 'area') => void;
  onCursorMove?: (lngLat: { lng: number; lat: number } | null) => void;
  onMeasurementUpdate?: (stats: {
    points: Array<[number, number]>;
    distanceKm: number;
    bearingDeg: number | null;
    areaKm2: number | null;
  }) => void;
  compactControls?: boolean;
}

const TYPE_COLORS: Record<string, string> = {
  site: '#4a9eb0',
  power_feed: '#c88b32',
  fibre_route: '#4f8f66',
  cloud_region: '#7c74b8',
  service: '#b0648b',
};

/** Build a subtle 15-degree WGS84 graticule GeoJSON offline */
function buildGraticuleGeoJson() {
  const features: any[] = [];
  for (let lon = -165; lon <= 180; lon += 15) {
    const coords: Array<[number, number]> = [];
    for (let lat = -80; lat <= 80; lat += 5) {
      coords.push([lon, lat]);
    }
    features.push({
      type: 'Feature',
      geometry: { type: 'LineString', coordinates: coords },
      properties: { kind: lon === 0 ? 'prime' : 'meridian' },
    });
  }
  for (let lat = -75; lat <= 75; lat += 15) {
    const coords: Array<[number, number]> = [];
    for (let lon = -180; lon <= 180; lon += 10) {
      coords.push([lon, lat]);
    }
    features.push({
      type: 'Feature',
      geometry: { type: 'LineString', coordinates: coords },
      properties: { kind: lat === 0 ? 'equator' : 'parallel' },
    });
  }
  return { type: 'FeatureCollection', features };
}

export { haversineKm, computeBearingDeg };

/** Approximate geodesic polygon area in km^2 using spherical excess approximation */
function computePolygonAreaKm2(pts: Array<[number, number]>): number {
  if (pts.length < 3) return 0;
  const toRad = (d: number) => (d * Math.PI) / 180;
  const R = 6371;
  let total = 0;
  for (let i = 0; i < pts.length; i++) {
    const p1 = pts[i];
    const p2 = pts[(i + 1) % pts.length];
    total += toRad(p2[0] - p1[0]) * (2 + Math.sin(toRad(p1[1])) + Math.sin(toRad(p2[1])));
  }
  return Math.abs((total * R * R) / 2);
}

/** Create small octagonal GeoJSON circle polygon for risk zones */
function createCirclePolygon(center: [number, number], radiusKm: number, sides = 24) {
  const coords: Array<[number, number]> = [];
  const latRad = (center[1] * Math.PI) / 180;
  const dLat = radiusKm / 111.32;
  const dLon = radiusKm / (111.32 * Math.max(Math.cos(latRad), 0.15));
  for (let i = 0; i <= sides; i++) {
    const theta = (i / sides) * Math.PI * 2;
    coords.push([center[0] + dLon * Math.cos(theta), center[1] + dLat * Math.sin(theta)]);
  }
  return coords;
}

export const TacticalAtlasMap: React.FC<TacticalAtlasMapProps> = ({
  intel,
  selectedEntity,
  onSelectEntity,
  layerVisibility,
  onToggleLayer,
  typeFilter,
  onChangeTypeFilter,
  minCriticality,
  onChangeMinCriticality,
  customSources = [],
  camerasGeoJson,
  bufferGeoJson,
  centerTarget,
  measureMode = 'none',
  onChangeMeasureMode,
  onCursorMove,
  onMeasurementUpdate,
  compactControls = false,
}) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const mapRef = useRef<maplibregl.Map | null>(null);
  const [mapReady, setMapReady] = useState(false);

  const [locationSearch, setLocationSearch] = useState('');
  const [measurePoints, setMeasurePoints] = useState<Array<[number, number]>>([]);
  const [layersPopoverOpen, setLayersPopoverOpen] = useState(false);

  const measureModeRef = useRef(measureMode);
  measureModeRef.current = measureMode;

  const onSelectEntityRef = useRef(onSelectEntity);
  onSelectEntityRef.current = onSelectEntity;

  const onCursorMoveRef = useRef(onCursorMove);
  onCursorMoveRef.current = onCursorMove;

  // Derived filtered GeoJSON features
  const filteredAssetsGeoJson = useMemo(() => {
    const features = intel.assetsGeoJson.features.filter((f) => {
      if (typeFilter !== 'all' && f.properties.type !== typeFilter) return false;
      if (Number(f.properties.criticality) < minCriticality) return false;
      return true;
    });
    return { type: 'FeatureCollection' as const, features };
  }, [intel.assetsGeoJson, typeFilter, minCriticality]);

  // Derived Dependency Line GeoJSON
  const dependenciesGeoJson = useMemo(() => {
    const features: any[] = [];
    for (const edge of intel.edges) {
      const fromCoord = intel.assetCoordsMap.get(edge.from_asset_id);
      const toCoord = intel.assetCoordsMap.get(edge.to_asset_id);
      if (fromCoord && toCoord) {
        features.push({
          type: 'Feature',
          id: edge.id,
          geometry: {
            type: 'LineString',
            coordinates: [fromCoord, toCoord],
          },
          properties: {
            id: edge.id,
            relation_type: edge.relation_type,
            criticality: edge.criticality,
            from_asset_id: edge.from_asset_id,
            to_asset_id: edge.to_asset_id,
          },
        });
      }
    }
    return { type: 'FeatureCollection' as const, features };
  }, [intel.edges, intel.assetCoordsMap]);

  // Derived Incident Link Markers & Geographic Risk Zones
  const { incidentGeoJson, riskZonesGeoJson } = useMemo(() => {
    const incidentFeatures: any[] = [];
    const zoneFeatures: any[] = [];
    const assetMatchStatus = new Map<string, { status: string; incidentId: string; eventId: string }>();

    for (const m of intel.matches) {
      if (m.status === 'rejected') continue;
      const inc = intel.incidents.find((i) => i.id === m.incident_id);
      const existing = assetMatchStatus.get(m.asset_id);
      const priorityRank = (s: string) => (s === 'confirmed' ? 3 : s === 'auto' ? 2 : 1);
      if (!existing || priorityRank(m.status) > priorityRank(existing.status)) {
        assetMatchStatus.set(m.asset_id, {
          status: m.status,
          incidentId: m.incident_id,
          eventId: inc?.event_id || m.incident_id.slice(0, 8),
        });
      }
    }

    for (const asset of intel.assets) {
      const coord = intel.assetCoordsMap.get(asset.id);
      if (!coord) continue;
      const matchInfo = assetMatchStatus.get(asset.id);

      if (matchInfo) {
        incidentFeatures.push({
          type: 'Feature',
          id: `inc-pin-${asset.id}`,
          geometry: { type: 'Point', coordinates: coord },
          properties: {
            asset_id: asset.id,
            incident_id: matchInfo.incidentId,
            event_id: matchInfo.eventId,
            status: matchInfo.status,
            site_code: asset.site_code,
          },
        });

        zoneFeatures.push({
          type: 'Feature',
          id: `rz-inc-${asset.id}`,
          geometry: {
            type: 'Polygon',
            coordinates: [createCirclePolygon(coord, matchInfo.status === 'proposed' ? 18 : 28)],
          },
          properties: {
            kind: matchInfo.status === 'proposed' ? 'proposed' : 'confirmed',
          },
        });
      } else if (asset.criticality >= 5) {
        zoneFeatures.push({
          type: 'Feature',
          id: `rz-crit-${asset.id}`,
          geometry: {
            type: 'Polygon',
            coordinates: [createCirclePolygon(coord, 12)],
          },
          properties: { kind: 'critical_infra' },
        });
      }
    }

    return {
      incidentGeoJson: { type: 'FeatureCollection' as const, features: incidentFeatures },
      riskZonesGeoJson: { type: 'FeatureCollection' as const, features: zoneFeatures },
    };
  }, [intel.matches, intel.incidents, intel.assets, intel.assetCoordsMap]);

  // Initialize MapLibre instance
  useEffect(() => {
    if (!containerRef.current || mapRef.current) return;

    const blankStyle: maplibregl.StyleSpecification = {
      version: 8,
      name: 'ATLAS Tactical Blank Vector',
      sources: {},
      layers: [
        {
          id: 'atlas-bg',
          type: 'background',
          paint: { 'background-color': '#090c10' },
        },
      ],
    };

    const map = new maplibregl.Map({
      container: containerRef.current,
      style: blankStyle,
      center: [0, 22],
      zoom: 1.7,
      attributionControl: false,
    });

    map.addControl(new maplibregl.NavigationControl({ showCompass: true }), 'bottom-right');

    map.on('load', () => {
      // Offline Graticule Source
      map.addSource('atlas-graticule', {
        type: 'geojson',
        data: buildGraticuleGeoJson() as any,
      });
      map.addLayer({
        id: 'atlas-graticule-lines',
        type: 'line',
        source: 'atlas-graticule',
        paint: {
          'line-color': ['match', ['get', 'kind'], ['equator', 'prime'], '#242c38', '#161b23'],
          'line-width': ['match', ['get', 'kind'], ['equator', 'prime'], 1.2, 0.7],
        },
      });

      // Geographic Risk Zones
      map.addSource('atlas-risk-zones', {
        type: 'geojson',
        data: { type: 'FeatureCollection', features: [] },
      });
      map.addLayer({
        id: 'risk-zones-fill',
        type: 'fill',
        source: 'atlas-risk-zones',
        paint: {
          'fill-color': [
            'match',
            ['get', 'kind'],
            'confirmed',
            'rgba(201, 74, 74, 0.14)',
            'proposed',
            'rgba(200, 139, 50, 0.12)',
            'rgba(74, 158, 176, 0.08)',
          ],
          'fill-outline-color': [
            'match',
            ['get', 'kind'],
            'confirmed',
            '#c94a4a',
            'proposed',
            '#c88b32',
            '#4a9eb0',
          ],
        },
      });

      // Dependency Topology Lines
      map.addSource('atlas-dependencies', {
        type: 'geojson',
        data: { type: 'FeatureCollection', features: [] },
      });
      map.addLayer({
        id: 'dependency-lines',
        type: 'line',
        source: 'atlas-dependencies',
        filter: ['==', '$type', 'LineString'],
        paint: {
          'line-color': '#5682b0',
          'line-width': 1.5,
          'line-dasharray': [3, 2],
          'line-opacity': 0.75,
        },
      });

      // Workspace Assets
      map.addSource('workspace-assets', {
        type: 'geojson',
        data: { type: 'FeatureCollection', features: [] },
      });

      // Approximate accuracy halo
      map.addLayer({
        id: 'assets-approx-halo',
        type: 'circle',
        source: 'workspace-assets',
        filter: ['==', ['get', 'is_approximate'], true],
        paint: {
          'circle-radius': ['interpolate', ['linear'], ['zoom'], 1, 10, 8, 22, 14, 34],
          'circle-color': 'rgba(200, 139, 50, 0.10)',
          'circle-stroke-width': 1.25,
          'circle-stroke-color': '#c88b32',
          'circle-stroke-opacity': 0.8,
        },
      });

      // Asset linear geometry (fibre routes)
      map.addLayer({
        id: 'assets-lines',
        type: 'line',
        source: 'workspace-assets',
        filter: ['==', '$type', 'LineString'],
        paint: {
          'line-color': '#4f8f66',
          'line-width': 2.25,
          'line-opacity': 0.9,
        },
      });

      // Asset Points
      map.addLayer({
        id: 'assets-points',
        type: 'circle',
        source: 'workspace-assets',
        filter: ['==', '$type', 'Point'],
        paint: {
          'circle-radius': ['interpolate', ['linear'], ['get', 'criticality'], 1, 4, 3, 5.5, 5, 8],
          'circle-color': [
            'match',
            ['get', 'type'],
            'site',
            TYPE_COLORS.site,
            'power_feed',
            TYPE_COLORS.power_feed,
            'fibre_route',
            TYPE_COLORS.fibre_route,
            'cloud_region',
            TYPE_COLORS.cloud_region,
            'service',
            TYPE_COLORS.service,
            '#8c97a8',
          ],
          'circle-stroke-width': 1.5,
          'circle-stroke-color': '#0b0d10',
        },
      });

      // Incident Epicenter Rings
      map.addSource('atlas-incidents', {
        type: 'geojson',
        data: { type: 'FeatureCollection', features: [] },
      });
      map.addLayer({
        id: 'incident-rings',
        type: 'circle',
        source: 'atlas-incidents',
        filter: ['==', '$type', 'Point'],
        paint: {
          'circle-radius': ['interpolate', ['linear'], ['zoom'], 1, 8, 8, 15, 14, 22],
          'circle-color': 'rgba(0,0,0,0)',
          'circle-stroke-width': 2,
          'circle-stroke-color': [
            'match',
            ['get', 'status'],
            'proposed',
            '#c88b32',
            '#c94a4a',
          ],
        },
      });

      // Measurement Tool Source & Layers
      map.addSource('atlas-measure', {
        type: 'geojson',
        data: { type: 'FeatureCollection', features: [] },
      });
      map.addLayer({
        id: 'measure-lines',
        type: 'line',
        source: 'atlas-measure',
        filter: ['==', '$type', 'LineString'],
        paint: {
          'line-color': '#8fa36d',
          'line-width': 2,
          'line-dasharray': [2, 2],
        },
      });
      map.addLayer({
        id: 'measure-points',
        type: 'circle',
        source: 'atlas-measure',
        filter: ['==', '$type', 'Point'],
        paint: {
          'circle-radius': 4,
          'circle-color': '#8fa36d',
          'circle-stroke-width': 1.5,
          'circle-stroke-color': '#0b0d10',
        },
      });

      // Module E Geodesic Buffer Analysis Zone
      map.addSource('atlas-buffer-zone', {
        type: 'geojson',
        data: { type: 'FeatureCollection', features: [] },
      });
      map.addLayer({
        id: 'buffer-zone-fill',
        type: 'fill',
        source: 'atlas-buffer-zone',
        filter: ['==', '$type', 'Polygon'],
        paint: {
          'fill-color': 'rgba(74, 158, 176, 0.14)',
          'fill-outline-color': '#4a9eb0',
        },
      });

      // Module C Registered Camera Points & Geodesic FOV Cones
      map.addSource('atlas-cameras', {
        type: 'geojson',
        data: { type: 'FeatureCollection', features: [] },
      });
      map.addLayer({
        id: 'camera-fov-fill',
        type: 'fill',
        source: 'atlas-cameras',
        filter: ['==', '$type', 'Polygon'],
        paint: {
          'fill-color': 'rgba(79, 143, 102, 0.18)',
          'fill-outline-color': '#4f8f66',
        },
      });
      map.addLayer({
        id: 'camera-points',
        type: 'circle',
        source: 'atlas-cameras',
        filter: ['==', '$type', 'Point'],
        paint: {
          'circle-radius': 5,
          'circle-color': '#4f8f66',
          'circle-stroke-width': 1.5,
          'circle-stroke-color': '#0b0d10',
        },
      });

      // Interactive cursor hover
      map.on('mouseenter', 'assets-points', () => {
        if (measureModeRef.current === 'none') map.getCanvas().style.cursor = 'pointer';
      });
      map.on('mouseleave', 'assets-points', () => {
        map.getCanvas().style.cursor = measureModeRef.current === 'none' ? '' : 'crosshair';
      });
      map.on('mouseenter', 'incident-rings', () => {
        if (measureModeRef.current === 'none') map.getCanvas().style.cursor = 'pointer';
      });
      map.on('mouseleave', 'incident-rings', () => {
        map.getCanvas().style.cursor = measureModeRef.current === 'none' ? '' : 'crosshair';
      });

      map.on('mousemove', (e) => {
        onCursorMoveRef.current?.({ lng: e.lngLat.lng, lat: e.lngLat.lat });
      });
      map.on('mouseout', () => {
        onCursorMoveRef.current?.(null);
      });

      // Map clicks: Measurement or Entity Selection
      map.on('click', (e) => {
        if (measureModeRef.current !== 'none') {
          const pt: [number, number] = [e.lngLat.lng, e.lngLat.lat];
          setMeasurePoints((prev) => [...prev, pt]);
          return;
        }

        const features = map.queryRenderedFeatures(e.point, {
          layers: ['assets-points', 'assets-lines', 'incident-rings'],
        });
        if (!features.length) return;

        const top = features[0];
        if (top.layer.id === 'incident-rings' && top.properties?.incident_id) {
          onSelectEntityRef.current({ kind: 'incident', id: top.properties.incident_id });
        } else if (top.properties?.id || top.id) {
          onSelectEntityRef.current({ kind: 'asset', id: String(top.properties?.id || top.id) });
        }
      });

      mapRef.current = map;
      setMapReady(true);
    });

    return () => {
      map.remove();
      mapRef.current = null;
      setMapReady(false);
    };
  }, []);

  // Push GeoJSON updates into MapLibre sources
  useEffect(() => {
    const map = mapRef.current;
    if (!map || !mapReady) return;

    (map.getSource('workspace-assets') as maplibregl.GeoJSONSource)?.setData(filteredAssetsGeoJson as any);
    (map.getSource('atlas-dependencies') as maplibregl.GeoJSONSource)?.setData(dependenciesGeoJson as any);
    (map.getSource('atlas-incidents') as maplibregl.GeoJSONSource)?.setData(incidentGeoJson as any);
    (map.getSource('atlas-risk-zones') as maplibregl.GeoJSONSource)?.setData(riskZonesGeoJson as any);
    (map.getSource('atlas-cameras') as maplibregl.GeoJSONSource)?.setData(
      (camerasGeoJson || { type: 'FeatureCollection', features: [] }) as any
    );
    (map.getSource('atlas-buffer-zone') as maplibregl.GeoJSONSource)?.setData(
      (bufferGeoJson || { type: 'FeatureCollection', features: [] }) as any
    );
  }, [mapReady, filteredAssetsGeoJson, dependenciesGeoJson, incidentGeoJson, riskZonesGeoJson, camerasGeoJson, bufferGeoJson]);

  // Fit bounds when workspace data arrives
  useEffect(() => {
    const map = mapRef.current;
    if (!map || !mapReady || filteredAssetsGeoJson.features.length === 0) return;

    const bounds = new maplibregl.LngLatBounds();
    let hasCoords = false;

    for (const f of filteredAssetsGeoJson.features) {
      if (f.geometry?.type === 'Point' && Array.isArray(f.geometry.coordinates)) {
        bounds.extend(f.geometry.coordinates as [number, number]);
        hasCoords = true;
      } else if (f.geometry?.type === 'LineString' && Array.isArray(f.geometry.coordinates)) {
        for (const pt of f.geometry.coordinates) {
          if (Array.isArray(pt)) {
            bounds.extend(pt as [number, number]);
            hasCoords = true;
          }
        }
      }
    }

    if (hasCoords) {
      map.fitBounds(bounds, { padding: 64, maxZoom: 11, duration: 500 });
    }
  }, [mapReady, intel.orgId, filteredAssetsGeoJson.features.length]);

  // Update layer visibility
  useEffect(() => {
    const map = mapRef.current;
    if (!map || !mapReady) return;

    const setVis = (layerId: string, vis: boolean) => {
      if (map.getLayer(layerId)) {
        map.setLayoutProperty(layerId, 'visibility', vis ? 'visible' : 'none');
      }
    };

    setVis('assets-points', layerVisibility.assets);
    setVis('assets-lines', layerVisibility.assets);
    setVis('assets-approx-halo', layerVisibility.assets && layerVisibility.approxHalos);
    setVis('dependency-lines', layerVisibility.dependencies);
    setVis('incident-rings', layerVisibility.incidents);
    setVis('risk-zones-fill', layerVisibility.riskZones);
    setVis('atlas-graticule-lines', layerVisibility.graticule);
    setVis('camera-fov-fill', layerVisibility.cameras !== false);
    setVis('camera-points', layerVisibility.cameras !== false);
  }, [mapReady, layerVisibility]);

  // Manage user-configured custom tile/GeoJSON overlay layers
  useEffect(() => {
    const map = mapRef.current;
    if (!map || !mapReady) return;

    // Remove stale custom layers not in enabled list
    const activeIds = new Set(customSources.filter((s) => s.enabled).map((s) => `custom-src-${s.id}`));
    const style = map.getStyle();
    if (style && style.layers) {
      for (const l of style.layers) {
        if (l.id.startsWith('custom-lyr-') && !activeIds.has(l.id.replace('custom-lyr-', 'custom-src-'))) {
          map.removeLayer(l.id);
        }
      }
    }
    if (style && style.sources) {
      for (const sId of Object.keys(style.sources)) {
        if (sId.startsWith('custom-src-') && !activeIds.has(sId)) {
          map.removeSource(sId);
        }
      }
    }

    for (const src of customSources) {
      if (!src.enabled || !src.url.trim()) continue;
      const sourceId = `custom-src-${src.id}`;
      const layerId = `custom-lyr-${src.id}`;
      if (map.getSource(sourceId)) continue;

      try {
        if (src.protocol === 'GeoJSON') {
          map.addSource(sourceId, { type: 'geojson', data: src.url.trim() });
          map.addLayer(
            {
              id: layerId,
              type: 'line',
              source: sourceId,
              paint: { 'line-color': '#4a9eb0', 'line-width': 1.5, 'line-opacity': 0.8 },
            },
            'assets-approx-halo'
          );
        } else {
          map.addSource(sourceId, {
            type: 'raster',
            tiles: [src.url.trim()],
            tileSize: 256,
          });
          map.addLayer(
            {
              id: layerId,
              type: 'raster',
              source: sourceId,
              paint: { 'raster-opacity': 0.65 },
            },
            'atlas-graticule-lines'
          );
        }
      } catch {
        // Ignore invalid runtime source additions safely
      }
    }
  }, [mapReady, customSources]);

  // Fly to center target or selected asset
  useEffect(() => {
    const map = mapRef.current;
    if (!map || !mapReady) return;
    if (centerTarget) {
      map.flyTo({ center: centerTarget, zoom: Math.max(map.getZoom(), 9), duration: 500 });
    }
  }, [mapReady, centerTarget]);

  useEffect(() => {
    const map = mapRef.current;
    if (!map || !mapReady || !selectedEntity) return;
    if (selectedEntity.kind === 'asset') {
      const coord = intel.assetCoordsMap.get(selectedEntity.id);
      if (coord) {
        map.flyTo({ center: coord, zoom: Math.max(map.getZoom(), 8.5), duration: 450 });
      }
    }
  }, [mapReady, selectedEntity, intel.assetCoordsMap]);

  // Cursor style for measure mode
  useEffect(() => {
    const map = mapRef.current;
    if (!map || !mapReady) return;
    map.getCanvas().style.cursor = measureMode === 'none' ? '' : 'crosshair';
  }, [mapReady, measureMode]);

  // Update Measurement layer and emit stats
  useEffect(() => {
    const map = mapRef.current;
    const features: any[] = measurePoints.map((pt, idx) => ({
      type: 'Feature',
      id: `m-pt-${idx}`,
      geometry: { type: 'Point', coordinates: pt },
      properties: {},
    }));

    if (measurePoints.length >= 2) {
      const lineCoords =
        measureMode === 'area' && measurePoints.length >= 3
          ? [...measurePoints, measurePoints[0]]
          : measurePoints;
      features.push({
        type: 'Feature',
        id: 'm-line',
        geometry: { type: 'LineString', coordinates: lineCoords },
        properties: {},
      });
    }

    if (map && mapReady) {
      (map.getSource('atlas-measure') as maplibregl.GeoJSONSource)?.setData({
        type: 'FeatureCollection',
        features,
      } as any);
    }

    let distanceKm = 0;
    for (let i = 1; i < measurePoints.length; i++) {
      distanceKm += haversineKm(measurePoints[i - 1], measurePoints[i]);
    }
    const bearingDeg =
      measurePoints.length >= 2
        ? computeBearingDeg(measurePoints[measurePoints.length - 2], measurePoints[measurePoints.length - 1])
        : null;
    const areaKm2 =
      measureMode === 'area' && measurePoints.length >= 3
        ? computePolygonAreaKm2(measurePoints)
        : null;

    onMeasurementUpdate?.({ points: measurePoints, distanceKm, bearingDeg, areaKm2 });
  }, [mapReady, measurePoints, measureMode, onMeasurementUpdate]);

  const handleLocationSearch = useCallback(
    (e: React.FormEvent) => {
      e.preventDefault();
      const q = locationSearch.trim();
      if (!q || !mapRef.current) return;

      // Check coordinate pair "lat, lon"
      const coordMatch = q.match(/^(-?\d+(?:\.\d+)?)\s*,\s*(-?\d+(?:\.\d+)?)$/);
      if (coordMatch) {
        const lat = parseFloat(coordMatch[1]);
        const lng = parseFloat(coordMatch[2]);
        if (lat >= -90 && lat <= 90 && lng >= -180 && lng <= 180) {
          mapRef.current.flyTo({ center: [lng, lat], zoom: 10, duration: 500 });
          return;
        }
      }

      // Match site code or asset name
      const lower = q.toLowerCase();
      const matchedAsset = intel.assets.find(
        (a) => a.site_code.toLowerCase().includes(lower) || a.name.toLowerCase().includes(lower)
      );
      if (matchedAsset) {
        onSelectEntity({ kind: 'asset', id: matchedAsset.id });
      }
    },
    [locationSearch, intel.assets, onSelectEntity]
  );

  const handleFitAll = () => {
    const map = mapRef.current;
    if (!map) return;
    if (filteredAssetsGeoJson.features.length === 0) {
      map.flyTo({ center: [0, 22], zoom: 1.7, duration: 400 });
      return;
    }
    const bounds = new maplibregl.LngLatBounds();
    for (const f of filteredAssetsGeoJson.features) {
      if (f.geometry?.type === 'Point') bounds.extend(f.geometry.coordinates);
    }
    map.fitBounds(bounds, { padding: 64, maxZoom: 11, duration: 400 });
  };

  return (
    <div className="relative w-full h-full bg-[#090c10] overflow-hidden">
      <div ref={containerRef} className="w-full h-full" />

      {/* Top-Left Compact Map Toolbar */}
      <div className="absolute top-2.5 left-2.5 z-10 flex flex-wrap items-center gap-1.5">
        {/* Location / Coordinate Jump */}
        <form
          onSubmit={handleLocationSearch}
          className="flex items-center bg-[#12151b]/95 border border-[#252b36] rounded-[2px]"
        >
          <Search className="w-3 h-3 text-[#5d6778] ml-2 pointer-events-none" />
          <input
            type="text"
            value={locationSearch}
            onChange={(e) => setLocationSearch(e.target.value)}
            placeholder="Site code or lat, lon..."
            className="bg-transparent px-2 py-1 text-[11px] font-mono text-[#e8ecf1] placeholder-[#5d6778] focus:outline-none w-40"
          />
          <button
            type="submit"
            className="px-2 py-1 border-l border-[#252b36] text-[10px] font-mono text-[#8c97a8] hover:text-[#e8ecf1] hover:bg-[#181c24] cursor-pointer"
          >
            GO
          </button>
        </form>

        {/* Type & Criticality Filters */}
        {!compactControls && onChangeTypeFilter && (
          <select
            aria-label="Filter asset type on map"
            value={typeFilter}
            onChange={(e) => onChangeTypeFilter(e.target.value)}
            className="bg-[#12151b]/95 border border-[#252b36] text-[#e8ecf1] px-2 py-1 text-[11px] font-mono rounded-[2px] focus:outline-none focus:border-[#6f8054]"
          >
            <option value="all">All Assets ({intel.assets.length})</option>
            <option value="site">Sites</option>
            <option value="power_feed">Power Feeds</option>
            <option value="fibre_route">Fibre Routes</option>
            <option value="cloud_region">Cloud Regions</option>
            <option value="service">Services</option>
          </select>
        )}

        {!compactControls && onChangeMinCriticality && (
          <div className="flex items-center bg-[#12151b]/95 border border-[#252b36] rounded-[2px] px-1.5 py-0.5 gap-1 font-mono text-[10px]">
            <span className="text-[#8c97a8]">TIER≥</span>
            {[1, 2, 3, 4, 5].map((t) => (
              <button
                key={t}
                onClick={() => onChangeMinCriticality(t)}
                className={`px-1.5 py-0.5 rounded-[1px] cursor-pointer ${
                  minCriticality === t
                    ? 'bg-[#6f8054] text-[#0b0d10] font-bold'
                    : 'text-[#8c97a8] hover:text-[#e8ecf1]'
                }`}
              >
                {t}
              </button>
            ))}
          </div>
        )}

        {/* Layer Visibility Toggle Popover */}
        {onToggleLayer && (
          <div className="relative">
            <button
              onClick={() => setLayersPopoverOpen((v) => !v)}
              className="px-2 py-1 bg-[#12151b]/95 hover:bg-[#181c24] border border-[#252b36] text-[#e8ecf1] text-[11px] font-mono rounded-[2px] flex items-center gap-1 cursor-pointer"
            >
              <Layers className="w-3 h-3 text-[#4a9eb0]" />
              <span>Layers</span>
            </button>

            {layersPopoverOpen && (
              <div className="absolute left-0 top-full mt-1 w-56 bg-[#12151b] border border-[#323a48] p-2 shadow-xl z-20 space-y-1 font-mono text-[11px]">
                {(
                  [
                    ['assets', 'Infrastructure Assets'],
                    ['approxHalos', 'Approximate Halos'],
                    ['dependencies', 'Dependency Topology'],
                    ['incidents', 'Incident Epicenters'],
                    ['riskZones', 'Geographic Risk Zones'],
                    ['cameras', 'Camera FOV Estimates'],
                    ['graticule', 'WGS84 Graticule Grid'],
                  ] as Array<[keyof MapLayerVisibility, string]>
                ).map(([key, label]) => (
                  <label
                    key={key}
                    className="flex items-center justify-between px-1.5 py-1 hover:bg-[#181c24] cursor-pointer text-[#e8ecf1]"
                  >
                    <span>{label}</span>
                    <input
                      type="checkbox"
                      checked={layerVisibility[key] !== false}
                      onChange={() => onToggleLayer(key)}
                      className="accent-[#6f8054]"
                    />
                  </label>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Measure Controls */}
        {onChangeMeasureMode && (
          <div className="flex items-center bg-[#12151b]/95 border border-[#252b36] rounded-[2px] font-mono text-[10px]">
            <button
              onClick={() => {
                setMeasurePoints([]);
                onChangeMeasureMode(measureMode === 'distance' ? 'none' : 'distance');
              }}
              className={`px-2 py-1 flex items-center gap-1 cursor-pointer ${
                measureMode === 'distance' ? 'bg-[#6f8054]/30 text-[#e8ecf1]' : 'text-[#8c97a8] hover:text-[#e8ecf1]'
              }`}
              title="Measure Distance & Bearing"
            >
              <Ruler className="w-3 h-3" />
              <span>Dist</span>
            </button>
            <button
              onClick={() => {
                setMeasurePoints([]);
                onChangeMeasureMode(measureMode === 'area' ? 'none' : 'area');
              }}
              className={`px-2 py-1 border-l border-[#252b36] cursor-pointer ${
                measureMode === 'area' ? 'bg-[#6f8054]/30 text-[#e8ecf1]' : 'text-[#8c97a8] hover:text-[#e8ecf1]'
              }`}
              title="Measure Polygon Area"
            >
              Area
            </button>
            {measurePoints.length > 0 && (
              <button
                onClick={() => setMeasurePoints([])}
                className="px-1.5 py-1 border-l border-[#252b36] text-[#c94a4a] hover:bg-[#181c24] cursor-pointer"
                title="Clear measurement"
              >
                <Trash2 className="w-3 h-3" />
              </button>
            )}
          </div>
        )}

        <button
          onClick={handleFitAll}
          className="p-1.5 bg-[#12151b]/95 hover:bg-[#181c24] border border-[#252b36] text-[#8c97a8] hover:text-[#e8ecf1] rounded-[2px] cursor-pointer"
          title="Fit all visible assets"
          aria-label="Fit map bounds"
        >
          <Maximize2 className="w-3 h-3" />
        </button>
      </div>

      {/* Bottom-Left Compact Source & Basemap Honesty Legend */}
      <div className="absolute bottom-2.5 left-2.5 z-10 bg-[#12151b]/90 border border-[#252b36] px-2.5 py-1.5 text-[10px] font-mono text-[#8c97a8] space-y-1 pointer-events-none">
        <div className="flex items-center gap-3">
          <span className="text-[#e8ecf1]">
            BASEMAP: {customSources.some((s) => s.enabled) ? 'CUSTOM TILE OVERLAY' : 'OFFLINE NEUTRAL VECTOR (0 EXTERNAL REQUESTS)'}
          </span>
          <span className="text-[#323a48]">|</span>
          <span className="tabular-nums">FEATURES: {filteredAssetsGeoJson.features.length}</span>
        </div>
        <div className="flex flex-wrap items-center gap-3 text-[10px]">
          <span className="flex items-center gap-1">
            <span className="w-2 h-2 rounded-full bg-[#4a9eb0]" /> Site
          </span>
          <span className="flex items-center gap-1">
            <span className="w-2 h-2 rounded-full bg-[#c88b32]" /> Power / Approx Halo
          </span>
          <span className="flex items-center gap-1">
            <span className="w-2 h-2 rounded-full bg-[#4f8f66]" /> Fibre
          </span>
          <span className="flex items-center gap-1">
            <span className="w-2 h-2 rounded-full bg-[#5682b0]" /> Dependency
          </span>
          <span className="flex items-center gap-1">
            <span className="w-2 h-2 rounded-full border border-[#c94a4a]" /> Incident Ring
          </span>
          <span className="flex items-center gap-1">
            <span className="w-2 h-2 rounded-full bg-[#4f8f66]/60 border border-[#4f8f66]" /> Camera FOV (Est.)
          </span>
        </div>
      </div>

      {/* Empty Assets Notice */}
      {intel.assets.length === 0 && !intel.isLoading && (
        <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
          <div className="bg-[#12151b]/95 border border-[#252b36] px-4 py-3 text-xs font-mono text-[#8c97a8] flex items-center gap-2">
            <Crosshair className="w-4 h-4 text-[#4a9eb0]" />
            <span>No geospatial assets imported in this workspace yet. Use Infrastructure Mapping to ingest CSV/GeoJSON.</span>
          </div>
        </div>
      )}
    </div>
  );
};
