/**
 * Project ATLAS: Map Screen (Stage 2)
 *
 * HARD RULES:
 * 1. MapLibre GL JS with blank neutral style (#090d16).
 *    No public tile servers, no basemap API keys, no external raster tiles.
 * 2. Load assets strictly via SQL function get_workspace_assets_geojson().
 * 3. Filter by type and criticality.
 * 4. Approximate points are drawn with an accuracy halo and labelled approximate,
 *    never as exact points (Rule 12).
 * 5. Handles up to 10,000 assets efficiently via vector GeoJSON source.
 * 6. Asset profile side panel displays owner, criticality, source, accuracy, identifiers.
 */

import React, { useEffect, useRef, useState, useCallback, useMemo } from 'react';
import * as maplibregl from 'maplibre-gl';
import 'maplibre-gl/dist/maplibre-gl.css';
import maplibreWorkerUrl from 'maplibre-gl/dist/maplibre-gl-worker.mjs?worker&url';

// Register bundled worker URL with MapLibre GL for Vite bundler
maplibregl.setWorkerUrl(maplibreWorkerUrl);
import { atlasService } from '../data/api';
import { AssetType } from '../types/atlas';
import {
  Layers,
  Filter,
  Shield,
  ShieldAlert,
  Server,
  Zap,
  Radio,
  Cloud,
  Cpu,
  X,
  Crosshair,
  Info,
  RefreshCw,
  Search,
  CheckCircle2,
} from 'lucide-react';

interface MapScreenProps {
  activeOrgId: string;
}

interface AssetProperties {
  id: string;
  site_code: string;
  name: string;
  type: AssetType;
  criticality: number;
  owner: string;
  accuracy_class: string;
  is_approximate: boolean;
  positional_accuracy_m: number | null;
  identifiers: {
    hostnames?: string[];
    ip_addresses?: string[];
    cidrs?: string[];
    cloud_account_ids?: string[];
  };
  source: string;
  confidence: number;
  sharing_policy: string;
  created_at: string;
}

const TYPE_COLORS: Record<AssetType, string> = {
  site: '#06b6d4', // cyan-500
  power_feed: '#eab308', // yellow-500
  fibre_route: '#10b981', // emerald-500
  cloud_region: '#a855f7', // purple-500
  service: '#ec4899', // pink-500
};

export const MapScreen: React.FC<MapScreenProps> = ({ activeOrgId }) => {
  const mapContainerRef = useRef<HTMLDivElement>(null);
  const mapRef = useRef<maplibregl.Map | null>(null);

  const [typeFilter, setTypeFilter] = useState<string>('all');
  const [minCriticality, setMinCriticality] = useState<number>(1);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedAsset, setSelectedAsset] = useState<AssetProperties | null>(null);

  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [totalAssetCount, setTotalAssetCount] = useState<number>(0);
  const [approximateCount, setApproximateCount] = useState<number>(0);

  // Initialize MapLibre map with blank neutral style
  useEffect(() => {
    if (!mapContainerRef.current || mapRef.current) return;

    // Blank neutral dark canvas style: 0 network requests, no external tiles
    const neutralBlankStyle: maplibregl.StyleSpecification = {
      version: 8,
      name: 'Project ATLAS Neutral Blank',
      sources: {},
      layers: [
        {
          id: 'neutral-background',
          type: 'background',
          paint: {
            'background-color': '#090d16',
          },
        },
      ],
    };

    const map = new maplibregl.Map({
      container: mapContainerRef.current,
      style: neutralBlankStyle,
      center: [0, 20],
      zoom: 1.8,
      attributionControl: false,
    });

    map.addControl(new maplibregl.NavigationControl({ showCompass: true }), 'bottom-right');

    map.on('load', () => {
      // Add empty GeoJSON source for assets
      map.addSource('workspace-assets', {
        type: 'geojson',
        data: {
          type: 'FeatureCollection',
          features: [],
        },
      });

      // 1. Accuracy Halos layer (approximate points only: facility_approximate & regional_approximate)
      // Visualises spatial uncertainty ring around the asset
      map.addLayer({
        id: 'assets-approx-halo',
        type: 'circle',
        source: 'workspace-assets',
        filter: ['==', ['get', 'is_approximate'], true],
        paint: {
          'circle-radius': ['interpolate', ['linear'], ['zoom'], 1, 10, 8, 22, 14, 34],
          'circle-color': 'rgba(245, 158, 11, 0.12)',
          'circle-stroke-width': 1.5,
          'circle-stroke-color': '#f59e0b',
          'circle-stroke-opacity': 0.85,
        },
      });

      // 2. Fibre routes / linear geometries layer
      map.addLayer({
        id: 'assets-lines',
        type: 'line',
        source: 'workspace-assets',
        filter: ['==', '$type', 'LineString'],
        paint: {
          'line-color': '#10b981',
          'line-width': 2.5,
          'line-opacity': 0.85,
        },
      });

      // 3. Asset Point Circles layer (colored by asset type)
      map.addLayer({
        id: 'assets-points',
        type: 'circle',
        source: 'workspace-assets',
        filter: ['==', '$type', 'Point'],
        paint: {
          'circle-radius': [
            'interpolate',
            ['linear'],
            ['get', 'criticality'],
            1,
            4,
            3,
            6,
            5,
            8.5,
          ],
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
            '#94a3b8',
          ],
          'circle-stroke-width': 1.5,
          'circle-stroke-color': '#020617',
        },
      });

      // Interactive hover pointers
      map.on('mouseenter', 'assets-points', () => {
        map.getCanvas().style.cursor = 'pointer';
      });
      map.on('mouseleave', 'assets-points', () => {
        map.getCanvas().style.cursor = '';
      });

      map.on('mouseenter', 'assets-lines', () => {
        map.getCanvas().style.cursor = 'pointer';
      });
      map.on('mouseleave', 'assets-lines', () => {
        map.getCanvas().style.cursor = '';
      });

      // Asset Selection on Click
      const handleAssetClick = (e: maplibregl.MapMouseEvent & { features?: maplibregl.MapGeoJSONFeature[] }) => {
        if (!e.features || e.features.length === 0) return;
        const feature = e.features[0];
        const props = feature.properties as any;

        // Parse identifiers if stored as string in properties
        let identifiers = props.identifiers;
        if (typeof identifiers === 'string') {
          try {
            identifiers = JSON.parse(identifiers);
          } catch {
            identifiers = {};
          }
        }

        setSelectedAsset({
          id: props.id || feature.id,
          site_code: props.site_code,
          name: props.name,
          type: props.type,
          criticality: Number(props.criticality),
          owner: props.owner,
          accuracy_class: props.accuracy_class,
          is_approximate: Boolean(props.is_approximate),
          positional_accuracy_m: props.positional_accuracy_m ? Number(props.positional_accuracy_m) : null,
          identifiers: identifiers || {},
          source: props.source,
          confidence: Number(props.confidence),
          sharing_policy: props.sharing_policy,
          created_at: props.created_at,
        });
      };

      map.on('click', 'assets-points', handleAssetClick);
      map.on('click', 'assets-lines', handleAssetClick);

      mapRef.current = map;
      loadMapAssets();
    });

    return () => {
      map.remove();
      mapRef.current = null;
    };
  }, []);

  // Fetch workspace assets GeoJSON from SQL function
  const loadMapAssets = useCallback(async () => {
    if (!activeOrgId) return;

    setIsLoading(true);
    setLoadError(null);

    try {
      const geojson = await atlasService.fetchWorkspaceAssetsGeoJson(
        activeOrgId,
        typeFilter,
        minCriticality
      );

      setTotalAssetCount(geojson.features.length);
      const approx = geojson.features.filter((f) => f.properties.is_approximate).length;
      setApproximateCount(approx);

      if (mapRef.current) {
        const source = mapRef.current.getSource('workspace-assets') as maplibregl.GeoJSONSource;
        if (source) {
          source.setData(geojson as any);
        }

        // Fit bounds if we have points and not currently focused
        if (geojson.features.length > 0) {
          const bounds = new maplibregl.LngLatBounds();
          let hasCoords = false;

          geojson.features.forEach((f) => {
            if (f.geometry && f.geometry.type === 'Point' && Array.isArray(f.geometry.coordinates)) {
              bounds.extend(f.geometry.coordinates as [number, number]);
              hasCoords = true;
            } else if (f.geometry && f.geometry.type === 'LineString' && Array.isArray(f.geometry.coordinates)) {
              f.geometry.coordinates.forEach((pt: any) => {
                if (Array.isArray(pt)) {
                  bounds.extend(pt as [number, number]);
                  hasCoords = true;
                }
              });
            }
          });

          if (hasCoords) {
            mapRef.current.fitBounds(bounds, {
              padding: 60,
              maxZoom: 12,
              duration: 800,
            });
          }
        }
      }
    } catch (err: any) {
      setLoadError(err.message || 'Error querying workspace assets.');
    } finally {
      setIsLoading(false);
    }
  }, [activeOrgId, typeFilter, minCriticality]);

  // Re-query whenever filters change or active organisation changes
  useEffect(() => {
    if (mapRef.current?.isStyleLoaded()) {
      loadMapAssets();
    }
  }, [loadMapAssets]);

  const getTypeIcon = (type: AssetType) => {
    switch (type) {
      case 'site':
        return <Server className="w-4 h-4 text-cyan-400" />;
      case 'power_feed':
        return <Zap className="w-4 h-4 text-amber-400" />;
      case 'fibre_route':
        return <Radio className="w-4 h-4 text-emerald-400" />;
      case 'cloud_region':
        return <Cloud className="w-4 h-4 text-purple-400" />;
      case 'service':
        return <Cpu className="w-4 h-4 text-pink-400" />;
      default:
        return <Server className="w-4 h-4 text-slate-400" />;
    }
  };

  return (
    <div className="relative w-full h-[calc(100vh-57px)] flex overflow-hidden bg-slate-950 font-sans">
      {/* Map Canvas */}
      <div className="relative flex-1 h-full">
        <div ref={mapContainerRef} className="w-full h-full bg-[#090d16]" />

        {/* Top Control Bar: Filters & Asset Metrics */}
        <div className="absolute top-4 left-4 z-10 flex flex-wrap items-center gap-2.5 bg-slate-900/90 backdrop-blur-md border border-slate-800 p-2.5 rounded-xl shadow-2xl text-xs max-w-3xl">
          {/* Type Filter */}
          <div className="flex items-center gap-1.5 border-r border-slate-800 pr-3">
            <Filter className="w-3.5 h-3.5 text-slate-400" />
            <select
              value={typeFilter}
              onChange={(e) => setTypeFilter(e.target.value)}
              className="bg-slate-950 border border-slate-700 rounded px-2 py-1 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono text-xs"
            >
              <option value="all">All Types ({totalAssetCount})</option>
              <option value="site">Physical Sites</option>
              <option value="power_feed">Power Feeds</option>
              <option value="fibre_route">Fibre Routes</option>
              <option value="cloud_region">Cloud Regions</option>
              <option value="service">Services</option>
            </select>
          </div>

          {/* Criticality Filter */}
          <div className="flex items-center gap-1.5 border-r border-slate-800 pr-3">
            <span className="text-slate-400 font-mono">Min Tier:</span>
            <div className="flex items-center gap-1">
              {[1, 2, 3, 4, 5].map((tier) => (
                <button
                  key={tier}
                  onClick={() => setMinCriticality(tier)}
                  className={`w-6 h-6 rounded flex items-center justify-center font-mono font-bold text-[11px] transition cursor-pointer ${
                    minCriticality === tier
                      ? 'bg-rose-500 text-slate-950 shadow-sm'
                      : minCriticality < tier
                      ? 'bg-slate-800 text-slate-400 hover:bg-slate-700'
                      : 'bg-rose-950 text-rose-300 border border-rose-800/60'
                  }`}
                  title={`Show assets with criticality >= ${tier}`}
                >
                  T{tier}
                </button>
              ))}
            </div>
          </div>

          {/* Counts & Refresh */}
          <div className="flex items-center gap-3 pl-1 font-mono text-[11px]">
            <span className="text-slate-300">
              Assets: <strong className="text-cyan-400">{totalAssetCount}</strong>
            </span>
            {approximateCount > 0 && (
              <span className="flex items-center gap-1 text-amber-400 bg-amber-950/60 px-2 py-0.5 rounded border border-amber-900/60">
                <ShieldAlert className="w-3 h-3 text-amber-400" />
                <span>{approximateCount} Approximate</span>
              </span>
            )}
            <button
              onClick={loadMapAssets}
              disabled={isLoading}
              className="p-1 hover:bg-slate-800 text-slate-400 hover:text-slate-200 rounded transition cursor-pointer"
              title="Refresh Map Assets from Database"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin text-cyan-400' : ''}`} />
            </button>
          </div>
        </div>

        {/* Map Legend */}
        <div className="absolute bottom-6 left-4 z-10 bg-slate-900/90 backdrop-blur-md border border-slate-800 px-3 py-2 rounded-lg text-[11px] font-mono shadow-xl space-y-1.5 hidden sm:block">
          <div className="text-slate-400 text-[10px] font-semibold uppercase tracking-wider mb-1">Layer Legend</div>
          <div className="grid grid-cols-2 gap-x-3 gap-y-1">
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: TYPE_COLORS.site }}></span>
              <span className="text-slate-300">Site</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: TYPE_COLORS.power_feed }}></span>
              <span className="text-slate-300">Power Feed</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: TYPE_COLORS.fibre_route }}></span>
              <span className="text-slate-300">Fibre Route</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: TYPE_COLORS.cloud_region }}></span>
              <span className="text-slate-300">Cloud Region</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: TYPE_COLORS.service }}></span>
              <span className="text-slate-300">Service</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full border border-amber-400 bg-amber-500/20"></span>
              <span className="text-amber-300">Approx Halo</span>
            </div>
          </div>
        </div>

        {/* Error Notification */}
        {loadError && (
          <div className="absolute top-20 left-4 z-20 max-w-md bg-rose-950/95 border border-rose-800 text-rose-200 p-3 rounded-lg text-xs shadow-2xl flex items-start gap-2">
            <ShieldAlert className="w-4 h-4 shrink-0 text-rose-400 mt-0.5" />
            <div className="space-y-1">
              <div className="font-semibold">Map Query Failed</div>
              <p className="text-[11px] leading-relaxed">{loadError}</p>
            </div>
            <button
              onClick={() => setLoadError(null)}
              className="text-rose-400 hover:text-rose-200 ml-auto p-0.5"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        )}
      </div>

      {/* Asset Profile Side Drawer */}
      {selectedAsset && (
        <aside className="w-96 shrink-0 h-full bg-slate-900 border-l border-slate-800 shadow-2xl flex flex-col z-20 overflow-y-auto">
          {/* Header */}
          <div className="p-4 border-b border-slate-800 flex items-start justify-between gap-3 bg-slate-950/50">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                {getTypeIcon(selectedAsset.type)}
                <span className="font-mono text-xs uppercase tracking-wider text-slate-400">
                  {selectedAsset.type.replace('_', ' ')}
                </span>
                <span className="text-slate-600">•</span>
                <span className="font-mono text-xs font-bold text-cyan-400">
                  {selectedAsset.site_code}
                </span>
              </div>
              <h2 className="text-base font-bold text-slate-100 leading-snug">{selectedAsset.name}</h2>
            </div>
            <button
              onClick={() => setSelectedAsset(null)}
              className="text-slate-400 hover:text-slate-100 p-1 rounded hover:bg-slate-800 transition cursor-pointer"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          <div className="p-5 space-y-5 text-xs">
            {/* Accuracy & Uncertainty Warning Banner (HARD RULE 12) */}
            {selectedAsset.is_approximate ? (
              <div className="p-3 rounded-lg bg-amber-950/70 border border-amber-800/80 text-amber-200 space-y-1.5">
                <div className="flex items-center gap-1.5 font-bold font-mono text-[11px] text-amber-300">
                  <ShieldAlert className="w-4 h-4 text-amber-400" />
                  <span>APPROXIMATE LOCATION ({selectedAsset.accuracy_class.toUpperCase().replace('_', ' ')})</span>
                </div>
                <p className="text-[11px] leading-relaxed text-amber-300/90">
                  This asset is registered with an approximate position and drawn with an uncertainty halo. It is not an exact physical survey point.
                  {selectedAsset.positional_accuracy_m && ` Estimated accuracy: ±${selectedAsset.positional_accuracy_m} m.`}
                </p>
              </div>
            ) : (
              <div className="p-2.5 rounded-lg bg-emerald-950/40 border border-emerald-900/60 text-emerald-300 flex items-center gap-2 font-mono text-[11px]">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                <span>EXACT SURVEY GEOMETRY</span>
              </div>
            )}

            {/* Core Specifications */}
            <div className="space-y-3 bg-slate-950/60 p-3.5 rounded-xl border border-slate-800">
              <div className="text-[11px] font-mono font-semibold uppercase tracking-wider text-slate-400">
                Asset Specifications
              </div>

              <div className="grid grid-cols-2 gap-3 font-mono text-xs">
                <div>
                  <div className="text-slate-400 text-[10px]">CRITICALITY TIER</div>
                  <div className="flex items-center gap-1 mt-0.5 font-bold text-rose-400">
                    <span>Tier {selectedAsset.criticality}</span>
                    <span className="text-[10px] text-slate-400">/ 5</span>
                  </div>
                </div>

                <div>
                  <div className="text-slate-400 text-[10px]">OWNER / OPERATOR</div>
                  <div className="text-slate-200 font-semibold truncate mt-0.5" title={selectedAsset.owner}>
                    {selectedAsset.owner}
                  </div>
                </div>

                <div>
                  <div className="text-slate-400 text-[10px]">INGEST SOURCE</div>
                  <div className="text-slate-300 truncate mt-0.5" title={selectedAsset.source}>
                    {selectedAsset.source}
                  </div>
                </div>

                <div>
                  <div className="text-slate-400 text-[10px]">CONFIDENCE SCORE</div>
                  <div className="text-emerald-400 font-bold mt-0.5">
                    {(selectedAsset.confidence * 100).toFixed(0)}%
                  </div>
                </div>
              </div>
            </div>

            {/* Identifiers (Cyber-Physical Correlation Keys) */}
            <div className="space-y-2 bg-slate-950/60 p-3.5 rounded-xl border border-slate-800">
              <div className="text-[11px] font-mono font-semibold uppercase tracking-wider text-slate-400">
                Network & Physical Identifiers
              </div>

              {/* Hostnames */}
              {selectedAsset.identifiers?.hostnames && selectedAsset.identifiers.hostnames.length > 0 && (
                <div className="space-y-1">
                  <div className="text-[10px] text-slate-400 font-mono">HOSTNAMES</div>
                  <div className="flex flex-wrap gap-1">
                    {selectedAsset.identifiers.hostnames.map((h, i) => (
                      <span
                        key={i}
                        className="font-mono text-[11px] bg-slate-900 px-2 py-0.5 rounded border border-slate-700 text-cyan-300"
                      >
                        {h}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* IP Addresses */}
              {selectedAsset.identifiers?.ip_addresses && selectedAsset.identifiers.ip_addresses.length > 0 && (
                <div className="space-y-1">
                  <div className="text-[10px] text-slate-400 font-mono">IP ADDRESSES</div>
                  <div className="flex flex-wrap gap-1">
                    {selectedAsset.identifiers.ip_addresses.map((ip, i) => (
                      <span
                        key={i}
                        className="font-mono text-[11px] bg-slate-900 px-2 py-0.5 rounded border border-slate-700 text-emerald-300"
                      >
                        {ip}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* CIDRs */}
              {selectedAsset.identifiers?.cidrs && selectedAsset.identifiers.cidrs.length > 0 && (
                <div className="space-y-1">
                  <div className="text-[10px] text-slate-400 font-mono">CIDR RANGES</div>
                  <div className="flex flex-wrap gap-1">
                    {selectedAsset.identifiers.cidrs.map((cidr, i) => (
                      <span
                        key={i}
                        className="font-mono text-[11px] bg-slate-900 px-2 py-0.5 rounded border border-slate-700 text-amber-300"
                      >
                        {cidr}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Cloud Account IDs */}
              {selectedAsset.identifiers?.cloud_account_ids && selectedAsset.identifiers.cloud_account_ids.length > 0 && (
                <div className="space-y-1">
                  <div className="text-[10px] text-slate-400 font-mono">CLOUD ACCOUNTS</div>
                  <div className="flex flex-wrap gap-1">
                    {selectedAsset.identifiers.cloud_account_ids.map((acc, i) => (
                      <span
                        key={i}
                        className="font-mono text-[11px] bg-slate-900 px-2 py-0.5 rounded border border-slate-700 text-purple-300"
                      >
                        {acc}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {(!selectedAsset.identifiers ||
                (!selectedAsset.identifiers.hostnames?.length &&
                  !selectedAsset.identifiers.ip_addresses?.length &&
                  !selectedAsset.identifiers.cidrs?.length &&
                  !selectedAsset.identifiers.cloud_account_ids?.length)) && (
                <div className="text-slate-400 italic text-[11px]">
                  No network identifiers recorded for this asset.
                </div>
              )}
            </div>

            {/* Ingest Metadata */}
            <div className="p-3 bg-slate-950/60 rounded-xl border border-slate-800 text-[11px] font-mono text-slate-400 space-y-1">
              <div>
                <span className="text-slate-400">SHARING POLICY:</span>{' '}
                <span className="text-slate-200">{selectedAsset.sharing_policy}</span>
              </div>
              <div>
                <span className="text-slate-400">REGISTERED:</span>{' '}
                <span className="text-slate-300">
                  {new Date(selectedAsset.created_at).toLocaleString()}
                </span>
              </div>
              <div className="text-[10px] text-slate-400 truncate">
                <span className="text-slate-400">UUID:</span> {selectedAsset.id}
              </div>
            </div>
          </div>
        </aside>
      )}
    </div>
  );
};
