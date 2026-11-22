import React, { useEffect, useMemo, useState } from 'react';
import {
  AppRole,
  CameraRegistryItem,
  GisCustomSource,
  ModuleId,
  SelectedEntity,
} from '../../types/atlas';
import { WorkspaceIntelligenceState } from '../../hooks/useWorkspaceIntelligence';
import { validateGisSourceInput } from '../../utils/intelligence';
import {
  CAMERA_GATEWAY_ADAPTERS,
  GIS_SOURCE_ADAPTER_CATALOG,
  buildCamerasGeoJson,
  validateAuthorisedEndpointUrl,
} from '../../adapters/gisSurveillanceAdapters';
import {
  analyzeBufferZone,
  computeInfrastructureConcentration,
  computeProximityRankings,
  computeSpatialClusters,
  inspectTerrainDemAvailability,
} from '../../utils/geospatialAnalysis';
import { atlasService } from '../../data/api';
import {
  TacticalAtlasMap,
  MapLayerVisibility,
  haversineKm,
  computeBearingDeg,
} from '../map/TacticalAtlasMap';
import { IntelligenceDossierPanel } from '../common/IntelligenceDossierPanel';
import { AssetImportScreen } from '../AssetImportScreen';
import {
  Layers,
  Plus,
  Trash2,
  Satellite,
  Mountain,
  ShieldAlert,
  Crosshair,
  Search,
  PanelLeftClose,
  PanelLeftOpen,
  PanelRightClose,
  PanelRightOpen,
  Info,
  Video,
  Radar,
} from 'lucide-react';

interface GeointWorkspaceProps {
  mode:
    | 'global_map'
    | 'satellite_imagery'
    | 'terrain_intelligence'
    | 'infrastructure_mapping'
    | 'asset_tracking'
    | 'geographic_risk';
  intel: WorkspaceIntelligenceState;
  activeRole?: AppRole;
  settingsError?: string | null;
  selectedEntity: SelectedEntity;
  onSelectEntity: (entity: SelectedEntity) => void;
  onNavigateModule: (module: ModuleId) => void;
  customGisSources: GisCustomSource[];
  onAddGisSource: (src: Omit<GisCustomSource, 'id'>) => void;
  onToggleGisSource: (id: string) => void;
  onRemoveGisSource: (id: string) => void;
}

function toDms(deg: number, isLat: boolean): string {
  const dir = isLat ? (deg >= 0 ? 'N' : 'S') : deg >= 0 ? 'E' : 'W';
  const abs = Math.abs(deg);
  const d = Math.floor(abs);
  const mFloat = (abs - d) * 60;
  const m = Math.floor(mFloat);
  const s = ((mFloat - m) * 60).toFixed(1);
  return `${d}°${String(m).padStart(2, '0')}'${s}"${dir}`;
}

export const GeointWorkspace: React.FC<GeointWorkspaceProps> = ({
  mode,
  intel,
  activeRole = 'atlas:analyst',
  settingsError,
  selectedEntity,
  onSelectEntity,
  onNavigateModule,
  customGisSources,
  onAddGisSource,
  onToggleGisSource,
  onRemoveGisSource,
}) => {
  const isAdmin = activeRole === 'atlas:admin';
  // Interactive map & panel states
  const [leftPanelOpen, setLeftPanelOpen] = useState(true);
  const [rightPanelOpen, setRightPanelOpen] = useState(true);
  const [typeFilter, setTypeFilter] = useState('all');
  const [minCriticality, setMinCriticality] = useState(1);
  const [centerTarget, setCenterTarget] = useState<[number, number] | null>(null);
  const [measureMode, setMeasureMode] = useState<'none' | 'distance' | 'area'>('none');
  const [cursorCoord, setCursorCoord] = useState<{ lng: number; lat: number } | null>(null);
  const [measureStats, setMeasureStats] = useState<{
    points: Array<[number, number]>;
    distanceKm: number;
    bearingDeg: number | null;
    areaKm2: number | null;
  }>({ points: [], distanceKm: 0, bearingDeg: null, areaKm2: null });

  const [layerVisibility, setLayerVisibility] = useState<MapLayerVisibility>({
    assets: true,
    approxHalos: true,
    dependencies: true,
    incidents: true,
    riskZones: true,
    graticule: true,
    cameras: true,
  });

  // Left panel sub-tabs (GIS Layers vs Surveillance Cameras)
  const [leftTab, setLeftTab] = useState<'layers' | 'cameras'>('layers');

  // Custom GIS Source Form
  const [newSrcName, setNewSrcName] = useState('');
  const [newSrcProtocol, setNewSrcProtocol] = useState<GisCustomSource['protocol']>('XYZ_RASTER');
  const [newSrcUrl, setNewSrcUrl] = useState('');
  const [gisFormError, setGisFormError] = useState<string | null>(null);

  // Module C: Surveillance Camera Registry State (per-org database table, migration 018)
  const [cameras, setCameras] = useState<CameraRegistryItem[]>([]);
  const [camCode, setCamCode] = useState('');
  const [camName, setCamName] = useState('');
  const [camProtocol, setCamProtocol] = useState<CameraRegistryItem['protocol']>('RTSP_HLS');
  const [camLat, setCamLat] = useState('28.6139');
  const [camLng, setCamLng] = useState('77.2090');
  const [camBearing, setCamBearing] = useState('45');
  const [camFov, setCamFov] = useState('70');
  const [camRangeM, setCamRangeM] = useState('350');
  const [camUrl, setCamUrl] = useState('');
  const [camError, setCamError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    atlasService
      .fetchCameras(intel.orgId)
      .then((rows) => {
        if (!cancelled) setCameras(rows);
      })
      .catch((err) => console.error('Could not load camera registry:', err));
    setCamCode('');
    setCamName('');
    setCamUrl('');
    setCamError(null);
    setGisFormError(null);
    setNewSrcName('');
    setNewSrcUrl('');
    setProxAssetA('');
    setProxAssetB('');
    setBufferAnchorId('');
    return () => {
      cancelled = true;
    };
  }, [intel.orgId]);

  // Diffs the previous and requested camera lists (both call sites below either prepend one new
  // camera or remove one by id) and applies exactly that one change in the database. Optimistic:
  // the screen updates immediately and reverts if the database refuses the change.
  const persistCameras = (next: CameraRegistryItem[]) => {
    const prevIds = new Set(cameras.map((c) => c.id));
    const nextIds = new Set(next.map((c) => c.id));
    const added = next.filter((c) => !prevIds.has(c.id));
    const removedIds = cameras.filter((c) => !nextIds.has(c.id)).map((c) => c.id);
    const previous = cameras;
    setCameras(next);

    (async () => {
      try {
        for (const cam of added) {
          const saved = await atlasService.insertCamera(intel.orgId, cam);
          setCameras((cur) => cur.map((c) => (c.id === cam.id ? saved : c)));
        }
        for (const id of removedIds) {
          await atlasService.deleteCamera(intel.orgId, id);
        }
      } catch (err: any) {
        console.error(err);
        setCameras(previous);
        setCamError(err?.message || 'Camera change was rejected by the database.');
      }
    })();
  };

  const handleAddCamera = (e: React.FormEvent) => {
    e.preventDefault();
    setCamError(null);
    const lat = Number(camLat);
    const lng = Number(camLng);
    if (!camCode.trim() || !camName.trim()) {
      setCamError('Camera code and label are required.');
      return;
    }
    if (Number.isNaN(lat) || lat < -90 || lat > 90 || Number.isNaN(lng) || lng < -180 || lng > 180) {
      setCamError('Valid WGS84 latitude [-90..90] and longitude [-180..180] are required.');
      return;
    }
    if (camUrl.trim()) {
      const check = validateAuthorisedEndpointUrl(camUrl);
      if (!check.valid) {
        setCamError(check.reason || 'Invalid camera stream endpoint URL.');
        return;
      }
    }
    const hasUrl = Boolean(camUrl.trim());
    const newCam: CameraRegistryItem = {
      id: `cam-${Date.now()}`,
      cameraCode: camCode.trim(),
      name: camName.trim(),
      protocol: camProtocol,
      lat,
      lng,
      bearingDeg: Number(camBearing) || 0,
      fovDeg: Math.max(10, Math.min(180, Number(camFov) || 60)),
      rangeMeters: Math.max(20, Math.min(5000, Number(camRangeM) || 250)),
      connectionState: hasUrl ? 'configured' : 'registered',
      streamStatus: hasUrl
        ? 'CONFIGURED (HTTPS ENDPOINT ONLY — NOT CONNECTED / NO STREAM DECODE)'
        : 'REGISTERED (METADATA & CALCULATED FOV ESTIMATE ONLY — NOT CONNECTED)',
      endpointUrl: camUrl.trim() || undefined,
    };
    persistCameras([newCam, ...cameras]);
    setCamCode('');
    setCamName('');
    setCamUrl('');
  };

  // Asset Tracking search/filter state
  const [assetQuery, setAssetQuery] = useState('');
  const [assetTypeFilter, setAssetTypeFilter] = useState('all');

  // Terrain proximity & Module E analysis states
  const [proxAssetA, setProxAssetA] = useState('');
  const [proxAssetB, setProxAssetB] = useState('');
  const [proxRadiusKm, setProxRadiusKm] = useState(250);
  const [bufferAnchorId, setBufferAnchorId] = useState('');
  const [bufferRadiusKm, setBufferRadiusKm] = useState(50);
  const [showBufferOnMap, setShowBufferOnMap] = useState(true);

  const toggleLayer = (layer: keyof MapLayerVisibility) => {
    setLayerVisibility((prev) => ({ ...prev, [layer]: !prev[layer] }));
  };

  const handleAddSource = (e: React.FormEvent) => {
    e.preventDefault();
    const validationErr = validateGisSourceInput({
      name: newSrcName,
      protocol: newSrcProtocol,
      url: newSrcUrl,
    });
    if (validationErr) {
      setGisFormError(validationErr);
      return;
    }
    setGisFormError(null);
    onAddGisSource({
      name: newSrcName.trim(),
      protocol: newSrcProtocol,
      url: newSrcUrl.trim(),
      enabled: true,
      attribution: 'Operator-Configured GIS Feed',
    });
    setNewSrcName('');
    setNewSrcUrl('');
  };

  const demStatus = useMemo(
    () => inspectTerrainDemAvailability(customGisSources),
    [customGisSources]
  );

  // Proximity computation for terrain mode
  const assetA = intel.assets.find((a) => a.id === proxAssetA) || intel.assets[0];
  const assetB = intel.assets.find((a) => a.id === proxAssetB) || intel.assets[1];
  const coordA = assetA ? intel.assetCoordsMap.get(assetA.id) : null;
  const coordB = assetB ? intel.assetCoordsMap.get(assetB.id) : null;
  const pairDistKm = coordA && coordB ? haversineKm(coordA, coordB) : null;
  const pairBearing = coordA && coordB ? computeBearingDeg(coordA, coordB) : null;

  const proximityRankings = useMemo(() => {
    if (!coordA || !assetA) return [];
    return computeProximityRankings(coordA, proxRadiusKm, intel.assets, intel.assetCoordsMap, assetA.id);
  }, [coordA, assetA, proxRadiusKm, intel.assets, intel.assetCoordsMap]);

  // Module E: Buffer Zone, Spatial Clusters, Concentration Grid
  const bufferAnchorAsset =
    intel.assets.find((a) => a.id === bufferAnchorId) ||
    (selectedEntity?.kind === 'asset' ? intel.assets.find((a) => a.id === selectedEntity.id) : undefined) ||
    intel.assets[0];
  const bufferAnchorCoord = bufferAnchorAsset ? intel.assetCoordsMap.get(bufferAnchorAsset.id) : null;

  const bufferAnalysis = useMemo(() => {
    if (!bufferAnchorCoord) return null;
    return analyzeBufferZone(
      bufferAnchorCoord,
      bufferRadiusKm,
      intel.assets,
      intel.assetCoordsMap,
      intel.matches
    );
  }, [bufferAnchorCoord, bufferRadiusKm, intel.assets, intel.assetCoordsMap, intel.matches]);

  const bufferGeoJson = useMemo(() => {
    if (!showBufferOnMap || !bufferAnalysis) {
      return { type: 'FeatureCollection' as const, features: [] as any[] };
    }
    return {
      type: 'FeatureCollection' as const,
      features: [
        {
          type: 'Feature',
          id: 'module-e-buffer',
          geometry: { type: 'Polygon', coordinates: [bufferAnalysis.ringPolygon] },
          properties: { radiusKm: bufferAnalysis.radiusKm },
        },
      ],
    };
  }, [showBufferOnMap, bufferAnalysis]);

  const camerasGeoJson = useMemo(() => buildCamerasGeoJson(cameras), [cameras]);

  const spatialClusters = useMemo(
    () => computeSpatialClusters(intel.assets, intel.assetCoordsMap, intel.matches, 50),
    [intel.assets, intel.assetCoordsMap, intel.matches]
  );

  const concentrationGrid = useMemo(
    () => computeInfrastructureConcentration(intel.assets, intel.assetCoordsMap, intel.matches, 0.5),
    [intel.assets, intel.assetCoordsMap, intel.matches]
  );

  // =========================================================================
  // INFRASTRUCTURE MAPPING (EMBEDDED ASSET IMPORT)
  // =========================================================================
  if (mode === 'infrastructure_mapping') {
    return (
      <div className="flex-1 overflow-y-auto bg-[#0b0d10]">
        <AssetImportScreen
          activeOrgId={intel.orgId}
          onNavigateToMap={() => {
            intel.refreshAll();
            onNavigateModule('global_map');
          }}
        />
      </div>
    );
  }

  // =========================================================================
  // ASSET TRACKING REGISTRY TABLE
  // =========================================================================
  if (mode === 'asset_tracking') {
    const filteredAssets = intel.assets.filter((a) => {
      if (assetTypeFilter !== 'all' && a.type !== assetTypeFilter) return false;
      if (assetQuery.trim()) {
        const q = assetQuery.toLowerCase();
        const hay = `${a.site_code} ${a.name} ${a.owner} ${JSON.stringify(a.identifiers || {})}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });

    return (
      <div className="flex-1 flex overflow-hidden bg-[#0b0d10]">
        <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
          {/* Header */}
          <div className="px-4 py-2.5 border-b border-[#252b36] bg-[#12151b] flex flex-wrap items-center justify-between gap-2 shrink-0">
            <div>
              <div className="font-mono text-[10px] tracking-[0.12em] text-[#8fa36d]">
                GEOSPATIAL INTELLIGENCE // ASSET REGISTRY
              </div>
              <h1 className="text-sm font-semibold text-[#e8ecf1]">
                Infrastructure Asset Tracking ({filteredAssets.length} of {intel.assets.length})
              </h1>
            </div>
            <div className="flex items-center gap-2 font-mono text-xs">
              <div className="relative flex items-center">
                <Search className="w-3.5 h-3.5 text-[#5d6778] absolute left-2 pointer-events-none" />
                <input
                  type="text"
                  value={assetQuery}
                  onChange={(e) => setAssetQuery(e.target.value)}
                  placeholder="Filter site code, name, IP..."
                  className="bg-[#0b0d10] border border-[#252b36] text-[#e8ecf1] pl-7 pr-2.5 py-1 text-xs w-56 focus:outline-none focus:border-[#6f8054]"
                />
              </div>
              <select
                value={assetTypeFilter}
                onChange={(e) => setAssetTypeFilter(e.target.value)}
                className="bg-[#0b0d10] border border-[#252b36] text-[#e8ecf1] px-2 py-1 text-xs"
              >
                <option value="all">All Asset Types</option>
                <option value="site">Site</option>
                <option value="power_feed">Power Feed</option>
                <option value="fibre_route">Fibre Route</option>
                <option value="cloud_region">Cloud Region</option>
                <option value="service">Service</option>
              </select>
            </div>
          </div>

          {/* Registry Table */}
          <div className="flex-1 overflow-auto">
            <table className="w-full text-left font-mono text-[11px] border-collapse">
              <thead className="sticky top-0 bg-[#12151b] border-b border-[#252b36] text-[#8c97a8] text-[10px]">
                <tr>
                  <th className="py-2 px-3">SITE CODE</th>
                  <th className="py-2 px-2">ASSET NAME</th>
                  <th className="py-2 px-2">TYPE</th>
                  <th className="py-2 px-2">TIER</th>
                  <th className="py-2 px-2">ACCURACY</th>
                  <th className="py-2 px-2">WGS84 COORDS</th>
                  <th className="py-2 px-2">OWNER</th>
                  <th className="py-2 px-3 text-right">ACTION</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#181c24]">
                {filteredAssets.length === 0 ? (
                  <tr>
                    <td colSpan={8} className="py-8 text-center text-[#8c97a8] font-sans">
                      No assets match the current filter.
                    </td>
                  </tr>
                ) : (
                  filteredAssets.map((asset) => {
                    const coord = intel.assetCoordsMap.get(asset.id);
                    const isSelected = selectedEntity?.kind === 'asset' && selectedEntity.id === asset.id;
                    return (
                      <tr
                        key={asset.id}
                        onClick={() => onSelectEntity({ kind: 'asset', id: asset.id })}
                        className={`cursor-pointer hover:bg-[#151922] ${
                          isSelected ? 'bg-[#6f8054]/15' : ''
                        }`}
                      >
                        <td className="py-1.5 px-3 text-[#4a9eb0] font-semibold">{asset.site_code}</td>
                        <td className="py-1.5 px-2 text-[#e8ecf1] font-sans">{asset.name}</td>
                        <td className="py-1.5 px-2 text-[#8c97a8]">{asset.type}</td>
                        <td
                          className={`py-1.5 px-2 font-semibold tabular-nums ${
                            asset.criticality >= 5
                              ? 'text-[#c94a4a]'
                              : asset.criticality >= 4
                              ? 'text-[#c88b32]'
                              : 'text-[#e8ecf1]'
                          }`}
                        >
                          T{asset.criticality}
                        </td>
                        <td
                          className={`py-1.5 px-2 ${
                            asset.accuracy_class === 'exact_survey' ? 'text-[#4f8f66]' : 'text-[#c88b32]'
                          }`}
                        >
                          {asset.accuracy_class}
                        </td>
                        <td className="py-1.5 px-2 tabular-nums text-[#8c97a8]">
                          {coord ? `${coord[1].toFixed(4)}, ${coord[0].toFixed(4)}` : '—'}
                        </td>
                        <td className="py-1.5 px-2 text-[#8c97a8]">{asset.owner}</td>
                        <td className="py-1.5 px-3 text-right">
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              onSelectEntity({ kind: 'asset', id: asset.id });
                              onNavigateModule('global_map');
                            }}
                            className="px-2 py-0.5 bg-[#181c24] hover:bg-[#222834] border border-[#252b36] text-[#e8ecf1] inline-flex items-center gap-1 cursor-pointer"
                          >
                            <Crosshair className="w-3 h-3 text-[#4a9eb0]" />
                            <span>Map</span>
                          </button>
                        </td>
                      </tr>
                    );
                  })
                )}
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
  // GIS WORKSPACE MODES:
  // global_map | satellite_imagery | terrain_intelligence | geographic_risk
  // =========================================================================
  const modeHeader =
    mode === 'satellite_imagery'
      ? { title: 'Satellite Imagery & Raster Sources', icon: Satellite, tag: 'PARTIAL / EXTERNAL FEED REQUIRED' }
      : mode === 'terrain_intelligence'
      ? { title: 'Terrain Intelligence & Geodetic Proximity', icon: Mountain, tag: 'NO DEM ATTACHED — WGS84 SPATIAL TOOLS ACTIVE' }
      : mode === 'geographic_risk'
      ? { title: 'Geographic Risk Analysis', icon: ShieldAlert, tag: 'LIVE POSTGIS SPATIAL CORRELATION' }
      : { title: 'Global Intelligence Map', icon: Layers, tag: 'OFFLINE NEUTRAL VECTOR + USER GIS OVERLAYS' };

  const ModeIcon = modeHeader.icon;

  return (
    <div className="flex-1 flex flex-col overflow-hidden bg-[#0b0d10]">
      {/* Compact Mode Banner */}
      <div className="px-3 py-1.5 border-b border-[#252b36] bg-[#12151b] flex items-center justify-between gap-3 shrink-0">
        <div className="flex items-center gap-2 min-w-0">
          <ModeIcon className="w-3.5 h-3.5 text-[#4a9eb0] shrink-0" />
          <span className="text-xs font-semibold text-[#e8ecf1] truncate">{modeHeader.title}</span>
          <span className="font-mono text-[10px] text-[#c88b32] border border-[#c88b32]/40 bg-[#c88b32]/10 px-1.5 py-0.5 hidden md:inline">
            {mode === 'terrain_intelligence'
              ? demStatus.demAvailable
                ? `DEM RASTER ACTIVE: ${demStatus.activeDemSourceName}`
                : modeHeader.tag
              : modeHeader.tag}
          </span>
        </div>
        <div className="flex items-center gap-1.5 font-mono text-[10px]">
          <button
            onClick={() => setLeftPanelOpen((v) => !v)}
            className="px-2 py-0.5 bg-[#0b0d10] border border-[#252b36] text-[#8c97a8] hover:text-[#e8ecf1] flex items-center gap-1 cursor-pointer"
          >
            {leftPanelOpen ? <PanelLeftClose className="w-3 h-3" /> : <PanelLeftOpen className="w-3 h-3" />}
            <span>GIS Layers</span>
          </button>
          <button
            onClick={() => setRightPanelOpen((v) => !v)}
            className="px-2 py-0.5 bg-[#0b0d10] border border-[#252b36] text-[#8c97a8] hover:text-[#e8ecf1] flex items-center gap-1 cursor-pointer"
          >
            {rightPanelOpen ? <PanelRightClose className="w-3 h-3" /> : <PanelRightOpen className="w-3 h-3" />}
            <span>Analysis</span>
          </button>
        </div>
      </div>

      {/* Main 3-Column GIS Workspace */}
      <div className="flex-1 flex min-h-0 overflow-hidden">
        {/* Left Layer, Adapter Catalog & Surveillance Camera Manager */}
        {leftPanelOpen && (
          <aside className="w-72 border-r border-[#252b36] bg-[#0e1116] flex flex-col shrink-0 overflow-hidden">
            <div className="grid grid-cols-2 border-b border-[#252b36] font-mono text-[10px] shrink-0">
              <button
                onClick={() => setLeftTab('layers')}
                className={`py-2 flex items-center justify-center gap-1 cursor-pointer ${
                  leftTab === 'layers'
                    ? 'bg-[#12151b] text-[#e8ecf1] font-semibold border-b-2 border-[#6f8054]'
                    : 'text-[#8c97a8] hover:text-[#e8ecf1]'
                }`}
              >
                <Layers className="w-3 h-3 text-[#4a9eb0]" />
                <span>Layers & GIS</span>
              </button>
              <button
                onClick={() => setLeftTab('cameras')}
                className={`py-2 border-l border-[#252b36] flex items-center justify-center gap-1 cursor-pointer ${
                  leftTab === 'cameras'
                    ? 'bg-[#12151b] text-[#e8ecf1] font-semibold border-b-2 border-[#6f8054]'
                    : 'text-[#8c97a8] hover:text-[#e8ecf1]'
                }`}
              >
                <Video className="w-3 h-3 text-[#4f8f66]" />
                <span>Cameras ({cameras.length})</span>
              </button>
            </div>

            {leftTab === 'layers' ? (
              <div className="flex-1 overflow-y-auto p-3 space-y-4">
                <div className="space-y-1.5">
                  <div className="font-mono text-[10px] tracking-[0.12em] text-[#8c97a8] font-semibold">
                    VECTOR INTELLIGENCE LAYERS
                  </div>
                  {(
                    [
                      ['assets', 'Infrastructure Assets'],
                      ['approxHalos', 'Approximate Uncertainty Halos'],
                      ['dependencies', 'Dependency Topology Lines'],
                      ['incidents', 'Incident Epicenter Rings'],
                      ['riskZones', 'Geographic Risk Buffers'],
                      ['cameras', 'Camera Calculated FOV Estimates'],
                      ['graticule', 'WGS84 Graticule Grid (15°)'],
                    ] as Array<[keyof MapLayerVisibility, string]>
                  ).map(([key, label]) => (
                    <label
                      key={key}
                      className="flex items-center justify-between px-2 py-1 bg-[#12151b] border border-[#252b36] text-[11px] font-mono text-[#e8ecf1] cursor-pointer hover:bg-[#181c24]"
                    >
                      <span className="truncate">{label}</span>
                      <input
                        type="checkbox"
                        checked={layerVisibility[key] !== false}
                        onChange={() => toggleLayer(key)}
                        className="accent-[#6f8054]"
                      />
                    </label>
                  ))}
                </div>

                {/* External WMTS / WMS / XYZ / GeoJSON Tile Configuration */}
                <div className="border-t border-[#252b36] pt-3 space-y-2">
                  <div className="font-mono text-[10px] tracking-[0.12em] text-[#8c97a8] font-semibold">
                    EXTERNAL GIS / RASTER FEEDS ({customGisSources.length})
                  </div>
                  <div className="p-2 bg-[#c88b32]/10 border border-[#c88b32]/30 text-[10px] font-mono text-[#c88b32] leading-relaxed">
                    Zero external tile servers are queried automatically. Add an authorised HTTPS WMS/WMTS/XYZ template or GeoJSON URL below.
                  </div>

                  {customGisSources.map((src) => (
                    <div
                      key={src.id}
                      className="p-2 bg-[#12151b] border border-[#252b36] flex items-center justify-between gap-2 text-[11px] font-mono"
                    >
                      <label className={`flex items-center gap-1.5 min-w-0 ${isAdmin ? 'cursor-pointer' : 'opacity-80'}`}>
                        <input
                          type="checkbox"
                          checked={src.enabled}
                          disabled={!isAdmin}
                          onChange={() => onToggleGisSource(src.id)}
                          className="accent-[#6f8054] disabled:cursor-not-allowed"
                        />
                        <span className="truncate text-[#e8ecf1]" title={src.url.split('?')[0]}>
                          {src.name}
                        </span>
                      </label>
                      {isAdmin && (
                        <button
                          onClick={() => onRemoveGisSource(src.id)}
                          className="text-[#8c97a8] hover:text-[#c94a4a] cursor-pointer"
                          aria-label={`Remove ${src.name}`}
                        >
                          <Trash2 className="w-3 h-3" />
                        </button>
                      )}
                    </div>
                  ))}

                  {(gisFormError || settingsError) && (
                    <div className="p-2 bg-[#c94a4a]/10 border border-[#c94a4a]/40 font-mono text-[10px] text-[#c94a4a]">
                      {gisFormError || settingsError}
                    </div>
                  )}

                  {isAdmin ? (
                    <form onSubmit={handleAddSource} className="space-y-1.5 pt-1">
                      <input
                        type="text"
                        value={newSrcName}
                        onChange={(e) => setNewSrcName(e.target.value)}
                        placeholder="Feed label (e.g. Sentinel-2 WMTS)"
                        className="w-full bg-[#0b0d10] border border-[#252b36] px-2 py-1 text-[11px] font-mono text-[#e8ecf1]"
                      />
                      <select
                        value={newSrcProtocol}
                        onChange={(e) => setNewSrcProtocol(e.target.value as any)}
                        className="w-full bg-[#0b0d10] border border-[#252b36] px-2 py-1 text-[11px] font-mono text-[#e8ecf1]"
                      >
                        <option value="XYZ_RASTER">XYZ / WMTS Raster Tiles ({`{z}/{x}/{y}`})</option>
                        <option value="WMS">WMS Tile Endpoint</option>
                        <option value="WMTS">WMTS Service Template</option>
                        <option value="GeoJSON">GeoJSON Vector URL</option>
                      </select>
                      <input
                        type="url"
                        value={newSrcUrl}
                        onChange={(e) => setNewSrcUrl(e.target.value)}
                        placeholder="https://.../tiles/{z}/{x}/{y}.png"
                        className="w-full bg-[#0b0d10] border border-[#252b36] px-2 py-1 text-[11px] font-mono text-[#e8ecf1]"
                      />
                      <button
                        type="submit"
                        className="w-full py-1 bg-[#181c24] hover:bg-[#222834] border border-[#252b36] text-[11px] font-mono text-[#e8ecf1] flex items-center justify-center gap-1 cursor-pointer"
                      >
                        <Plus className="w-3 h-3 text-[#8fa36d]" />
                        <span>Attach GIS Source</span>
                      </button>
                    </form>
                  ) : (
                    <div className="p-2 bg-[#12151b] border border-[#252b36] font-mono text-[10px] text-[#8c97a8]">
                      Adding or toggling organisation GIS feeds requires <span className="text-[#e8ecf1]">atlas:admin</span>.
                    </div>
                  )}
                </div>

                {/* Module C: GIS Adapter Catalog Templates */}
                <div className="border-t border-[#252b36] pt-3 space-y-2">
                  <div className="font-mono text-[10px] tracking-[0.12em] text-[#8c97a8] font-semibold">
                    AUTHORISED GIS ADAPTER CATALOG
                  </div>
                  <div className="space-y-1.5">
                    {GIS_SOURCE_ADAPTER_CATALOG.map((adp) => (
                      <div key={adp.id} className="p-2 bg-[#12151b] border border-[#252b36] space-y-1 font-mono text-[10px]">
                        <div className="flex items-center justify-between gap-1">
                          <span className="text-[#e8ecf1] font-semibold truncate">{adp.label}</span>
                          <span className="text-[#4a9eb0] shrink-0">{adp.protocol}</span>
                        </div>
                        <div className="text-[#8c97a8] font-sans text-[10px]">{adp.licenceNote}</div>
                        {isAdmin && (
                          <button
                            type="button"
                            onClick={() => {
                              setNewSrcName(adp.label);
                              setNewSrcProtocol(adp.protocol);
                              setNewSrcUrl('');
                            }}
                            className="text-[#8fa36d] hover:underline cursor-pointer"
                          >
                            Prefill GIS Form →
                          </button>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            ) : (
              <div className="flex-1 overflow-y-auto p-3 space-y-3 font-mono text-[10px]">
                {/* Explicit 4-State Connection Honesty Matrix */}
                <div className="p-2 bg-[#c88b32]/10 border border-[#c88b32]/40 space-y-1.5">
                  <div className="text-[#c88b32] font-semibold">
                    NO LIVE VIDEO FEEDS CONNECTED (METADATA &amp; CALCULATED FOV ESTIMATES ONLY)
                  </div>
                  <div className="grid grid-cols-2 gap-1 text-[9px]">
                    <div className="px-1.5 py-1 bg-[#0b0d10] border border-[#252b36] text-[#e8ecf1]">
                      REGISTERED:{' '}
                      <strong>
                        {cameras.filter((c) => (c.connectionState || (c.endpointUrl ? 'configured' : 'registered')) === 'registered').length}
                      </strong>
                    </div>
                    <div className="px-1.5 py-1 bg-[#0b0d10] border border-[#252b36] text-[#4a9eb0]">
                      CONFIGURED:{' '}
                      <strong>
                        {cameras.filter((c) => (c.connectionState || (c.endpointUrl ? 'configured' : 'registered')) === 'configured').length}
                      </strong>
                    </div>
                    <div className="px-1.5 py-1 bg-[#0b0d10] border border-[#252b36] text-[#8c97a8]">
                      CONNECTED: <strong>0</strong>
                    </div>
                    <div className="px-1.5 py-1 bg-[#0b0d10] border border-[#252b36] text-[#8c97a8]">
                      OPERATIONAL: <strong>0</strong>
                    </div>
                  </div>
                </div>

                <div className="space-y-1.5">
                  <div className="tracking-[0.12em] text-[#8c97a8] font-semibold">
                    SURVEILLANCE GATEWAY ADAPTERS
                  </div>
                  {CAMERA_GATEWAY_ADAPTERS.map((gw) => (
                    <div key={gw.protocol} className="p-2 bg-[#12151b] border border-[#252b36] space-y-1">
                      <div className="text-[#e8ecf1] font-semibold">{gw.label}</div>
                      <div className="text-[#c88b32]">{gw.status}</div>
                      <div className="text-[#8c97a8] font-sans leading-relaxed">{gw.requirement}</div>
                    </div>
                  ))}
                </div>

                <form onSubmit={handleAddCamera} className="border-t border-[#252b36] pt-3 space-y-1.5">
                  <div className="tracking-[0.12em] text-[#8c97a8] font-semibold">
                    REGISTER CAMERA METADATA &amp; FOV ESTIMATE
                  </div>
                  {camError && (
                    <div className="p-1.5 bg-[#c94a4a]/10 border border-[#c94a4a]/40 text-[#c94a4a]">
                      {camError}
                    </div>
                  )}
                  <div className="grid grid-cols-2 gap-1.5">
                    <input
                      type="text"
                      value={camCode}
                      onChange={(e) => setCamCode(e.target.value)}
                      placeholder="Code (CAM-01)"
                      className="bg-[#0b0d10] border border-[#252b36] px-2 py-1 text-[#e8ecf1]"
                    />
                    <select
                      value={camProtocol}
                      onChange={(e) => setCamProtocol(e.target.value as any)}
                      className="bg-[#0b0d10] border border-[#252b36] px-1.5 py-1 text-[#e8ecf1]"
                    >
                      <option value="RTSP_HLS">RTSP_HLS</option>
                      <option value="RTSP_WEBRTC">RTSP_WEBRTC</option>
                      <option value="ONVIF">ONVIF</option>
                    </select>
                  </div>
                  <input
                    type="text"
                    value={camName}
                    onChange={(e) => setCamName(e.target.value)}
                    placeholder="Gate / Perimeter Label"
                    className="w-full bg-[#0b0d10] border border-[#252b36] px-2 py-1 text-[#e8ecf1]"
                  />
                  <div className="grid grid-cols-2 gap-1.5">
                    <input
                      type="number"
                      step="any"
                      value={camLat}
                      onChange={(e) => setCamLat(e.target.value)}
                      placeholder="Lat"
                      className="bg-[#0b0d10] border border-[#252b36] px-2 py-1 text-[#e8ecf1]"
                    />
                    <input
                      type="number"
                      step="any"
                      value={camLng}
                      onChange={(e) => setCamLng(e.target.value)}
                      placeholder="Lng"
                      className="bg-[#0b0d10] border border-[#252b36] px-2 py-1 text-[#e8ecf1]"
                    />
                  </div>
                  <div className="grid grid-cols-3 gap-1.5">
                    <input
                      type="number"
                      value={camBearing}
                      onChange={(e) => setCamBearing(e.target.value)}
                      title="Azimuth Bearing (deg)"
                      placeholder="Brg°"
                      className="bg-[#0b0d10] border border-[#252b36] px-2 py-1 text-[#e8ecf1]"
                    />
                    <input
                      type="number"
                      value={camFov}
                      onChange={(e) => setCamFov(e.target.value)}
                      title="FOV Cone Width (deg)"
                      placeholder="FOV°"
                      className="bg-[#0b0d10] border border-[#252b36] px-2 py-1 text-[#e8ecf1]"
                    />
                    <input
                      type="number"
                      value={camRangeM}
                      onChange={(e) => setCamRangeM(e.target.value)}
                      title="Range (meters)"
                      placeholder="Rng m"
                      className="bg-[#0b0d10] border border-[#252b36] px-2 py-1 text-[#e8ecf1]"
                    />
                  </div>
                  <input
                    type="url"
                    value={camUrl}
                    onChange={(e) => setCamUrl(e.target.value)}
                    placeholder="Optional https://...m3u8 endpoint"
                    className="w-full bg-[#0b0d10] border border-[#252b36] px-2 py-1 text-[#e8ecf1]"
                  />
                  <button
                    type="submit"
                    className="w-full py-1 bg-[#6f8054] hover:bg-[#7d905f] text-[#0b0d10] font-semibold flex items-center justify-center gap-1 cursor-pointer"
                  >
                    <Plus className="w-3 h-3" />
                    <span>Register Camera Footprint</span>
                  </button>
                </form>

                {cameras.length > 0 && (
                  <div className="border-t border-[#252b36] pt-2 space-y-1.5">
                    <div className="text-[#8c97a8] font-semibold">REGISTERED CAMERAS ({cameras.length})</div>
                    {cameras.map((cam) => {
                      const state = cam.connectionState || (cam.endpointUrl ? 'configured' : 'registered');
                      return (
                        <div key={cam.id} className="p-2 bg-[#12151b] border border-[#252b36] space-y-1">
                          <div className="flex items-center justify-between gap-1">
                            <button
                              type="button"
                              onClick={() => setCenterTarget([cam.lng, cam.lat])}
                              className="text-[#4a9eb0] font-semibold hover:underline truncate cursor-pointer"
                            >
                              {cam.cameraCode} · {cam.name}
                            </button>
                            <button
                              type="button"
                              onClick={() => persistCameras(cameras.filter((c) => c.id !== cam.id))}
                              className="text-[#8c97a8] hover:text-[#c94a4a] cursor-pointer"
                              title="Remove camera"
                            >
                              <Trash2 className="w-3 h-3" />
                            </button>
                          </div>
                          <div className="text-[#8c97a8] tabular-nums">
                            Est. Coverage: {cam.protocol} · Az {cam.bearingDeg}° · FOV {cam.fovDeg}° · {cam.rangeMeters}m
                          </div>
                          <div className="flex items-center justify-between gap-1">
                            <span className="px-1 py-0.5 bg-[#0b0d10] border border-[#252b36] text-[9px] text-[#c88b32]">
                              STATE: {state.toUpperCase()} (NOT OPERATIONAL)
                            </span>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            )}
          </aside>
        )}

        {/* Center Tactical Map */}
        <div className="flex-1 min-w-0 relative">
          <TacticalAtlasMap
            intel={intel}
            selectedEntity={selectedEntity}
            onSelectEntity={onSelectEntity}
            layerVisibility={layerVisibility}
            onToggleLayer={toggleLayer}
            typeFilter={typeFilter}
            onChangeTypeFilter={setTypeFilter}
            minCriticality={minCriticality}
            onChangeMinCriticality={setMinCriticality}
            customSources={customGisSources}
            camerasGeoJson={camerasGeoJson}
            bufferGeoJson={bufferGeoJson}
            centerTarget={centerTarget}
            measureMode={measureMode}
            onChangeMeasureMode={setMeasureMode}
            onCursorMove={setCursorCoord}
            onMeasurementUpdate={setMeasureStats}
          />
        </div>

        {/* Right Mode-Specific Analysis or Selected Dossier */}
        {rightPanelOpen && (
          <aside className="w-80 xl:w-96 border-l border-[#252b36] bg-[#12151b] flex flex-col shrink-0 overflow-hidden">
            {selectedEntity ? (
              <IntelligenceDossierPanel
                selectedEntity={selectedEntity}
                intel={intel}
                onSelectEntity={onSelectEntity}
                onNavigateModule={onNavigateModule}
                onClose={() => onSelectEntity(null)}
                onCenterCoordinate={(lngLat) => setCenterTarget([...lngLat])}
              />
            ) : (
              <div className="flex-1 overflow-y-auto p-3 space-y-3 text-xs">
                <div className="font-mono text-[10px] tracking-[0.12em] text-[#8c97a8] font-semibold border-b border-[#252b36] pb-2">
                  {mode === 'satellite_imagery'
                    ? 'IMAGERY FEED STATUS & FOOTPRINTS'
                    : mode === 'terrain_intelligence'
                    ? 'GEODETIC ACCURACY & PROXIMITY MATRIX'
                    : mode === 'geographic_risk'
                    ? 'GEOGRAPHIC RISK CONCENTRATION'
                    : 'COMPUTATIONAL SPATIAL ANALYSIS'}
                </div>

                {mode === 'satellite_imagery' && (
                  <div className="space-y-2.5 font-mono text-[11px]">
                    <div className="p-2.5 bg-[#0b0d10] border border-[#252b36] text-[#8c97a8] space-y-1">
                      <div className="text-[#c88b32] font-semibold">NO COMMERCIAL IMAGERY API CONNECTED</div>
                      <p className="font-sans text-xs leading-relaxed">
                        Live commercial electro-optical/SAR satellite tasking requires an operator-configured WMTS/XYZ endpoint in the left GIS Layer panel. Asset coordinate footprints below remain active.
                      </p>
                    </div>
                    <div className="text-[#e8ecf1] font-semibold">WORKSPACE TARGETS FOR IMAGERY</div>
                    {intel.assets.slice(0, 8).map((a) => {
                      const c = intel.assetCoordsMap.get(a.id);
                      return (
                        <button
                          key={a.id}
                          onClick={() => c && setCenterTarget([...c])}
                          className="w-full text-left p-2 bg-[#0b0d10] hover:bg-[#181c24] border border-[#252b36] flex items-center justify-between cursor-pointer"
                        >
                          <span className="truncate text-[#e8ecf1]">{a.site_code} · {a.name}</span>
                          <span className="text-[#4a9eb0] tabular-nums">
                            {c ? `${c[1].toFixed(2)}, ${c[0].toFixed(2)}` : '—'}
                          </span>
                        </button>
                      );
                    })}
                  </div>
                )}

                {mode === 'terrain_intelligence' && (
                  <div className="space-y-3 font-mono text-[11px]">
                    <div className="p-2.5 bg-[#0b0d10] border border-[#252b36] text-[#8c97a8] space-y-1">
                      <div
                        className={`font-semibold flex items-center gap-1.5 ${
                          demStatus.demAvailable ? 'text-[#4f8f66]' : 'text-[#c88b32]'
                        }`}
                      >
                        <Info className="w-3.5 h-3.5 shrink-0" />
                        <span>
                          {demStatus.demAvailable
                            ? `DEM LAYER ACTIVE (${demStatus.activeDemSourceName})`
                            : 'DEM ELEVATION: UNAVAILABLE'}
                        </span>
                      </div>
                      <p className="font-sans text-xs leading-relaxed">{demStatus.statusMessage}</p>
                    </div>

                    <div className="space-y-1.5">
                      <div className="text-[#e8ecf1] font-semibold">GREAT-CIRCLE DISTANCE & BEARING</div>
                      <select
                        value={assetA?.id || ''}
                        onChange={(e) => setProxAssetA(e.target.value)}
                        className="w-full bg-[#0b0d10] border border-[#252b36] px-2 py-1 text-[#e8ecf1]"
                      >
                        {intel.assets.map((a) => (
                          <option key={a.id} value={a.id}>
                            Origin: {a.site_code} ({a.name})
                          </option>
                        ))}
                      </select>
                      <select
                        value={assetB?.id || ''}
                        onChange={(e) => setProxAssetB(e.target.value)}
                        className="w-full bg-[#0b0d10] border border-[#252b36] px-2 py-1 text-[#e8ecf1]"
                      >
                        {intel.assets.map((a) => (
                          <option key={a.id} value={a.id}>
                            Target: {a.site_code} ({a.name})
                          </option>
                        ))}
                      </select>
                      {pairDistKm !== null && pairBearing !== null && (
                        <div className="p-2 bg-[#0b0d10] border border-[#252b36] grid grid-cols-2 gap-2">
                          <div>
                            <div className="text-[10px] text-[#8c97a8]">HAVERSINE DIST</div>
                            <div className="text-sm text-[#8fa36d] font-semibold tabular-nums">
                              {pairDistKm.toFixed(2)} km
                            </div>
                          </div>
                          <div>
                            <div className="text-[10px] text-[#8c97a8]">TRUE BEARING</div>
                            <div className="text-sm text-[#4a9eb0] font-semibold tabular-nums">
                              {pairBearing.toFixed(1)}°
                            </div>
                          </div>
                        </div>
                      )}
                    </div>

                    {/* Module E: Proximity Rankings */}
                    {assetA && (
                      <div className="border-t border-[#252b36] pt-2.5 space-y-1.5">
                        <div className="flex items-center justify-between">
                          <span className="text-[#e8ecf1] font-semibold">PROXIMITY RANKINGS FROM {assetA.site_code}</span>
                          <select
                            value={proxRadiusKm}
                            onChange={(e) => setProxRadiusKm(Number(e.target.value))}
                            className="bg-[#0b0d10] border border-[#252b36] px-1.5 py-0.5 text-[10px] text-[#e8ecf1]"
                          >
                            <option value={25}>≤ 25 km</option>
                            <option value={100}>≤ 100 km</option>
                            <option value={250}>≤ 250 km</option>
                            <option value={1500}>≤ 1500 km</option>
                          </select>
                        </div>
                        {proximityRankings.length === 0 ? (
                          <div className="text-[10px] text-[#8c97a8]">
                            No other infrastructure within {proxRadiusKm} km of {assetA.site_code}.
                          </div>
                        ) : (
                          <div className="space-y-1">
                            {proximityRankings.slice(0, 8).map((p) => (
                              <button
                                key={p.assetId}
                                onClick={() => onSelectEntity({ kind: 'asset', id: p.assetId })}
                                className="w-full text-left p-1.5 bg-[#0b0d10] hover:bg-[#181c24] border border-[#252b36] flex items-center justify-between cursor-pointer"
                              >
                                <span className="truncate text-[#e8ecf1]">
                                  {p.siteCode} · {p.name}
                                </span>
                                <span className="text-[#4a9eb0] tabular-nums shrink-0">
                                  {p.distanceKm.toFixed(1)} km @ {p.bearingDeg.toFixed(0)}°
                                </span>
                              </button>
                            ))}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                )}

                {(mode === 'geographic_risk' || mode === 'global_map') && (
                  <div className="space-y-3 font-mono text-[11px]">
                    <div className="grid grid-cols-2 gap-2">
                      <div className="p-2 bg-[#0b0d10] border border-[#252b36]">
                        <div className="text-[10px] text-[#8c97a8]">APPROX HALOS</div>
                        <div className="text-sm font-semibold text-[#c88b32] tabular-nums">
                          {intel.assets.filter((a) => a.accuracy_class !== 'exact_survey').length}
                        </div>
                      </div>
                      <div className="p-2 bg-[#0b0d10] border border-[#252b36]">
                        <div className="text-[10px] text-[#8c97a8]">INCIDENT ZONES</div>
                        <div className="text-sm font-semibold text-[#c94a4a] tabular-nums">
                          {new Set(intel.matches.filter((m) => m.status !== 'rejected').map((m) => m.asset_id)).size}
                        </div>
                      </div>
                    </div>

                    {/* Module E: Geodesic Buffer Zone Analyzer */}
                    {intel.assets.length > 0 && (
                      <div className="p-2.5 bg-[#0b0d10] border border-[#252b36] space-y-2">
                        <div className="flex items-center justify-between">
                          <span className="text-[#4a9eb0] font-semibold flex items-center gap-1">
                            <Radar className="w-3.5 h-3.5" />
                            <span>GEODESIC BUFFER ZONE</span>
                          </span>
                          <label className="flex items-center gap-1 text-[10px] text-[#8c97a8] cursor-pointer">
                            <input
                              type="checkbox"
                              checked={showBufferOnMap}
                              onChange={(e) => setShowBufferOnMap(e.target.checked)}
                              className="accent-[#6f8054]"
                            />
                            <span>Map Ring</span>
                          </label>
                        </div>
                        <div className="grid grid-cols-3 gap-1.5">
                          <select
                            value={bufferAnchorAsset?.id || ''}
                            onChange={(e) => {
                              setBufferAnchorId(e.target.value);
                              const c = intel.assetCoordsMap.get(e.target.value);
                              if (c) setCenterTarget([...c]);
                            }}
                            className="col-span-2 bg-[#12151b] border border-[#252b36] px-1.5 py-1 text-[10px] text-[#e8ecf1]"
                          >
                            {intel.assets.map((a) => (
                              <option key={a.id} value={a.id}>
                                {a.site_code} · {a.name}
                              </option>
                            ))}
                          </select>
                          <select
                            value={bufferRadiusKm}
                            onChange={(e) => setBufferRadiusKm(Number(e.target.value))}
                            className="bg-[#12151b] border border-[#252b36] px-1.5 py-1 text-[10px] text-[#e8ecf1]"
                          >
                            <option value={10}>10 km</option>
                            <option value={25}>25 km</option>
                            <option value={50}>50 km</option>
                            <option value={150}>150 km</option>
                            <option value={500}>500 km</option>
                          </select>
                        </div>
                        {bufferAnalysis && (
                          <div className="text-[10px] space-y-1">
                            <div className="flex justify-between text-[#8c97a8]">
                              <span>Assets within {bufferAnalysis.radiusKm} km:</span>
                              <span className="text-[#e8ecf1] font-semibold tabular-nums">
                                {bufferAnalysis.intersectingAssets.length} ({bufferAnalysis.linkedIncidentIds.length} inc)
                              </span>
                            </div>
                            {bufferAnalysis.hasApproximateAssets && (
                              <div className="text-[#c88b32]">
                                Note: Buffer includes approximate spatial coordinates.
                              </div>
                            )}
                            <div className="max-h-24 overflow-y-auto space-y-1 pt-0.5">
                              {bufferAnalysis.intersectingAssets.slice(0, 6).map((item) => (
                                <button
                                  key={item.assetId}
                                  onClick={() => onSelectEntity({ kind: 'asset', id: item.assetId })}
                                  className="w-full text-left px-1.5 py-1 bg-[#12151b] hover:bg-[#181c24] border border-[#252b36] flex justify-between cursor-pointer"
                                >
                                  <span className="truncate text-[#e8ecf1]">{item.siteCode}</span>
                                  <span className="text-[#4a9eb0] tabular-nums">{item.distanceKm.toFixed(1)} km</span>
                                </button>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    )}

                    {/* Module E: Spatial Grid Clusters & Concentration Hotspots */}
                    {spatialClusters.length > 0 && (
                      <div className="border-t border-[#252b36] pt-2 space-y-1.5">
                        <div className="text-[#e8ecf1] font-semibold">
                          SPATIAL CLUSTERS (~50 KM GRID)
                        </div>
                        {spatialClusters.slice(0, 4).map((cl) => (
                          <button
                            key={cl.id}
                            onClick={() => setCenterTarget([...cl.centroid])}
                            className="w-full text-left p-2 bg-[#0b0d10] hover:bg-[#181c24] border border-[#252b36] space-y-0.5 cursor-pointer"
                          >
                            <div className="flex items-center justify-between">
                              <span className="text-[#e8ecf1] font-semibold">{cl.assetIds.length} asset(s)</span>
                              <span className="text-[#c94a4a] tabular-nums">{cl.incidentCount} inc · Max T{cl.maxCriticality}</span>
                            </div>
                            <div className="text-[10px] text-[#8c97a8]">
                              Exact: {cl.accuracy.exact} · Approx: {cl.accuracy.facilityApprox + cl.accuracy.regionalApprox}
                            </div>
                          </button>
                        ))}
                      </div>
                    )}

                    {concentrationGrid.length > 0 && (
                      <div className="border-t border-[#252b36] pt-2 space-y-1.5">
                        <div className="text-[#e8ecf1] font-semibold">
                          CONCENTRATION & CO-LOCATION RISK CELLS
                        </div>
                        {concentrationGrid.slice(0, 3).map((cell) => (
                          <button
                            key={cell.cellId}
                            onClick={() => setCenterTarget([...cell.center])}
                            className="w-full text-left p-2 bg-[#0b0d10] hover:bg-[#181c24] border border-[#252b36] flex items-center justify-between cursor-pointer"
                          >
                            <span className="text-[#8c97a8]">
                              T4+: {cell.tier4PlusCount} · ≤5km pairs: {cell.coLocatedPairs}
                            </span>
                            <span className="text-[#c88b32] font-semibold tabular-nums">
                              IDX {cell.densityIndex.toFixed(1)}
                            </span>
                          </button>
                        ))}
                      </div>
                    )}

                    <div className="text-[#e8ecf1] font-semibold pt-1">
                      HIGH-CRITICALITY & EXPOSED SITES
                    </div>
                    {intel.assets
                      .filter((a) => a.criticality >= 4 || intel.matches.some((m) => m.asset_id === a.id))
                      .slice(0, 8)
                      .map((a) => (
                        <button
                          key={a.id}
                          onClick={() => onSelectEntity({ kind: 'asset', id: a.id })}
                          className="w-full text-left p-2 bg-[#0b0d10] hover:bg-[#181c24] border border-[#252b36] flex items-center justify-between cursor-pointer"
                        >
                          <span className="truncate text-[#e8ecf1]">{a.site_code} · {a.name}</span>
                          <span className={a.criticality >= 5 ? 'text-[#c94a4a]' : 'text-[#c88b32]'}>
                            T{a.criticality}
                          </span>
                        </button>
                      ))}
                  </div>
                )}
              </div>
            )}
          </aside>
        )}
      </div>

      {/* Bottom Coordinate & Spatial Measurement Bar */}
      <div className="h-7 px-3 border-t border-[#252b36] bg-[#12151b] flex items-center justify-between font-mono text-[11px] text-[#8c97a8] shrink-0">
        <div className="flex items-center gap-4 tabular-nums">
          <span>
            CURSOR WGS84:{' '}
            <strong className="text-[#e8ecf1]">
              {cursorCoord ? `${cursorCoord.lat.toFixed(5)}, ${cursorCoord.lng.toFixed(5)}` : 'Move cursor over map'}
            </strong>
          </span>
          {cursorCoord && (
            <span className="hidden md:inline text-[#8c97a8]">
              DMS: {toDms(cursorCoord.lat, true)} {toDms(cursorCoord.lng, false)}
            </span>
          )}
        </div>
        <div className="flex items-center gap-4 tabular-nums">
          <span>
            MEASURE MODE: <strong className="text-[#8fa36d]">{measureMode.toUpperCase()}</strong>
          </span>
          {measureStats.points.length >= 2 && (
            <span>
              DIST: <strong className="text-[#e8ecf1]">{measureStats.distanceKm.toFixed(2)} km</strong>
              {measureStats.bearingDeg !== null && ` · BRG: ${measureStats.bearingDeg.toFixed(1)}°`}
            </span>
          )}
          {measureStats.areaKm2 !== null && (
            <span>
              AREA: <strong className="text-[#4a9eb0]">{measureStats.areaKm2.toFixed(2)} km²</strong>
            </span>
          )}
        </div>
      </div>
    </div>
  );
};
