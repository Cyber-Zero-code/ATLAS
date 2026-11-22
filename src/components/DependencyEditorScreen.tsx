/**
 * Project ATLAS: Dependency Graph Editor (Stage 3)
 *
 * HARD RULES:
 * 1. Database as single source of truth: All reads and writes go to Supabase public.dependency_edges.
 * 2. Direction displayed strictly as Provider to Consumer (from_asset -> to_asset).
 * 3. Warn on circular dependencies / cycles before and after creation.
 * 4. Permission enforcement:
 *    - atlas:admin can create and delete edges.
 *    - atlas:analyst can create edges, but cannot delete (enforced by RLS in DB).
 * 5. Cross-organisation edges are impossible at the database level (composite foreign keys).
 */

import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { atlasService } from '../data/api';
import { Asset, DependencyEdge, AppRole } from '../types/atlas';
import {
  GitFork,
  ArrowRight,
  AlertTriangle,
  Plus,
  Trash2,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Server,
  Zap,
  Radio,
  Cloud,
  Cpu,
  Info,
} from 'lucide-react';

interface DependencyEditorScreenProps {
  activeOrgId: string;
  userRole: AppRole;
}

const RELATION_TYPES = [
  { value: 'powers', label: 'Powers (Electrical / UPS)', color: 'text-amber-400 border-amber-900/60 bg-amber-950/40' },
  { value: 'hosts', label: 'Hosts (Compute / Virtual)', color: 'text-purple-400 border-purple-900/60 bg-purple-950/40' },
  { value: 'connects_to', label: 'Connects To (Network / WAN)', color: 'text-emerald-400 border-emerald-900/60 bg-emerald-950/40' },
  { value: 'supplies', label: 'Supplies (Fuel / Hardware)', color: 'text-cyan-400 border-cyan-900/60 bg-cyan-950/40' },
  { value: 'monitors', label: 'Monitors (SCADA / Telemetry)', color: 'text-blue-400 border-blue-900/60 bg-blue-950/40' },
  { value: 'cools', label: 'Cools (HVAC / Chiller)', color: 'text-indigo-400 border-indigo-900/60 bg-indigo-950/40' },
];

export const DependencyEditorScreen: React.FC<DependencyEditorScreenProps> = ({
  activeOrgId,
  userRole,
}) => {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [edges, setEdges] = useState<Array<DependencyEdge & { from_asset?: Asset; to_asset?: Asset }>>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [loadError, setLoadError] = useState<string | null>(null);

  // Form State
  const [fromAssetId, setFromAssetId] = useState<string>('');
  const [toAssetId, setToAssetId] = useState<string>('');
  const [relationType, setRelationType] = useState<string>('powers');
  const [criticality, setCriticality] = useState<number>(3);
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [pendingDeleteEdgeId, setPendingDeleteEdgeId] = useState<string | null>(null);
  const [formSuccess, setFormSuccess] = useState<string | null>(null);

  // Cycle warning state
  const [isCheckingCycle, setIsCheckingCycle] = useState<boolean>(false);
  const [hasCycleWarning, setHasCycleWarning] = useState<boolean>(false);

  // Load assets and edges from database
  const loadGraphData = useCallback(async () => {
    if (!activeOrgId) return;

    setIsLoading(true);
    setLoadError(null);

    try {
      const [fetchedAssets, fetchedEdges] = await Promise.all([
        atlasService.fetchWorkspaceAssetsList(activeOrgId),
        atlasService.fetchDependencyEdges(activeOrgId),
      ]);

      setAssets(fetchedAssets);
      setEdges(fetchedEdges);

      if (fetchedAssets.length >= 2 && !fromAssetId && !toAssetId) {
        setFromAssetId(fetchedAssets[0].id);
        setToAssetId(fetchedAssets[1].id);
      }
    } catch (err: any) {
      setLoadError(err.message || 'Error loading dependency graph.');
    } finally {
      setIsLoading(false);
    }
  }, [activeOrgId]);

  useEffect(() => {
    loadGraphData();
  }, [loadGraphData]);

  // Asset Map for fast lookup
  const assetMap = useMemo(() => {
    const map = new Map<string, Asset>();
    assets.forEach((a) => map.set(a.id, a));
    return map;
  }, [assets]);

  // Check for circular dependency whenever from or to changes
  useEffect(() => {
    const verifyCycle = async () => {
      if (!fromAssetId || !toAssetId || fromAssetId === toAssetId) {
        setHasCycleWarning(fromAssetId === toAssetId && fromAssetId !== '');
        return;
      }

      setIsCheckingCycle(true);
      try {
        const hasCycle = await atlasService.checkDependencyCycle(activeOrgId, fromAssetId, toAssetId);
        setHasCycleWarning(hasCycle);
      } catch (err) {
        console.warn('Cycle check failed:', err);
      } finally {
        setIsCheckingCycle(false);
      }
    };

    verifyCycle();
  }, [activeOrgId, fromAssetId, toAssetId]);

  // Create dependency edge
  const handleCreateEdge = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!fromAssetId || !toAssetId) {
      setFormError('Please select both provider and consumer assets.');
      return;
    }

    if (fromAssetId === toAssetId) {
      setFormError('Self-referencing edges are prohibited. Provider and consumer must be different assets.');
      return;
    }

    setIsSubmitting(true);
    setFormError(null);
    setFormSuccess(null);

    try {
      await atlasService.createDependencyEdge({
        org_id: activeOrgId,
        from_asset_id: fromAssetId,
        to_asset_id: toAssetId,
        relation_type: relationType,
        criticality,
        source: 'Analyst Dependency Editor',
      });

      setFormSuccess('Dependency edge successfully established in database.');
      await loadGraphData();
    } catch (err: any) {
      setFormError(err.message || 'Database rejected dependency edge creation.');
    } finally {
      setIsSubmitting(false);
    }
  };

  // Delete dependency edge (Admin only)
  const handleDeleteEdge = async (edgeId: string) => {
    if (userRole !== 'atlas:admin') {
      setFormError('Permission denied: Only atlas:admin can delete dependency edges.');
      return;
    }

    setPendingDeleteEdgeId(null);
    try {
      await atlasService.deleteDependencyEdge(activeOrgId, edgeId);
      setEdges((prev) => prev.filter((e) => e.id !== edgeId));
    } catch (err: any) {
      setFormError(err.message || 'Database rejected edge deletion.');
    }
  };

  const getAssetTypeIcon = (type?: string) => {
    switch (type) {
      case 'site':
        return <Server className="w-3.5 h-3.5 text-cyan-400" />;
      case 'power_feed':
        return <Zap className="w-3.5 h-3.5 text-amber-400" />;
      case 'fibre_route':
        return <Radio className="w-3.5 h-3.5 text-emerald-400" />;
      case 'cloud_region':
        return <Cloud className="w-3.5 h-3.5 text-purple-400" />;
      case 'service':
        return <Cpu className="w-3.5 h-3.5 text-pink-400" />;
      default:
        return <Server className="w-3.5 h-3.5 text-slate-400" />;
    }
  };

  return (
    <div className="max-w-6xl mx-auto px-6 py-8 space-y-8 select-none text-slate-100 antialiased font-sans">
      {/* Page Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <div className="flex items-center gap-2 font-mono text-xs text-cyan-400 font-bold uppercase tracking-wider mb-1">
            <GitFork className="w-3.5 h-3.5" />
            Stage 3 Dependency Graph
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-100">
            Cyber-Physical Dependency Editor
          </h1>
          <p className="text-xs text-slate-400 mt-1 max-w-2xl leading-relaxed">
            Link upstream infrastructure providers to downstream consumers. Impact flows strictly from provider to consumer. Circular loops trigger cycle warnings. Cross-tenant edges are blocked at the database engine level via composite foreign keys.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5 text-xs font-mono bg-slate-900 px-3 py-1.5 rounded-lg border border-slate-800">
            <span className="text-slate-400">ROLE:</span>
            <span className={userRole === 'atlas:admin' ? 'text-amber-400 font-bold' : 'text-cyan-400'}>
              {userRole}
            </span>
          </div>

          <button
            onClick={loadGraphData}
            disabled={isLoading}
            className="p-2 bg-slate-900 hover:bg-slate-800 text-slate-300 rounded-lg border border-slate-800 transition cursor-pointer"
            title="Refresh dependency edges from database"
          >
            <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin text-cyan-400' : ''}`} />
          </button>
        </div>
      </div>

      {loadError && (
        <div className="p-4 bg-rose-950/80 border border-rose-800 rounded-xl text-rose-200 text-xs flex items-start gap-2">
          <AlertTriangle className="w-4 h-4 shrink-0 text-rose-400 mt-0.5" />
          <div>{loadError}</div>
        </div>
      )}

      {/* Editor & Creation Form */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Create Edge Form */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="font-mono text-xs font-semibold uppercase tracking-wider text-slate-300 flex items-center gap-2">
              <Plus className="w-3.5 h-3.5 text-cyan-400" />
              Link Dependency
            </h2>
            <span className="text-[10px] font-mono text-slate-500">Provider → Consumer</span>
          </div>

          <form onSubmit={handleCreateEdge} className="space-y-4 text-xs">
            {/* From Asset (Provider / Upstream) */}
            <div>
              <label className="block text-slate-400 mb-1 font-mono text-[11px]">
                1. Provider Asset (Upstream / Source)
              </label>
              <select
                value={fromAssetId}
                onChange={(e) => setFromAssetId(e.target.value)}
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-2.5 py-2 text-slate-200 font-mono text-xs focus:outline-none focus:border-cyan-500"
              >
                {assets.map((a) => (
                  <option key={a.id} value={a.id}>
                    [{a.site_code}] {a.name} ({a.type}) - T{a.criticality}
                  </option>
                ))}
              </select>
            </div>

            {/* Relation Type */}
            <div>
              <label className="block text-slate-400 mb-1 font-mono text-[11px]">
                2. Relationship Type (Operational Coupling)
              </label>
              <select
                value={relationType}
                onChange={(e) => setRelationType(e.target.value)}
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-2.5 py-2 text-slate-200 font-mono text-xs focus:outline-none focus:border-cyan-500"
              >
                {RELATION_TYPES.map((r) => (
                  <option key={r.value} value={r.value}>
                    {r.label}
                  </option>
                ))}
              </select>
            </div>

            {/* To Asset (Consumer / Downstream) */}
            <div>
              <label className="block text-slate-400 mb-1 font-mono text-[11px]">
                3. Consumer Asset (Downstream / Impacted)
              </label>
              <select
                value={toAssetId}
                onChange={(e) => setToAssetId(e.target.value)}
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-2.5 py-2 text-slate-200 font-mono text-xs focus:outline-none focus:border-cyan-500"
              >
                {assets.map((a) => (
                  <option key={a.id} value={a.id}>
                    [{a.site_code}] {a.name} ({a.type}) - T{a.criticality}
                  </option>
                ))}
              </select>
            </div>

            {/* Criticality */}
            <div>
              <label className="block text-slate-400 mb-1 font-mono text-[11px]">
                4. Dependency Criticality Tier (1 to 5)
              </label>
              <div className="flex items-center gap-1.5">
                {[1, 2, 3, 4, 5].map((tier) => (
                  <button
                    key={tier}
                    type="button"
                    onClick={() => setCriticality(tier)}
                    className={`flex-1 py-1.5 rounded font-mono font-bold text-xs transition cursor-pointer ${
                      criticality === tier
                        ? 'bg-rose-500 text-slate-950'
                        : 'bg-slate-950 text-slate-400 hover:bg-slate-800 border border-slate-800'
                    }`}
                  >
                    T{tier}
                  </button>
                ))}
              </div>
            </div>

            {/* Cycle Warning Banner */}
            {hasCycleWarning && (
              <div className="p-3 bg-amber-950/70 border border-amber-800 rounded-xl space-y-1 text-amber-200 text-xs">
                <div className="flex items-center gap-1.5 font-bold font-mono text-[11px] text-amber-300">
                  <ShieldAlert className="w-4 h-4 text-amber-400 shrink-0" />
                  <span>CIRCULAR DEPENDENCY DETECTED</span>
                </div>
                <p className="text-[11px] leading-relaxed text-amber-300/90">
                  Adding this edge introduces a cycle in the dependency graph. Impact propagation handles cycles via visited path tracking, but cyclic dependencies should be reviewed.
                </p>
              </div>
            )}

            {formError && (
              <div className="p-3 bg-rose-950/80 border border-rose-800 rounded-lg text-rose-200 text-xs">
                {formError}
              </div>
            )}

            {formSuccess && (
              <div className="p-3 bg-emerald-950/80 border border-emerald-800 rounded-lg text-emerald-300 text-xs">
                {formSuccess}
              </div>
            )}

            <button
              type="submit"
              disabled={isSubmitting || assets.length < 2}
              className="w-full py-2.5 bg-cyan-500 hover:bg-cyan-400 disabled:bg-slate-800 text-slate-950 font-bold rounded-lg text-xs font-mono transition cursor-pointer flex items-center justify-center gap-2 shadow-lg"
            >
              {isSubmitting ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  <span>Committing Edge...</span>
                </>
              ) : (
                <>
                  <GitFork className="w-3.5 h-3.5" />
                  <span>Create Dependency Edge</span>
                </>
              )}
            </button>
          </form>
        </div>

        {/* Existing Edges Table */}
        <div className="lg:col-span-2 space-y-3">
          <div className="flex items-center justify-between text-xs font-mono text-slate-400 px-1">
            <span>ACTIVE DEPENDENCY EDGES ({edges.length})</span>
            <span className="text-[11px] text-slate-500">Direction: Provider → Consumer</span>
          </div>

          <div className="bg-slate-900/60 border border-slate-800 rounded-2xl overflow-hidden shadow-xl max-h-[550px] overflow-y-auto">
            {edges.length === 0 ? (
              <div className="p-10 text-center text-slate-500 text-xs font-mono">
                No dependency edges defined in this workspace. Create your first edge using the form on the left.
              </div>
            ) : (
              <div className="divide-y divide-slate-800">
                {edges.map((edge) => {
                  const fromAsset = edge.from_asset || assetMap.get(edge.from_asset_id);
                  const toAsset = edge.to_asset || assetMap.get(edge.to_asset_id);
                  const relMeta = RELATION_TYPES.find((r) => r.value === edge.relation_type);

                  return (
                    <div
                      key={edge.id}
                      className="p-3.5 hover:bg-slate-850 transition flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs"
                    >
                      {/* Relationship Flow: Provider -> Consumer */}
                      <div className="flex flex-wrap items-center gap-2.5 min-w-0">
                        {/* Provider */}
                        <div className="flex items-center gap-2 bg-slate-950 px-2.5 py-1.5 rounded-lg border border-slate-800">
                          {getAssetTypeIcon(fromAsset?.type)}
                          <div className="truncate">
                            <span className="font-mono font-bold text-cyan-300">
                              {fromAsset?.site_code || '...'}
                            </span>
                            <span className="text-slate-400 ml-1.5 text-[11px] truncate hidden md:inline">
                              {fromAsset?.name}
                            </span>
                          </div>
                        </div>

                        {/* Arrow & Relation Badge */}
                        <div className="flex items-center gap-1.5">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-mono font-semibold border ${
                              relMeta?.color || 'text-slate-300 border-slate-700 bg-slate-800'
                            }`}
                          >
                            {edge.relation_type}
                          </span>
                          <ArrowRight className="w-3.5 h-3.5 text-slate-600 shrink-0" />
                        </div>

                        {/* Consumer */}
                        <div className="flex items-center gap-2 bg-slate-950 px-2.5 py-1.5 rounded-lg border border-slate-800">
                          {getAssetTypeIcon(toAsset?.type)}
                          <div className="truncate">
                            <span className="font-mono font-bold text-emerald-300">
                              {toAsset?.site_code || '...'}
                            </span>
                            <span className="text-slate-400 ml-1.5 text-[11px] truncate hidden md:inline">
                              {toAsset?.name}
                            </span>
                          </div>
                        </div>
                      </div>

                      {/* Tier & Delete action */}
                      <div className="flex items-center gap-3 shrink-0 self-end sm:self-auto">
                        <span className="font-mono text-[11px] text-rose-400 font-bold bg-rose-950/40 px-2 py-0.5 rounded border border-rose-900/60">
                          T{edge.criticality}
                        </span>

                        {userRole === 'atlas:admin' ? (
                          pendingDeleteEdgeId === edge.id ? (
                            <span className="flex items-center gap-2 font-mono text-[10px]">
                              <button
                                onClick={() => handleDeleteEdge(edge.id)}
                                className="px-1.5 py-0.5 bg-rose-700 hover:bg-rose-600 text-white rounded cursor-pointer"
                              >
                                Confirm delete
                              </button>
                              <button
                                onClick={() => setPendingDeleteEdgeId(null)}
                                className="text-slate-400 hover:text-slate-200 underline cursor-pointer"
                              >
                                Cancel
                              </button>
                            </span>
                          ) : (
                            <button
                              onClick={() => setPendingDeleteEdgeId(edge.id)}
                              className="p-1 text-slate-500 hover:text-rose-400 rounded hover:bg-slate-800 transition cursor-pointer"
                              title="Delete dependency edge (Admin)"
                            >
                              <Trash2 className="w-3.5 h-3.5" />
                            </button>
                          )
                        ) : (
                          <span
                            className="text-slate-600 text-[10px] font-mono cursor-not-allowed"
                            title="Deletion restricted to atlas:admin"
                          >
                            Read-Only
                          </span>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
