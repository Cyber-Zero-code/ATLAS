/**
 * Project ATLAS: Cyber-Physical Risk Intelligence
 * Stage 1 Front-End Shell
 */

import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { supabase } from './lib/supabase';
import { atlasService } from './data/api';
import {
  ClassificationLevel,
  GisCustomSource,
  Membership,
  ModuleId,
  SchemaValidationResult,
  SelectedEntity,
} from './types/atlas';
import { ConfigSetupScreen } from './components/ConfigSetupScreen';
import { AuthScreen } from './components/AuthScreen';
import { MfaScreen } from './components/MfaScreen';
import { TopCommandBar } from './components/shell/TopCommandBar';
import { LeftSidebar } from './components/shell/LeftSidebar';
import { useWorkspaceIntelligence } from './hooks/useWorkspaceIntelligence';
import { CommandCentreWorkspace } from './components/workspaces/CommandCentreWorkspace';
import { GeointWorkspace } from './components/workspaces/GeointWorkspace';
import { CyberSecurityWorkspace } from './components/workspaces/CyberSecurityWorkspace';
import { RelationshipGraphWorkspace } from './components/workspaces/RelationshipGraphWorkspace';
import { AiMlWorkspace } from './components/workspaces/AiMlWorkspace';
import { AdminWorkspace } from './components/workspaces/AdminWorkspace';
import { loadOrgScopedValue, saveOrgScopedValue } from './utils/orgStorage';
import { ShieldAlert, RefreshCw, LogOut, AlertTriangle, Database } from 'lucide-react';

// UI preferences (classification display banner & local custom map overlays) are stored per organisation in browser storage via orgStorage.ts.

export default function App() {
  const isConfigured = atlasService.isConfigured();

  // Startup Schema Validation State
  const [schemaResult, setSchemaResult] = useState<SchemaValidationResult | null>(null);
  const [isCheckingSchema, setIsCheckingSchema] = useState<boolean>(true);

  // Authentication & Session States
  const [user, setUser] = useState<any>(null);
  const [isAal2, setIsAal2] = useState<boolean>(false);
  const [memberships, setMemberships] = useState<Membership[]>([]);
  const [activeOrgId, setActiveOrgId] = useState<string>('');
  const [activeModule, setActiveModule] = useState<ModuleId>('command_centre');
  const [sidebarCollapsed, setSidebarCollapsed] = useState<boolean>(false);
  const [selectedEntity, setSelectedEntity] = useState<SelectedEntity>(null);

  const [classification, setClassification] = useState<ClassificationLevel>('INTERNAL // RESTRICTED');
  const [customGisSources, setCustomGisSources] = useState<GisCustomSource[]>([]);
  const [settingsError, setSettingsError] = useState<string | null>(null);

  // Load this organisation's local UI preferences whenever the signed-in (MFA) user or active organisation changes.
  useEffect(() => {
    if (!user || !isAal2 || !activeOrgId) {
      setClassification('INTERNAL // RESTRICTED');
      setCustomGisSources([]);
      setSettingsError(null);
      return;
    }
    setSettingsError(null);
    const prefs = loadOrgScopedValue<{
      classification?: ClassificationLevel;
      gisSources?: GisCustomSource[];
    }>('ui_preferences', activeOrgId, {});
    setClassification(prefs.classification || 'INTERNAL // RESTRICTED');
    setCustomGisSources(Array.isArray(prefs.gisSources) ? prefs.gisSources : []);
  }, [user, isAal2, activeOrgId]);

  const handleChangeClassification = useCallback(
    (level: ClassificationLevel) => {
      setSettingsError(null);
      setClassification(level);
      if (activeOrgId) {
        saveOrgScopedValue('ui_preferences', activeOrgId, {
          classification: level,
          gisSources: customGisSources,
        });
      }
    },
    [activeOrgId, customGisSources]
  );

  const persistGisSources = useCallback(
    (next: GisCustomSource[]) => {
      setSettingsError(null);
      setCustomGisSources(next);
      if (activeOrgId) {
        saveOrgScopedValue('ui_preferences', activeOrgId, {
          classification,
          gisSources: next,
        });
      }
    },
    [activeOrgId, classification]
  );

  const handleAddGisSource = useCallback(
    (src: Omit<GisCustomSource, 'id'>) => {
      persistGisSources([...customGisSources, { ...src, id: `gis-${Date.now()}` }]);
    },
    [customGisSources, persistGisSources]
  );

  const handleToggleGisSource = useCallback(
    (id: string) => {
      persistGisSources(
        customGisSources.map((s) => (s.id === id ? { ...s, enabled: !s.enabled } : s))
      );
    },
    [customGisSources, persistGisSources]
  );

  const handleRemoveGisSource = useCallback(
    (id: string) => {
      persistGisSources(customGisSources.filter((s) => s.id !== id));
    },
    [customGisSources, persistGisSources]
  );

  const [isCheckingAuth, setIsCheckingAuth] = useState<boolean>(true);
  const [authError, setAuthError] = useState<string | null>(null);

  // Shared authorised workspace intelligence data
  const intel = useWorkspaceIntelligence(user && isAal2 && activeOrgId ? activeOrgId : '');

  const sidebarCounts = useMemo(
    () => ({
      incidents: intel.incidents.length,
      proposedMatches: intel.matches.filter((m) => m.status === 'proposed').length,
      assets: intel.assets.length,
    }),
    [intel.incidents.length, intel.matches, intel.assets.length]
  );

  const checkSchema = useCallback(async () => {
    if (!atlasService.isConfigured()) {
      setIsCheckingSchema(false);
      return;
    }

    setIsCheckingSchema(true);
    try {
      const res = await atlasService.validateExpectedSchema();
      setSchemaResult(res);
    } catch (err: any) {
      setSchemaResult({
        valid: false,
        checkedTables: [],
        missingTables: [],
        missingColumns: [],
        error: err.message || 'Unknown schema check failure',
      });
    } finally {
      setIsCheckingSchema(false);
    }
  }, []);

  const checkAuthStatus = useCallback(async () => {
    if (!atlasService.isConfigured()) {
      setIsCheckingAuth(false);
      return;
    }

    setIsCheckingAuth(true);
    setAuthError(null);

    try {
      const { data: { user: currentUser } } = await supabase.auth.getUser();
      setUser(currentUser);

      if (!currentUser) {
        setIsAal2(false);
        setMemberships([]);
        setActiveOrgId('');
        setIsCheckingAuth(false);
        return;
      }

      // 1. Check Authenticator Assurance Level (AAL2 required)
      const aal = await atlasService.getMfaAssuranceLevel();
      const verifiedAal2 = aal.currentLevel === 'aal2';
      setIsAal2(verifiedAal2);

      if (!verifiedAal2) {
        setIsCheckingAuth(false);
        return;
      }

      // 2. Fetch Authorised Memberships strictly from public.memberships
      const userMemberships = await atlasService.fetchUserMemberships();
      setMemberships(userMemberships);

      if (userMemberships.length > 0) {
        // Retain current activeOrgId if still valid, otherwise default to first membership
        setActiveOrgId((prev) => {
          const exists = userMemberships.some((m) => m.org_id === prev);
          return exists ? prev : userMemberships[0].org_id;
        });
      }
    } catch (err: any) {
      setAuthError(err.message || 'Error resolving session or workspace memberships.');
    } finally {
      setIsCheckingAuth(false);
    }
  }, []);

  useEffect(() => {
    checkSchema();
    checkAuthStatus();

    if (isConfigured) {
      const { data: authListener } = supabase.auth.onAuthStateChange(() => {
        checkAuthStatus();
      });

      return () => {
        authListener.subscription.unsubscribe();
      };
    }
  }, [checkAuthStatus, checkSchema, isConfigured]);

  const handleSignOut = async () => {
    await atlasService.signOut();
    setUser(null);
    setIsAal2(false);
    setMemberships([]);
    setActiveOrgId('');
    setSelectedEntity(null);
    setClassification('INTERNAL // RESTRICTED');
    setCustomGisSources([]);
    setSettingsError(null);
    setAuthError(null);
  };

  // 1. Configuration Gate: .env credentials check
  if (!isConfigured) {
    return <ConfigSetupScreen />;
  }

  // 1b. Schema Verification Loading State
  if (isCheckingSchema) {
    return (
      <div className="min-h-screen bg-slate-950 text-slate-100 flex items-center justify-center p-6">
        <div className="flex items-center gap-2.5 text-xs font-mono text-cyan-300">
          <RefreshCw className="w-4 h-4 animate-spin text-cyan-400" />
          <span>Validating database schema with Supabase...</span>
        </div>
      </div>
    );
  }

  // 1c. Startup Schema Gate: Fail loudly if expected tables or columns are missing
  if (schemaResult && !schemaResult.valid) {
    return (
      <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col items-center justify-center p-6 antialiased select-text">
        <div className="max-w-2xl w-full bg-slate-900 border border-rose-800 rounded-xl p-6 shadow-2xl space-y-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-full bg-rose-950/80 border border-rose-800 text-rose-400 flex items-center justify-center shrink-0">
              <Database className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-lg font-bold text-slate-100">Database Schema Validation Failed</h2>
              <p className="text-xs text-rose-300 font-mono">
                Project ATLAS detected that the expected Supabase PostgreSQL schema is missing or incomplete.
              </p>
            </div>
          </div>

          <div className="p-3 bg-slate-950 border border-rose-900/60 rounded-lg space-y-2 text-xs font-mono">
            {schemaResult.missingTables.length > 0 && (
              <div>
                <span className="text-rose-400 font-bold">Missing Tables: </span>
                <span className="text-slate-300">{schemaResult.missingTables.join(', ')}</span>
              </div>
            )}
            {schemaResult.missingColumns.length > 0 && (
              <div>
                <span className="text-amber-400 font-bold">Missing / Malformed Columns: </span>
                <span className="text-slate-300">{schemaResult.missingColumns.join(', ')}</span>
              </div>
            )}
            {schemaResult.error && (
              <div className="text-rose-300">
                <span className="font-bold">Error Detail: </span>
                <span>{schemaResult.error}</span>
              </div>
            )}
          </div>

          <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg text-left text-[11px] font-mono text-slate-400 space-y-1.5">
            <div className="text-slate-200 font-semibold">Required Migration Run Order (in Supabase SQL Editor):</div>
            <ol className="list-decimal list-inside space-y-0.5 text-slate-300 max-h-56 overflow-y-auto pr-1">
              <li>001_schema_and_extensions.sql (Tables, composite keys)</li>
              <li>002_rls_policies_and_roles.sql (RLS, AAL2, RBAC)</li>
              <li>003_audit.sql (Cryptographic audit ledger)</li>
              <li>003b_fix_core_function_names.sql (Core Postgres function patch)</li>
              <li>004_storage.sql (Private evidence storage)</li>
              <li>005_synthetic_seed.sql (Seed workspaces &amp; scoring config)</li>
              <li>006_asset_import_and_map.sql (Import &amp; GeoJSON)</li>
              <li>007_dependencies_and_blast_radius.sql (Edges &amp; blast radius)</li>
              <li>008_incident_intake_and_matching.sql (CSX intake &amp; matching)</li>
              <li>009_timeline_and_custody.sql (Incident timeline &amp; evidence custody)</li>
              <li>010_harden_log_event.sql – 017_blast_radius_scalable.sql (Hardening, HMAC keys, checkpoints, scalable BFS)</li>
              <li>018_camera_and_threat_indicators.sql (Camera registry &amp; external threat indicators)</li>
            </ol>
          </div>

          <div className="pt-2 flex items-center justify-end">
            <button
              onClick={() => {
                checkSchema();
                checkAuthStatus();
              }}
              className="px-4 py-2 bg-rose-600 hover:bg-rose-500 text-white font-mono text-xs font-semibold rounded-lg transition cursor-pointer flex items-center gap-1.5"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              Re-check Database Schema
            </button>
          </div>
        </div>
      </div>
    );
  }

  // Loading state during auth resolution
  if (isCheckingAuth) {
    return (
      <div className="min-h-screen bg-slate-950 text-slate-100 flex items-center justify-center p-6">
        <div className="flex items-center gap-2.5 text-xs font-mono text-cyan-300">
          <RefreshCw className="w-4 h-4 animate-spin text-cyan-400" />
          <span>Verifying session with Supabase...</span>
        </div>
      </div>
    );
  }

  // 2. Sign In Gate
  if (!user) {
    return <AuthScreen onAuthSuccess={checkAuthStatus} />;
  }

  // 3. MFA Gate: Mandatory AAL2
  if (!isAal2) {
    return <MfaScreen onMfaVerified={checkAuthStatus} onSignOut={handleSignOut} />;
  }

  // 4a. Membership Query Error Screen: Show only error screen when memberships query fails
  if (authError) {
    return (
      <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col items-center justify-center p-6 antialiased select-text">
        <div className="max-w-md w-full bg-slate-900 border border-rose-800 rounded-xl p-6 shadow-2xl space-y-4 text-center">
          <div className="w-12 h-12 rounded-full bg-rose-950/80 border border-rose-800 text-rose-400 flex items-center justify-center mx-auto">
            <AlertTriangle className="w-6 h-6" />
          </div>
          <h2 className="text-lg font-bold text-slate-100">Database Query Failed</h2>
          <p className="text-xs text-slate-300 leading-relaxed">
            An error occurred while communicating with Supabase or querying your workspace memberships.
          </p>
          <div className="p-3 bg-slate-950 border border-rose-900/60 rounded-lg text-left text-xs font-mono text-rose-300 break-words">
            {authError}
          </div>
          <div className="pt-2 flex items-center justify-between">
            <button
              onClick={checkAuthStatus}
              className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono rounded-lg transition cursor-pointer flex items-center gap-1.5"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              Retry Query
            </button>
            <button
              onClick={handleSignOut}
              className="px-3 py-1.5 bg-rose-950/60 hover:bg-rose-900 text-rose-300 text-xs font-mono rounded-lg transition cursor-pointer flex items-center gap-1.5 border border-rose-800"
            >
              <LogOut className="w-3.5 h-3.5" />
              Sign Out
            </button>
          </div>
        </div>
      </div>
    );
  }

  // 4b. No Workspace Membership Gate: Shown ONLY when query succeeds and returns zero rows
  if (!authError && memberships.length === 0) {
    return (
      <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col items-center justify-center p-6 antialiased select-text">
        <div className="max-w-md w-full bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-2xl space-y-4 text-center">
          <div className="w-12 h-12 rounded-full bg-amber-950/80 border border-amber-800 text-amber-400 flex items-center justify-center mx-auto">
            <ShieldAlert className="w-6 h-6" />
          </div>
          <h2 className="text-lg font-bold text-slate-100">No Workspace Membership Found</h2>
          <p className="text-xs text-slate-300 leading-relaxed">
            Your user account (<code className="text-cyan-300 font-mono">{user.email}</code>) is authenticated with AAL2 MFA, but has not been assigned to any organisation in <code className="text-slate-200 font-mono">public.memberships</code>.
          </p>
          <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg text-left text-[11px] font-mono text-slate-400 space-y-1">
            <div className="text-slate-300 font-semibold">To grant access via Supabase SQL Editor:</div>
            <div className="text-emerald-400 select-all">
              INSERT INTO public.memberships (user_id, org_id, role)<br />
              VALUES ('{user.id}', '&lt;org_id&gt;', 'atlas:analyst');
            </div>
          </div>
          <div className="pt-2 flex items-center justify-between">
            <button
              onClick={checkAuthStatus}
              className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs rounded-lg transition cursor-pointer flex items-center gap-1.5"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              Re-check Memberships
            </button>
            <button
              onClick={handleSignOut}
              className="px-3 py-1.5 bg-rose-950/60 hover:bg-rose-900 text-rose-300 text-xs rounded-lg transition cursor-pointer flex items-center gap-1.5 border border-rose-800"
            >
              <LogOut className="w-3.5 h-3.5" />
              Sign Out
            </button>
          </div>
        </div>
      </div>
    );
  }

  // 5. Authorised Unified Project ATLAS Intelligence Workstation
  const activeMembership = memberships.find((m) => m.org_id === activeOrgId);
  const activeRole = activeMembership?.role || 'atlas:analyst';

  const handleOrgChange = (orgId: string) => {
    setActiveOrgId(orgId);
    setSelectedEntity(null);
  };

  const renderWorkspace = () => {
    switch (activeModule) {
      // COMMAND
      case 'command_centre':
      case 'operational_overview':
      case 'mission_workspace':
        return (
          <CommandCentreWorkspace
            mode={activeModule}
            intel={intel}
            activeRole={activeRole}
            selectedEntity={selectedEntity}
            onSelectEntity={setSelectedEntity}
            onNavigateModule={setActiveModule}
            customGisSources={customGisSources}
          />
        );

      // GEOSPATIAL INTELLIGENCE
      case 'global_map':
      case 'satellite_imagery':
      case 'terrain_intelligence':
      case 'infrastructure_mapping':
      case 'asset_tracking':
      case 'geographic_risk':
        return (
          <GeointWorkspace
            mode={activeModule}
            intel={intel}
            activeRole={activeRole}
            settingsError={settingsError}
            selectedEntity={selectedEntity}
            onSelectEntity={setSelectedEntity}
            onNavigateModule={setActiveModule}
            customGisSources={customGisSources}
            onAddGisSource={handleAddGisSource}
            onToggleGisSource={handleToggleGisSource}
            onRemoveGisSource={handleRemoveGisSource}
          />
        );

      // CYBER INTELLIGENCE
      case 'threat_intelligence':
      case 'cyber_monitoring':
      case 'vulnerability_intelligence':
      case 'attack_surface':
      case 'cyber_incidents':
      case 'ioc_investigation':
        return (
          <CyberSecurityWorkspace
            mode={activeModule}
            intel={intel}
            activeRole={activeRole}
            userEmail={user.email}
            selectedEntity={selectedEntity}
            onSelectEntity={setSelectedEntity}
            onNavigateModule={setActiveModule}
          />
        );

      // INTELLIGENCE ANALYSIS
      case 'entity_intelligence':
      case 'relationship_graph':
      case 'network_analysis':
      case 'geospatial_correlation':
      case 'intelligence_reports':
        return (
          <RelationshipGraphWorkspace
            mode={activeModule}
            intel={intel}
            activeRole={activeRole}
            userEmail={user.email}
            selectedEntity={selectedEntity}
            onSelectEntity={setSelectedEntity}
            onNavigateModule={setActiveModule}
          />
        );

      // AI & MACHINE LEARNING
      case 'predictive_risk':
      case 'anomaly_detection':
      case 'behavioural_analysis':
      case 'ai_assistant':
      case 'model_performance':
        return (
          <AiMlWorkspace
            mode={activeModule}
            intel={intel}
            onSelectEntity={setSelectedEntity}
            onNavigateModule={setActiveModule}
          />
        );

      // SYSTEM ADMINISTRATION
      case 'user_management':
      case 'roles_permissions':
      case 'audit_logs':
      case 'data_sources':
      case 'system_configuration':
        return (
          <AdminWorkspace
            mode={activeModule}
            intel={intel}
            userEmail={user.email}
            userId={user.id}
            activeRole={activeRole}
            classification={classification}
            onChangeClassification={handleChangeClassification}
            settingsError={settingsError}
            customGisSources={customGisSources}
          />
        );
    }
  };

  return (
    <div className="h-screen overflow-hidden bg-[#0b0d10] text-[#e8ecf1] flex flex-col font-sans antialiased">
      <TopCommandBar
        userEmail={user.email}
        activeRole={activeRole}
        memberships={memberships}
        activeOrgId={activeOrgId}
        onSelectOrg={handleOrgChange}
        classification={classification}
        intel={intel}
        onNavigateModule={setActiveModule}
        onSelectEntity={(ent, targetMod) => {
          setSelectedEntity(ent);
          if (targetMod) setActiveModule(targetMod);
        }}
        onSignOut={handleSignOut}
      />

      {settingsError && (
        <div className="px-4 py-1.5 bg-[#c94a4a]/15 border-b border-[#c94a4a]/50 font-mono text-[11px] text-[#e8ecf1] flex items-center justify-between gap-2 shrink-0">
          <span>Workspace preference warning: {settingsError}</span>
          <button onClick={() => setSettingsError(null)} className="underline text-[#c94a4a] cursor-pointer">
            Dismiss
          </button>
        </div>
      )}

      <div className="flex-1 flex min-h-0 overflow-hidden">
        <LeftSidebar
          activeModule={activeModule}
          onSelectModule={setActiveModule}
          collapsed={sidebarCollapsed}
          onToggleCollapse={() => setSidebarCollapsed((v) => !v)}
          counts={sidebarCounts}
        />

        <main className="flex-1 flex flex-col min-w-0 min-h-0 overflow-hidden">
          {renderWorkspace()}
        </main>
      </div>
    </div>
  );
}
