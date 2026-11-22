import React, { useState } from 'react';
import {
  AppRole,
  ClassificationLevel,
  GisCustomSource,
  SchemaValidationResult,
} from '../../types/atlas';
import { WorkspaceIntelligenceState } from '../../hooks/useWorkspaceIntelligence';
import { AuditLogViewer } from '../AuditLogViewer';
import { atlasService } from '../../data/api';
import { verifyWebCryptoEngine } from '../../utils/crypto';
import {
  Users,
  KeyRound,
  Database,
  Settings,
  ShieldCheck,
  CheckCircle2,
  XCircle,
  RefreshCw,
} from 'lucide-react';

interface AdminWorkspaceProps {
  mode:
    | 'user_management'
    | 'roles_permissions'
    | 'audit_logs'
    | 'data_sources'
    | 'system_configuration';
  intel: WorkspaceIntelligenceState;
  userEmail: string;
  userId: string;
  activeRole: AppRole;
  classification: ClassificationLevel;
  onChangeClassification: (level: ClassificationLevel) => void;
  settingsError?: string | null;
  customGisSources: GisCustomSource[];
}

const CLASSIFICATION_OPTIONS: ClassificationLevel[] = [
  'INTERNAL // RESTRICTED',
  'CLIENT CONFIDENTIAL',
  'TLP:AMBER+STRICT',
  'TLP:GREEN',
  'UNCLASSIFIED // DEMO',
];

export const AdminWorkspace: React.FC<AdminWorkspaceProps> = ({
  mode,
  intel,
  userEmail,
  userId,
  activeRole,
  classification,
  onChangeClassification,
  settingsError,
  customGisSources,
}) => {
  const [cryptoCheck, setCryptoCheck] = useState<{ passed: boolean; error?: string } | null>(null);
  const [schemaCheck, setSchemaCheck] = useState<SchemaValidationResult | null>(null);
  const [checkingConfig, setCheckingConfig] = useState(false);

  const runDiagnostics = async () => {
    setCheckingConfig(true);
    try {
      const [cRes, sRes] = await Promise.all([
        verifyWebCryptoEngine(),
        atlasService.validateExpectedSchema(),
      ]);
      setCryptoCheck(cRes);
      setSchemaCheck(sRes);
    } finally {
      setCheckingConfig(false);
    }
  };

  // =========================================================================
  // 1. AUDIT LOGS
  // =========================================================================
  if (mode === 'audit_logs') {
    return (
      <div className="flex-1 overflow-y-auto bg-[#0b0d10]">
        <AuditLogViewer activeOrgId={intel.orgId} userRole={activeRole} />
      </div>
    );
  }

  // =========================================================================
  // 2. USER MANAGEMENT
  // =========================================================================
  if (mode === 'user_management') {
    return (
      <div className="flex-1 overflow-y-auto bg-[#0b0d10] p-4 space-y-4">
        <div className="bg-[#12151b] border border-[#252b36] p-4 flex flex-wrap items-center justify-between gap-2">
          <div>
            <div className="font-mono text-[10px] tracking-[0.12em] text-[#8fa36d]">
              SYSTEM ADMINISTRATION // IDENTITY & WORKSPACE ACCESS
            </div>
            <h1 className="text-base font-semibold text-[#e8ecf1] mt-0.5 flex items-center gap-2">
              <Users className="w-4 h-4 text-[#4a9eb0]" />
              <span>User Management & Workspace Memberships</span>
            </h1>
          </div>
          <span className="font-mono text-[10px] text-[#4f8f66] border border-[#4f8f66]/40 bg-[#4f8f66]/10 px-2 py-0.5">
            EXPLICIT DB MEMBERSHIPS ONLY (RLS ENFORCED)
          </span>
        </div>

        {/* Authenticated Operator Card */}
        <div className="bg-[#12151b] border border-[#252b36] p-4 grid grid-cols-1 md:grid-cols-4 gap-3 font-mono text-xs">
          <div>
            <div className="text-[10px] text-[#8c97a8]">AUTHENTICATED OPERATOR</div>
            <div className="text-[#e8ecf1] font-semibold mt-0.5 truncate">{userEmail}</div>
          </div>
          <div>
            <div className="text-[10px] text-[#8c97a8]">USER UUID</div>
            <div className="text-[#8c97a8] mt-0.5 truncate">{userId}</div>
          </div>
          <div>
            <div className="text-[10px] text-[#8c97a8]">ACTIVE WORKSPACE ROLE</div>
            <div className="text-[#8fa36d] font-semibold mt-0.5">{activeRole}</div>
          </div>
          <div>
            <div className="text-[10px] text-[#8c97a8]">ASSURANCE LEVEL</div>
            <div className="text-[#4f8f66] font-semibold mt-0.5 flex items-center gap-1">
              <ShieldCheck className="w-3.5 h-3.5" />
              <span>AAL2 TOTP VERIFIED</span>
            </div>
          </div>
        </div>

        {/* Memberships visible under RLS */}
        <div className="bg-[#12151b] border border-[#252b36]">
          <div className="px-3 py-2 border-b border-[#252b36] font-mono text-[11px] font-semibold text-[#e8ecf1] flex justify-between">
            <span>AUTHORISED WORKSPACE MEMBERSHIPS (public.memberships)</span>
            <span className="text-[#8c97a8]">{intel.orgMemberships.length} VISIBLE ROWS</span>
          </div>
          <table className="w-full text-left font-mono text-[11px] border-collapse">
            <thead className="bg-[#0e1116] border-b border-[#252b36] text-[#8c97a8] text-[10px]">
              <tr>
                <th className="py-2 px-3">USER ID</th>
                <th className="py-2 px-2">ROLE</th>
                <th className="py-2 px-2">PROVENANCE SOURCE</th>
                <th className="py-2 px-2">POLICY</th>
                <th className="py-2 px-3 text-right">GRANTED AT (UTC)</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#181c24]">
              {intel.orgMemberships.map((m) => (
                <tr key={m.id} className="hover:bg-[#181c24]">
                  <td className="py-1.5 px-3 text-[#e8ecf1]">
                    {m.user_id} {m.user_id === userId && <span className="text-[#8fa36d]">(YOU)</span>}
                  </td>
                  <td className="py-1.5 px-2 text-[#4a9eb0] font-semibold">{m.role}</td>
                  <td className="py-1.5 px-2 text-[#8c97a8]">{m.source}</td>
                  <td className="py-1.5 px-2 text-[#8c97a8]">{m.sharing_policy}</td>
                  <td className="py-1.5 px-3 text-right tabular-nums text-[#8c97a8]">
                    {new Date(m.created_at).toISOString().slice(0, 19).replace('T', ' ')}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    );
  }

  // =========================================================================
  // 3. ROLES & PERMISSIONS MATRIX
  // =========================================================================
  if (mode === 'roles_permissions') {
    const matrix = [
      { cap: 'Read Assets, Dependencies, Incidents, Matches, Evidence', admin: 'ALLOW (AAL2 + Org)', analyst: 'ALLOW (AAL2 + Org)', aal1: 'DENY' },
      { cap: 'Import Asset Batches (import_assets RPC)', admin: 'ALLOW', analyst: 'ALLOW', aal1: 'DENY' },
      { cap: 'Create Dependency Edges', admin: 'ALLOW', analyst: 'ALLOW', aal1: 'DENY' },
      { cap: 'Delete Dependency Edges', admin: 'ALLOW', analyst: 'DENY (RLS)', aal1: 'DENY' },
      { cap: 'Confirm / Reject Proposed Asset Matches', admin: 'ALLOW', analyst: 'ALLOW', aal1: 'DENY' },
      { cap: 'Upload Evidence & Record Custody Events', admin: 'ALLOW', analyst: 'ALLOW', aal1: 'DENY' },
      { cap: 'Issue / Rotate / Revoke Signed Ingest Keys', admin: 'ALLOW', analyst: 'DENY', aal1: 'DENY' },
      { cap: 'Record Audit Checkpoints (audit_checkpoint RPC)', admin: 'ALLOW', analyst: 'DENY', aal1: 'DENY' },
      { cap: 'Verify SHA-256 Cryptographic Audit Ledger', admin: 'ALLOW', analyst: 'ALLOW', aal1: 'DENY' },
      { cap: 'Workspace UI Preferences (Classification / GIS Overlays)', admin: 'LOCAL BROWSER ONLY', analyst: 'LOCAL BROWSER ONLY', aal1: 'N/A' },
      { cap: 'Mutate or Delete Append-Only Audit Ledger', admin: 'DENY (TRIGGER)', analyst: 'DENY (TRIGGER)', aal1: 'DENY' },
    ];

    return (
      <div className="flex-1 overflow-y-auto bg-[#0b0d10] p-4 space-y-4">
        <div className="bg-[#12151b] border border-[#252b36] p-4">
          <div className="font-mono text-[10px] tracking-[0.12em] text-[#8fa36d]">
            SYSTEM ADMINISTRATION // AUTHORIZATION POLICY
          </div>
          <h1 className="text-base font-semibold text-[#e8ecf1] mt-0.5 flex items-center gap-2">
            <KeyRound className="w-4 h-4 text-[#c88b32]" />
            <span>Roles and PostgreSQL RLS Permission Matrix</span>
          </h1>
          <p className="text-xs text-[#8c97a8] mt-1">
            All authorization boundaries are enforced server-side inside Supabase PostgreSQL row-level security policies and <code className="font-mono text-[#e8ecf1]">SECURITY DEFINER</code> RPCs.
          </p>
        </div>

        <div className="bg-[#12151b] border border-[#252b36]">
          <table className="w-full text-left font-mono text-[11px] border-collapse">
            <thead className="bg-[#0e1116] border-b border-[#252b36] text-[#8c97a8] text-[10px]">
              <tr>
                <th className="py-2 px-3">CAPABILITY / RESOURCE</th>
                <th className="py-2 px-3">atlas:admin</th>
                <th className="py-2 px-3">atlas:analyst</th>
                <th className="py-2 px-3">AAL1 / UNAUTHENTICATED</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#181c24]">
              {matrix.map((row) => (
                <tr key={row.cap} className="hover:bg-[#181c24]">
                  <td className="py-2 px-3 font-sans text-xs text-[#e8ecf1]">{row.cap}</td>
                  <td className="py-2 px-3 text-[#4f8f66]">{row.admin}</td>
                  <td className={`py-2 px-3 ${row.analyst.startsWith('ALLOW') ? 'text-[#4f8f66]' : 'text-[#c94a4a]'}`}>
                    {row.analyst}
                  </td>
                  <td className="py-2 px-3 text-[#c94a4a]">{row.aal1}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    );
  }

  // =========================================================================
  // 4. DATA SOURCES
  // =========================================================================
  if (mode === 'data_sources') {
    return (
      <div className="flex-1 overflow-y-auto bg-[#0b0d10] p-4 space-y-4">
        <div className="bg-[#12151b] border border-[#252b36] p-4 flex items-center justify-between">
          <div>
            <div className="font-mono text-[10px] tracking-[0.12em] text-[#8fa36d]">
              SYSTEM ADMINISTRATION // DATA PROVENANCE
            </div>
            <h1 className="text-base font-semibold text-[#e8ecf1] mt-0.5 flex items-center gap-2">
              <Database className="w-4 h-4 text-[#4a9eb0]" />
              <span>Data Sources & Geospatial Feeds</span>
            </h1>
          </div>
          <span className="font-mono text-[11px] text-[#e8ecf1] tabular-nums">
            {intel.datasets.length} DATASETS · {customGisSources.length} GIS OVERLAYS
          </span>
        </div>

        <div className="bg-[#12151b] border border-[#252b36]">
          <div className="px-3 py-2 border-b border-[#252b36] font-mono text-[11px] font-semibold text-[#e8ecf1]">
            INGESTED DATASET BATCHES (public.datasets)
          </div>
          <table className="w-full text-left font-mono text-[11px] border-collapse">
            <thead className="bg-[#0e1116] border-b border-[#252b36] text-[#8c97a8] text-[10px]">
              <tr>
                <th className="py-2 px-3">DATASET NAME</th>
                <th className="py-2 px-2">SOURCE</th>
                <th className="py-2 px-2">LICENCE</th>
                <th className="py-2 px-2">DECLARED CRS</th>
                <th className="py-2 px-2 text-right">ROWS</th>
                <th className="py-2 px-3 text-right">INGESTED (UTC)</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#181c24]">
              {intel.datasets.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-6 text-center text-[#8c97a8] font-sans">
                    No dataset batches recorded in this workspace yet.
                  </td>
                </tr>
              ) : (
                intel.datasets.map((ds) => (
                  <tr key={ds.id} className="hover:bg-[#181c24]">
                    <td className="py-1.5 px-3 text-[#e8ecf1] font-semibold">{ds.name}</td>
                    <td className="py-1.5 px-2 text-[#8c97a8]">{ds.source}</td>
                    <td className="py-1.5 px-2 text-[#8c97a8]">{ds.licence}</td>
                    <td className="py-1.5 px-2 text-[#4f8f66]">{ds.declared_crs}</td>
                    <td className="py-1.5 px-2 text-right tabular-nums text-[#e8ecf1]">{ds.row_count}</td>
                    <td className="py-1.5 px-3 text-right tabular-nums text-[#8c97a8]">
                      {new Date(ds.created_at).toISOString().slice(0, 19).replace('T', ' ')}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    );
  }

  // =========================================================================
  // 5. SYSTEM CONFIGURATION
  // =========================================================================
  return (
    <div className="flex-1 overflow-y-auto bg-[#0b0d10] p-4 space-y-4">
      <div className="max-w-4xl space-y-4">
        <div className="bg-[#12151b] border border-[#252b36] p-4 flex flex-wrap items-center justify-between gap-2">
          <div>
            <div className="font-mono text-[10px] tracking-[0.12em] text-[#8fa36d]">
              SYSTEM ADMINISTRATION // POLICY & RUNTIME DIAGNOSTICS
            </div>
            <h1 className="text-base font-semibold text-[#e8ecf1] mt-0.5 flex items-center gap-2">
              <Settings className="w-4 h-4 text-[#8fa36d]" />
              <span>System Configuration</span>
            </h1>
          </div>
          <button
            onClick={runDiagnostics}
            disabled={checkingConfig}
            className="px-3 py-1.5 bg-[#6f8054] hover:bg-[#7d905f] text-[#0b0d10] font-mono text-xs font-semibold flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${checkingConfig ? 'animate-spin' : ''}`} />
            <span>Run Schema & Crypto Self-Test</span>
          </button>
        </div>

        {/* Classification Policy Selector (Frontend-Only Non-Authoritative Preference) */}
        <div className="bg-[#12151b] border border-[#252b36] p-4 space-y-2">
          <div className="flex items-center justify-between gap-2">
            <div className="font-mono text-xs font-semibold text-[#e8ecf1]">
              WORKSPACE CLASSIFICATION BANNER (FRONTEND PREFERENCE)
            </div>
            <span className="font-mono text-[10px] text-[#c88b32] border border-[#c88b32]/40 bg-[#c88b32]/10 px-1.5 py-0.5">
              NON-AUTHORITATIVE · BROWSER STORAGE ONLY
            </span>
          </div>
          <p className="text-xs text-[#8c97a8]">
            Configures the local Top Command Bar classification display label per workspace. Stored strictly in browser local storage and does not alter PostgreSQL authorization or server policy.
          </p>
          <select
            value={classification}
            onChange={(e) => onChangeClassification(e.target.value as ClassificationLevel)}
            className="bg-[#0b0d10] border border-[#252b36] px-3 py-1.5 font-mono text-xs text-[#e8ecf1] focus:outline-none focus:border-[#6f8054]"
          >
            {CLASSIFICATION_OPTIONS.map((opt) => (
              <option key={opt} value={opt}>
                {opt}
              </option>
            ))}
          </select>
          {settingsError && (
            <div className="font-mono text-[11px] text-[#c94a4a]">
              {settingsError}
            </div>
          )}
        </div>

        {/* Live Verification Readout */}
        {(cryptoCheck || schemaCheck) && (
          <div className="bg-[#12151b] border border-[#252b36] p-4 space-y-3 font-mono text-xs">
            {cryptoCheck && (
              <div className="flex items-center gap-2">
                {cryptoCheck.passed ? (
                  <CheckCircle2 className="w-4 h-4 text-[#4f8f66]" />
                ) : (
                  <XCircle className="w-4 h-4 text-[#c94a4a]" />
                )}
                <span className="text-[#e8ecf1]">
                  Web Crypto SHA-256 Engine (NIST / RFC 6234 Vectors):{' '}
                  <strong className={cryptoCheck.passed ? 'text-[#4f8f66]' : 'text-[#c94a4a]'}>
                    {cryptoCheck.passed ? 'PASSED' : `FAILED (${cryptoCheck.error})`}
                  </strong>
                </span>
              </div>
            )}

            {schemaCheck && (
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  {schemaCheck.valid ? (
                    <CheckCircle2 className="w-4 h-4 text-[#4f8f66]" />
                  ) : (
                    <XCircle className="w-4 h-4 text-[#c94a4a]" />
                  )}
                  <span className="text-[#e8ecf1]">
                    Supabase PostgreSQL Schema Check ({schemaCheck.checkedTables.length} tables):{' '}
                    <strong className={schemaCheck.valid ? 'text-[#4f8f66]' : 'text-[#c94a4a]'}>
                      {schemaCheck.valid ? 'VALID' : 'INCOMPLETE'}
                    </strong>
                  </span>
                </div>
                <div className="text-[11px] text-[#8c97a8] pl-6">
                  Verified tables: {schemaCheck.checkedTables.join(', ')}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
