import React, { useState, useEffect, useMemo, useRef } from 'react';
import {
  ClassificationLevel,
  Membership,
  ModuleId,
  SelectedEntity,
} from '../../types/atlas';
import { WorkspaceIntelligenceState } from '../../hooks/useWorkspaceIntelligence';
import { isWebCryptoAvailable } from '../../utils/crypto';
import {
  Bell,
  Briefcase,
  Database,
  LogOut,
  RefreshCw,
  Search,
  Settings,
  ShieldCheck,
  User,
  AlertTriangle,
  Server,
  Radio,
  FileCheck,
  X,
} from 'lucide-react';

interface TopCommandBarProps {
  userEmail: string;
  activeRole: string;
  memberships: Membership[];
  activeOrgId: string;
  onSelectOrg: (orgId: string) => void;
  classification: ClassificationLevel;
  intel: WorkspaceIntelligenceState;
  onNavigateModule: (module: ModuleId) => void;
  onSelectEntity: (entity: SelectedEntity, targetModule?: ModuleId) => void;
  onSignOut: () => void;
}

interface SearchHit {
  id: string;
  kind: 'asset' | 'incident' | 'evidence' | 'indicator';
  title: string;
  subtitle: string;
  badge: string;
  targetEntity: SelectedEntity;
  targetModule: ModuleId;
}

export const TopCommandBar: React.FC<TopCommandBarProps> = ({
  userEmail,
  activeRole,
  memberships,
  activeOrgId,
  onSelectOrg,
  classification,
  intel,
  onNavigateModule,
  onSelectEntity,
  onSignOut,
}) => {
  const [utcNow, setUtcNow] = useState<string>(() => formatUtcNow());
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [searchOpen, setSearchOpen] = useState<boolean>(false);
  const [alertsOpen, setAlertsOpen] = useState<boolean>(false);

  const searchRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const alertsRef = useRef<HTMLDivElement>(null);

  const cryptoReady = useMemo(() => isWebCryptoAvailable(), []);

  useEffect(() => {
    const timer = setInterval(() => {
      setUtcNow(formatUtcNow());
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        inputRef.current?.focus();
        setSearchOpen(true);
      }
      if (e.key === 'Escape') {
        setSearchOpen(false);
        setAlertsOpen(false);
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, []);

  useEffect(() => {
    const onClickOutside = (e: MouseEvent) => {
      if (searchRef.current && !searchRef.current.contains(e.target as Node)) {
        setSearchOpen(false);
      }
      if (alertsRef.current && !alertsRef.current.contains(e.target as Node)) {
        setAlertsOpen(false);
      }
    };
    document.addEventListener('mousedown', onClickOutside);
    return () => document.removeEventListener('mousedown', onClickOutside);
  }, []);

  useEffect(() => {
    setSearchQuery('');
    setSearchOpen(false);
    setAlertsOpen(false);
  }, [activeOrgId]);

  const searchHits = useMemo<SearchHit[]>(() => {
    const q = searchQuery.trim().toLowerCase();
    if (!q) return [];

    const hits: SearchHit[] = [];

    for (const asset of intel.assets) {
      const hostnames = asset.identifiers?.hostnames || [];
      const ips = asset.identifiers?.ip_addresses || [];
      const cidrs = asset.identifiers?.cidrs || [];
      const cloudIds = asset.identifiers?.cloud_account_ids || [];

      const textMatch =
        asset.site_code.toLowerCase().includes(q) ||
        asset.name.toLowerCase().includes(q) ||
        asset.owner.toLowerCase().includes(q) ||
        asset.type.toLowerCase().includes(q);

      const iocMatch =
        hostnames.some((h) => h.toLowerCase().includes(q)) ||
        ips.some((ip) => ip.toLowerCase().includes(q)) ||
        cidrs.some((c) => c.toLowerCase().includes(q)) ||
        cloudIds.some((cid) => cid.toLowerCase().includes(q));

      if (textMatch || iocMatch) {
        hits.push({
          id: `asset-${asset.id}`,
          kind: 'asset',
          title: `${asset.site_code} — ${asset.name}`,
          subtitle: `${asset.type.replace('_', ' ')} · Owner: ${asset.owner} · Tier ${asset.criticality}`,
          badge: 'ASSET',
          targetEntity: { kind: 'asset', id: asset.id },
          targetModule: 'command_centre',
        });
      }
    }

    for (const inc of intel.incidents) {
      const sigStr = JSON.stringify(inc.signals || {}).toLowerCase();
      if (
        inc.event_id.toLowerCase().includes(q) ||
        inc.event_type.toLowerCase().includes(q) ||
        inc.severity.toLowerCase().includes(q) ||
        sigStr.includes(q)
      ) {
        hits.push({
          id: `inc-${inc.id}`,
          kind: 'incident',
          title: `${inc.event_id} — ${inc.event_type}`,
          subtitle: `${inc.severity.toUpperCase()} · Source: ${inc.source}`,
          badge: 'INCIDENT',
          targetEntity: { kind: 'incident', id: inc.id },
          targetModule: 'cyber_incidents',
        });
      }
    }

    for (const ev of intel.evidence) {
      if (
        ev.file_name.toLowerCase().includes(q) ||
        ev.sha256.toLowerCase().includes(q)
      ) {
        hits.push({
          id: `ev-${ev.id}`,
          kind: 'evidence',
          title: ev.file_name,
          subtitle: `SHA-256: ${ev.sha256.slice(0, 18)}... · ${ev.target_type}`,
          badge: 'EVIDENCE',
          targetEntity: { kind: 'evidence', id: ev.id },
          targetModule: 'cyber_incidents',
        });
      }
    }

    return hits.slice(0, 12);
  }, [searchQuery, intel.assets, intel.incidents, intel.evidence]);

  const classColor =
    classification.includes('AMBER')
      ? 'text-(--atlas-amber) border-(--atlas-amber)/40 bg-(--atlas-amber)/10'
      : classification.includes('RESTRICTED') || classification.includes('CONFIDENTIAL')
      ? 'text-(--atlas-red) border-(--atlas-red)/40 bg-(--atlas-red)/10'
      : 'text-(--atlas-green) border-(--atlas-green)/40 bg-(--atlas-green)/10';

  const dbConnected = !intel.error;

  return (
    <header className="h-12 bg-(--atlas-bg-primary) border-b border-(--atlas-border) px-3 flex items-center justify-between gap-3 shrink-0 z-40 select-none">
      {/* Zone 1: Brand Identity + Workspace Switcher */}
      <div className="flex items-center gap-3 min-w-0">
        <button
          onClick={() => onNavigateModule('command_centre')}
          className="flex items-center gap-2 text-left cursor-pointer group shrink-0"
          title="Return to Command Centre"
        >
          <svg
            width="20"
            height="20"
            viewBox="0 0 24 24"
            fill="none"
            className="text-(--atlas-olive-bright) shrink-0"
            aria-hidden="true"
          >
            <polygon
              points="12,2 21,7 21,17 12,22 3,17 3,7"
              stroke="currentColor"
              strokeWidth="1.75"
              style={{ fill: 'var(--atlas-accent-olive)' }}
              fillOpacity="0.16"
            />
            <circle cx="12" cy="12" r="2.75" fill="currentColor" />
            <line x1="12" y1="2" x2="12" y2="9" stroke="currentColor" strokeWidth="1.25" />
            <line x1="21" y1="17" x2="14.4" y2="13.4" stroke="currentColor" strokeWidth="1.25" />
            <line x1="3" y1="17" x2="9.6" y2="13.4" stroke="currentColor" strokeWidth="1.25" />
          </svg>
          <span className="font-semibold tracking-[0.14em] text-xs text-(--atlas-text-primary) whitespace-nowrap">
            PROJECT ATLAS
          </span>
        </button>

        <div className="h-5 w-px bg-(--atlas-border) shrink-0" />

        {/* Active Operational Workspace */}
        <div className="flex items-center gap-1.5 min-w-0">
          <Briefcase className="w-3.5 h-3.5 text-(--atlas-text-secondary) shrink-0" />
          <select
            aria-label="Active Operational Workspace"
            value={activeOrgId}
            onChange={(e) => onSelectOrg(e.target.value)}
            className="bg-(--atlas-bg-secondary) border border-(--atlas-border) hover:border-(--atlas-border-strong) text-(--atlas-text-primary) text-xs px-2 py-1 rounded-[2px] font-medium focus:outline-none focus:border-(--atlas-accent-olive) cursor-pointer max-w-[220px] truncate"
          >
            {memberships.map((m) => {
              const org = m.organization;
              const label = org ? `${org.name} [${org.code}]` : m.org_id.slice(0, 8);
              return (
                <option key={m.org_id} value={m.org_id} className="bg-(--atlas-bg-primary) text-(--atlas-text-primary)">
                  {label}
                </option>
              );
            })}
          </select>
        </div>
      </div>

      {/* Zone 2: Global Intelligence Search */}
      <div ref={searchRef} className="relative flex-1 max-w-md hidden lg:block">
        <div className="relative flex items-center">
          <Search className="w-3.5 h-3.5 text-(--atlas-text-muted) absolute left-2.5 pointer-events-none" />
          <input
            ref={inputRef}
            type="text"
            value={searchQuery}
            onFocus={() => setSearchOpen(true)}
            onChange={(e) => {
              setSearchQuery(e.target.value);
              setSearchOpen(true);
            }}
            placeholder="Search site codes, assets, incidents, IPs, hostnames (Ctrl+K)"
            className="w-full bg-(--atlas-bg-secondary) border border-(--atlas-border) focus:border-(--atlas-accent-olive) rounded-[2px] pl-8 pr-7 py-1 text-xs text-(--atlas-text-primary) placeholder:text-(--atlas-text-muted) font-mono focus:outline-none"
          />
          {searchQuery && (
            <button
              onClick={() => setSearchQuery('')}
              className="absolute right-2 text-(--atlas-text-muted) hover:text-(--atlas-text-primary) cursor-pointer"
              aria-label="Clear global search"
            >
              <X className="w-3 h-3" />
            </button>
          )}
        </div>

        {searchOpen && searchQuery.trim().length > 0 && (
          <div className="absolute left-0 right-0 top-full mt-1 atlas-raised border-(--atlas-border-strong) rounded-[2px] z-50 max-h-80 overflow-y-auto divide-y divide-(--atlas-border-subtle)">
            {searchHits.length === 0 ? (
              <div className="p-3 text-xs font-mono text-(--atlas-text-secondary)">
                No matching authorised records found for "{searchQuery}".
              </div>
            ) : (
              searchHits.map((hit) => (
                <button
                  key={hit.id}
                  onClick={() => {
                    onSelectEntity(hit.targetEntity, hit.targetModule);
                    setSearchOpen(false);
                  }}
                  className="w-full px-3 py-2 text-left hover:bg-(--atlas-bg-elevated) flex items-center justify-between gap-2 cursor-pointer transition-colors"
                >
                  <div className="flex items-center gap-2 min-w-0">
                    {hit.kind === 'asset' && <Server className="w-3.5 h-3.5 text-(--atlas-cyan) shrink-0" />}
                    {hit.kind === 'incident' && <Radio className="w-3.5 h-3.5 text-(--atlas-red) shrink-0" />}
                    {hit.kind === 'evidence' && <FileCheck className="w-3.5 h-3.5 text-(--atlas-olive-bright) shrink-0" />}
                    <div className="min-w-0">
                      <div className="text-xs font-medium text-(--atlas-text-primary) truncate">{hit.title}</div>
                      <div className="text-[11px] font-mono text-(--atlas-text-secondary) truncate">{hit.subtitle}</div>
                    </div>
                  </div>
                  <span className="text-[10px] font-mono text-(--atlas-text-secondary) border border-(--atlas-border) px-1.5 py-0.5 shrink-0">
                    {hit.badge}
                  </span>
                </button>
              ))
            )}
          </div>
        )}
      </div>

      {/* Zone 3: Classification, Health, UTC Time, Alerts, Operator & Controls */}
      <div className="flex items-center gap-2.5 shrink-0">
        {/* Classification Indicator */}
        <button
          onClick={() => onNavigateModule('system_configuration')}
          className={`hidden xl:inline-flex items-center px-2 py-0.5 text-[10px] font-mono font-semibold tracking-wider border rounded-[2px] cursor-pointer whitespace-nowrap ${classColor}`}
          title="Configure classification policy in System Configuration"
        >
          {classification}
        </button>

        {/* Authoritative DB + Crypto Connection Status */}
        <div
          className="hidden md:flex items-center gap-2 px-2 py-1 bg-(--atlas-bg-secondary) border border-(--atlas-border) rounded-[2px] text-[11px] font-mono"
          title={
            dbConnected
              ? `Supabase PostGIS connected · Last sync: ${intel.lastSyncedAt || 'initializing'}`
              : `Database error: ${intel.error}`
          }
        >
          <span
            className={`atlas-led ${dbConnected ? 'text-(--atlas-green)' : 'text-(--atlas-red)'}`}
            data-state={dbConnected ? 'live' : 'error'}
            aria-hidden="true"
          />
          <Database className={`w-3 h-3 ${dbConnected ? 'text-(--atlas-green)' : 'text-(--atlas-red)'}`} />
          <span className={dbConnected ? 'text-(--atlas-green)' : 'text-(--atlas-red)'}>
            {dbConnected ? 'DB:LIVE' : 'DB:ERR'}
          </span>
          <span className="text-(--atlas-border-strong)">·</span>
          <span className={cryptoReady ? 'text-(--atlas-text-secondary)' : 'text-(--atlas-red)'}>
            {cryptoReady ? 'CRYPTO:OK' : 'CRYPTO:UNAVAIL'}
          </span>
          <button
            onClick={() => intel.refreshAll()}
            disabled={intel.isLoading}
            className="text-(--atlas-text-secondary) hover:text-(--atlas-text-primary) cursor-pointer disabled:opacity-50 ml-0.5"
            title="Synchronize workspace data from Supabase"
            aria-label="Refresh workspace intelligence"
          >
            <RefreshCw className={`w-3 h-3 ${intel.isLoading ? 'animate-spin text-(--atlas-olive-bright)' : ''}`} />
          </button>
        </div>

        {/* UTC Clock */}
        <div className="hidden sm:block font-mono text-[11px] text-(--atlas-text-secondary) tabular-nums whitespace-nowrap px-1.5">
          {utcNow}
        </div>

        {/* Notification Centre */}
        <div ref={alertsRef} className="relative">
          <button
            onClick={() => setAlertsOpen((v) => !v)}
            className="relative p-1.5 bg-(--atlas-bg-secondary) hover:bg-(--atlas-bg-elevated) border border-(--atlas-border) rounded-[2px] text-(--atlas-text-secondary) hover:text-(--atlas-text-primary) cursor-pointer transition-colors"
            title="Workspace Intelligence Alerts"
            aria-label="Notification Centre"
          >
            <Bell className="w-3.5 h-3.5" />
            {intel.alerts.length > 0 && (
              <span className="ml-1 font-mono text-[10px] text-(--atlas-amber) font-semibold tabular-nums">
                {intel.alerts.length}
              </span>
            )}
          </button>

          {alertsOpen && (
            <div className="absolute right-0 top-full mt-1 w-96 atlas-raised border-(--atlas-border-strong) rounded-[2px] z-50">
              <div className="px-3 py-2 border-b border-(--atlas-border) flex items-center justify-between">
                <span className="text-xs font-semibold text-(--atlas-text-primary) tabular-nums">
                  Intelligence Alerts ({intel.alerts.length})
                </span>
                <span className="text-[10px] font-mono text-(--atlas-text-secondary)">DERIVED FROM LIVE DB</span>
              </div>
              <div className="max-h-80 overflow-y-auto divide-y divide-(--atlas-border-subtle)">
                {intel.alerts.length === 0 ? (
                  <div className="p-4 text-xs text-(--atlas-text-secondary)">
                    No unresolved intelligence alerts in this workspace.
                  </div>
                ) : (
                  intel.alerts.slice(0, 20).map((alert) => (
                    <button
                      key={alert.id}
                      onClick={() => {
                        onSelectEntity(
                          { kind: alert.targetKind, id: alert.targetId },
                          alert.targetKind === 'incident' ? 'cyber_incidents' : 'command_centre'
                        );
                        setAlertsOpen(false);
                      }}
                      className="w-full px-3 py-2 text-left hover:bg-(--atlas-bg-elevated) flex items-start gap-2 cursor-pointer transition-colors"
                    >
                      <AlertTriangle
                        className={`w-3.5 h-3.5 shrink-0 mt-0.5 ${
                          alert.severity === 'critical'
                            ? 'text-(--atlas-red)'
                            : alert.severity === 'high'
                            ? 'text-(--atlas-amber)'
                            : 'text-(--atlas-cyan)'
                        }`}
                      />
                      <div className="min-w-0 flex-1">
                        <div className="text-xs font-medium text-(--atlas-text-primary) truncate">{alert.title}</div>
                        <div className="text-[11px] font-mono text-(--atlas-text-secondary) truncate">{alert.detail}</div>
                        <div className="text-[10px] font-mono text-(--atlas-text-muted) tabular-nums mt-0.5">
                          {new Date(alert.timestamp).toISOString().replace('T', ' ').slice(0, 19)} UTC
                        </div>
                      </div>
                    </button>
                  ))
                )}
              </div>
            </div>
          )}
        </div>

        {/* Authenticated User & Role */}
        <div className="hidden md:flex items-center gap-1.5 px-2 py-1 bg-(--atlas-bg-secondary) border border-(--atlas-border) rounded-[2px] text-[11px] font-mono">
          <User className="w-3 h-3 text-(--atlas-text-secondary)" />
          <span className="text-(--atlas-text-primary) max-w-[130px] truncate" title={userEmail}>
            {userEmail}
          </span>
          <span className="text-(--atlas-border-strong)">·</span>
          <span className="text-(--atlas-olive-bright)">{activeRole}</span>
          <span className="text-(--atlas-border-strong)">·</span>
          <span title="AAL2 MFA Verified" className="inline-flex items-center">
            <ShieldCheck className="w-3 h-3 text-(--atlas-green)" />
          </span>
        </div>

        {/* Settings */}
        <button
          onClick={() => onNavigateModule('system_configuration')}
          className="p-1.5 bg-(--atlas-bg-secondary) hover:bg-(--atlas-bg-elevated) border border-(--atlas-border) rounded-[2px] text-(--atlas-text-secondary) hover:text-(--atlas-text-primary) cursor-pointer transition-colors"
          title="System Configuration & Policy Settings"
          aria-label="Settings"
        >
          <Settings className="w-3.5 h-3.5" />
        </button>

        {/* Sign Out */}
        <button
          onClick={onSignOut}
          className="px-2 py-1 bg-(--atlas-bg-secondary) hover:bg-(--atlas-red-tint) border border-(--atlas-border) hover:border-(--atlas-red)/60 rounded-[2px] text-(--atlas-text-secondary) hover:text-(--atlas-text-primary) text-[11px] font-mono cursor-pointer transition-colors flex items-center gap-1 whitespace-nowrap"
          title="Sign Out of Project ATLAS"
        >
          <LogOut className="w-3 h-3" />
          <span className="hidden xl:inline">Sign Out</span>
        </button>
      </div>
    </header>
  );
};

function formatUtcNow(): string {
  const iso = new Date().toISOString();
  return `${iso.slice(0, 10)} ${iso.slice(11, 19)} UTC`;
}
