/**
 * Project ATLAS — Module A: Hybrid Defensive Intelligence Terminal Engine
 *
 * Implements:
 * 1. Expanded ATLAS-native command interpreter across Workspace, Assets, Incidents,
 *    Threat Intelligence, Geospatial Analysis, Infrastructure Resilience, Investigation,
 *    and Markdown Report Generation.
 * 2. Policy enforcement integration via `terminalPolicy.ts`.
 * 3. Deterministic correlation of external Linux Gateway results (Nmap, TShark) back
 *    into ATLAS infrastructure, incidents, dependencies, CTI, and coordinates.
 */

import type {
  AppRole,
  Asset,
  AtlasTerminalCorrelation,
  AttributionRecord,
  ExternalThreatIndicator,
  GatewayHealthSnapshot,
  GatewayJobRecord,
  Incident,
  NmapParsedResult,
  RemoteTerminalAdapter,
  TerminalCommandResult,
  TerminalOutputLine,
  TsharkParsedResult,
} from '../types/atlas';
import type { WorkspaceIntelligenceState } from '../hooks/useWorkspaceIntelligence';
import { evaluateCommandPolicy, parseTerminalInput } from './terminalPolicy';
import {
  analyzeBufferZone,
  computeProximityRankings,
  computeSpatialClusters,
} from '../utils/geospatialAnalysis';
import {
  analyzeInfrastructureResilience,
  simulateNodeFailureCascade,
} from '../utils/resilience';
import { CTI_ADAPTER_CATALOG } from './ctiAdapters';

export const REMOTE_TERMINAL_ADAPTERS: RemoteTerminalAdapter[] = [
  {
    id: 'linux_exec_gateway',
    label: 'Isolated Linux Security Worker Gateway',
    protocol: 'HTTPS_JWT_EXEC_GATEWAY',
    status: 'awaiting_authorised_connection',
    requiredConfiguration:
      'Optional external Linux container gateway (`/gateway`). Configure HTTPS/localhost endpoint and verify AAL2 JWT.',
  },
  {
    id: 'passive_dns_proxy',
    label: 'Authorised DNS / Threat Reputation HTTPS Proxy',
    protocol: 'HTTPS_READONLY_GATEWAY',
    status: 'not_configured',
    requiredConfiguration: 'Requires backend proxy holding DNS/WHOIS/VirusTotal/GreyNoise credentials.',
  },
];

export interface TerminalExecutionContext {
  externalIndicators?: ExternalThreatIndicator[];
  attributionRecords?: AttributionRecord[];
  userEmail?: string;
  userRole?: AppRole;
  commandHistory?: string[];
  gatewayHealth?: GatewayHealthSnapshot;
  gatewayJobs?: GatewayJobRecord[];
}

function findAssetByToken(assets: Asset[], token: string): Asset | undefined {
  const q = token.trim().toLowerCase();
  return assets.find(
    (a) =>
      a.id.toLowerCase() === q ||
      a.site_code.toLowerCase() === q ||
      a.name.toLowerCase() === q
  );
}

function findIncidentByToken(incidents: Incident[], token: string): Incident | undefined {
  const q = token.trim().toLowerCase();
  return incidents.find(
    (i) => i.event_id.toLowerCase() === q || i.id.toLowerCase() === q
  );
}

/**
 * Correlates Nmap XML/parsed output against ATLAS assets, incidents, CTI, and topology
 * without automatically creating authoritative assets or verified attribution.
 */
export function correlateNmapWithAtlas(
  nmap: NmapParsedResult,
  intel: WorkspaceIntelligenceState,
  externalIndicators: ExternalThreatIndicator[] = []
): AtlasTerminalCorrelation {
  const matchedAssetSet = new Set<string>();
  const matchedIncidentSet = new Set<string>();
  const matchedCtiSet = new Set<string>();
  const unmatchedIps: string[] = [];
  const notes: string[] = [];

  for (const host of nmap.hosts) {
    const ip = host.ip.trim();
    const hostname = (host.hostname || '').trim().toLowerCase();

    const assetHits = intel.assets.filter((a) => {
      const ips = (a.identifiers?.ip_addresses || []).map((x) => x.toLowerCase());
      const hosts = (a.identifiers?.hostnames || []).map((x) => x.toLowerCase());
      return ips.includes(ip.toLowerCase()) || (hostname && hosts.includes(hostname));
    });

    if (assetHits.length > 0) {
      assetHits.forEach((a) => matchedAssetSet.add(a.id));
    } else if (host.state === 'up') {
      unmatchedIps.push(ip);
    }

    for (const inc of intel.incidents) {
      const sigStr = JSON.stringify(inc.signals || {}).toLowerCase();
      if (sigStr.includes(ip.toLowerCase()) || (hostname && sigStr.includes(hostname))) {
        matchedIncidentSet.add(inc.id);
      }
    }

    for (const cti of externalIndicators) {
      const val = cti.value.toLowerCase();
      if (val === ip.toLowerCase() || (hostname && val === hostname)) {
        matchedCtiSet.add(cti.value);
      }
    }
  }

  let downstreamAssetCount = 0;
  if (matchedAssetSet.size > 0) {
    const sim = simulateNodeFailureCascade(
      Array.from(matchedAssetSet),
      intel.assets,
      intel.edges,
      intel.matches
    );
    downstreamAssetCount = sim.totalCascadingOutageCount;
  }

  if (unmatchedIps.length > 0) {
    notes.push(
      `${unmatchedIps.length} live host(s) not registered in ATLAS assets (${unmatchedIps.slice(0, 5).join(', ')}). Network reachability does NOT prove organisational ownership — suggest manual asset review.`
    );
  }
  if (matchedAssetSet.size > 0 && nmap.openPortsCount > 0) {
    notes.push(
      `${matchedAssetSet.size} registered asset(s) observed with ${nmap.openPortsCount} open TCP port(s); ${downstreamAssetCount} downstream dependent asset(s) reachable along dependency edges.`
    );
  }

  return {
    sourceTool: 'nmap',
    collectedAtUtc: nmap.startedAtUtc,
    matchedAssetIds: Array.from(matchedAssetSet),
    unmatchedObservedIps: unmatchedIps,
    matchedIncidentIds: Array.from(matchedIncidentSet),
    matchedCtiValues: Array.from(matchedCtiSet),
    downstreamAssetCount,
    notes,
    provenanceNote:
      'UNVERIFIED EXTERNAL SCAN OBSERVATION — Nmap discovery preserves gateway collection provenance only; requires operator verification before asset registration or attribution.',
  };
}

/**
 * Correlates offline TShark PCAP findings (IPs, DNS queries) against ATLAS assets, incidents, and CTI.
 */
export function correlateTsharkWithAtlas(
  tshark: TsharkParsedResult,
  intel: WorkspaceIntelligenceState,
  externalIndicators: ExternalThreatIndicator[] = []
): AtlasTerminalCorrelation {
  const matchedAssetSet = new Set<string>();
  const matchedIncidentSet = new Set<string>();
  const matchedCtiSet = new Set<string>();
  const unmatchedIps: string[] = [];
  const notes: string[] = [];

  for (const ip of tshark.uniqueIps) {
    const lowerIp = ip.toLowerCase();
    const aHits = intel.assets.filter((a) =>
      (a.identifiers?.ip_addresses || []).some((x) => x.toLowerCase() === lowerIp)
    );
    if (aHits.length > 0) {
      aHits.forEach((a) => matchedAssetSet.add(a.id));
    } else {
      unmatchedIps.push(ip);
    }

    intel.incidents.forEach((inc) => {
      if (JSON.stringify(inc.signals || {}).toLowerCase().includes(lowerIp)) {
        matchedIncidentSet.add(inc.id);
      }
    });

    externalIndicators.forEach((cti) => {
      if (cti.value.toLowerCase() === lowerIp) matchedCtiSet.add(cti.value);
    });
  }

  for (const dns of tshark.dnsQueries) {
    const q = dns.query.toLowerCase();
    intel.assets.forEach((a) => {
      if ((a.identifiers?.hostnames || []).some((h) => h.toLowerCase() === q)) {
        matchedAssetSet.add(a.id);
      }
    });
    intel.incidents.forEach((inc) => {
      if (JSON.stringify(inc.signals || {}).toLowerCase().includes(q)) {
        matchedIncidentSet.add(inc.id);
      }
    });
    externalIndicators.forEach((cti) => {
      if (cti.value.toLowerCase() === q) matchedCtiSet.add(cti.value);
    });
  }

  let downstreamAssetCount = 0;
  if (matchedAssetSet.size > 0) {
    downstreamAssetCount = simulateNodeFailureCascade(
      Array.from(matchedAssetSet),
      intel.assets,
      intel.edges,
      intel.matches
    ).totalCascadingOutageCount;
  }

  if (matchedCtiSet.size > 0) {
    notes.push(`PCAP indicators overlapped with ${matchedCtiSet.size} unverified external CTI indicator(s).`);
  }
  if (matchedIncidentSet.size > 0) {
    notes.push(`PCAP traffic correlates with ${matchedIncidentSet.size} existing ATLAS incident(s).`);
  }
  if (unmatchedIps.length > 0) {
    notes.push(`${unmatchedIps.length} communicating IP(s) in capture are external/unregistered in workspace assets.`);
  }

  return {
    sourceTool: 'tshark',
    collectedAtUtc: new Date().toISOString(),
    matchedAssetIds: Array.from(matchedAssetSet),
    unmatchedObservedIps: unmatchedIps.slice(0, 25),
    matchedIncidentIds: Array.from(matchedIncidentSet),
    matchedCtiValues: Array.from(matchedCtiSet),
    downstreamAssetCount,
    notes,
    provenanceNote:
      'OFFLINE PCAP ANALYSIS — Indicators extracted from packet capture require corroboration; traffic presence alone is not verified attribution.',
  };
}

export function executeDefensiveTerminalCommand(
  rawCommand: string,
  intel: WorkspaceIntelligenceState,
  externalIndicators: ExternalThreatIndicator[] = [],
  attributionRecords: AttributionRecord[] = [],
  ctx: TerminalExecutionContext = {}
): TerminalCommandResult {
  const startedMs = Date.now();
  const cmd = rawCommand.trim();
  const timestampUtc = new Date().toISOString().slice(11, 19) + ' UTC';
  const id = `term-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
  const userRole: AppRole = ctx.userRole || 'atlas:analyst';

  if (!cmd) {
    return {
      id,
      command: cmd,
      environment: 'atlas_native',
      timestampUtc,
      scopeLabel: 'READ-ONLY ATLAS QUERY ENGINE',
      status: 'ok',
      durationMs: 0,
      lines: [{ text: 'Enter `help` to list authorised ATLAS-native cybersecurity commands.', tone: 'muted' }],
    };
  }

  // Run structured policy evaluation first (fail closed on chaining, offensive tools, or wrong env)
  const policyEval = evaluateCommandPolicy(cmd, 'atlas_native', userRole);
  if (!policyEval.allowed) {
    const isRejected = policyEval.riskLevel === 'RESTRICTED';
    return {
      id,
      command: cmd,
      environment: 'atlas_native',
      policyId: policyEval.policy?.id,
      riskLevel: policyEval.riskLevel,
      timestampUtc,
      scopeLabel: 'SECURITY POLICY GUARD',
      status: isRejected ? 'rejected' : 'blocked_by_policy',
      durationMs: Date.now() - startedMs,
      lines: [
        {
          text: policyEval.reason || 'Command rejected by security policy.',
          tone: 'err',
        },
        {
          text: 'Type `help` for structured ATLAS commands or switch to LINUX SECURITY WORKER for gateway tools.',
          tone: 'muted',
        },
      ],
    };
  }

  const parsed = parseTerminalInput(cmd);
  const { verb, subcommand, tokens } = parsed;
  const arg = tokens.slice(1).join(' ').trim();
  const lowerArg = arg.toLowerCase();
  const thirdArg = (tokens[2] || '').trim();
  const gatewayJobs = ctx.gatewayJobs || [];

  const finish = (
    scopeLabel: string,
    lines: TerminalOutputLine[],
    opts: Partial<TerminalCommandResult> = {}
  ): TerminalCommandResult => ({
    id,
    command: cmd,
    environment: 'atlas_native',
    policyId: policyEval.policy?.id,
    riskLevel: policyEval.riskLevel,
    timestampUtc,
    scopeLabel,
    status: opts.status || 'ok',
    durationMs: Date.now() - startedMs,
    exportReportMarkdown: opts.exportReportMarkdown,
    correlation: opts.correlation,
    lines,
  });

  // -------------------------------------------------------------------------
  // WORKSPACE COMMANDS
  // -------------------------------------------------------------------------
  if (verb === 'help' || verb === '?') {
    return finish('ATLAS-NATIVE COMMAND REFERENCE', [
      { text: 'WORKSPACE:        help | status | workspace | whoami | history | clear', tone: 'accent' },
      { text: 'ASSETS:           assets | assets search <q> | asset inspect|dependencies|exposure <id>', tone: 'normal' },
      { text: 'INCIDENTS:        incidents [severity] | incidents critical | incident inspect|timeline|assets <event_id>', tone: 'normal' },
      { text: 'THREAT INTEL:     ioc <value> | ioc search <val> | cti status|expired|provider <id> | threat correlate <val>', tone: 'normal' },
      { text: 'ATTRIBUTION/DNS:  attribution <term> | dns <domain> | rep <indicator> | netflow | blast <event_id>', tone: 'normal' },
      { text: 'GEOSPATIAL:       geo locate <id> | geo nearby <id> [km] | geo exposure <id> | geo cluster | geo blast-radius <evt>', tone: 'normal' },
      { text: 'RESILIENCE:       resilience assess <id> | resilience dependencies <id> | resilience simulate <id>', tone: 'normal' },
      { text: 'REPORTS/JOBS:     investigation open <evt> | investigation correlate <val> | report incident|network|resilience <id>', tone: 'normal' },
      { text: 'NETWORK/GATEWAY:  network status | network scan status <job_id> | network scan results <job_id>', tone: 'normal' },
      { text: 'LINUX WORKER ENV: nmap --help | nmap -sn <target> | nmap -sV -p <ports> <target> | pcap summary|dns|conversations <file> | sysinfo | interfaces | processes | services | disk | memory | py_analyze', tone: 'muted' },
    ]);
  }

  if (verb === 'status') {
    const crits = intel.incidents.filter((i) => i.severity === 'critical').length;
    const proposed = intel.matches.filter((m) => m.status === 'proposed').length;
    const approx = intel.assets.filter((a) => a.accuracy_class !== 'exact_survey').length;
    const head = intel.auditEvents[0];
    const gwState = ctx.gatewayHealth?.state || 'NOT_CONFIGURED';
    return finish(`ORG:${intel.orgId.slice(0, 8)}`, [
      { text: `Workspace ID: ${intel.orgId}`, tone: 'accent' },
      {
        text: `Assets: ${intel.assets.length} (${approx} approximate) | Edges: ${intel.edges.length} | Evidence: ${intel.evidence.length}`,
        tone: 'normal',
      },
      {
        text: `Incidents: ${intel.incidents.length} (${crits} CRITICAL) | Matches: ${intel.matches.length} (${proposed} PROPOSED REVIEW)`,
        tone: crits > 0 || proposed > 0 ? 'warn' : 'ok',
      },
      {
        text: `Audit Ledger Head: ${head ? `seq #${head.seq} (${head.record_hash.slice(0, 14)}...)` : 'NONE'} | External CTI: ${externalIndicators.length} | Attribution Drafts: ${attributionRecords.length}`,
        tone: 'normal',
      },
      {
        text: `Linux Execution Gateway: ${gwState} | Gateway Jobs (Session): ${gatewayJobs.length}`,
        tone: gwState === 'READY' ? 'ok' : 'muted',
      },
    ]);
  }

  if (verb === 'workspace') {
    const calStatuses = Array.from(new Set(intel.scoringConfig.map((s) => s.calibration_status))).join(', ') || 'UNCALIBRATED';
    return finish('WORKSPACE CONTEXT', [
      { text: `AUTHORISED WORKSPACE SUMMARY (${intel.orgId})`, tone: 'accent' },
      { text: `  Datasets Registered: ${intel.datasets.length} | Org Memberships Visible: ${intel.orgMemberships.length}`, tone: 'normal' },
      { text: `  Scoring Config Entries: ${intel.scoringConfig.length} (Calibration: ${calStatuses})`, tone: 'warn' },
      { text: `  Mapped Coordinates (EPSG:4326): ${intel.assetCoordsMap.size}/${intel.assets.length} assets`, tone: 'normal' },
      { text: `  Last DB Sync (UTC): ${intel.lastSyncedAt || 'NOT_SYNCED'}`, tone: 'muted' },
    ]);
  }

  if (verb === 'whoami') {
    return finish('OPERATOR IDENTITY', [
      { text: `OPERATOR: ${ctx.userEmail || '(authenticated AAL2 session)'}`, tone: 'accent' },
      { text: `ROLE: ${userRole} | MFA ASSURANCE: AAL2 REQUIRED BY RLS`, tone: 'ok' },
      { text: `ACTIVE ORGANISATION: ${intel.orgId}`, tone: 'normal' },
      { text: `NOTE: Role and organisation membership are verified by Supabase RLS; client state cannot elevate permissions.`, tone: 'muted' },
    ]);
  }

  if (verb === 'history') {
    const hist = ctx.commandHistory || [];
    if (hist.length === 0) {
      return finish('COMMAND HISTORY', [{ text: 'No commands recorded in current workspace history.', tone: 'muted' }]);
    }
    return finish(
      'COMMAND HISTORY',
      [
        { text: `RECENT TERMINAL COMMANDS (${hist.length}):`, tone: 'accent' },
        ...hist.slice(0, 20).map((c, idx) => ({
          text: `  ${String(idx + 1).padStart(2, ' ')}. ${c}`,
          tone: 'normal' as const,
        })),
      ]
    );
  }

  if (verb === 'clear') {
    return finish('UI ACTION', [{ text: 'Terminal scrollback clear requested.', tone: 'muted' }]);
  }

  // -------------------------------------------------------------------------
  // ASSETS COMMANDS
  // -------------------------------------------------------------------------
  if (verb === 'assets') {
    const searchQ = subcommand === 'search' ? tokens.slice(2).join(' ').trim().toLowerCase() : lowerArg;
    const filtered = intel.assets.filter(
      (a) =>
        !searchQ ||
        `${a.site_code} ${a.name} ${a.type} ${a.owner} ${JSON.stringify(a.identifiers || {})}`
          .toLowerCase()
          .includes(searchQ)
    );
    const lines: TerminalOutputLine[] = [
      { text: `Matched ${filtered.length} infrastructure asset(s):`, tone: 'accent' },
    ];
    filtered.slice(0, 15).forEach((a) => {
      lines.push({
        text: `  ${a.site_code} | T${a.criticality} | ${a.type} | ${a.name} [${a.accuracy_class}]`,
        tone: 'normal',
        entityRef: { kind: 'asset', id: a.id },
      });
    });
    if (filtered.length === 0) lines.push({ text: '  No assets matched filter.', tone: 'muted' });
    return finish('SUPABASE assets', lines);
  }

  if (verb === 'asset') {
    if (!thirdArg) {
      return finish('USAGE', [{ text: `Usage: asset ${subcommand} <asset_id|site_code>`, tone: 'warn' }]);
    }
    const asset = findAssetByToken(intel.assets, thirdArg);
    if (!asset) {
      return finish('ASSET LOOKUP', [{ text: `Asset "${thirdArg}" not found in active workspace.`, tone: 'warn' }]);
    }

    if (subcommand === 'inspect') {
      const coord = intel.assetCoordsMap.get(asset.id);
      const links = intel.matches.filter((m) => m.asset_id === asset.id && m.status !== 'rejected');
      return finish('ASSET PROFILE', [
        { text: `ASSET ${asset.site_code} — ${asset.name}`, tone: 'accent', entityRef: { kind: 'asset', id: asset.id } },
        { text: `  ID: ${asset.id} | Type: ${asset.type} | Criticality: Tier ${asset.criticality}`, tone: 'normal' },
        { text: `  Owner: ${asset.owner} | Precision: ${asset.accuracy_class} | Confidence: ${(Number(asset.confidence) * 100).toFixed(0)}%`, tone: 'normal' },
        { text: `  Coordinates (EPSG:4326): ${coord ? `${coord[1].toFixed(5)}, ${coord[0].toFixed(5)}` : 'No mapped coordinate'}`, tone: 'normal' },
        { text: `  IPs: ${(asset.identifiers?.ip_addresses || []).join(', ') || 'none'} | CIDRs: ${(asset.identifiers?.cidrs || []).join(', ') || 'none'}`, tone: 'normal' },
        { text: `  Hostnames: ${(asset.identifiers?.hostnames || []).join(', ') || 'none'} | Active Matches: ${links.length}`, tone: links.length > 0 ? 'warn' : 'ok' },
      ]);
    }

    if (subcommand === 'dependencies') {
      const upstream = intel.edges.filter((e) => e.to_asset_id === asset.id);
      const downstream = intel.edges.filter((e) => e.from_asset_id === asset.id);
      const lines: TerminalOutputLine[] = [
        { text: `DEPENDENCY TOPOLOGY FOR ${asset.site_code} (${asset.name}):`, tone: 'accent', entityRef: { kind: 'asset', id: asset.id } },
        { text: `  UPSTREAM PROVIDERS (${upstream.length}):`, tone: 'muted' },
      ];
      upstream.forEach((e) => {
        const src = intel.assets.find((a) => a.id === e.from_asset_id);
        lines.push({
          text: `    <- ${src?.site_code || e.from_asset_id} [${e.relation_type}, T${e.criticality}]`,
          tone: 'normal',
          entityRef: src ? { kind: 'asset', id: src.id } : undefined,
        });
      });
      lines.push({ text: `  DOWNSTREAM DEPENDENTS (${downstream.length}):`, tone: 'muted' });
      downstream.forEach((e) => {
        const dst = intel.assets.find((a) => a.id === e.to_asset_id);
        lines.push({
          text: `    -> ${dst?.site_code || e.to_asset_id} [${e.relation_type}, T${e.criticality}]`,
          tone: 'normal',
          entityRef: dst ? { kind: 'asset', id: dst.id } : undefined,
        });
      });
      return finish('DEPENDENCY TOPOLOGY', lines);
    }

    if (subcommand === 'exposure') {
      const links = intel.matches.filter((m) => m.asset_id === asset.id && m.status !== 'rejected');
      const assetIps = (asset.identifiers?.ip_addresses || []).map((x) => x.toLowerCase());
      const assetHosts = (asset.identifiers?.hostnames || []).map((x) => x.toLowerCase());
      const ctiHits = externalIndicators.filter(
        (c) => assetIps.includes(c.value.toLowerCase()) || assetHosts.includes(c.value.toLowerCase())
      );
      const profile = analyzeInfrastructureResilience(
        intel.assets,
        intel.edges,
        intel.assetCoordsMap,
        intel.matches
      ).find((p) => p.assetId === asset.id);

      const lines: TerminalOutputLine[] = [
        { text: `EXPOSURE PROFILE: ${asset.site_code} (${asset.name})`, tone: 'accent', entityRef: { kind: 'asset', id: asset.id } },
        { text: `  Linked Incidents (${links.length}): ${links.map((m) => `${m.incident_id.slice(0, 8)}[${m.status}]`).join(', ') || 'None'}`, tone: links.length > 0 ? 'warn' : 'ok' },
        { text: `  Unverified External CTI Overlaps: ${ctiHits.length}`, tone: ctiHits.length > 0 ? 'warn' : 'normal' },
        {
          text: `  Resilience Heuristic Score: ${profile ? `${profile.structuralVulnerabilityScore}/100` : 'N/A'} | SPOF: ${profile?.isSinglePointOfFailure ? `YES (${profile.spofReason})` : 'NO'}`,
          tone: profile?.isSinglePointOfFailure ? 'warn' : 'normal',
        },
        { text: `  Backup / Recovery Status: NO_VERIFIED_DATA (not tracked in locked schema)`, tone: 'muted' },
      ];
      return finish('ASSET EXPOSURE', lines);
    }
  }

  // -------------------------------------------------------------------------
  // INCIDENTS COMMANDS
  // -------------------------------------------------------------------------
  if (verb === 'incidents') {
    const filterSev = lowerArg;
    const filtered = intel.incidents.filter((i) => !filterSev || i.severity.toLowerCase() === filterSev);
    const lines: TerminalOutputLine[] = [
      { text: `Matched ${filtered.length} incident(s)${filterSev ? ` (severity=${filterSev})` : ''}:`, tone: 'accent' },
    ];
    filtered.slice(0, 15).forEach((i) => {
      lines.push({
        text: `  [${i.severity.toUpperCase()}] ${i.event_id} · ${i.event_type} · ${i.observed_at.slice(0, 19)}Z`,
        tone: i.severity === 'critical' ? 'err' : i.severity === 'high' ? 'warn' : 'normal',
        entityRef: { kind: 'incident', id: i.id },
      });
    });
    if (filtered.length === 0) lines.push({ text: '  No matching incidents in workspace.', tone: 'muted' });
    return finish('SUPABASE incidents', lines);
  }

  if (verb === 'incident') {
    if (!thirdArg) {
      return finish('USAGE', [{ text: `Usage: incident ${subcommand} <event_id>`, tone: 'warn' }]);
    }
    const inc = findIncidentByToken(intel.incidents, thirdArg);
    if (!inc) {
      return finish('INCIDENT LOOKUP', [{ text: `Incident "${thirdArg}" not found in workspace.`, tone: 'warn' }]);
    }

    if (subcommand === 'inspect') {
      const matches = intel.matches.filter((m) => m.incident_id === inc.id);
      const evCount = intel.evidence.filter((e) => e.target_id === inc.id).length;
      return finish('INCIDENT PROFILE', [
        { text: `INCIDENT ${inc.event_id} (${inc.severity.toUpperCase()})`, tone: inc.severity === 'critical' ? 'err' : 'accent', entityRef: { kind: 'incident', id: inc.id } },
        { text: `  Type: ${inc.event_type} | Source: ${inc.source} | Confidence: ${(Number(inc.confidence) * 100).toFixed(0)}%`, tone: 'normal' },
        { text: `  Observed UTC: ${inc.observed_at} | Correlation ID: ${inc.correlation_id}`, tone: 'normal' },
        { text: `  Signals: ${JSON.stringify(inc.signals || {})}`, tone: 'normal' },
        { text: `  Asset Matches: ${matches.length} | Sealed Evidence Objects: ${evCount}`, tone: matches.length > 0 ? 'warn' : 'muted' },
      ]);
    }

    if (subcommand === 'timeline') {
      const audits = intel.auditEvents.filter((a) => a.target_id === inc.id || a.correlation_id === inc.correlation_id);
      const evs = intel.evidence.filter((e) => e.target_id === inc.id);
      const lines: TerminalOutputLine[] = [
        { text: `INCIDENT TIMELINE SUMMARY FOR ${inc.event_id}:`, tone: 'accent', entityRef: { kind: 'incident', id: inc.id } },
        { text: `  • ${inc.observed_at.slice(0, 19)}Z [OBSERVED] Incident ${inc.event_id} generated by ${inc.source}`, tone: 'normal' },
        { text: `  • ${inc.created_at.slice(0, 19)}Z [INGESTED] Recorded in public.incidents`, tone: 'normal' },
      ];
      audits.slice(0, 8).forEach((a) => {
        lines.push({
          text: `  • ${a.timestamp.slice(0, 19)}Z [AUDIT #${a.seq}] ${a.action} (${a.actor_role}) hash:${a.record_hash.slice(0, 10)}`,
          tone: 'ok',
        });
      });
      evs.forEach((e) => {
        lines.push({
          text: `  • ${e.created_at.slice(0, 19)}Z [EVIDENCE] ${e.file_name} SHA256:${e.sha256.slice(0, 12)}...`,
          tone: 'accent',
          entityRef: { kind: 'evidence', id: e.id },
        });
      });
      return finish('INCIDENT TIMELINE', lines);
    }

    if (subcommand === 'assets') {
      const matches = intel.matches.filter((m) => m.incident_id === inc.id);
      const lines: TerminalOutputLine[] = [
        { text: `ASSET MATCHES FOR ${inc.event_id} (${matches.length}):`, tone: 'accent', entityRef: { kind: 'incident', id: inc.id } },
      ];
      matches.forEach((m) => {
        const a = m.asset || intel.assets.find((x) => x.id === m.asset_id);
        lines.push({
          text: `  • ${a?.site_code || m.asset_id} (${a?.name || 'unknown'}) | rule=${m.rule_fired} | score=${(Number(m.score) * 100).toFixed(0)}% | status=${m.status.toUpperCase()}`,
          tone: m.status === 'confirmed' || m.status === 'auto' ? 'ok' : m.status === 'proposed' ? 'warn' : 'muted',
          entityRef: { kind: 'asset', id: m.asset_id },
        });
      });
      if (matches.length === 0) lines.push({ text: '  No asset matches recorded.', tone: 'muted' });
      return finish('INCIDENT ASSETS', lines);
    }
  }

  // -------------------------------------------------------------------------
  // THREAT INTEL, IOC, CTI, ATTRIBUTION, DNS/REP
  // -------------------------------------------------------------------------
  if (verb === 'ioc' || verb === 'rep' || verb === 'dns' || (verb === 'threat' && subcommand === 'correlate')) {
    const rawTerm =
      verb === 'threat'
        ? tokens.slice(2).join(' ').trim()
        : verb === 'ioc' && subcommand === 'search'
        ? tokens.slice(2).join(' ').trim()
        : arg;
    const term = rawTerm.toLowerCase();
    if (!term) {
      return finish('INPUT REQUIRED', [{ text: `Usage: ${verb} <ip|cidr|domain|hostname|cve|site_code>`, tone: 'warn' }], {
        status: 'ok',
      });
    }

    const assetHits = intel.assets.filter((a) =>
      `${a.site_code} ${JSON.stringify(a.identifiers || {})}`.toLowerCase().includes(term)
    );
    const incHits = intel.incidents.filter((i) =>
      `${i.event_id} ${JSON.stringify(i.signals || {})}`.toLowerCase().includes(term)
    );
    const ctiHits = externalIndicators.filter((c) => `${c.value} ${c.rawSummary}`.toLowerCase().includes(term));
    const attrHits = attributionRecords.filter((r) =>
      `${r.indicatorValue} ${r.entityLabel}`.toLowerCase().includes(term)
    );
    const matchedEdges = intel.edges.filter((e) =>
      assetHits.some((a) => a.id === e.from_asset_id || a.id === e.to_asset_id)
    );

    const lines: TerminalOutputLine[] = [
      { text: `LOOKUP RESULT FOR INDICATOR: "${rawTerm}"`, tone: 'accent' },
      {
        text: `  ATLAS Assets: ${assetHits.length} | ATLAS Incidents: ${incHits.length} | External CTI: ${ctiHits.length} | Attribution Links: ${attrHits.length} | Topology Edges: ${matchedEdges.length}`,
        tone: 'normal',
      },
    ];
    assetHits.slice(0, 6).forEach((a) =>
      lines.push({
        text: `  [ASSET] ${a.site_code} — ${a.name} (T${a.criticality})`,
        tone: 'ok',
        entityRef: { kind: 'asset', id: a.id },
      })
    );
    incHits.slice(0, 6).forEach((i) =>
      lines.push({
        text: `  [INCIDENT] ${i.event_id} (${i.severity.toUpperCase()})`,
        tone: 'warn',
        entityRef: { kind: 'incident', id: i.id },
      })
    );
    ctiHits.slice(0, 5).forEach((c) =>
      lines.push({
        text: `  [EXTERNAL CTI:${c.providerId}] ${c.value} (${c.verificationStatus.toUpperCase()}${c.isExpired ? ', EXPIRED' : ''})`,
        tone: 'warn',
      })
    );
    attrHits.slice(0, 4).forEach((r) =>
      lines.push({
        text: `  [ATTRIBUTION DRAFT:${r.attributionClass.toUpperCase()}] ${r.indicatorValue} -> ${r.entityLabel} (${(r.confidence * 100).toFixed(0)}%, LOCAL DRAFT — NON-AUTHORITATIVE)`,
        tone: 'warn',
        entityRef: r.incidentId
          ? { kind: 'incident', id: r.incidentId }
          : r.assetId
          ? { kind: 'asset', id: r.assetId }
          : undefined,
      })
    );

    if (verb === 'dns' || verb === 'rep') {
      lines.push({
        text: `EXTERNAL ${verb.toUpperCase()} ENRICHMENT ADAPTER: NOT CONFIGURED — No external DNS/reputation API proxy is connected in locked mode.`,
        tone: 'muted',
      });
    }

    return finish('IOC CROSS-REFERENCE', lines);
  }

  if (verb === 'cti') {
    if (subcommand === 'status') {
      const expiredCount = externalIndicators.filter((i) => i.isExpired).length;
      const triagedCount = externalIndicators.filter((i) => i.verificationStatus === 'verified_by_analyst').length;
      const lines: TerminalOutputLine[] = [
        { text: `THREAT INTELLIGENCE ADAPTER STATUS (${externalIndicators.length} local cached indicators):`, tone: 'accent' },
        { text: `  Expired: ${expiredCount} | Locally Reviewed: ${triagedCount} | Unverified: ${externalIndicators.length - triagedCount}`, tone: expiredCount > 0 ? 'warn' : 'normal' },
      ];
      CTI_ADAPTER_CATALOG.forEach((adp) => {
        const count = externalIndicators.filter((i) => i.providerId === adp.id).length;
        const statusLabel = adp.requiresServerProxy
          ? `GATEWAY PROXY (${adp.proxyEndpoint || '/api/v1/cti/indicators'})`
          : adp.status.toUpperCase();
        lines.push({
          text: `  • ${adp.id} [${statusLabel}] — ${count} staged record(s)`,
          tone: adp.status === 'local_bundle_ready' ? 'ok' : 'normal',
        });
      });
      return finish('CTI STATUS', lines);
    }

    if (subcommand === 'expired') {
      const exp = externalIndicators.filter((i) => i.isExpired);
      const lines: TerminalOutputLine[] = [
        { text: `EXPIRED EXTERNAL CTI INDICATORS (${exp.length}):`, tone: 'accent' },
      ];
      exp.slice(0, 15).forEach((i) => {
        lines.push({
          text: `  [EXPIRED] ${i.providerId} | ${i.indicatorType.toUpperCase()} ${i.value} | valid_until=${i.validUntil || 'unknown'}`,
          tone: 'warn',
        });
      });
      if (exp.length === 0) lines.push({ text: '  No expired indicators in org cache.', tone: 'ok' });
      return finish('CTI EXPIRED', lines);
    }

    if (subcommand === 'provider') {
      const p = thirdArg.toUpperCase();
      const hits = externalIndicators.filter((i) => i.providerId.toUpperCase() === p);
      const adp = CTI_ADAPTER_CATALOG.find((a) => a.id.toUpperCase() === p);
      if (!adp) {
        return finish('CTI PROVIDER', [
          { text: `Unknown CTI provider "${thirdArg}". Available: ${CTI_ADAPTER_CATALOG.map((a) => a.id).join(', ')}`, tone: 'warn' },
        ]);
      }
      const statusLabel = adp.requiresServerProxy ? 'GATEWAY PROXY' : adp.status.toUpperCase();
      const lines: TerminalOutputLine[] = [
        { text: `PROVIDER ${adp.name} (${adp.id}) — STATUS: ${statusLabel}`, tone: 'accent' },
        {
          text: `  Staged Local Indicators: ${hits.length} | Proxy Required: ${adp.requiresServerProxy ? adp.proxyEndpoint || 'YES' : 'NO'}`,
          tone: 'normal',
        },
        { text: `  Requirements: ${adp.credentialRequirement}`, tone: 'muted' },
      ];
      hits.slice(0, 12).forEach((i) => {
        lines.push({
          text: `  • ${i.value} (${i.indicatorType}, ${i.verificationStatus}${i.isExpired ? ', EXPIRED' : ''})`,
          tone: i.isExpired ? 'warn' : 'normal',
        });
      });
      return finish('CTI PROVIDER', lines);
    }
  }

  if (verb === 'attribution') {
    const hits = attributionRecords.filter(
      (r) => !lowerArg || `${r.indicatorValue} ${r.entityLabel} ${r.analystNotes}`.toLowerCase().includes(lowerArg)
    );
    const lines: TerminalOutputLine[] = [
      { text: `EVIDENCE-BASED ATTRIBUTION RECORDS (${hits.length}):`, tone: 'accent' },
    ];
    hits.slice(0, 8).forEach((r) => {
      lines.push({
        text: `  [ATTRIBUTION DRAFT:${r.attributionClass.toUpperCase()}] ${r.indicatorValue} -> ${r.entityLabel} (${(r.confidence * 100).toFixed(0)}%, LOCAL DRAFT — NON-AUTHORITATIVE)`,
        tone: 'warn',
        entityRef: r.incidentId
          ? { kind: 'incident', id: r.incidentId }
          : r.assetId
          ? { kind: 'asset', id: r.assetId }
          : undefined,
      });
    });
    lines.push({
      text: 'POLICY NOTE: Browser attribution drafts are non-authoritative. IP/host indicators establish technical links only — verified identity requires Evidence Custody archival and authorised backend workflow.',
      tone: 'muted',
    });
    return finish('ATTRIBUTION INDEX', lines);
  }

  // -------------------------------------------------------------------------
  // GEOSPATIAL INTELLIGENCE COMMANDS
  // -------------------------------------------------------------------------
  if (verb === 'geo') {
    if (subcommand === 'locate') {
      const asset = findAssetByToken(intel.assets, thirdArg);
      if (!asset) return finish('GEOINT', [{ text: `Asset "${thirdArg}" not found.`, tone: 'warn' }]);
      const coord = intel.assetCoordsMap.get(asset.id);
      return finish('GEO LOCATE', [
        { text: `GEOSPATIAL FIX: ${asset.site_code} (${asset.name})`, tone: 'accent', entityRef: { kind: 'asset', id: asset.id } },
        { text: `  Coordinates: ${coord ? `${coord[1].toFixed(5)}° N/S, ${coord[0].toFixed(5)}° E/W (EPSG:4326)` : 'UNAVAILABLE (no geometry)'}`, tone: coord ? 'ok' : 'warn' },
        { text: `  Accuracy Class: ${asset.accuracy_class}${asset.positional_accuracy_m ? ` (±${asset.positional_accuracy_m}m)` : ''}`, tone: asset.accuracy_class === 'exact_survey' ? 'ok' : 'warn' },
      ]);
    }

    if (subcommand === 'nearby') {
      const asset = findAssetByToken(intel.assets, thirdArg);
      if (!asset) return finish('GEOINT', [{ text: `Asset "${thirdArg}" not found.`, tone: 'warn' }]);
      const coord = intel.assetCoordsMap.get(asset.id);
      if (!coord) return finish('GEOINT', [{ text: `Asset "${asset.site_code}" has no mapped coordinate.`, tone: 'warn' }]);
      const radiusKm = Math.max(1, Math.min(500, Number(tokens[3]) || 25));
      const ranked = computeProximityRankings(coord, radiusKm, intel.assets, intel.assetCoordsMap, asset.id);
      const lines: TerminalOutputLine[] = [
        { text: `ASSETS WITHIN ${radiusKm} KM OF ${asset.site_code} (${ranked.length} found):`, tone: 'accent', entityRef: { kind: 'asset', id: asset.id } },
      ];
      ranked.slice(0, 12).forEach((r) => {
        lines.push({
          text: `  • ${r.siteCode} (${r.name}) | ${r.distanceKm.toFixed(2)} km @ ${r.bearingDeg.toFixed(0)}° | T${r.criticality} [${r.accuracyClass}]`,
          tone: 'normal',
          entityRef: { kind: 'asset', id: r.assetId },
        });
      });
      return finish('GEO PROXIMITY', lines);
    }

    if (subcommand === 'exposure') {
      const asset = findAssetByToken(intel.assets, thirdArg);
      if (!asset) return finish('GEOINT', [{ text: `Asset "${thirdArg}" not found.`, tone: 'warn' }]);
      const coord = intel.assetCoordsMap.get(asset.id);
      if (!coord) return finish('GEOINT', [{ text: `Asset "${asset.site_code}" has no coordinate.`, tone: 'warn' }]);
      const buf = analyzeBufferZone(coord, 15, intel.assets, intel.assetCoordsMap, intel.matches);
      return finish('GEO BUFFER EXPOSURE', [
        { text: `15 KM SPATIAL BUFFER AROUND ${asset.site_code}:`, tone: 'accent', entityRef: { kind: 'asset', id: asset.id } },
        { text: `  Co-located Assets: ${buf.intersectingAssets.length} | Linked Incidents: ${buf.linkedIncidentIds.length}`, tone: buf.linkedIncidentIds.length > 0 ? 'warn' : 'ok' },
        { text: `  Approximate Geometry Warning: ${buf.hasApproximateAssets ? 'YES — contains facility/regional approximate coordinates' : 'Exact survey only'}`, tone: buf.hasApproximateAssets ? 'warn' : 'ok' },
      ]);
    }

    if (subcommand === 'cluster') {
      const cellKm = Math.max(5, Math.min(500, Number(tokens[2]) || 50));
      const clusters = computeSpatialClusters(intel.assets, intel.assetCoordsMap, intel.matches, cellKm);
      const lines: TerminalOutputLine[] = [
        { text: `SPATIAL INFRASTRUCTURE CLUSTERS (${clusters.length} cells @ ${cellKm} km):`, tone: 'accent' },
      ];
      clusters.slice(0, 10).forEach((c) => {
        lines.push({
          text: `  • ${c.cellLabel} | Assets: ${c.assetIds.length} | Incidents: ${c.incidentCount} | Max Tier: ${c.maxCriticality} (Exact:${c.accuracy.exact}, Approx:${c.accuracy.facilityApprox + c.accuracy.regionalApprox})`,
          tone: c.incidentCount > 0 ? 'warn' : 'normal',
        });
      });
      return finish('GEO CLUSTERS', lines);
    }

    if (subcommand === 'blast-radius') {
      const inc = findIncidentByToken(intel.incidents, thirdArg);
      if (!inc) return finish('GEO BLAST RADIUS', [{ text: `Incident "${thirdArg}" not found.`, tone: 'warn' }]);
      const rootMatches = intel.matches.filter((m) => m.incident_id === inc.id && m.status !== 'rejected');
      const rootIds = rootMatches.map((m) => m.asset_id);
      const sim = simulateNodeFailureCascade(rootIds, intel.assets, intel.edges, intel.matches);
      const lines: TerminalOutputLine[] = [
        { text: `SPATIAL + TOPOLOGICAL BLAST RADIUS FOR ${inc.event_id}:`, tone: 'accent', entityRef: { kind: 'incident', id: inc.id } },
        { text: `  Root Matched Assets: ${rootIds.length} | Downstream Cascading Nodes: ${sim.totalCascadingOutageCount} (Tier4+: ${sim.tier4PlusAffectedCount})`, tone: sim.totalCascadingOutageCount > 0 ? 'warn' : 'normal' },
      ];
      sim.affectedAssets.slice(0, 10).forEach((n) => {
        const coord = intel.assetCoordsMap.get(n.assetId);
        lines.push({
          text: `  • Hop ${n.hopDepth}: ${n.siteCode} (${n.name}) via ${n.viaRelation} | ${coord ? `${coord[1].toFixed(3)}, ${coord[0].toFixed(3)}` : 'no coord'}`,
          tone: 'normal',
          entityRef: { kind: 'asset', id: n.assetId },
        });
      });
      return finish('GEO BLAST RADIUS', lines);
    }
  }

  // -------------------------------------------------------------------------
  // RESILIENCE COMMANDS (Module F)
  // -------------------------------------------------------------------------
  if (verb === 'resilience') {
    const asset = findAssetByToken(intel.assets, thirdArg);
    if (!asset) return finish('RESILIENCE', [{ text: `Asset "${thirdArg}" not found.`, tone: 'warn' }]);

    if (subcommand === 'assess') {
      const profiles = analyzeInfrastructureResilience(intel.assets, intel.edges, intel.assetCoordsMap, intel.matches);
      const p = profiles.find((x) => x.assetId === asset.id);
      if (!p) return finish('RESILIENCE', [{ text: 'Profile unavailable.', tone: 'warn' }]);
      return finish('RESILIENCE PROFILE', [
        { text: `INFRASTRUCTURE RESILIENCE ASSESSMENT: ${p.siteCode} (${p.name})`, tone: 'accent', entityRef: { kind: 'asset', id: p.assetId } },
        { text: `  Heuristic Structural Vulnerability: ${p.structuralVulnerabilityScore}/100 | SPOF: ${p.isSinglePointOfFailure ? `YES (${p.spofReason})` : 'NO'}`, tone: p.isSinglePointOfFailure ? 'warn' : 'ok' },
        { text: `  Upstream Links: Power=${p.powerUpstreamCount}, Telecom=${p.telecomUpstreamCount}, Other=${p.otherUpstreamCount} | Downstream Dependents=${p.downstreamDependentCount}`, tone: 'normal' },
        { text: `  Co-located Tier3+ within 2km: ${p.coLocatedCriticalCount} | Active Incidents: ${p.activeIncidentExposureCount}`, tone: 'normal' },
        { text: `  Backup / UPS / RTO / RPO: ${p.backupRecoveryStatus} (never fabricated — not in locked database)`, tone: 'muted' },
      ]);
    }

    if (subcommand === 'dependencies') {
      const upstream = intel.edges.filter((e) => e.to_asset_id === asset.id);
      const downstream = intel.edges.filter((e) => e.from_asset_id === asset.id);
      return finish('RESILIENCE DEPENDENCIES', [
        { text: `RESILIENCE DEPENDENCY SUMMARY FOR ${asset.site_code}:`, tone: 'accent', entityRef: { kind: 'asset', id: asset.id } },
        { text: `  Upstream Feeds: ${upstream.length} (${upstream.filter((e) => e.relation_type === 'powers').length} power, ${upstream.filter((e) => e.relation_type === 'connects_to').length} telecom)`, tone: 'normal' },
        { text: `  Downstream Dependents: ${downstream.length}`, tone: 'normal' },
        { text: `  Note: Redundant failover circuits / UPS autonomy are marked NO_VERIFIED_DATA in locked schema.`, tone: 'muted' },
      ]);
    }

    if (subcommand === 'simulate') {
      const sim = simulateNodeFailureCascade([asset.id], intel.assets, intel.edges, intel.matches);
      const lines: TerminalOutputLine[] = [
        { text: `CASCADING OUTAGE SIMULATION (ROOT: ${asset.site_code})`, tone: 'accent', entityRef: { kind: 'asset', id: asset.id } },
        { text: `  Direct Dependents: ${sim.directDependentsCount} | Total Downstream Outage: ${sim.totalCascadingOutageCount} | Tier-4/5 Affected: ${sim.tier4PlusAffectedCount}`, tone: sim.totalCascadingOutageCount > 0 ? 'err' : 'ok' },
        { text: `  Power Hops: ${sim.powerCascadeCount} | Telecom Hops: ${sim.telecomCascadeCount}`, tone: 'normal' },
      ];
      sim.affectedAssets.slice(0, 12).forEach((n) => {
        lines.push({
          text: `  • Hop ${n.hopDepth}: ${n.siteCode} (T${n.criticality}) via ${n.viaRelation}`,
          tone: n.criticality >= 4 ? 'warn' : 'normal',
          entityRef: { kind: 'asset', id: n.assetId },
        });
      });
      lines.push({ text: `  Methodology: ${sim.methodologyNote}`, tone: 'muted' });
      return finish('CASCADE SIMULATION', lines);
    }
  }

  // -------------------------------------------------------------------------
  // NETWORK STATUS & GATEWAY JOB QUERIES
  // -------------------------------------------------------------------------
  if (verb === 'network') {
    if (subcommand === 'status') {
      const gw = ctx.gatewayHealth;
      const lines: TerminalOutputLine[] = [
        { text: `HYBRID NETWORK & GATEWAY STATUS`, tone: 'accent' },
        { text: `  Linux Security Worker State: ${gw?.state || 'NOT_CONFIGURED'}`, tone: gw?.state === 'READY' ? 'ok' : 'warn' },
        { text: `  Endpoint: ${gw?.endpointUrl || 'Not configured'} | Active Org Jobs: ${gatewayJobs.length}`, tone: 'normal' },
      ];
      if (gw?.tools?.length) {
        gw.tools.forEach((t) => {
          lines.push({
            text: `  • Tool ${t.name}: ${t.available ? `READY (${t.version || 'installed'})` : 'UNAVAILABLE'}`,
            tone: t.available ? 'ok' : 'muted',
          });
        });
      }
      return finish('NETWORK STATUS', lines);
    }

    if (subcommand === 'scan' && (tokens[2] === 'status' || tokens[2] === 'results')) {
      const jobId = tokens[3] || '';
      const job = gatewayJobs.find((j) => j.jobId === jobId);
      if (!job) {
        return finish('GATEWAY JOB LOOKUP', [
          { text: `Job "${jobId || '(empty)'}" not found in active organisation session.`, tone: 'warn' },
        ]);
      }
      if (tokens[2] === 'status') {
        return finish('GATEWAY JOB STATUS', [
          { text: `JOB ${job.jobId} [${job.status.toUpperCase()}]`, tone: job.status === 'completed' ? 'ok' : 'warn' },
          { text: `  Tool: ${job.tool} | Target: ${job.target} | Risk: ${job.riskLevel} | Approval: ${job.approvalState}`, tone: 'normal' },
          { text: `  Duration: ${job.durationMs ?? 'running'} ms | Exit Code: ${job.exitCode ?? 'pending'}`, tone: 'normal' },
        ]);
      }
      const lines: TerminalOutputLine[] = [
        { text: `JOB RESULTS ${job.jobId} (${job.command}):`, tone: 'accent' },
        ...(job.stdoutLines.slice(0, 20).map((l) => ({ text: `  ${l}`, tone: 'normal' as const }))),
      ];
      if (job.correlation) {
        lines.push({ text: `  CORRELATION NOTES: ${job.correlation.notes.join(' ') || 'None'}`, tone: 'warn' });
      }
      return finish('GATEWAY JOB RESULTS', lines, { correlation: job.correlation });
    }
  }

  // -------------------------------------------------------------------------
  // INVESTIGATION & REPORT GENERATION
  // -------------------------------------------------------------------------
  if (verb === 'investigation') {
    if (subcommand === 'open') {
      const inc = findIncidentByToken(intel.incidents, thirdArg);
      if (!inc) return finish('INVESTIGATION', [{ text: `Incident "${thirdArg}" not found.`, tone: 'warn' }]);
      const matches = intel.matches.filter((m) => m.incident_id === inc.id && m.status !== 'rejected');
      return finish('INVESTIGATION CASE', [
        { text: `OPENED INVESTIGATION BRIEF: ${inc.event_id} — ${inc.event_type}`, tone: 'accent', entityRef: { kind: 'incident', id: inc.id } },
        { text: `  Severity: ${inc.severity.toUpperCase()} | Linked Assets: ${matches.length}`, tone: 'warn' },
        { text: `  Recommended Next Steps: \`incident assets ${inc.event_id}\`, \`geo blast-radius ${inc.event_id}\`, \`report incident ${inc.event_id}\``, tone: 'muted' },
      ]);
    }
    if (subcommand === 'correlate') {
      return executeDefensiveTerminalCommand(`threat correlate ${thirdArg}`, intel, externalIndicators, attributionRecords, ctx);
    }
  }

  if (verb === 'report') {
    if (subcommand === 'incident') {
      const inc = findIncidentByToken(intel.incidents, thirdArg);
      if (!inc) return finish('REPORT', [{ text: `Incident "${thirdArg}" not found.`, tone: 'warn' }]);
      const matches = intel.matches.filter((m) => m.incident_id === inc.id);
      const sim = simulateNodeFailureCascade(
        matches.filter((m) => m.status !== 'rejected').map((m) => m.asset_id),
        intel.assets,
        intel.edges,
        intel.matches
      );
      const md = [
        `# ATLAS Incident Investigation Report — ${inc.event_id}`,
        `- Organisation ID: \`${intel.orgId}\``,
        `- Generated UTC: ${new Date().toISOString()}`,
        `- Event Type: ${inc.event_type} | Severity: ${inc.severity.toUpperCase()}`,
        `- Signals: \`${JSON.stringify(inc.signals || {})}\``,
        `- Asset Matches: ${matches.length} | Downstream Cascade Nodes: ${sim.totalCascadingOutageCount}`,
        `- Note: Derived from authoritative Supabase records at generation time.`,
      ].join('\n');
      return finish(
        'INCIDENT REPORT READY',
        [
          { text: `GENERATED MARKDOWN REPORT FOR ${inc.event_id}`, tone: 'ok', entityRef: { kind: 'incident', id: inc.id } },
          { text: `  Use the Export action on this result card to download Markdown or archive via Evidence & Custody.`, tone: 'muted' },
        ],
        { exportReportMarkdown: md }
      );
    }

    if (subcommand === 'network') {
      const job = gatewayJobs.find((j) => j.jobId === thirdArg);
      if (!job) return finish('REPORT', [{ text: `Gateway job "${thirdArg}" not found.`, tone: 'warn' }]);
      const md = [
        `# ATLAS External Gateway Network Report — ${job.jobId}`,
        `- Record Classification: EXTERNAL_GATEWAY_EXECUTION_RECORD (Non-Authoritative)`,
        `- Organisation ID: \`${job.orgId}\` | Tool: \`${job.tool}\` | Target: \`${job.target}\``,
        `- Status: ${job.status} | Duration: ${job.durationMs ?? 0} ms | Exit Code: ${job.exitCode ?? 'N/A'}`,
        `- Summary: ${job.resultSummary || 'See raw stdout'}`,
        `\n## Output\n\`\`\`\n${job.stdoutLines.join('\n')}\n\`\`\``,
      ].join('\n');
      return finish(
        'NETWORK REPORT READY',
        [{ text: `GENERATED NETWORK REPORT FOR JOB ${job.jobId} (Use Export to download).`, tone: 'ok' }],
        { exportReportMarkdown: md, correlation: job.correlation }
      );
    }

    if (subcommand === 'resilience') {
      const asset = findAssetByToken(intel.assets, thirdArg);
      if (!asset) return finish('REPORT', [{ text: `Asset "${thirdArg}" not found.`, tone: 'warn' }]);
      const sim = simulateNodeFailureCascade([asset.id], intel.assets, intel.edges, intel.matches);
      const md = [
        `# ATLAS Infrastructure Resilience Report — ${asset.site_code}`,
        `- Asset: ${asset.name} (${asset.type}, Tier ${asset.criticality})`,
        `- Direct Dependents: ${sim.directDependentsCount} | Cascading Outage Total: ${sim.totalCascadingOutageCount}`,
        `- Backup / Recovery Data: NO_VERIFIED_DATA (not tracked in locked database)`,
        `- Methodology: ${sim.methodologyNote}`,
      ].join('\n');
      return finish(
        'RESILIENCE REPORT READY',
        [{ text: `GENERATED RESILIENCE REPORT FOR ${asset.site_code} (Use Export to download).`, tone: 'ok', entityRef: { kind: 'asset', id: asset.id } }],
        { exportReportMarkdown: md }
      );
    }
  }

  // -------------------------------------------------------------------------
  // LEGACY ALIASES (netflow, blast, remote)
  // -------------------------------------------------------------------------
  if (verb === 'netflow') {
    const withNetSignals = intel.incidents.filter((i) => {
      const s = i.signals || {};
      return Boolean((s as any).ips?.length || (s as any).cidrs?.length || (s as any).hostnames?.length);
    });
    const lines: TerminalOutputLine[] = [
      {
        text: `LIVE PACKET / NETFLOW SENSOR STREAM: DATA SOURCE UNAVAILABLE (Use Linux Worker \`pcap summary <file.pcap>\` for authorised offline PCAP analysis).`,
        tone: 'warn',
      },
      {
        text: `INGESTED INCIDENT NETWORK SIGNALS (${withNetSignals.length} records in public.incidents):`,
        tone: 'accent',
      },
    ];
    withNetSignals.slice(0, 8).forEach((i) => {
      const s = (i.signals || {}) as Record<string, any>;
      const summary = [
        ...(s.ips || []).map((ip: string) => `IP:${ip}`),
        ...(s.hostnames || []).map((h: string) => `HOST:${h}`),
        ...(s.cidrs || []).map((c: string) => `CIDR:${c}`),
      ]
        .slice(0, 5)
        .join(', ');
      lines.push({
        text: `  ${i.event_id} (${i.observed_at.slice(0, 19)}Z) -> ${summary}`,
        tone: 'normal',
        entityRef: { kind: 'incident', id: i.id },
      });
    });
    return finish('NETWORK SIGNAL SUMMARY', lines, { status: 'unavailable' });
  }

  if (verb === 'blast') {
    const inc = findIncidentByToken(intel.incidents, lowerArg);
    if (!inc) {
      return finish('BLAST TRACE', [{ text: `Incident "${arg || '(empty)'}" not found. Example: blast <event_id>`, tone: 'warn' }]);
    }
    const matches = intel.matches.filter((m) => m.incident_id === inc.id && m.status !== 'rejected');
    const lines: TerminalOutputLine[] = [
      { text: `LOCAL GRAPH BLAST SUMMARY FOR ${inc.event_id} (${inc.severity.toUpperCase()}):`, tone: 'accent' },
      { text: `  Root Matched Assets: ${matches.length}`, tone: 'normal' },
    ];
    for (const m of matches) {
      const deps = intel.edges.filter((e) => e.from_asset_id === m.asset_id);
      lines.push({
        text: `  • ${m.asset?.site_code || m.asset_id} [${m.status}] -> ${deps.length} direct dependency edge(s)`,
        tone: 'normal',
        entityRef: { kind: 'asset', id: m.asset_id },
      });
    }
    return finish('TOPOLOGY TRACE', lines);
  }

  if (verb === 'remote') {
    const gwState = ctx.gatewayHealth?.state || 'NOT_CONFIGURED';
    return finish(
      'REMOTE TERMINAL ADAPTER',
      [
        {
          text:
            gwState === 'READY'
              ? `LINUX EXECUTION GATEWAY CONNECTED (${ctx.gatewayHealth?.endpointUrl}) — Switch environment to LINUX SECURITY WORKER to execute registered tools.`
              : `AWAITING AUTHORISED CONNECTION: Linux Security Worker Gateway state is ${gwState}. Configure gateway URL or switch environment selector to inspect tool status.`,
          tone: gwState === 'READY' ? 'ok' : 'warn',
        },
      ],
      { status: gwState === 'READY' ? 'ok' : 'unavailable' }
    );
  }

  return finish('UNKNOWN COMMAND', [
    { text: `Unrecognised command "${verb}". Type \`help\` for authorised commands.`, tone: 'warn' },
  ]);
}
