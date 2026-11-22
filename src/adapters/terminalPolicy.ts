/**
 * Project ATLAS — Central Command Policy Engine & Structured Parser
 *
 * Security Invariants:
 * - Every command in ATLAS NATIVE or LINUX SECURITY WORKER must match an entry
 *   in `COMMAND_POLICY_REGISTRY`. Unlisted or shell-chained commands fail closed.
 * - Rejects shell metacharacters, offensive tooling, NSE scripts, live packet
 *   injection/sniffing, loopback/link-local/metadata IPs, and path traversal.
 */

import type {
  AppRole,
  CommandPolicyDescriptor,
  CommandRiskLevel,
  TerminalEnvironment,
} from '../types/atlas';

export const SHELL_METACHAR_PATTERN = /[;|&`$><()\\{}\n\r\0]/;

export const RESTRICTED_KEYWORDS = new Set([
  'rm',
  'rmdir',
  'mkfs',
  'dd',
  'sudo',
  'su',
  'chmod',
  'chown',
  'mount',
  'umount',
  'kill',
  'pkill',
  'shutdown',
  'reboot',
  'iptables',
  'nft',
  'ufw',
  'curl',
  'wget',
  'bash',
  'sh',
  'zsh',
  'dash',
  'ash',
  'nc',
  'netcat',
  'ncat',
  'socat',
  'ssh',
  'scp',
  'sftp',
  'telnet',
  'ftp',
  'python',
  'python3',
  'perl',
  'ruby',
  'php',
  'node',
  'eval',
  'exec',
  'msfconsole',
  'msfvenom',
  'hydra',
  'medusa',
  'john',
  'hashcat',
  'sqlmap',
  'nikto',
  'gobuster',
  'dirb',
  'ffuf',
  'ettercap',
  'arpspoof',
  'responder',
  'mimikatz',
  'tcpreplay',
  'hping3',
  'masscan',
  'zmap',
  'aircrack-ng',
]);

export const COMMAND_POLICY_REGISTRY: CommandPolicyDescriptor[] = [
  // ---- ATLAS NATIVE: Workspace ----
  {
    id: 'atlas.help',
    command: 'help',
    environment: 'atlas_native',
    requiredPermission: 'any_member',
    requiredArgs: 'none',
    targetRestrictions: 'none',
    riskLevel: 'LOW',
    requiresApproval: false,
    maxRuntimeMs: 500,
    maxOutputBytes: 32768,
    auditCategory: 'WORKSPACE_QUERY',
    description: 'Display categorised ATLAS-native command reference and operational policies.',
  },
  {
    id: 'atlas.status',
    command: 'status',
    environment: 'atlas_native',
    requiredPermission: 'any_member',
    requiredArgs: 'none',
    targetRestrictions: 'Active authenticated org scope only',
    riskLevel: 'LOW',
    requiresApproval: false,
    maxRuntimeMs: 1000,
    maxOutputBytes: 16384,
    auditCategory: 'WORKSPACE_QUERY',
    description: 'Report workspace DB counts, match backlog, audit ledger head, and gateway status.',
  },
  {
    id: 'atlas.workspace',
    command: 'workspace',
    environment: 'atlas_native',
    requiredPermission: 'any_member',
    requiredArgs: 'none',
    targetRestrictions: 'Active authenticated org scope only',
    riskLevel: 'LOW',
    requiresApproval: false,
    maxRuntimeMs: 1000,
    maxOutputBytes: 16384,
    auditCategory: 'WORKSPACE_QUERY',
    description: 'Inspect active workspace metadata, datasets, members, and calibration status.',
  },
  {
    id: 'atlas.whoami',
    command: 'whoami',
    environment: 'atlas_native',
    requiredPermission: 'any_member',
    requiredArgs: 'none',
    targetRestrictions: 'Active authenticated session only',
    riskLevel: 'LOW',
    requiresApproval: false,
    maxRuntimeMs: 500,
    maxOutputBytes: 8192,
    auditCategory: 'IDENTITY_INSPECT',
    description: 'Show current operator identity, verified MFA level (AAL2), role, and active organisation.',
  },
  {
    id: 'atlas.history',
    command: 'history',
    environment: 'atlas_native',
    requiredPermission: 'any_member',
    requiredArgs: 'none',
    targetRestrictions: 'Local org-scoped browser history',
    riskLevel: 'LOW',
    requiresApproval: false,
    maxRuntimeMs: 500,
    maxOutputBytes: 32768,
    auditCategory: 'WORKSPACE_QUERY',
    description: 'List recent terminal commands executed in this browser workspace session.',
  },
  {
    id: 'atlas.clear',
    command: 'clear',
    environment: 'atlas_native',
    requiredPermission: 'any_member',
    requiredArgs: 'none',
    targetRestrictions: 'UI scrollback only',
    riskLevel: 'LOW',
    requiresApproval: false,
    maxRuntimeMs: 500,
    maxOutputBytes: 4096,
    auditCategory: 'UI_ACTION',
    description: 'Clear terminal display output buffer cleanly.',
  },

  // ---- ATLAS NATIVE: Assets ----
  {
    id: 'atlas.assets.list',
    command: 'assets',
    environment: 'atlas_native',
    requiredPermission: 'any_member',
    requiredArgs: 'optional filter',
    targetRestrictions: 'Authorised workspace assets',
    riskLevel: 'LOW',
    requiresApproval: false,
    maxRuntimeMs: 1000,
    maxOutputBytes: 32768,
    auditCategory: 'ASSET_QUERY',
    description: 'List or filter workspace infrastructure assets.',
  },
  {
    id: 'atlas.assets.search',
    command: 'assets search <query>',
    environment: 'atlas_native',
    requiredPermission: 'any_member',
    requiredArgs: '<query>',
    targetRestrictions: 'Authorised workspace assets',
    riskLevel: 'LOW',
    requiresApproval: false,
    maxRuntimeMs: 1000,
    maxOutputBytes: 32768,
    auditCategory: 'ASSET_QUERY',
    description: 'Search workspace assets by site code, name, IP, CIDR, hostname, or cloud ID.',
  },
  {
    id: 'atlas.asset.inspect',
    command: 'asset inspect <asset_id>',
    environment: 'atlas_native',
    requiredPermission: 'any_member',
    requiredArgs: '<asset_id|site_code>',
    targetRestrictions: 'Authorised workspace assets',
    riskLevel: 'LOW',
    requiresApproval: false,
    maxRuntimeMs: 1000,
    maxOutputBytes: 32768,
    auditCategory: 'ASSET_INSPECT',
    description: 'Display full asset telemetry profile, identifiers, coordinate precision, and linked matches.',
  },
  {
    id: 'atlas.asset.dependencies',
    command: 'asset dependencies <asset_id>',
    environment: 'atlas_native',
    requiredPermission: 'any_member',
    requiredArgs: '<asset_id|site_code>',
    targetRestrictions: 'Authorised dependency_edges',
    riskLevel: 'LOW',
    requiresApproval: false,
    maxRuntimeMs: 1000,
    maxOutputBytes: 32768,
    auditCategory: 'TOPOLOGY_QUERY',
    description: 'List upstream providers and downstream dependents for an infrastructure asset.',
  },
  {
    id: 'atlas.asset.exposure',
    command: 'asset exposure <asset_id>',
    environment: 'atlas_native',
    requiredPermission: 'any_member',
    requiredArgs: '<asset_id|site_code>',
    targetRestrictions: 'Authorised workspace state',
    riskLevel: 'LOW',
    requiresApproval: false,
    maxRuntimeMs: 1000,
    maxOutputBytes: 32768,
    auditCategory: 'EXPOSURE_QUERY',
    description: 'Evaluate active incident matches, external CTI overlaps, and SPOF exposure for an asset.',
  },

  // ---- ATLAS NATIVE: Incidents ----
  {
    id: 'atlas.incidents.list',
    command: 'incidents [critical|severity]',
    environment: 'atlas_native',
    requiredPermission: 'any_member',
    requiredArgs: 'optional severity',
    targetRestrictions: 'Authorised incidents',
    riskLevel: 'LOW',
    requiresApproval: false,
    maxRuntimeMs: 1000,
    maxOutputBytes: 32768,
    auditCategory: 'INCIDENT_QUERY',
    description: 'List security incidents (supports `incidents critical`).',
  },
  {
    id: 'atlas.incident.inspect',
    command: 'incident inspect <event_id>',
    environment: 'atlas_native',
    requiredPermission: 'any_member',
    requiredArgs: '<event_id|uuid>',
    targetRestrictions: 'Authorised incidents',
    riskLevel: 'LOW',
    requiresApproval: false,
    maxRuntimeMs: 1000,
    maxOutputBytes: 32768,
    auditCategory: 'INCIDENT_INSPECT',
    description: 'Inspect incident metadata, signals payload, matched assets, and linked evidence.',
  },
  {
    id: 'atlas.incident.timeline',
    command: 'incident timeline <event_id>',
    environment: 'atlas_native',
    requiredPermission: 'any_member',
    requiredArgs: '<event_id|uuid>',
    targetRestrictions: 'Authorised audit_events & evidence',
    riskLevel: 'LOW',
    requiresApproval: false,
    maxRuntimeMs: 1000,
    maxOutputBytes: 32768,
    auditCategory: 'TIMELINE_QUERY',
    description: 'Reconstruct incident observation, audit-ledger references, and custody sequence.',
  },
  {
    id: 'atlas.incident.assets',
    command: 'incident assets <event_id>',
    environment: 'atlas_native',
    requiredPermission: 'any_member',
    requiredArgs: '<event_id|uuid>',
    targetRestrictions: 'Authorised asset_matches',
    riskLevel: 'LOW',
    requiresApproval: false,
    maxRuntimeMs: 1000,
    maxOutputBytes: 32768,
    auditCategory: 'INCIDENT_QUERY',
    description: 'List all asset matches associated with an incident along with rule and decision state.',
  },

  // ---- ATLAS NATIVE: Threat Intelligence ----
  {
    id: 'atlas.ioc.lookup',
    command: 'ioc <indicator>',
    environment: 'atlas_native',
    requiredPermission: 'any_member',
    requiredArgs: '<indicator>',
    targetRestrictions: 'Workspace DB + local CTI + attribution drafts',
    riskLevel: 'LOW',
    requiresApproval: false,
    maxRuntimeMs: 1000,
    maxOutputBytes: 32768,
    auditCategory: 'IOC_QUERY',
    description: 'Correlate an IP, CIDR, domain, hostname, CVE, or hash across ATLAS and CTI caches.',
  },
  {
    id: 'atlas.cti.status',
    command: 'cti status',
    environment: 'atlas_native',
    requiredPermission: 'any_member',
    requiredArgs: 'none',
    targetRestrictions: 'Org-scoped CTI cache',
    riskLevel: 'LOW',
    requiresApproval: false,
    maxRuntimeMs: 1000,
    maxOutputBytes: 16384,
    auditCategory: 'CTI_QUERY',
    description: 'Show CTI indicator counts by provider, verification status, and proxy availability.',
  },
  {
    id: 'atlas.cti.expired',
    command: 'cti expired',
    environment: 'atlas_native',
    requiredPermission: 'any_member',
    requiredArgs: 'none',
    targetRestrictions: 'Org-scoped CTI cache',
    riskLevel: 'LOW',
    requiresApproval: false,
    maxRuntimeMs: 1000,
    maxOutputBytes: 32768,
    auditCategory: 'CTI_QUERY',
    description: 'List expired external CTI indicators currently staged in local workspace cache.',
  },
  {
    id: 'atlas.cti.provider',
    command: 'cti provider <provider>',
    environment: 'atlas_native',
    requiredPermission: 'any_member',
    requiredArgs: '<provider>',
    targetRestrictions: 'Org-scoped CTI cache',
    riskLevel: 'LOW',
    requiresApproval: false,
    maxRuntimeMs: 1000,
    maxOutputBytes: 32768,
    auditCategory: 'CTI_QUERY',
    description: 'Filter staged CTI indicators and connector status by provider ID.',
  },
  {
    id: 'atlas.threat.correlate',
    command: 'threat correlate <indicator>',
    environment: 'atlas_native',
    requiredPermission: 'any_member',
    requiredArgs: '<indicator>',
    targetRestrictions: 'Workspace DB + CTI + Attribution drafts',
    riskLevel: 'LOW',
    requiresApproval: false,
    maxRuntimeMs: 1500,
    maxOutputBytes: 32768,
    auditCategory: 'CORRELATION',
    description: 'Run cross-domain correlation (Assets -> Matches -> Incidents -> CTI -> Draft Attribution).',
  },
  {
    id: 'atlas.attribution',
    command: 'attribution <term>',
    environment: 'atlas_native',
    requiredPermission: 'any_member',
    requiredArgs: 'optional term',
    targetRestrictions: 'Org-scoped non-authoritative local drafts',
    riskLevel: 'LOW',
    requiresApproval: false,
    maxRuntimeMs: 1000,
    maxOutputBytes: 32768,
    auditCategory: 'ATTRIBUTION_QUERY',
    description: 'Query evidence-based attribution drafts with non-authoritative draft guardrails.',
  },
  {
    id: 'atlas.dns_rep',
    command: 'dns <domain> | rep <indicator>',
    environment: 'atlas_native',
    requiredPermission: 'any_member',
    requiredArgs: '<indicator>',
    targetRestrictions: 'Local cross-ref + proxy status check',
    riskLevel: 'LOW',
    requiresApproval: false,
    maxRuntimeMs: 1000,
    maxOutputBytes: 16384,
    auditCategory: 'CTI_QUERY',
    description: 'Cross-reference domain/reputation locally and check remote enrichment proxy availability.',
  },

  // ---- ATLAS NATIVE: Geospatial Intelligence ----
  {
    id: 'atlas.geo.locate',
    command: 'geo locate <asset_id>',
    environment: 'atlas_native',
    requiredPermission: 'any_member',
    requiredArgs: '<asset_id|site_code>',
    targetRestrictions: 'Authorised PostGIS coordinates',
    riskLevel: 'LOW',
    requiresApproval: false,
    maxRuntimeMs: 1000,
    maxOutputBytes: 16384,
    auditCategory: 'GEOINT_QUERY',
    description: 'Inspect authoritative asset coordinates, accuracy class, and spatial precision metadata.',
  },
  {
    id: 'atlas.geo.nearby',
    command: 'geo nearby <asset_id> [km]',
    environment: 'atlas_native',
    requiredPermission: 'any_member',
    requiredArgs: '<asset_id|site_code>',
    targetRestrictions: 'Authorised PostGIS coordinates',
    riskLevel: 'LOW',
    requiresApproval: false,
    maxRuntimeMs: 1500,
    maxOutputBytes: 32768,
    auditCategory: 'GEOINT_ANALYSIS',
    description: 'Rank neighbouring assets within radius (default 25 km) by Haversine distance and bearing.',
  },
  {
    id: 'atlas.geo.exposure',
    command: 'geo exposure <asset_id>',
    environment: 'atlas_native',
    requiredPermission: 'any_member',
    requiredArgs: '<asset_id|site_code>',
    targetRestrictions: 'Authorised PostGIS coordinates & incidents',
    riskLevel: 'LOW',
    requiresApproval: false,
    maxRuntimeMs: 1500,
    maxOutputBytes: 32768,
    auditCategory: 'GEOINT_ANALYSIS',
    description: 'Evaluate 15 km spatial buffer exposure and active linked incidents around an asset.',
  },
  {
    id: 'atlas.geo.cluster',
    command: 'geo cluster [cell_km]',
    environment: 'atlas_native',
    requiredPermission: 'any_member',
    requiredArgs: 'optional cell_km',
    targetRestrictions: 'Authorised PostGIS coordinates',
    riskLevel: 'LOW',
    requiresApproval: false,
    maxRuntimeMs: 1500,
    maxOutputBytes: 32768,
    auditCategory: 'GEOINT_ANALYSIS',
    description: 'Compute spatial grid clusters and co-location density across workspace assets.',
  },
  {
    id: 'atlas.geo.blast_radius',
    command: 'geo blast-radius <event_id>',
    environment: 'atlas_native',
    requiredPermission: 'any_member',
    requiredArgs: '<event_id>',
    targetRestrictions: 'Authorised topology & coordinates',
    riskLevel: 'LOW',
    requiresApproval: false,
    maxRuntimeMs: 2000,
    maxOutputBytes: 32768,
    auditCategory: 'GEOINT_ANALYSIS',
    description: 'Trace incident-affected assets, downstream BFS dependencies, and geographic spread.',
  },

  // ---- ATLAS NATIVE: Resilience & Reporting ----
  {
    id: 'atlas.resilience.assess',
    command: 'resilience assess <asset_id>',
    environment: 'atlas_native',
    requiredPermission: 'any_member',
    requiredArgs: '<asset_id|site_code>',
    targetRestrictions: 'Authorised dependency topology',
    riskLevel: 'LOW',
    requiresApproval: false,
    maxRuntimeMs: 1500,
    maxOutputBytes: 32768,
    auditCategory: 'RESILIENCE_QUERY',
    description: 'Compute resilience profile, SPOF triggers, upstream power/telecom links, and missing data.',
  },
  {
    id: 'atlas.resilience.dependencies',
    command: 'resilience dependencies <asset_id>',
    environment: 'atlas_native',
    requiredPermission: 'any_member',
    requiredArgs: '<asset_id|site_code>',
    targetRestrictions: 'Authorised dependency topology',
    riskLevel: 'LOW',
    requiresApproval: false,
    maxRuntimeMs: 1500,
    maxOutputBytes: 32768,
    auditCategory: 'RESILIENCE_QUERY',
    description: 'Inspect directional power, telecom, and hosting dependency chains for an asset.',
  },
  {
    id: 'atlas.resilience.simulate',
    command: 'resilience simulate <asset_id>',
    environment: 'atlas_native',
    requiredPermission: 'any_member',
    requiredArgs: '<asset_id|site_code>',
    targetRestrictions: 'Client-side deterministic BFS simulation',
    riskLevel: 'LOW',
    requiresApproval: false,
    maxRuntimeMs: 2000,
    maxOutputBytes: 32768,
    auditCategory: 'RESILIENCE_SIMULATE',
    description: 'Simulate deterministic downstream failure cascade from an infrastructure node.',
  },
  {
    id: 'atlas.investigation',
    command: 'investigation open <event_id> | correlate <indicator>',
    environment: 'atlas_native',
    requiredPermission: 'any_member',
    requiredArgs: 'subcommand + target',
    targetRestrictions: 'Authorised workspace records',
    riskLevel: 'LOW',
    requiresApproval: false,
    maxRuntimeMs: 1500,
    maxOutputBytes: 32768,
    auditCategory: 'INVESTIGATION',
    description: 'Assemble an integrated investigation brief or pivot EntityRef for an event or indicator.',
  },
  {
    id: 'atlas.report',
    command: 'report incident <event_id> | network <job_id> | resilience <asset_id>',
    environment: 'atlas_native',
    requiredPermission: 'any_member',
    requiredArgs: 'subcommand + target',
    targetRestrictions: 'Authorised workspace & gateway records',
    riskLevel: 'LOW',
    requiresApproval: false,
    maxRuntimeMs: 2000,
    maxOutputBytes: 65536,
    auditCategory: 'REPORT_GENERATION',
    description: 'Generate structured Markdown investigation report ready for download or Evidence Custody archival.',
  },

  // ---- NETWORK QUERIES & BRIDGES ----
  {
    id: 'atlas.network.status',
    command: 'network status',
    environment: 'atlas_native',
    requiredPermission: 'any_member',
    requiredArgs: 'none',
    targetRestrictions: 'Gateway health & workspace net signals',
    riskLevel: 'LOW',
    requiresApproval: false,
    maxRuntimeMs: 1000,
    maxOutputBytes: 16384,
    auditCategory: 'NETWORK_STATUS',
    description: 'Report Linux Execution Gateway connection state, tool health, and active gateway jobs.',
  },
  {
    id: 'atlas.network.scan.inspect',
    command: 'network scan status <job_id> | results <job_id>',
    environment: 'atlas_native',
    requiredPermission: 'any_member',
    requiredArgs: '<job_id>',
    targetRestrictions: 'Active org gateway jobs',
    riskLevel: 'LOW',
    requiresApproval: false,
    maxRuntimeMs: 1000,
    maxOutputBytes: 65536,
    auditCategory: 'JOB_INSPECT',
    description: 'Inspect status or correlated output of an existing gateway reconnaissance job.',
  },

  // ---- LINUX SECURITY WORKER COMMANDS ----
  {
    id: 'linux.diag.sysinfo',
    command: 'sysinfo | interfaces | processes | services | disk | memory | network interfaces',
    environment: 'linux_worker',
    requiredPermission: 'any_member',
    requiredArgs: 'none',
    targetRestrictions: 'Isolated Linux worker container only',
    riskLevel: 'LOW',
    requiresApproval: false,
    maxRuntimeMs: 10000,
    maxOutputBytes: 65536,
    auditCategory: 'LINUX_DIAGNOSTIC',
    description: 'Execute fixed read-only system diagnostic utility on isolated Linux Security Worker.',
  },
  {
    id: 'linux.nmap.help',
    command: 'nmap --help',
    environment: 'linux_worker',
    requiredPermission: 'any_member',
    requiredArgs: '--help',
    targetRestrictions: 'No network target contacted',
    riskLevel: 'LOW',
    requiresApproval: false,
    maxRuntimeMs: 5000,
    maxOutputBytes: 65536,
    auditCategory: 'TOOL_HELP',
    description: 'Display installed Nmap usage documentation from isolated gateway container.',
  },
  {
    id: 'linux.nmap.discovery',
    command: 'nmap -sn <approved_target> | network scan <approved_target>',
    environment: 'linux_worker',
    requiredPermission: 'any_member',
    requiredArgs: '<approved_target>',
    targetRestrictions: 'Gateway CIDR/host allowlist; loopback & cloud metadata blocked',
    riskLevel: 'MEDIUM',
    requiresApproval: true,
    maxRuntimeMs: 30000,
    maxOutputBytes: 262144,
    auditCategory: 'NETWORK_DISCOVERY',
    description: 'Authorised host discovery ping sweep (-sn) against allowlisted CIDR or host.',
  },
  {
    id: 'linux.nmap.service_scan',
    command: 'nmap -sV -p <ports> <approved_target>',
    environment: 'linux_worker',
    requiredPermission: 'atlas:admin',
    requiredArgs: '-sV -p <ports> <approved_target>',
    targetRestrictions: 'Admin-only; allowlisted target; max 64 ports; NSE scripts prohibited',
    riskLevel: 'HIGH',
    requiresApproval: true,
    maxRuntimeMs: 45000,
    maxOutputBytes: 262144,
    auditCategory: 'NETWORK_SERVICE_SCAN',
    description: 'Authorised TCP port & service version identification (-sV) against allowlisted target.',
  },
  {
    id: 'linux.tshark.pcap',
    command: 'pcap summary|dns|conversations <file.pcap>',
    environment: 'linux_worker',
    requiredPermission: 'any_member',
    requiredArgs: '<summary|dns|conversations> <file.pcap>',
    targetRestrictions: 'Validated .pcap/.pcapng file in org-isolated sandbox (no live capture)',
    riskLevel: 'MEDIUM',
    requiresApproval: false,
    maxRuntimeMs: 25000,
    maxOutputBytes: 262144,
    auditCategory: 'PCAP_ANALYSIS',
    description: 'Run offline TShark analysis over an uploaded/staged PCAP in isolated workspace.',
  },
  {
    id: 'linux.python.defensive',
    command: 'py_analyze <ioc_stats|log_summary|csv_correlate> <dataset>',
    environment: 'linux_worker',
    requiredPermission: 'any_member',
    requiredArgs: '<preset> <dataset>',
    targetRestrictions: 'Fixed audited Python 3 defensive scripts only (-I -S -E, timeout capped)',
    riskLevel: 'MEDIUM',
    requiresApproval: false,
    maxRuntimeMs: 15000,
    maxOutputBytes: 131072,
    auditCategory: 'PYTHON_DEFENSIVE',
    description: 'Execute audited Python 3 defensive parser over staged JSON/CSV/PCAP-derived datasets.',
  },
];

export interface ParsedTerminalCommand {
  valid: boolean;
  raw: string;
  tokens: string[];
  verb: string;
  subcommand: string;
  args: string[];
  rejectionReason?: string;
}

/**
 * Structured non-shell tokenizer with strict metacharacter rejection.
 */
export function parseTerminalInput(rawCommand: string): ParsedTerminalCommand {
  const raw = rawCommand.trim();
  if (!raw) {
    return { valid: true, raw: '', tokens: [], verb: '', subcommand: '', args: [] };
  }

  if (raw.length > 512) {
    return {
      valid: false,
      raw,
      tokens: [],
      verb: '',
      subcommand: '',
      args: [],
      rejectionReason: 'Command exceeds maximum length (512 characters).',
    };
  }

  if (SHELL_METACHAR_PATTERN.test(raw)) {
    return {
      valid: false,
      raw,
      tokens: [],
      verb: '',
      subcommand: '',
      args: [],
      rejectionReason:
        'SHELL METACHARACTER BLOCKED: Chaining, pipes, redirection, subshells, and escapes are strictly prohibited.',
    };
  }

  // Safe whitespace / quoted-token splitter (no eval)
  const tokens: string[] = [];
  let current = '';
  let inQuote: '"' | "'" | null = null;
  for (let i = 0; i < raw.length; i++) {
    const ch = raw[i];
    if (inQuote) {
      if (ch === inQuote) {
        inQuote = null;
      } else {
        current += ch;
      }
    } else if (ch === '"' || ch === "'") {
      inQuote = ch;
    } else if (/\s/.test(ch)) {
      if (current.length > 0) {
        tokens.push(current);
        current = '';
      }
    } else {
      current += ch;
    }
  }
  if (inQuote) {
    return {
      valid: false,
      raw,
      tokens: [],
      verb: '',
      subcommand: '',
      args: [],
      rejectionReason: 'Malformed command: unterminated string quote.',
    };
  }
  if (current.length > 0) tokens.push(current);

  const verb = (tokens[0] || '').toLowerCase();
  const subcommand = (tokens[1] || '').toLowerCase();
  const args = tokens.slice(1);

  if (RESTRICTED_KEYWORDS.has(verb)) {
    return {
      valid: false,
      raw,
      tokens,
      verb,
      subcommand,
      args,
      rejectionReason: `RESTRICTED COMMAND "${verb}": Offensive tools, shells, and arbitrary OS binaries are blocked by security policy.`,
    };
  }

  return { valid: true, raw, tokens, verb, subcommand, args };
}

function ipToUint32(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let num = 0;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return null;
    const n = Number(p);
    if (n < 0 || n > 255) return null;
    num = (num << 8) + n;
  }
  return num >>> 0;
}

/**
 * Validates authorised reconnaissance targets.
 * Blocks loopback (127.0.0.0/8, ::1), link-local / cloud metadata (169.254.0.0/16),
 * unspecified (0.0.0.0/8), multicast/broadcast, and wide CIDRs (< /22).
 */
export function validateAuthorisedTarget(target: string): { valid: boolean; reason?: string } {
  const trimmed = target.trim();
  if (!trimmed) return { valid: false, reason: 'Target IP, CIDR, or hostname is required.' };
  if (trimmed.length > 128 || /[^a-zA-Z0-9.:/_-]/.test(trimmed)) {
    return { valid: false, reason: 'Target contains disallowed characters.' };
  }

  const lower = trimmed.toLowerCase();
  if (
    lower === 'localhost' ||
    lower.endsWith('.localhost') ||
    lower === '::1' ||
    lower.startsWith('fe80:') ||
    lower === 'metadata.google.internal' ||
    lower === '169.254.169.254' ||
    lower === '100.100.100.200'
  ) {
    return { valid: false, reason: `Target "${trimmed}" is blocked by safety policy (loopback/link-local/metadata prohibited).` };
  }

  // IPv4 or CIDR check
  const cidrMatch = trimmed.match(/^(\d{1,3}(?:\.\d{1,3}){3})(?:\/(\d{1,2}))?$/);
  if (cidrMatch) {
    const ip = cidrMatch[1];
    const prefix = cidrMatch[2] !== undefined ? Number(cidrMatch[2]) : 32;
    const u = ipToUint32(ip);
    if (u === null) return { valid: false, reason: `Malformed IPv4 address "${ip}".` };
    if (prefix < 22 || prefix > 32) {
      return {
        valid: false,
        reason: `CIDR prefix /${prefix} exceeds maximum scan scope (smallest permitted subnet prefix is /22).`,
      };
    }
    const firstOctet = (u >>> 24) & 0xff;
    const secondOctet = (u >>> 16) & 0xff;
    if (firstOctet === 127) {
      return { valid: false, reason: 'Loopback range (127.0.0.0/8) is blocked by policy.' };
    }
    if (firstOctet === 0) {
      return { valid: false, reason: 'Unspecified range (0.0.0.0/8) is blocked by policy.' };
    }
    if (firstOctet === 169 && secondOctet === 254) {
      return { valid: false, reason: 'Link-local / cloud metadata range (169.254.0.0/16) is blocked by policy.' };
    }
    if (firstOctet >= 224) {
      return { valid: false, reason: 'Multicast/reserved IPv4 ranges (224.0.0.0+) are blocked by policy.' };
    }
    return { valid: true };
  }

  // Hostname validation
  if (/^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/.test(trimmed)) {
    return { valid: true };
  }

  return { valid: false, reason: `Invalid or unsupported target format: "${trimmed}".` };
}

export function validatePcapFileName(fileName: string): { valid: boolean; reason?: string } {
  const trimmed = (fileName || '').trim();
  if (!trimmed) return { valid: false, reason: 'PCAP filename is required.' };
  if (trimmed.includes('/') || trimmed.includes('\\') || trimmed.includes('..')) {
    return { valid: false, reason: 'Path traversal or directory separators are prohibited in PCAP filename.' };
  }
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,95}\.(pcap|pcapng)$/i.test(trimmed)) {
    return { valid: false, reason: 'PCAP filename must end with .pcap or .pcapng and use safe alphanumeric characters.' };
  }
  return { valid: true };
}

export function validatePortSpec(spec: string): { valid: boolean; reason?: string } {
  if (!/^[0-9,-]{1,120}$/.test(spec)) {
    return { valid: false, reason: 'Invalid port list specification.' };
  }
  const segments = spec.split(',').filter(Boolean);
  if (segments.length === 0 || segments.length > 64) {
    return { valid: false, reason: 'Port specification must include between 1 and 64 port items.' };
  }
  let totalCount = 0;
  for (const seg of segments) {
    if (seg.includes('-')) {
      const [aStr, bStr, extra] = seg.split('-');
      if (extra !== undefined) return { valid: false, reason: `Malformed port range "${seg}".` };
      const a = Number(aStr);
      const b = Number(bStr);
      if (!Number.isInteger(a) || !Number.isInteger(b) || a < 1 || b > 65535 || a > b) {
        return { valid: false, reason: `Invalid port range "${seg}".` };
      }
      totalCount += b - a + 1;
    } else {
      const p = Number(seg);
      if (!Number.isInteger(p) || p < 1 || p > 65535) {
        return { valid: false, reason: `Invalid TCP port "${seg}".` };
      }
      totalCount += 1;
    }
    if (totalCount > 128) {
      return { valid: false, reason: 'Scan exceeds policy maximum of 128 TCP ports per job.' };
    }
  }
  return { valid: true };
}

export interface PolicyEvaluation {
  allowed: boolean;
  requiresApproval: boolean;
  environment: TerminalEnvironment;
  policy?: CommandPolicyDescriptor;
  riskLevel: CommandRiskLevel;
  normalizedTool?: string;
  normalizedArgs?: string[];
  target?: string;
  reason?: string;
}

const DIAG_VERBS = new Set(['sysinfo', 'interfaces', 'processes', 'services', 'disk', 'memory']);

export function evaluateCommandPolicy(
  rawCommand: string,
  environment: TerminalEnvironment,
  userRole: AppRole,
  options: { approvalGranted?: boolean } = {}
): PolicyEvaluation {
  const parsed = parseTerminalInput(rawCommand);
  if (!parsed.valid) {
    return {
      allowed: false,
      requiresApproval: false,
      environment,
      riskLevel: 'RESTRICTED',
      reason: parsed.rejectionReason || 'Command rejected by syntax guard.',
    };
  }
  if (!parsed.verb) {
    return {
      allowed: true,
      requiresApproval: false,
      environment,
      riskLevel: 'LOW',
    };
  }

  const { verb, subcommand, tokens } = parsed;

  // Detect wrong environment or Linux worker commands
  const isNmap = verb === 'nmap' || (verb === 'network' && subcommand === 'scan' && tokens[2] !== 'status' && tokens[2] !== 'results');
  const isPcap = verb === 'pcap';
  const isPyAnalyze = verb === 'py_analyze';
  const isDiag = DIAG_VERBS.has(verb) || (verb === 'network' && subcommand === 'interfaces');

  if (isNmap || isPcap || isPyAnalyze || isDiag) {
    if (environment !== 'linux_worker') {
      return {
        allowed: false,
        requiresApproval: false,
        environment,
        riskLevel: 'MEDIUM',
        reason: `Command "${verb}" belongs to the LINUX SECURITY WORKER environment. Switch environment selector to LINUX WORKER (atlas@linux-worker:~$).`,
      };
    }

    // ---- Linux Worker: System Diagnostics ----
    if (isDiag) {
      const policy = COMMAND_POLICY_REGISTRY.find((p) => p.id === 'linux.diag.sysinfo')!;
      const toolName = verb === 'network' ? 'interfaces' : verb;
      if (tokens.length > (verb === 'network' ? 2 : 1)) {
        return {
          allowed: false,
          requiresApproval: false,
          environment,
          policy,
          riskLevel: 'RESTRICTED',
          reason: `Diagnostic command "${toolName}" accepts no arbitrary arguments.`,
        };
      }
      return {
        allowed: true,
        requiresApproval: false,
        environment,
        policy,
        riskLevel: 'LOW',
        normalizedTool: toolName,
        normalizedArgs: [],
        target: 'linux-worker-container',
      };
    }

    // ---- Linux Worker: Nmap ----
    if (isNmap) {
      // Shorthand alias: network scan <target> -> nmap -sn <target>
      const effectiveArgs = verb === 'network' ? ['-sn', ...tokens.slice(2)] : tokens.slice(1);
      if (effectiveArgs.length === 1 && (effectiveArgs[0] === '--help' || effectiveArgs[0] === '-h')) {
        const policy = COMMAND_POLICY_REGISTRY.find((p) => p.id === 'linux.nmap.help')!;
        return {
          allowed: true,
          requiresApproval: false,
          environment,
          policy,
          riskLevel: 'LOW',
          normalizedTool: 'nmap',
          normalizedArgs: ['--help'],
          target: 'local-help',
        };
      }

      // Block NSE scripts and raw/intrusive flags strictly
      for (const arg of effectiveArgs) {
        const lowerArg = arg.toLowerCase();
        if (
          lowerArg.startsWith('--script') ||
          lowerArg === '-sc' ||
          lowerArg === '-a' ||
          lowerArg === '-o' ||
          lowerArg.startsWith('-o') ||
          lowerArg === '-su' ||
          lowerArg.startsWith('--datadir') ||
          lowerArg.startsWith('-iflist') ||
          lowerArg.includes('script')
        ) {
          return {
            allowed: false,
            requiresApproval: false,
            environment,
            riskLevel: 'RESTRICTED',
            reason: `Blocked Nmap flag "${arg}": NSE scripts, OS fingerprinting, UDP floods, and file-output redirection flags are prohibited.`,
          };
        }
      }

      // Extract target (last non-flag token)
      const target = effectiveArgs[effectiveArgs.length - 1] || '';
      const flags = effectiveArgs.slice(0, -1);
      if (!target || target.startsWith('-')) {
        return {
          allowed: false,
          requiresApproval: false,
          environment,
          riskLevel: 'MEDIUM',
          reason: 'Usage: `nmap --help`, `nmap -sn <cidr|host>`, or `nmap -sV -p <ports> <cidr|host>`.',
        };
      }

      const targetCheck = validateAuthorisedTarget(target);
      if (!targetCheck.valid) {
        return {
          allowed: false,
          requiresApproval: false,
          environment,
          riskLevel: 'RESTRICTED',
          reason: targetCheck.reason,
        };
      }

      // Profile 1: Ping sweep `-sn <target>`
      if (flags.length === 1 && flags[0] === '-sn') {
        const policy = COMMAND_POLICY_REGISTRY.find((p) => p.id === 'linux.nmap.discovery')!;
        if (policy.requiresApproval && !options.approvalGranted) {
          return {
            allowed: false,
            requiresApproval: true,
            environment,
            policy,
            riskLevel: policy.riskLevel,
            normalizedTool: 'nmap',
            normalizedArgs: ['-sn', '-oX', '-', target],
            target,
            reason: `Explicit operator approval required for MEDIUM-risk network discovery scan against "${target}".`,
          };
        }
        return {
          allowed: true,
          requiresApproval: false,
          environment,
          policy,
          riskLevel: policy.riskLevel,
          normalizedTool: 'nmap',
          normalizedArgs: ['-sn', '-oX', '-', target],
          target,
        };
      }

      // Profile 2: Service version scan `-sV -p <ports> <target>`
      if (flags.length === 3 && flags[0] === '-sV' && flags[1] === '-p') {
        const policy = COMMAND_POLICY_REGISTRY.find((p) => p.id === 'linux.nmap.service_scan')!;
        if (userRole !== 'atlas:admin') {
          return {
            allowed: false,
            requiresApproval: false,
            environment,
            policy,
            riskLevel: 'HIGH',
            reason: 'PERMISSION DENIED: TCP service/version scan (`nmap -sV`) requires `atlas:admin` role.',
          };
        }
        const portCheck = validatePortSpec(flags[2]);
        if (!portCheck.valid) {
          return {
            allowed: false,
            requiresApproval: false,
            environment,
            policy,
            riskLevel: 'RESTRICTED',
            reason: portCheck.reason,
          };
        }
        if (policy.requiresApproval && !options.approvalGranted) {
          return {
            allowed: false,
            requiresApproval: true,
            environment,
            policy,
            riskLevel: 'HIGH',
            normalizedTool: 'nmap',
            normalizedArgs: ['-sV', '-Pn', '--version-light', '-p', flags[2], '-oX', '-', target],
            target,
            reason: `Explicit Admin approval required for HIGH-risk TCP service scan (-sV -p ${flags[2]}) on "${target}".`,
          };
        }
        return {
          allowed: true,
          requiresApproval: false,
          environment,
          policy,
          riskLevel: 'HIGH',
          normalizedTool: 'nmap',
          normalizedArgs: ['-sV', '-Pn', '--version-light', '-p', flags[2], '-oX', '-', target],
          target,
        };
      }

      return {
        allowed: false,
        requiresApproval: false,
        environment,
        riskLevel: 'RESTRICTED',
        reason: 'Unsupported Nmap profile. Approved profiles: `nmap --help`, `nmap -sn <target>`, `nmap -sV -p <ports> <target>`.',
      };
    }

    // ---- Linux Worker: TShark PCAP Analysis ----
    if (isPcap) {
      const policy = COMMAND_POLICY_REGISTRY.find((p) => p.id === 'linux.tshark.pcap')!;
      if (!['summary', 'dns', 'conversations'].includes(subcommand)) {
        return {
          allowed: false,
          requiresApproval: false,
          environment,
          policy,
          riskLevel: 'MEDIUM',
          reason: 'Usage: `pcap <summary|dns|conversations> <filename.pcap>` (offline uploaded captures only; live interface sniffing disabled).',
        };
      }
      const fileArg = tokens[2] || '';
      const fileCheck = validatePcapFileName(fileArg);
      if (!fileCheck.valid) {
        return {
          allowed: false,
          requiresApproval: false,
          environment,
          policy,
          riskLevel: 'RESTRICTED',
          reason: fileCheck.reason,
        };
      }
      return {
        allowed: true,
        requiresApproval: false,
        environment,
        policy,
        riskLevel: policy.riskLevel,
        normalizedTool: 'tshark',
        normalizedArgs: [subcommand, fileArg],
        target: fileArg,
      };
    }

    // ---- Linux Worker: Isolated Python Defensive Analysis ----
    if (isPyAnalyze) {
      const policy = COMMAND_POLICY_REGISTRY.find((p) => p.id === 'linux.python.defensive')!;
      const preset = subcommand;
      const dataset = tokens[2] || '';
      if (!['ioc_stats', 'log_summary', 'csv_correlate'].includes(preset) || !dataset) {
        return {
          allowed: false,
          requiresApproval: false,
          environment,
          policy,
          riskLevel: 'MEDIUM',
          reason: 'Usage: `py_analyze <ioc_stats|log_summary|csv_correlate> <staged_file_or_job_id>`. Arbitrary inline Python `-c` is prohibited.',
        };
      }
      if (/[/\\]|\.\./.test(dataset) || !/^[a-zA-Z0-9._-]{1,96}$/.test(dataset)) {
        return {
          allowed: false,
          requiresApproval: false,
          environment,
          policy,
          riskLevel: 'RESTRICTED',
          reason: 'Invalid Python dataset identifier (path traversal characters prohibited).',
        };
      }
      return {
        allowed: true,
        requiresApproval: false,
        environment,
        policy,
        riskLevel: policy.riskLevel,
        normalizedTool: 'py_analyze',
        normalizedArgs: [preset, dataset],
        target: dataset,
      };
    }
  }

  // ---- ATLAS NATIVE COMMANDS ----
  if (environment === 'linux_worker') {
    return {
      allowed: false,
      requiresApproval: false,
      environment,
      riskLevel: 'LOW',
      reason: `"${verb}" is an ATLAS-native intelligence command. Switch environment selector to ATLAS NATIVE (atlas@soc:~$), or run Linux Worker commands (\`nmap\`, \`pcap\`, \`sysinfo\`, \`interfaces\`, \`processes\`, \`services\`, \`disk\`, \`memory\`, \`py_analyze\`).`,
    };
  }

  const descriptorId = resolveAtlasPolicyId(verb, subcommand, tokens);
  if (!descriptorId) {
    return {
      allowed: false,
      requiresApproval: false,
      environment,
      riskLevel: 'RESTRICTED',
      reason: `Unrecognised or non-allowlisted command "${verb}". Type \`help\` to view permitted ATLAS-native commands.`,
    };
  }

  const policy = COMMAND_POLICY_REGISTRY.find((p) => p.id === descriptorId);
  return {
    allowed: true,
    requiresApproval: false,
    environment,
    policy,
    riskLevel: policy?.riskLevel || 'LOW',
    normalizedTool: 'atlas_native',
    normalizedArgs: tokens,
  };
}

function resolveAtlasPolicyId(verb: string, sub: string, tokens: string[]): string | null {
  switch (verb) {
    case 'help':
    case '?':
      return 'atlas.help';
    case 'status':
      return 'atlas.status';
    case 'workspace':
      return 'atlas.workspace';
    case 'whoami':
      return 'atlas.whoami';
    case 'history':
      return 'atlas.history';
    case 'clear':
      return 'atlas.clear';
    case 'assets':
      return sub === 'search' ? 'atlas.assets.search' : 'atlas.assets.list';
    case 'asset':
      if (sub === 'inspect') return 'atlas.asset.inspect';
      if (sub === 'dependencies') return 'atlas.asset.dependencies';
      if (sub === 'exposure') return 'atlas.asset.exposure';
      return null;
    case 'incidents':
      return 'atlas.incidents.list';
    case 'incident':
      if (sub === 'inspect') return 'atlas.incident.inspect';
      if (sub === 'timeline') return 'atlas.incident.timeline';
      if (sub === 'assets') return 'atlas.incident.assets';
      return null;
    case 'ioc':
      return 'atlas.ioc.lookup';
    case 'cti':
      if (sub === 'status') return 'atlas.cti.status';
      if (sub === 'expired') return 'atlas.cti.expired';
      if (sub === 'provider') return 'atlas.cti.provider';
      return null;
    case 'threat':
      return sub === 'correlate' ? 'atlas.threat.correlate' : null;
    case 'attribution':
      return 'atlas.attribution';
    case 'dns':
    case 'rep':
      return 'atlas.dns_rep';
    case 'geo':
      if (sub === 'locate') return 'atlas.geo.locate';
      if (sub === 'nearby') return 'atlas.geo.nearby';
      if (sub === 'exposure') return 'atlas.geo.exposure';
      if (sub === 'cluster') return 'atlas.geo.cluster';
      if (sub === 'blast-radius') return 'atlas.geo.blast_radius';
      return null;
    case 'resilience':
      if (sub === 'assess') return 'atlas.resilience.assess';
      if (sub === 'dependencies') return 'atlas.resilience.dependencies';
      if (sub === 'simulate') return 'atlas.resilience.simulate';
      return null;
    case 'investigation':
      return sub === 'open' || sub === 'correlate' ? 'atlas.investigation' : null;
    case 'report':
      return ['incident', 'network', 'resilience'].includes(sub) ? 'atlas.report' : null;
    case 'network':
      if (sub === 'status') return 'atlas.network.status';
      if (sub === 'scan' && (tokens[2] === 'status' || tokens[2] === 'results')) {
        return 'atlas.network.scan.inspect';
      }
      return null;
    case 'netflow':
    case 'blast':
    case 'remote':
      return 'atlas.status'; // legacy supported read-only aliases
    default:
      return null;
  }
}
