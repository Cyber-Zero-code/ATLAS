/**
 * Gateway Domain Contracts
 */

export type AppRole = 'atlas:admin' | 'atlas:analyst';
export type CommandRiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'RESTRICTED';

export interface AuthenticatedContext {
  userId: string;
  email?: string;
  orgId: string;
  role: AppRole;
  aal: 'aal2';
  tokenExpiresAt: number;
}

export interface GatewayConfig {
  host: string;
  port: number;
  tlsCertPath?: string;
  tlsKeyPath?: string;
  corsOrigin: string;
  supabaseUrl: string;
  supabaseAnonKey: string;
  jwtIssuer?: string;
  jwtAudience: string;
  jwksUrl?: string;
  jwksJson?: string;
  jwtHs256Secret?: string;
  targetAllowlist: string[];
  workDir: string;
  maxConcurrentJobs: number;
  maxPcapBytes: number;
}

export interface LinuxToolDescriptor {
  id: string;
  name: string;
  category: 'reconnaissance' | 'packet_analysis' | 'diagnostics' | 'python_analysis' | 'future_adapter';
  installed: boolean;
  available: boolean;
  version: string | null;
  lastHealthCheckUtc: string | null;
  requiredPermission: AppRole | 'any_member';
  supportedOperations: string[];
  unavailableReason?: string;
}

export interface NmapDiscoveredPort {
  port: number;
  protocol: 'tcp' | 'udp';
  state: string;
  service: string;
  version?: string;
}

export interface NmapDiscoveredHost {
  ip: string;
  hostname?: string;
  state: string;
  ports: NmapDiscoveredPort[];
}

export interface NmapParsedResult {
  scannerArgs: string;
  startedAtUtc: string;
  hosts: NmapDiscoveredHost[];
  openPortsCount: number;
}

export interface TsharkParsedResult {
  operation: 'summary' | 'dns' | 'conversations';
  fileName: string;
  packetCount: number;
  uniqueIps: string[];
  dnsQueries: Array<{ query: string; type?: string; count: number }>;
  conversations: Array<{ src: string; dst: string; protocol: string; frames: number; bytes: number }>;
  protocols: Array<{ name: string; frames: number }>;
}

export interface GatewayJobRecord {
  jobId: string;
  userId: string;
  orgId: string;
  tool: string;
  command: string;
  args: string[];
  target: string;
  riskLevel: CommandRiskLevel;
  approvalState: 'not_required' | 'explicit_operator_approved';
  approvalJustification?: string;
  status: 'queued' | 'running' | 'completed' | 'failed' | 'cancelled' | 'timed_out' | 'blocked_by_policy';
  startedAtUtc: string;
  endedAtUtc?: string;
  durationMs?: number;
  exitCode?: number | null;
  stdoutLines: string[];
  stderrLines: string[];
  resultSummary?: string;
  errorSummary?: string;
  nmapParsed?: NmapParsedResult;
  tsharkParsed?: TsharkParsedResult;
  recordClassification: 'EXTERNAL_GATEWAY_EXECUTION_RECORD';
}

export interface GatewayJobRequest {
  tool: string;
  args: string[];
  target?: string;
  orgId?: string;
  approvalConfirmed?: boolean;
  approvalJustification?: string;
}

export interface ValidatedExecutionSpec {
  allowed: boolean;
  binaryKey:
    | 'nmap'
    | 'tshark'
    | 'sysinfo'
    | 'interfaces'
    | 'processes'
    | 'services'
    | 'disk'
    | 'memory'
    | 'py_analyze';
  fixedArgs: string[];
  target: string;
  riskLevel: CommandRiskLevel;
  maxRuntimeMs: number;
  maxOutputBytes: number;
  requiresApproval: boolean;
  rejectionReason?: string;
}
