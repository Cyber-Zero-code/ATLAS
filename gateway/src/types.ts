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

export type CtiSourceId = 'ALIENVAULT_OTX' | 'ABUSE_CH' | 'MISP' | 'TAXII_2_1';

export type NormalizedCtiIndicatorType =
  | 'ip'
  | 'cidr'
  | 'domain'
  | 'hostname'
  | 'url'
  | 'hash'
  | 'certificate'
  | 'malware'
  | 'threat_actor'
  | 'cve';

export interface CtiConfig {
  otxApiKey?: string;
  abuseChAuthKey?: string;
  mispUrl?: string;
  mispApiKey?: string;
  taxiiApiRoot?: string;
  taxiiCollectionId?: string;
}

export interface NormalizedCtiIndicator {
  type: NormalizedCtiIndicatorType;
  value: string;
  source: CtiSourceId;
  source_ref: string;
  first_seen: string;
  last_seen: string | null;
  confidence: number;
  tags: string[];
}

export interface CtiSourceStatus {
  id: CtiSourceId;
  configured: boolean;
  state: 'unconfigured' | 'live' | 'failing';
  cached: boolean;
  indicatorCount: number;
  error?: string;
  checkedAtUtc?: string;
}

export interface CtiFailedSource {
  source: CtiSourceId;
  reason: string;
}

export interface CameraAnalyticsConfig {
  analyticsUrl?: string;
  analyticsApiKey?: string;
}

export type CameraRetentionSetting = 'none' | '1h' | '24h' | '7d' | '30d';
export type CameraProtocol = 'ONVIF' | 'RTSP_WEBRTC' | 'RTSP_HLS';
export type CameraStreamState = 'registered' | 'streaming' | 'offline' | 'stopped';

export interface CameraRegistrationInput {
  cameraId?: string;
  siteId?: string;
  siteCode?: string;
  cameraCode: string;
  name: string;
  protocol: CameraProtocol;
  streamUrl: string;
  retentionSetting?: CameraRetentionSetting;
  legalBasisRef?: string;
  adminAcceptWithoutLegalBasis?: boolean;
  autoStart?: boolean;
}

export interface CameraBoundingBox {
  x: number;
  y: number;
  w: number;
  h: number;
}

export interface CameraFaceObservation {
  confidence: number;
  box: CameraBoundingBox;
  recognizedIdentityId?: string;
  recognizedLabel?: string;
  biometricSimilarity?: number;
}

export interface CameraPersonObservation {
  trackId: string;
  confidence: number;
  box: CameraBoundingBox;
  identityId?: string;
  personLabel?: string;
  crossCameraSeenIn?: string[];
}

export interface CameraPersonAlert {
  alertId: string;
  cameraId: string;
  cameraCode: string;
  personLabel: string;
  identityId?: string;
  trackId?: string;
  confidence: number;
  reason: string;
  triggeredAtUtc: string;
}

export interface CameraAnalyticsResult {
  status: 'ANALYZED' | 'ANALYTICS_UNAVAILABLE';
  unavailableReason?: string;
  analyzedAtUtc: string;
  faceCount: number;
  personCount: number;
  faces: CameraFaceObservation[];
  persons: CameraPersonObservation[];
  alerts: CameraPersonAlert[];
}

export interface SanitizedCameraRecord {
  cameraId: string;
  orgId: string;
  siteId?: string;
  siteCode?: string;
  cameraCode: string;
  name: string;
  protocol: CameraProtocol;
  retentionSetting: CameraRetentionSetting;
  legalBasisRef?: string;
  adminAcceptedWithoutLegalBasis: boolean;
  adminAcceptedBy?: string;
  status: CameraStreamState;
  consecutiveFailures: number;
  offlineReason?: string;
  lastFrameAtUtc?: string;
  hasLatestFrame: boolean;
  storedFramesCount: number;
  latestAnalytics?: CameraAnalyticsResult;
}

export interface CameraAuditRecord {
  id: string;
  orgId: string;
  userId: string;
  actorRole: string;
  action: 'CAMERA_FRAME_VIEW' | 'CAMERA_RETENTION_DELETE' | 'CAMERA_LEGAL_OVERRIDE' | 'CAMERA_PERSON_ALERT';
  cameraId: string;
  observedAtUtc: string;
  details: Record<string, unknown>;
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
  cti?: CtiConfig;
  cameraAnalytics?: CameraAnalyticsConfig;
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
