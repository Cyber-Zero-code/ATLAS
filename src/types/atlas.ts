/**
 * Project ATLAS: Core Data Model & Unified Platform Types
 */

export type OrgKind = 'standalone' | 'firm' | 'client';
export type AppRole = 'atlas:admin' | 'atlas:analyst';

export interface Organization {
  id: string;
  name: string;
  code: string;
  kind: OrgKind;
  parent_firm_id: string | null;
  source: string;
  created_at: string;
  confidence: number;
  sharing_policy: string;
  correlation_id: string;
}

export interface Membership {
  id: string;
  user_id: string;
  org_id: string;
  role: AppRole;
  source: string;
  created_at: string;
  confidence: number;
  sharing_policy: string;
  correlation_id: string;
  organization?: Organization;
}

export interface AuditEvent {
  id: string;
  org_id: string;
  seq: number;
  timestamp: string;
  timestamp_text: string;
  actor_id: string | null;
  actor_role: string;
  action: string;
  target_type: string;
  target_id: string;
  correlation_id: string;
  payload_hash: string;
  prev_hash: string;
  record_hash: string;
  details: Record<string, unknown>;
}

export interface AuditVerificationResult {
  is_valid: boolean;
  first_bad_seq: number | null;
  reason: string;
  total_verified: number;
}

export interface AuditCheckpointRecord {
  org_id: string;
  seq: number;
  record_hash: string;
  recorded_at: string;
  note: string;
}

export interface IngestKeyRecord {
  key_id: string;
  status: string;
  created_at: string;
  revoked_at: string | null;
  expires_at: string | null;
}

export interface UserSession {
  user_id: string;
  email: string;
  aal: 'aal1' | 'aal2';
  activeOrgId: string;
  activeRole: AppRole;
  memberships: Membership[];
}

export type AssetType = 'site' | 'power_feed' | 'fibre_route' | 'cloud_region' | 'service';
export type AccuracyClass = 'exact_survey' | 'facility_approximate' | 'regional_approximate';

export interface Asset {
  id: string;
  org_id: string;
  dataset_id?: string | null;
  site_code: string;
  name: string;
  type: AssetType;
  criticality: number; // 1 to 5
  owner: string;
  accuracy_class: AccuracyClass;
  positional_accuracy_m?: number | null;
  identifiers: {
    hostnames?: string[];
    ip_addresses?: string[];
    cidrs?: string[];
    cloud_account_ids?: string[];
  };
  source: string;
  created_at: string;
  confidence: number;
  sharing_policy: string;
  correlation_id: string;
}

export interface WorkspaceGeoJsonFeature {
  type: 'Feature';
  id: string;
  geometry: {
    type: string;
    coordinates: any;
  } | null;
  properties: {
    id: string;
    site_code: string;
    name: string;
    type: AssetType;
    criticality: number;
    owner: string;
    accuracy_class: AccuracyClass;
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
  };
}

export interface WorkspaceGeoJsonCollection {
  type: 'FeatureCollection';
  features: WorkspaceGeoJsonFeature[];
}

export interface DependencyEdge {
  id: string;
  org_id: string;
  from_asset_id: string;
  to_asset_id: string;
  relation_type: 'powers' | 'hosts' | 'connects_to' | 'supplies' | 'monitors' | 'cools';
  criticality: number; // 1 to 5
  valid_from: string;
  valid_to?: string | null;
  source: string;
  created_at: string;
  confidence: number;
  sharing_policy: string;
  correlation_id: string;
}

export interface Incident {
  id: string;
  org_id: string;
  event_id: string;
  schema_version: string;
  event_type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  observed_at: string;
  signals: Record<string, unknown>;
  source: string;
  created_at: string;
  confidence: number;
  sharing_policy: string;
  correlation_id: string;
}

export interface AssetMatch {
  id: string;
  org_id: string;
  incident_id: string;
  asset_id: string;
  rule_fired: string;
  score: number;
  status: 'auto' | 'proposed' | 'confirmed' | 'rejected';
  decided_by?: string | null;
  decided_at?: string | null;
  source: string;
  created_at: string;
  confidence: number;
  sharing_policy: string;
  correlation_id: string;
  asset?: Asset;
}

export interface BlastRadiusNode {
  asset_id: string;
  site_code: string;
  name: string;
  type: AssetType;
  criticality: number;
  accuracy_class: AccuracyClass;
  hop_depth: number;
  c: number;
  r: number;
  i_factor: number;
  exposure: number;
  likelihood: number;
  calibration_status: string;
  priority: number;
  range_low: number;
  range_high: number;
  path: Array<{
    asset_id: string;
    relation_type: string;
  }>;
  root_asset_id: string;
  match_id: string;
  match_status: string;
  match_confidence: number;
}

export interface CustodyEvent {
  id: string;
  org_id: string;
  evidence_id: string;
  event_type: 'INTAKE' | 'VERIFY_HASH' | 'ACCESS' | 'TRANSFERRED' | 'RETENTION_FLAG';
  actor_id: string;
  sha256_verified: string;
  details: Record<string, any>;
  source: string;
  created_at: string;
  confidence: number;
  sharing_policy: string;
  correlation_id: string;
}

export interface Evidence {
  id: string;
  org_id: string;
  target_type: string;
  target_id: string;
  file_name: string;
  file_path: string;
  file_size_bytes: number;
  mime_type: string;
  sha256: string;
  uploader_id: string;
  source: string;
  created_at: string;
  confidence: number;
  sharing_policy: string;
  correlation_id: string;
  custody_events?: CustodyEvent[];
}

export interface TimelineEvent {
  event_id: string;
  seq: number;
  timestamp: string;
  action: string;
  actor_id: string | null;
  actor_role: string;
  target_type: string;
  target_id: string;
  payload_hash: string;
  prev_hash: string;
  record_hash: string;
  details: Record<string, any>;
}

export interface SchemaValidationResult {
  valid: boolean;
  checkedTables: string[];
  missingTables: string[];
  missingColumns: string[];
  error?: string;
}

export interface DatasetRecord {
  id: string;
  org_id: string;
  name: string;
  source: string;
  licence: string;
  declared_crs: string;
  validation_report: Record<string, unknown>;
  row_count: number;
  created_at: string;
  confidence: number;
  sharing_policy: string;
  correlation_id: string;
}

export interface ScoringConfigRecord {
  id: string;
  org_id: string;
  config_key: string;
  weight: number;
  scale: number;
  calibration_status: string;
  description: string;
  source: string;
  created_at: string;
}

export type ModuleGroupId =
  | 'command'
  | 'geoint'
  | 'cyber'
  | 'analysis'
  | 'ai'
  | 'admin';

export type ModuleId =
  // COMMAND
  | 'command_centre'
  | 'operational_overview'
  | 'mission_workspace'
  // GEOSPATIAL INTELLIGENCE
  | 'global_map'
  | 'satellite_imagery'
  | 'terrain_intelligence'
  | 'infrastructure_mapping'
  | 'asset_tracking'
  | 'geographic_risk'
  // CYBER INTELLIGENCE
  | 'threat_intelligence'
  | 'cyber_monitoring'
  | 'vulnerability_intelligence'
  | 'attack_surface'
  | 'cyber_incidents'
  | 'ioc_investigation'
  // INTELLIGENCE ANALYSIS
  | 'entity_intelligence'
  | 'relationship_graph'
  | 'network_analysis'
  | 'geospatial_correlation'
  | 'intelligence_reports'
  // AI & MACHINE LEARNING
  | 'predictive_risk'
  | 'anomaly_detection'
  | 'behavioural_analysis'
  | 'ai_assistant'
  | 'model_performance'
  // SYSTEM ADMINISTRATION
  | 'user_management'
  | 'roles_permissions'
  | 'audit_logs'
  | 'data_sources'
  | 'system_configuration';

export type SelectedEntity =
  | { kind: 'asset'; id: string }
  | { kind: 'incident'; id: string }
  | { kind: 'evidence'; id: string }
  | { kind: 'indicator'; value: string; indicatorType: 'hostname' | 'ip' | 'cidr' | 'cloud_account' | 'site_code' }
  | null;

export interface GisCustomSource {
  id: string;
  name: string;
  protocol: 'GeoJSON' | 'WMS' | 'WMTS' | 'XYZ_RASTER';
  url: string;
  layerName?: string;
  enabled: boolean;
  attribution: string;
}

export type ClassificationLevel =
  | 'INTERNAL // RESTRICTED'
  | 'CLIENT CONFIDENTIAL'
  | 'TLP:AMBER+STRICT'
  | 'TLP:GREEN'
  | 'UNCLASSIFIED // DEMO';

// ============================================================================
// Module A: Hybrid Defensive & Security Operations Terminal Types
// ============================================================================

export type TerminalEnvironment = 'atlas_native' | 'linux_worker';

export type GatewayConnectionState =
  | 'NOT_CONFIGURED'
  | 'OFFLINE'
  | 'CONNECTING'
  | 'AUTHENTICATED'
  | 'READY'
  | 'EXECUTING'
  | 'COMPLETED'
  | 'FAILED'
  | 'BLOCKED_BY_POLICY';

export type CommandRiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'RESTRICTED';

export interface CommandPolicyDescriptor {
  id: string;
  command: string;
  environment: TerminalEnvironment;
  requiredPermission: AppRole | 'any_member';
  requiredArgs: string;
  targetRestrictions: string;
  riskLevel: CommandRiskLevel;
  requiresApproval: boolean;
  maxRuntimeMs: number;
  maxOutputBytes: number;
  auditCategory: string;
  description: string;
}

export interface RemoteTerminalAdapter {
  id: string;
  label: string;
  protocol: string;
  status: 'awaiting_authorised_connection' | 'not_configured' | 'connected';
  requiredConfiguration: string;
}

export interface TerminalOutputLine {
  text: string;
  tone?: 'normal' | 'accent' | 'ok' | 'warn' | 'err' | 'muted';
  entityRef?: SelectedEntity;
}

export interface TerminalCommandResult {
  id: string;
  command: string;
  environment?: TerminalEnvironment;
  policyId?: string;
  riskLevel?: CommandRiskLevel;
  timestampUtc: string;
  scopeLabel: string;
  status: 'ok' | 'rejected' | 'unavailable' | 'blocked_by_policy' | 'approval_required' | 'failed';
  durationMs?: number;
  exportReportMarkdown?: string;
  correlation?: AtlasTerminalCorrelation;
  lines: TerminalOutputLine[];
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

export interface GatewayHealthSnapshot {
  state: GatewayConnectionState;
  endpointUrl: string | null;
  authenticatedUserId: string | null;
  authenticatedOrgId: string | null;
  authenticatedRole: AppRole | null;
  checkedAtUtc: string | null;
  tools: LinuxToolDescriptor[];
  errorMessage?: string;
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

export interface AtlasTerminalCorrelation {
  sourceTool: 'nmap' | 'tshark' | 'atlas_native';
  collectedAtUtc: string;
  matchedAssetIds: string[];
  unmatchedObservedIps: string[];
  matchedIncidentIds: string[];
  matchedCtiValues: string[];
  downstreamAssetCount: number;
  notes: string[];
  provenanceNote: string;
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
  correlation?: AtlasTerminalCorrelation;
  recordClassification: 'EXTERNAL_GATEWAY_EXECUTION_RECORD';
}

// ============================================================================
// Module B: Evidence-Based Infrastructure Attribution Types
// ============================================================================

export type AttributionClass =
  | 'observed_technical'
  | 'suspected_relationship'
  | 'assessed_threat_group'
  | 'verified_identity';

export type AttributionIndicatorKind =
  | 'ip_address'
  | 'domain'
  | 'hostname'
  | 'network_infra'
  | 'malware_indicator'
  | 'certificate'
  | 'threat_group';

export type AttributionReviewStatus =
  | 'active_review'
  | 'corroborated'
  | 'contested'
  | 'archived';

export interface AttributionRecord {
  id: string;
  orgId: string;
  indicatorValue: string;
  indicatorType: AttributionIndicatorKind;
  attributionClass: AttributionClass;
  entityLabel: string;
  relationshipType: string;
  observedTimestamp: string;
  source: string;
  evidenceRef: string;
  incidentId?: string;
  assetId?: string;
  confidence: number;
  status: AttributionReviewStatus;
  analystNotes: string;
  createdBy: string;
  createdAt: string;
  draftMarkedAt?: string;
}

// ============================================================================
// Module C: Geospatial, Elevation & Camera Gateway Types
// ============================================================================

export interface CameraRegistryItem {
  id: string;
  cameraCode: string;
  name: string;
  protocol: 'ONVIF' | 'RTSP_WEBRTC' | 'RTSP_HLS';
  lng: number;
  lat: number;
  bearingDeg: number;
  fovDeg: number;
  rangeMeters: number;
  connectionState?: 'registered' | 'configured' | 'connected' | 'operational';
  streamStatus: string;
  endpointUrl?: string;
}

export interface GisAdapterCatalogEntry {
  id: string;
  label: string;
  category: 'DEM_ELEVATION' | 'SATELLITE_IMAGERY' | 'NATIONAL_GIS' | 'VECTOR_OVERLAY';
  protocol: 'WMS' | 'WMTS' | 'XYZ_RASTER' | 'GeoJSON';
  status: 'requires_operator_endpoint' | 'local_upload_ready';
  endpointPlaceholder: string;
  licenceNote: string;
  capabilityEffect: string;
}

// ============================================================================
// Module D: Threat Intelligence Feed Adapters Types
// ============================================================================

export type CtiProviderId =
  | 'STIX_2_1'
  | 'CISA_KEV'
  | 'MISP'
  | 'TAXII_2_1'
  | 'ALIENVAULT_OTX'
  | 'ABUSE_CH';

export interface CtiAdapterDescriptor {
  id: CtiProviderId;
  name: string;
  protocol: string;
  status: 'local_bundle_ready' | 'deferred_phase_2';
  requiresServerProxy: boolean;
  deferredExplanation?: string;
  credentialRequirement: string;
  description: string;
}

export type ExternalIocKind =
  | 'ip'
  | 'cidr'
  | 'domain'
  | 'hostname'
  | 'hash'
  | 'certificate'
  | 'malware'
  | 'threat_actor'
  | 'cve';

export interface ExternalThreatIndicator {
  id: string;
  orgId: string;
  providerId: CtiProviderId;
  stixId?: string;
  indicatorType: ExternalIocKind;
  value: string;
  sourceName: string;
  confidence: number;
  validFrom: string;
  validUntil?: string;
  isExpired: boolean;
  isExternalIntel: true;
  verificationStatus: 'unverified' | 'verified_by_analyst' | 'false_positive';
  matchedAssetIds: string[];
  matchedIncidentIds: string[];
  rawSummary: string;
  importedAt: string;
}

// ============================================================================
// Module E: Computational Geospatial Analysis Types
// ============================================================================

export interface BufferIntersectAsset {
  assetId: string;
  siteCode: string;
  name: string;
  type: AssetType;
  criticality: number;
  accuracyClass: AccuracyClass;
  distanceKm: number;
  bearingDeg: number;
}

export interface BufferAnalysisResult {
  center: [number, number];
  radiusKm: number;
  ringPolygon: Array<[number, number]>;
  intersectingAssets: BufferIntersectAsset[];
  linkedIncidentIds: string[];
  hasApproximateAssets: boolean;
}

export interface SpatialCluster {
  id: string;
  centroid: [number, number];
  cellLabel: string;
  assetIds: string[];
  incidentCount: number;
  maxCriticality: number;
  accuracy: {
    exact: number;
    facilityApprox: number;
    regionalApprox: number;
  };
}

export interface ConcentrationCell {
  cellId: string;
  center: [number, number];
  assetCount: number;
  tier4PlusCount: number;
  coLocatedPairs: number;
  incidentLinkCount: number;
  densityIndex: number;
}

// ============================================================================
// Module F: Infrastructure Resilience & Cascading Failure Types
// ============================================================================

export interface ResilienceAssetProfile {
  assetId: string;
  siteCode: string;
  name: string;
  type: AssetType;
  criticality: number;
  accuracyClass: AccuracyClass;
  powerUpstreamCount: number;
  telecomUpstreamCount: number;
  otherUpstreamCount: number;
  totalUpstreamCount: number;
  downstreamDependentCount: number;
  uniqueProviderTypes: number;
  isSinglePointOfFailure: boolean;
  spofReason?: string;
  coLocatedCriticalCount: number;
  activeIncidentExposureCount: number;
  backupRecoveryStatus: 'NO_VERIFIED_DATA';
  structuralVulnerabilityScore: number;
}

export interface CascadeImpactedAsset {
  assetId: string;
  siteCode: string;
  name: string;
  type: AssetType;
  criticality: number;
  hopDepth: number;
  viaRelation: string;
  activeIncidents: number;
}

export interface FailureScenarioResult {
  failedAssetIds: string[];
  directDependentsCount: number;
  totalCascadingOutageCount: number;
  powerCascadeCount: number;
  telecomCascadeCount: number;
  tier4PlusAffectedCount: number;
  affectedAssets: CascadeImpactedAsset[];
  methodologyNote: string;
}

