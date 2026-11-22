import { ModuleGroupId, ModuleId } from '../types/atlas';

export interface NavModuleItem {
  id: ModuleId;
  groupId: ModuleGroupId;
  label: string;
  shortLabel: string;
  description: string;
  iconName:
    | 'Command'
    | 'Activity'
    | 'Briefcase'
    | 'Globe'
    | 'Satellite'
    | 'Mountain'
    | 'UploadCloud'
    | 'Crosshair'
    | 'ShieldAlert'
    | 'Radar'
    | 'Radio'
    | 'Bug'
    | 'Network'
    | 'AlertOctagon'
    | 'SearchCode'
    | 'Box'
    | 'Share2'
    | 'GitFork'
    | 'MapPin'
    | 'FileText'
    | 'TrendingUp'
    | 'AlertTriangle'
    | 'BarChart3'
    | 'Bot'
    | 'Cpu'
    | 'Users'
    | 'KeyRound'
    | 'ScrollText'
    | 'Database'
    | 'Settings';
  status: 'implemented' | 'partial_demo';
}

export interface NavGroup {
  id: ModuleGroupId;
  title: string;
  modules: NavModuleItem[];
}

export const ATLAS_NAV_GROUPS: NavGroup[] = [
  {
    id: 'command',
    title: 'COMMAND',
    modules: [
      {
        id: 'command_centre',
        groupId: 'command',
        label: 'Command Centre',
        shortLabel: 'Command',
        description: 'Central multi-panel geospatial, cyber, and timeline workstation.',
        iconName: 'Command',
        status: 'implemented',
      },
      {
        id: 'operational_overview',
        groupId: 'command',
        label: 'Operational Overview',
        shortLabel: 'Overview',
        description: 'Cross-domain situational summary from authorised database tables.',
        iconName: 'Activity',
        status: 'implemented',
      },
      {
        id: 'mission_workspace',
        groupId: 'command',
        label: 'Mission Workspace',
        shortLabel: 'Mission',
        description: 'End-to-end case workflow: incident -> matches -> blast radius -> custody.',
        iconName: 'Briefcase',
        status: 'implemented',
      },
    ],
  },
  {
    id: 'geoint',
    title: 'GEOSPATIAL INTELLIGENCE',
    modules: [
      {
        id: 'global_map',
        groupId: 'geoint',
        label: 'Global Intelligence Map',
        shortLabel: 'Global Map',
        description: 'Full-viewport MapLibre GIS canvas with layer & vector controls.',
        iconName: 'Globe',
        status: 'implemented',
      },
      {
        id: 'satellite_imagery',
        groupId: 'geoint',
        label: 'Satellite Imagery',
        shortLabel: 'Satellite',
        description: 'WMTS/WMS/XYZ raster tile configuration & footprint comparison.',
        iconName: 'Satellite',
        status: 'partial_demo',
      },
      {
        id: 'terrain_intelligence',
        groupId: 'geoint',
        label: 'Terrain Intelligence',
        shortLabel: 'Terrain',
        description: 'Coordinate elevation inspection, spatial accuracy & DEM source status.',
        iconName: 'Mountain',
        status: 'partial_demo',
      },
      {
        id: 'infrastructure_mapping',
        groupId: 'geoint',
        label: 'Infrastructure Mapping',
        shortLabel: 'Infra Import',
        description: 'CSV/GeoJSON EPSG:4326 validation and atomic asset publishing.',
        iconName: 'UploadCloud',
        status: 'implemented',
      },
      {
        id: 'asset_tracking',
        groupId: 'geoint',
        label: 'Asset Tracking',
        shortLabel: 'Assets',
        description: 'Searchable critical infrastructure registry & geospatial jump links.',
        iconName: 'Crosshair',
        status: 'implemented',
      },
      {
        id: 'geographic_risk',
        groupId: 'geoint',
        label: 'Geographic Risk Analysis',
        shortLabel: 'Geo Risk',
        description: 'Spatial criticality concentration, uncertainty halos & risk zones.',
        iconName: 'ShieldAlert',
        status: 'implemented',
      },
    ],
  },
  {
    id: 'cyber',
    title: 'CYBER INTELLIGENCE',
    modules: [
      {
        id: 'threat_intelligence',
        groupId: 'cyber',
        label: 'Threat Intelligence',
        shortLabel: 'Threat Intel',
        description: 'Event classifications, rule-matching distribution & signal coverage.',
        iconName: 'Radar',
        status: 'implemented',
      },
      {
        id: 'cyber_monitoring',
        groupId: 'cyber',
        label: 'Cyber Threat Monitoring',
        shortLabel: 'SOC Monitor',
        description: 'Live security event table & signed CyberShield X intake console.',
        iconName: 'Radio',
        status: 'implemented',
      },
      {
        id: 'vulnerability_intelligence',
        groupId: 'cyber',
        label: 'Vulnerability Intelligence',
        shortLabel: 'Vuln Intel',
        description: 'Asset exposure & blast consequence priority across workspace services.',
        iconName: 'Bug',
        status: 'implemented',
      },
      {
        id: 'attack_surface',
        groupId: 'cyber',
        label: 'Attack Surface Intelligence',
        shortLabel: 'Attack Surface',
        description: 'Hostnames, IPs, CIDRs and cloud accounts linked to physical assets.',
        iconName: 'Network',
        status: 'implemented',
      },
      {
        id: 'cyber_incidents',
        groupId: 'cyber',
        label: 'Cyber Incident Management',
        shortLabel: 'Incidents',
        description: 'Incident investigation queue, match confirmation & evidence custody.',
        iconName: 'AlertOctagon',
        status: 'implemented',
      },
      {
        id: 'ioc_investigation',
        groupId: 'cyber',
        label: 'IOC Investigation',
        shortLabel: 'IOC Pivot',
        description: 'Cross-incident & cross-asset lookup of cyber-physical indicators.',
        iconName: 'SearchCode',
        status: 'implemented',
      },
    ],
  },
  {
    id: 'analysis',
    title: 'INTELLIGENCE ANALYSIS',
    modules: [
      {
        id: 'entity_intelligence',
        groupId: 'analysis',
        label: 'Entity Intelligence',
        shortLabel: 'Entities',
        description: 'Unified entity explorer across sites, incidents, indicators and files.',
        iconName: 'Box',
        status: 'implemented',
      },
      {
        id: 'relationship_graph',
        groupId: 'analysis',
        label: 'Relationship Graph',
        shortLabel: 'Graph',
        description: 'Interactive multi-entity relationship topology & path tracing.',
        iconName: 'Share2',
        status: 'implemented',
      },
      {
        id: 'network_analysis',
        groupId: 'analysis',
        label: 'Network Analysis',
        shortLabel: 'Dependencies',
        description: 'Directed provider-to-consumer dependency editor & cycle detection.',
        iconName: 'GitFork',
        status: 'implemented',
      },
      {
        id: 'geospatial_correlation',
        groupId: 'analysis',
        label: 'Geospatial Correlation',
        shortLabel: 'Geo Correlate',
        description: 'Cyber-to-physical correlation mapping & deterministic blast radius.',
        iconName: 'MapPin',
        status: 'implemented',
      },
      {
        id: 'intelligence_reports',
        groupId: 'analysis',
        label: 'Intelligence Reports',
        shortLabel: 'Reports',
        description: 'Evidence-backed situational brief export with audit logging.',
        iconName: 'FileText',
        status: 'implemented',
      },
    ],
  },
  {
    id: 'ai',
    title: 'AI & MACHINE LEARNING',
    modules: [
      {
        id: 'predictive_risk',
        groupId: 'ai',
        label: 'Predictive Risk Analysis',
        shortLabel: 'Risk Model',
        description: 'Uncalibrated deterministic blast propagation & range modelling.',
        iconName: 'TrendingUp',
        status: 'implemented',
      },
      {
        id: 'anomaly_detection',
        groupId: 'ai',
        label: 'Anomaly Detection',
        shortLabel: 'Anomalies',
        description: 'Automated structural, spatial, and telemetry anomaly checks.',
        iconName: 'AlertTriangle',
        status: 'implemented',
      },
      {
        id: 'behavioural_analysis',
        groupId: 'ai',
        label: 'Behavioural Analysis',
        shortLabel: 'Behavioural',
        description: 'Analyst confirmation/rejection patterns & ledger activity trends.',
        iconName: 'BarChart3',
        status: 'implemented',
      },
      {
        id: 'ai_assistant',
        groupId: 'ai',
        label: 'AI Intelligence Assistant',
        shortLabel: 'AI Assistant',
        description: 'Grounded natural-language query interface over authorised datasets.',
        iconName: 'Bot',
        status: 'implemented',
      },
      {
        id: 'model_performance',
        groupId: 'ai',
        label: 'Model Performance',
        shortLabel: 'Model Metrics',
        description: 'Rule precision/recall on labelled matches & scoring parameters.',
        iconName: 'Cpu',
        status: 'implemented',
      },
    ],
  },
  {
    id: 'admin',
    title: 'SYSTEM ADMINISTRATION',
    modules: [
      {
        id: 'user_management',
        groupId: 'admin',
        label: 'User Management',
        shortLabel: 'Users',
        description: 'Authenticated operator profile, AAL2 MFA status & org memberships.',
        iconName: 'Users',
        status: 'implemented',
      },
      {
        id: 'roles_permissions',
        groupId: 'admin',
        label: 'Roles and Permissions',
        shortLabel: 'RBAC Matrix',
        description: 'PostgreSQL RLS & role capability enforcement matrix.',
        iconName: 'KeyRound',
        status: 'implemented',
      },
      {
        id: 'audit_logs',
        groupId: 'admin',
        label: 'Audit Logs',
        shortLabel: 'Audit Chain',
        description: 'Append-only cryptographic SHA-256 ledger & integrity verifier.',
        iconName: 'ScrollText',
        status: 'implemented',
      },
      {
        id: 'data_sources',
        groupId: 'admin',
        label: 'Data Sources',
        shortLabel: 'Data Sources',
        description: 'Ingested dataset batches, CRS provenance & external GIS feeds.',
        iconName: 'Database',
        status: 'implemented',
      },
      {
        id: 'system_configuration',
        groupId: 'admin',
        label: 'System Configuration',
        shortLabel: 'Config',
        description: 'Classification policy, Web Crypto verification & schema diagnostics.',
        iconName: 'Settings',
        status: 'implemented',
      },
    ],
  },
];

export const ALL_MODULES: NavModuleItem[] = ATLAS_NAV_GROUPS.flatMap((g) => g.modules);

export function getModuleMeta(id: ModuleId): NavModuleItem {
  return ALL_MODULES.find((m) => m.id === id) || ALL_MODULES[0];
}
