/**
 * Unit tests for Modules A–F pure logic & adapters:
 *  - Module A: executeDefensiveTerminalCommand
 *  - Module C: validateAuthorisedEndpointUrl, buildCamerasGeoJson
 *  - Module D: parseCtiJsonBundle
 *  - Module E: analyzeBufferZone, computeSpatialClusters, computeProximityRankings,
 *              computeInfrastructureConcentration, inspectTerrainDemAvailability
 *  - Module F: analyzeInfrastructureResilience, simulateNodeFailureCascade
 *
 * Run: npm test
 */

import {
  executeDefensiveTerminalCommand,
  correlateNmapWithAtlas,
  correlateTsharkWithAtlas,
} from '../adapters/terminalAdapter';
import {
  parseTerminalInput,
  evaluateCommandPolicy,
  validatePortSpec,
  validatePcapFileName,
} from '../adapters/terminalPolicy';
import {
  validateGatewayEndpointUrl,
  checkGatewayHealth,
} from '../adapters/gatewayClient';
import { parseCtiJsonBundle } from '../adapters/ctiAdapters';
import {
  validateAuthorisedEndpointUrl,
  buildCamerasGeoJson,
} from '../adapters/gisSurveillanceAdapters';
import {
  analyzeBufferZone,
  computeSpatialClusters,
  computeProximityRankings,
  computeInfrastructureConcentration,
  inspectTerrainDemAvailability,
} from './geospatialAnalysis';
import {
  analyzeInfrastructureResilience,
  simulateNodeFailureCascade,
} from './resilience';
import {
  isValidOrgId,
  sanitizeForBrowserStorage,
  loadOrgScopedList,
  saveOrgScopedList,
  clearOrgScopedDomain,
} from './orgStorage';
import { validateGisSourceInput } from './intelligence';
import type { WorkspaceIntelligenceState } from '../hooks/useWorkspaceIntelligence';
import type {
  Asset,
  AssetMatch,
  AttributionRecord,
  CameraRegistryItem,
  DependencyEdge,
  ExternalThreatIndicator,
  GisCustomSource,
  Incident,
} from '../types/atlas';

let failed = 0;
let passed = 0;
function check(name: string, ok: boolean, detail = '') {
  if (ok) {
    passed++;
    console.log(`  PASS: ${name}`);
  } else {
    failed++;
    console.error(`  FAIL: ${name} ${detail}`);
  }
}

const ORG_ID = '11111111-1111-4111-8111-111111111111';

const sampleAssets: Asset[] = [
  {
    id: 'a1',
    org_id: ORG_ID,
    site_code: 'SUB-01',
    name: 'North Grid Substation',
    type: 'power_feed',
    criticality: 5,
    owner: 'Grid Ops',
    accuracy_class: 'exact_survey',
    identifiers: { ip_addresses: ['198.51.100.10'], hostnames: ['sub01.grid.internal'] },
    source: 'registry',
    created_at: '2026-11-01T00:00:00Z',
    confidence: 0.95,
    sharing_policy: 'org_only',
    correlation_id: 'corr-1',
  },
  {
    id: 'a2',
    org_id: ORG_ID,
    site_code: 'PUMP-02',
    name: 'Eastern Water Lift',
    type: 'site',
    criticality: 4,
    owner: 'Water Ops',
    accuracy_class: 'facility_approximate',
    identifiers: { ip_addresses: ['198.51.100.22'] },
    source: 'registry',
    created_at: '2026-11-01T00:00:00Z',
    confidence: 0.9,
    sharing_policy: 'org_only',
    correlation_id: 'corr-2',
  },
  {
    id: 'a3',
    org_id: ORG_ID,
    site_code: 'FBR-03',
    name: 'Metro Fibre Relay',
    type: 'fibre_route',
    criticality: 3,
    owner: 'Telecom Ops',
    accuracy_class: 'exact_survey',
    identifiers: {},
    source: 'registry',
    created_at: '2026-11-01T00:00:00Z',
    confidence: 0.9,
    sharing_policy: 'org_only',
    correlation_id: 'corr-3',
  },
  {
    id: 'a4',
    org_id: ORG_ID,
    site_code: 'DC-04',
    name: 'Regional Edge Cluster',
    type: 'cloud_region',
    criticality: 5,
    owner: 'Cloud Ops',
    accuracy_class: 'regional_approximate',
    identifiers: {},
    source: 'registry',
    created_at: '2026-11-01T00:00:00Z',
    confidence: 0.85,
    sharing_policy: 'org_only',
    correlation_id: 'corr-4',
  },
];

const sampleEdges: DependencyEdge[] = [
  {
    id: 'e1',
    org_id: ORG_ID,
    from_asset_id: 'a1',
    to_asset_id: 'a2',
    relation_type: 'powers',
    criticality: 5,
    valid_from: '2026-11-01T00:00:00Z',
    source: 'topology',
    created_at: '2026-11-01T00:00:00Z',
    confidence: 0.95,
    sharing_policy: 'org_only',
    correlation_id: 'corr-e1',
  },
  {
    id: 'e2',
    org_id: ORG_ID,
    from_asset_id: 'a2',
    to_asset_id: 'a3',
    relation_type: 'supplies',
    criticality: 4,
    valid_from: '2026-11-01T00:00:00Z',
    source: 'topology',
    created_at: '2026-11-01T00:00:00Z',
    confidence: 0.9,
    sharing_policy: 'org_only',
    correlation_id: 'corr-e2',
  },
  {
    id: 'e3',
    org_id: ORG_ID,
    from_asset_id: 'a3',
    to_asset_id: 'a4',
    relation_type: 'connects_to',
    criticality: 5,
    valid_from: '2026-11-01T00:00:00Z',
    source: 'topology',
    created_at: '2026-11-01T00:00:00Z',
    confidence: 0.9,
    sharing_policy: 'org_only',
    correlation_id: 'corr-e3',
  },
];

const sampleIncidents: Incident[] = [
  {
    id: 'inc1',
    org_id: ORG_ID,
    schema_version: '1.0',
    event_id: 'EV-2026-0091',
    event_type: 'unauthorized_scada_probe',
    severity: 'critical',
    source: 'cybershield-x',
    observed_at: '2026-11-10T10:00:00Z',
    created_at: '2026-11-10T10:00:05Z',
    signals: { ips: ['203.0.113.45', '198.51.100.10'], hostnames: ['sub01.grid.internal'] },
    confidence: 0.92,
    sharing_policy: 'org_only',
    correlation_id: 'corr-inc1',
  },
];

const sampleMatches: AssetMatch[] = [
  {
    id: 'm1',
    org_id: ORG_ID,
    incident_id: 'inc1',
    asset_id: 'a1',
    score: 0.94,
    rule_fired: 'ip_exact',
    status: 'confirmed',
    source: 'correlation',
    created_at: '2026-11-10T10:01:00Z',
    confidence: 0.94,
    sharing_policy: 'org_only',
    correlation_id: 'corr-m1',
    asset: sampleAssets[0],
  },
];

const coordsMap = new Map<string, [number, number]>([
  ['a1', [77.209, 28.6139]], // Delhi center
  ['a2', [77.218, 28.620]],  // ~1.1 km away (co-located within 2 km)
  ['a3', [77.310, 28.650]],  // ~10.6 km away
  ['a4', [72.8777, 19.076]], // Mumbai (~1153 km away)
]);

const mockIntel: WorkspaceIntelligenceState = {
  orgId: ORG_ID,
  assetsGeoJson: { type: 'FeatureCollection', features: [] },
  assets: sampleAssets,
  edges: sampleEdges,
  incidents: sampleIncidents,
  matches: sampleMatches,
  evidence: [],
  auditEvents: [],
  auditTotal: 0,
  datasets: [],
  scoringConfig: [],
  orgMemberships: [],
  isLoading: false,
  error: null,
  lastSyncedAt: '2026-11-10T10:05:00Z',
  alerts: [],
  assetCoordsMap: coordsMap,
  refreshAll: async () => {},
};

// ---------------- Module A: Defensive Terminal ----------------
console.log('Module A: Defensive Terminal');
const rHelp = executeDefensiveTerminalCommand('help', mockIntel);
check('help returns ok with command list', rHelp.status === 'ok' && rHelp.lines.some((l) => l.text.includes('ioc <value>')));

const rStatus = executeDefensiveTerminalCommand('status', mockIntel);
check('status reports workspace counts cleanly', rStatus.status === 'ok' && rStatus.lines.some((l) => l.text.includes('Assets: 4')));

const rCrossEnv = executeDefensiveTerminalCommand('nmap -sV 198.51.100.10', mockIntel);
check('nmap command in atlas_native is blocked by policy with environment guidance', rCrossEnv.status === 'blocked_by_policy');

const rUnsafe1 = executeDefensiveTerminalCommand('msfconsole -q', mockIntel);
check('offensive msfconsole command is rejected', rUnsafe1.status === 'rejected');

const rUnsafe2 = executeDefensiveTerminalCommand('status; rm -rf /', mockIntel);
check('shell chaining is rejected', rUnsafe2.status === 'rejected');

const rIoc = executeDefensiveTerminalCommand('ioc 198.51.100.10', mockIntel);
check('ioc correlates against asset and incident', rIoc.status === 'ok' && rIoc.lines.some((l) => l.text.includes('SUB-01')) && rIoc.lines.some((l) => l.text.includes('EV-2026-0091')));

const rNetflow = executeDefensiveTerminalCommand('netflow', mockIntel);
check('netflow honestly discloses unavailable live collector', rNetflow.status === 'unavailable' && rNetflow.lines.some((l) => l.text.includes('DATA SOURCE UNAVAILABLE')));

const sampleAttr: AttributionRecord[] = [
  {
    id: 'attr-1',
    orgId: ORG_ID,
    indicatorType: 'ip_address',
    indicatorValue: '203.0.113.45',
    attributionClass: 'observed_technical',
    entityLabel: 'ASN-64512 Scanner Node',
    relationshipType: 'probed',
    observedTimestamp: '2026-11-10T10:00:00Z',
    source: 'cybershield-x',
    evidenceRef: 'EV-2026-0091',
    incidentId: 'inc1',
    confidence: 0.72,
    status: 'active_review',
    analystNotes: 'Observed probing SCADA port.',
    createdBy: 'analyst@atlas.test',
    createdAt: '2026-11-10T10:02:00Z',
  },
];
const rAttr = executeDefensiveTerminalCommand('attribution 203.0.113.45', mockIntel, [], sampleAttr);
check(
  'attribution command surfaces non-authoritative local draft label, entityRef, and policy note',
  rAttr.status === 'ok' &&
    rAttr.lines.some(
      (l) =>
        l.text.includes('ASN-64512') &&
        l.text.includes('LOCAL DRAFT — NON-AUTHORITATIVE') &&
        l.tone === 'warn' &&
        l.entityRef?.kind === 'incident' &&
        l.entityRef.id === 'inc1'
    ) &&
    rAttr.lines.some((l) => l.text.includes('POLICY NOTE'))
);

const sampleVerifiedDraft: AttributionRecord[] = [
  {
    ...sampleAttr[0],
    id: 'attr-v1',
    attributionClass: 'verified_identity',
    status: 'corroborated',
    entityLabel: 'APT-Test Operator Handle',
  },
];
const rVerifiedAttr = executeDefensiveTerminalCommand('attribution 203.0.113.45', mockIntel, [], sampleVerifiedDraft);
check(
  'verified_identity local draft is rendered as warn (never ok) and marked non-authoritative',
  rVerifiedAttr.status === 'ok' &&
    rVerifiedAttr.lines.some((l) => l.text.includes('LOCAL DRAFT — NON-AUTHORITATIVE') && l.tone === 'warn') &&
    !rVerifiedAttr.lines.some((l) => l.text.includes('ATTRIBUTION DRAFT:') && l.tone === 'ok')
);

const rIocAttr = executeDefensiveTerminalCommand('ioc 203.0.113.45', mockIntel, [], sampleAttr);
check(
  'ioc command cross-references attributionRecords as ATTRIBUTION DRAFT and attaches incident entityRef',
  rIocAttr.status === 'ok' &&
    rIocAttr.lines.some(
      (l) =>
        l.text.includes('[ATTRIBUTION DRAFT:OBSERVED_TECHNICAL]') &&
        l.text.includes('LOCAL DRAFT — NON-AUTHORITATIVE') &&
        l.entityRef?.kind === 'incident' &&
        l.entityRef.id === 'inc1'
    )
);

// ---- Hybrid Terminal: Policy Engine, Expanded Commands & Correlation ----
console.log('Module A+: Hybrid Terminal Policy, Expanded Commands & Gateway Correlation');
const parsedQuoted = parseTerminalInput('assets search "North Grid Substation"');
check(
  'parseTerminalInput preserves quoted arguments cleanly',
  parsedQuoted.valid && parsedQuoted.tokens[0] === 'assets' && parsedQuoted.tokens[1] === 'search' && parsedQuoted.tokens[2] === 'North Grid Substation'
);

const parsedInject = parseTerminalInput('assets | grep SUB');
check('parseTerminalInput blocks pipe shell chaining', !parsedInject.valid);

check(
  'policy engine rejects dangerous loopbacks, link-local metadata IP, and invalid PCAP path',
  !evaluateCommandPolicy('nmap -sn 127.0.0.1', 'linux_worker', 'atlas:admin').allowed &&
    !evaluateCommandPolicy('nmap -sn 169.254.169.254', 'linux_worker', 'atlas:admin').allowed &&
    !validatePcapFileName('../etc/passwd.pcap').valid &&
    !validatePortSpec('1-500').valid &&
    validatePortSpec('22,80,443').valid
);

const analystNmap = evaluateCommandPolicy('nmap -sV -p 22,80 192.168.10.15', 'linux_worker', 'atlas:analyst');
check('policy engine blocks atlas:analyst from restricted nmap -sV service scan', !analystNmap.allowed && analystNmap.riskLevel === 'HIGH' && !analystNmap.requiresApproval);

const adminNmapNoApproval = evaluateCommandPolicy('nmap -sV -p 22,80 192.168.10.15', 'linux_worker', 'atlas:admin', { approvalGranted: false });
check('policy engine requires explicit approval gate for admin nmap -sV', !adminNmapNoApproval.allowed && adminNmapNoApproval.requiresApproval === true);

const adminNmapApproved = evaluateCommandPolicy('nmap -sV -p 22,80 192.168.10.15', 'linux_worker', 'atlas:admin', { approvalGranted: true });
check('policy engine approves nmap -sV once explicit operator approval is granted', adminNmapApproved.allowed && !adminNmapApproved.requiresApproval);

const rWhoami = executeDefensiveTerminalCommand('whoami', mockIntel, [], [], {
  userRole: 'atlas:admin',
  userEmail: 'operator@atlas.test',
});
check(
  'whoami reports operator identity, role, AAL2, and org scope',
  rWhoami.status === 'ok' &&
    rWhoami.lines.some((l) => l.text.includes('operator@atlas.test')) &&
    rWhoami.lines.some((l) => l.text.includes('atlas:admin') && l.text.includes('AAL2'))
);

const rGeoLocate = executeDefensiveTerminalCommand('geo locate a1', mockIntel);
check('geo locate resolves asset coordinates', rGeoLocate.status === 'ok' && rGeoLocate.lines.some((l) => l.text.includes('28.6139')));

const rGeoBlast = executeDefensiveTerminalCommand('geo blast-radius inc1', mockIntel);
check('geo blast-radius propagates incident cascade across dependency topology', rGeoBlast.status === 'ok' && rGeoBlast.lines.some((l) => l.text.includes('Downstream Cascading Nodes: 3')));

const rResAssess = executeDefensiveTerminalCommand('resilience assess a1', mockIntel);
check('resilience assess flags SPOF and discloses NO_VERIFIED_DATA honestly', rResAssess.status === 'ok' && rResAssess.lines.some((l) => l.text.includes('NO_VERIFIED_DATA')));

const rResSim = executeDefensiveTerminalCommand('resilience simulate a1', mockIntel);
check('resilience simulate computes 3 downstream cascading outages', rResSim.status === 'ok' && rResSim.lines.some((l) => l.text.includes('Total Downstream Outage: 3')));

const rReportInc = executeDefensiveTerminalCommand('report incident inc1', mockIntel);
check('report incident generates downloadable Markdown report payload', rReportInc.status === 'ok' && Boolean(rReportInc.exportReportMarkdown?.includes('ATLAS Incident Investigation Report')));

const sampleCtiForCorrelation: ExternalThreatIndicator[] = [
  {
    id: 'cti-1',
    orgId: ORG_ID,
    providerId: 'STIX_2_1',
    indicatorType: 'ip',
    value: '198.51.100.10',
    sourceName: 'Test External Feed',
    confidence: 80,
    validFrom: '2026-11-10T00:00:00Z',
    isExpired: false,
    isExternalIntel: true,
    verificationStatus: 'unverified',
    matchedAssetIds: ['a1'],
    matchedIncidentIds: ['inc1'],
    rawSummary: 'External feed IP',
    importedAt: '2026-11-10T00:00:00Z',
  },
];

const nmapCorr = correlateNmapWithAtlas(
  {
    scannerArgs: '-sV -p 502 198.51.100.10',
    startedAtUtc: '2026-11-10T11:00:00Z',
    openPortsCount: 1,
    hosts: [
      { ip: '198.51.100.10', hostname: 'sub01.grid.internal', state: 'up', ports: [{ port: 502, protocol: 'tcp', state: 'open', service: 'modbus' }] },
      { ip: '10.99.99.99', state: 'up', ports: [] },
    ],
  },
  mockIntel,
  sampleCtiForCorrelation
);
check(
  'correlateNmapWithAtlas matches registered assets/incidents/CTI and segregates unmatched live IPs',
  nmapCorr.matchedAssetIds.includes('a1') &&
    nmapCorr.matchedIncidentIds.includes('inc1') &&
    nmapCorr.matchedCtiValues.includes('198.51.100.10') &&
    nmapCorr.unmatchedObservedIps.includes('10.99.99.99') &&
    nmapCorr.downstreamAssetCount === 3 &&
    nmapCorr.provenanceNote.includes('UNVERIFIED EXTERNAL SCAN OBSERVATION')
);

const tsharkCorr = correlateTsharkWithAtlas(
  {
    operation: 'dns',
    fileName: 'capture.pcap',
    packetCount: 12,
    protocols: [{ name: 'dns', frames: 12 }],
    uniqueIps: ['198.51.100.10', '8.8.8.8'],
    dnsQueries: [{ query: 'sub01.grid.internal', count: 4 }],
    conversations: [],
  },
  mockIntel,
  sampleCtiForCorrelation
);
check(
  'correlateTsharkWithAtlas matches PCAP IPs and DNS queries without claiming verified attribution',
  tsharkCorr.matchedAssetIds.includes('a1') &&
    tsharkCorr.unmatchedObservedIps.includes('8.8.8.8') &&
    tsharkCorr.provenanceNote.includes('OFFLINE PCAP ANALYSIS') &&
    tsharkCorr.provenanceNote.includes('not verified attribution')
);

check(
  'validateGatewayEndpointUrl permits HTTPS and loopback HTTP only, blocking remote HTTP and query tokens',
  validateGatewayEndpointUrl('https://gw.atlas.internal:8443').valid &&
    validateGatewayEndpointUrl('http://127.0.0.1:8443').valid &&
    !validateGatewayEndpointUrl('http://gw.atlas.internal:8443').valid &&
    !validateGatewayEndpointUrl('https://gw.atlas.internal/?token=secret').valid
);

// ---------------- Module C: GIS & Surveillance Adapters ----------------
console.log('Module C: GIS & Surveillance Adapters');
check('valid https camera/WMS url passes', validateAuthorisedEndpointUrl('https://vms.org.internal/stream/cam01.m3u8').valid === true);
check('plain http url rejected', validateAuthorisedEndpointUrl('http://vms.org.internal/cam.m3u8').valid === false);
check('embedded credentials rejected', validateAuthorisedEndpointUrl('https://admin:secret@vms.org.internal/cam.m3u8').valid === false);
check('rtsp scheme rejected in browser registry', validateAuthorisedEndpointUrl('rtsp://cam.local/live').valid === false);
check('query token rejected in camera/WMS endpoint', validateAuthorisedEndpointUrl('https://vms.org.internal/cam.m3u8?token=abc123').valid === false);
check('query auth & sig params rejected in camera/WMS endpoint', validateAuthorisedEndpointUrl('https://vms.org.internal/cam.m3u8?auth=xyz').valid === false && validateAuthorisedEndpointUrl('https://vms.org.internal/cam.m3u8?sig=deadbeef').valid === false);
check('fragment access_token rejected in camera/WMS endpoint', validateAuthorisedEndpointUrl('https://vms.org.internal/cam.m3u8#access_token=secret').valid === false);
check('query api_key rejected in GIS source validation', validateGisSourceInput({ name: 'SAT', protocol: 'XYZ_RASTER', url: 'https://tiles.example.com/{z}/{x}/{y}.png?api_key=secret' }) !== null);
check('fragment token & signed query rejected in GIS source validation', validateGisSourceInput({ name: 'SAT', protocol: 'XYZ_RASTER', url: 'https://tiles.example.com/{z}/{x}/{y}.png#token=secret' }) !== null && validateGisSourceInput({ name: 'WMS', protocol: 'WMS', url: 'https://tiles.example.com/wms?x-amz-signature=abc' }) !== null);

const cams: CameraRegistryItem[] = [
  {
    id: 'cam-1',
    cameraCode: 'CAM-N01',
    name: 'North Gate PTZ',
    protocol: 'RTSP_HLS',
    endpointUrl: 'https://vms.org.internal/cam-n01.m3u8',
    lng: 77.209,
    lat: 28.6139,
    bearingDeg: 45,
    fovDeg: 60,
    rangeMeters: 250,
    streamStatus: 'awaiting_authorised_gateway',
    connectionState: 'configured',
  },
  {
    id: 'cam-2',
    cameraCode: 'CAM-S02',
    name: 'South Perimeter',
    protocol: 'ONVIF',
    lng: 77.211,
    lat: 28.615,
    bearingDeg: 180,
    fovDeg: 75,
    rangeMeters: 180,
    streamStatus: 'metadata_only',
  },
];
const camGeo = buildCamerasGeoJson(cams);
check(
  'buildCamerasGeoJson emits Point + Polygon FOV (no Multi* types) with calculated estimate & connectionState flags',
  camGeo.features.length === 4 &&
    camGeo.features[0].geometry.type === 'Point' &&
    camGeo.features[0].properties.connectionState === 'configured' &&
    camGeo.features[1].geometry.type === 'Polygon' &&
    camGeo.features[1].properties.isCalculatedCoverageEstimate === true &&
    camGeo.features[2].properties.connectionState === 'registered'
);

// ---------------- Module D: CTI Adapters & STIX/KEV Parser ----------------
console.log('Module D: CTI Adapters & STIX/KEV Parser');
const stixBundle = JSON.stringify({
  type: 'bundle',
  id: 'bundle--1',
  objects: [
    {
      type: 'indicator',
      id: 'indicator--1',
      name: 'Observed Substation Probe',
      pattern: "[ipv4-addr:value = '198.51.100.10']",
      confidence: 88,
      valid_from: '2026-11-01T00:00:00Z',
      valid_until: '2020-01-01T00:00:00Z',
    },
    {
      type: 'malware',
      id: 'malware--1',
      name: 'Industroyer2',
      malware_types: ['wiper'],
    },
  ],
});
const stixReport = parseCtiJsonBundle(stixBundle, 'STIX_2_1', ORG_ID, sampleAssets, sampleIncidents, [], Date.parse('2026-11-15T00:00:00Z'));
check('STIX parser extracts indicators & malware tagged isExternalIntel=true', stixReport.indicators.length === 2 && stixReport.indicators.every((i) => i.isExternalIntel && i.verificationStatus === 'unverified'));
check('STIX indicator flags expired valid_until and correlates asset/incident', stixReport.indicators[0].isExpired === true && stixReport.indicators[0].matchedAssetIds.includes('a1') && stixReport.indicators[0].matchedIncidentIds.includes('inc1'));

const dedupReport = parseCtiJsonBundle(stixBundle, 'STIX_2_1', ORG_ID, sampleAssets, sampleIncidents, stixReport.indicators);
check('STIX parser deduplicates previously imported indicators', dedupReport.indicators.length === 0 && dedupReport.skippedDuplicates === 2);

const kevBundle = JSON.stringify({
  vulnerabilities: [
    {
      cveID: 'CVE-2026-9999',
      vendorProject: 'OT-Vendor',
      vulnerabilityName: 'Modbus Buffer Overflow',
      shortDescription: 'Remote code execution in gateway.',
      dateAdded: '2026-11-05',
    },
  ],
});
const kevReport = parseCtiJsonBundle(kevBundle, 'CISA_KEV', ORG_ID, sampleAssets, sampleIncidents);
check('CISA KEV parser extracts CVE records accurately', kevReport.indicators.length === 1 && kevReport.indicators[0].indicatorType === 'cve' && kevReport.indicators[0].value === 'CVE-2026-9999');

// ---------------- Module E: Computational Geospatial Analysis ----------------
console.log('Module E: Computational Geospatial Analysis');
const buf = analyzeBufferZone([77.209, 28.6139], 15, sampleAssets, coordsMap, sampleMatches);
check('buffer 15km around Delhi finds SUB-01, PUMP-02, FBR-03 and excludes Mumbai DC-04', buf.intersectingAssets.length === 3 && !buf.intersectingAssets.some((a) => a.assetId === 'a4'));
check('buffer propagates approximate accuracy warning & linked incident', buf.hasApproximateAssets === true && buf.linkedIncidentIds.includes('inc1'));
check('buffer ringPolygon is a closed ring', buf.ringPolygon.length > 10 && JSON.stringify(buf.ringPolygon[0]) === JSON.stringify(buf.ringPolygon[buf.ringPolygon.length - 1]));

const clusters = computeSpatialClusters(sampleAssets, coordsMap, sampleMatches, 50);
check('spatial clusters group regional assets without inventing clusters for empty zones', clusters.length >= 2 && clusters[0].assetIds.length >= 2);

const prox = computeProximityRankings([77.209, 28.6139], 20, sampleAssets, coordsMap, 'a1');
check('proximity rankings exclude origin asset and sort nearest first', prox.length === 2 && prox[0].assetId === 'a2' && prox[1].assetId === 'a3' && prox[0].distanceKm < prox[1].distanceKm);

const conc = computeInfrastructureConcentration(sampleAssets, coordsMap, sampleMatches, 0.5);
check('concentration grid detects co-located pairs within 5km', conc.length === 2 && conc[0].coLocatedPairs >= 1);

const noDem = inspectTerrainDemAvailability([]);
check('inspectTerrainDemAvailability returns unavailable when no DEM attached', noDem.demAvailable === false && noDem.activeDemSourceName === null);
const withDem: GisCustomSource[] = [
  {
    id: 'dem1',
    name: 'Copernicus DEM GLO-30',
    protocol: 'WMS',
    url: 'https://sh.dataspace.copernicus.eu/ogc/wms/demo',
    attribution: 'Copernicus',
    enabled: true,
  },
];
const yesDem = inspectTerrainDemAvailability(withDem);
check('inspectTerrainDemAvailability detects active enabled DEM source', yesDem.demAvailable === true && yesDem.activeDemSourceName === 'Copernicus DEM GLO-30');

// ---------------- Module F: Infrastructure Resilience & Cascade ----------------
console.log('Module F: Infrastructure Resilience & Cascade Simulator');
const profiles = analyzeInfrastructureResilience(sampleAssets, sampleEdges, coordsMap, sampleMatches);
const a1Profile = profiles.find((p) => p.assetId === 'a1');
const a4Profile = profiles.find((p) => p.assetId === 'a4');
check('resilience marks unrecorded backup state honestly as NO_VERIFIED_DATA', profiles.every((p) => p.backupRecoveryStatus === 'NO_VERIFIED_DATA'));
check('resilience flags sole-provider / Tier-5 SPOFs accurately', a1Profile?.isSinglePointOfFailure === true && a4Profile?.isSinglePointOfFailure === true);
check('resilience measures 2km co-location and active incident exposure on a1', (a1Profile?.coLocatedCriticalCount || 0) >= 1 && a1Profile?.activeIncidentExposureCount === 1);

const cascade = simulateNodeFailureCascade(['a1'], sampleAssets, sampleEdges, sampleMatches);
check('cascade BFS traverses a1 -> a2 -> a3 -> a4 (3 downstream)', cascade.directDependentsCount === 1 && cascade.totalCascadingOutageCount === 3);
check('cascade classifies power vs telecom hops and Tier-4+ impact', cascade.powerCascadeCount === 1 && cascade.telecomCascadeCount === 1 && cascade.tier4PlusAffectedCount === 2);

// ---------------- Task 4: Org Storage Security & Isolation ----------------
console.log('Security: Org-Scoped Browser Storage & Secret Stripping');
check('isValidOrgId rejects empty and no-org fallback', !isValidOrgId('') && !isValidOrgId('no-org') && isValidOrgId(ORG_ID));
const cleaned = sanitizeForBrowserStorage({
  classification: 'INTERNAL // RESTRICTED',
  apiKey: 'should-be-stripped',
  access_token: 'jwt-secret',
  nested: { secret: 'nope', label: 'ok' },
}) as Record<string, any>;
check('sanitizeForBrowserStorage strips apiKey, access_token, and secret keys', !('apiKey' in cleaned) && !('access_token' in cleaned) && !('secret' in cleaned.nested) && cleaned.nested.label === 'ok');

// Mock window.localStorage in Node test runner to verify cross-org list filtering
const store = new Map<string, string>();
(globalThis as any).window = {
  localStorage: {
    getItem: (k: string) => store.get(k) ?? null,
    setItem: (k: string, v: string) => store.set(k, v),
    removeItem: (k: string) => store.delete(k),
  },
};
const ORG_B = '22222222-2222-4222-8222-222222222222';
saveOrgScopedList('attributions', ORG_ID, [
  ...sampleAttr,
  { ...sampleAttr[0], id: 'foreign-leak', orgId: ORG_B },
]);
const loadedA = loadOrgScopedList<AttributionRecord>('attributions', ORG_ID);
const loadedB = loadOrgScopedList<AttributionRecord>('attributions', ORG_B);
check('orgStorage enforces strict orgId isolation and drops mismatched org items', loadedA.length === 1 && loadedA[0].id === 'attr-1' && loadedB.length === 0);
clearOrgScopedDomain('attributions', ORG_ID);

const gwNotConf = await checkGatewayHealth('', ORG_ID);
check('checkGatewayHealth returns NOT_CONFIGURED cleanly when gateway URL is unset', gwNotConf.state === 'NOT_CONFIGURED' && gwNotConf.tools.length === 0);

const gwOffline = await checkGatewayHealth('http://127.0.0.1:59999', ORG_ID);
check('checkGatewayHealth handles missing Supabase session / offline gateway cleanly without throwing', gwOffline.state === 'OFFLINE');

console.log('\n===============================================');
console.log(`MODULES A-F TESTS: ${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
