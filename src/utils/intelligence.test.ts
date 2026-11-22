/**
 * Unit tests for the pure workspace logic (alerts, geodesic maths, coordinates, path tracing).
 * Run: npm test
 */
import {
  computeAlerts,
  extractRepresentativeCoord,
  haversineKm,
  computeBearingDeg,
  shortestPathUndirected,
  validateGisSourceInput,
} from './intelligence';

let failed = 0;
let passed = 0;
function check(name: string, ok: boolean, detail = '') {
  if (ok) { passed++; console.log(`  PASS: ${name}`); }
  else { failed++; console.error(`  FAIL: ${name} ${detail}`); }
}
const near = (a: number, b: number, tol: number) => Math.abs(a - b) <= tol;

// ---------------- geodesic maths ----------------
console.log('Geodesic maths');
check('same point is 0 km', haversineKm([77.2, 28.6], [77.2, 28.6]) === 0);
// Delhi (77.2090, 28.6139) to Mumbai (72.8777, 19.0760) is about 1,153 km
const dm = haversineKm([77.209, 28.6139], [72.8777, 19.076]);
check('Delhi to Mumbai about 1153 km', near(dm, 1153, 15), `got ${dm.toFixed(1)}`);
check('distance is symmetric', near(haversineKm([10, 10], [20, 30]), haversineKm([20, 30], [10, 10]), 1e-9));
check('one degree of latitude about 111.2 km', near(haversineKm([0, 0], [0, 1]), 111.19, 0.1));
check('bearing due north is 0', near(computeBearingDeg([0, 0], [0, 10]), 0, 1e-6));
check('bearing due east is 90', near(computeBearingDeg([0, 0], [10, 0]), 90, 1e-6));
check('bearing due south is 180', near(computeBearingDeg([0, 10], [0, 0]), 180, 1e-6));
check('bearing due west is 270', near(computeBearingDeg([10, 0], [0, 0]), 270, 1e-6));

// ---------------- representative coordinates ----------------
console.log('Representative coordinates');
check('null geometry gives null', extractRepresentativeCoord(null) === null);
check('Point returns [lng, lat]', JSON.stringify(extractRepresentativeCoord({ type: 'Point', coordinates: [77, 28] })) === '[77,28]');
check('LineString returns the middle vertex', JSON.stringify(extractRepresentativeCoord({ type: 'LineString', coordinates: [[0, 0], [5, 5], [9, 9]] })) === '[5,5]');
const poly = extractRepresentativeCoord({ type: 'Polygon', coordinates: [[[0, 0], [4, 0], [4, 4], [0, 4], [0, 0]]] });
check('Polygon returns a point inside the ring bounds', !!poly && poly[0] >= 0 && poly[0] <= 4 && poly[1] >= 0 && poly[1] <= 4);
check('unknown geometry type gives null', extractRepresentativeCoord({ type: 'MultiPoint', coordinates: [[1, 1]] }) === null);
check('empty coordinates give null', extractRepresentativeCoord({ type: 'Point', coordinates: [] }) === null);

// ---------------- alerts ----------------
console.log('Alerts');
const mk = (o: any) => o as any;
const incidents = [
  mk({ id: 'i1', event_id: 'EV-1', severity: 'critical', event_type: 'telemetry', source: 'sensor', observed_at: '2026-11-01T10:00:00Z' }),
  mk({ id: 'i2', event_id: 'EV-2', severity: 'high', event_type: 'telemetry', source: 'sensor', observed_at: '2026-11-02T10:00:00Z' }),
  mk({ id: 'i3', event_id: 'EV-3', severity: 'low', event_type: 'telemetry', source: 'sensor', observed_at: '2026-11-03T10:00:00Z' }),
];
const matches = [
  mk({ id: 'm1', incident_id: 'i1', asset_id: 'aaaaaaaa-1', status: 'proposed', score: 0.9, rule_fired: 'R1', created_at: '2026-11-04T10:00:00Z', asset: { site_code: 'S-1' } }),
  mk({ id: 'm2', incident_id: 'i2', asset_id: 'bbbbbbbb-2', status: 'confirmed', score: 0.8, rule_fired: 'R2', created_at: '2026-11-04T11:00:00Z' }),
  mk({ id: 'm3', incident_id: 'i3', asset_id: 'cccccccc-3', status: 'proposed', score: 0.5, rule_fired: 'R3', created_at: '2026-11-04T12:00:00Z' }),
];
const assets = [
  mk({ id: 'a1', site_code: 'S-1', name: 'Hub', criticality: 5, accuracy_class: 'approximate', created_at: '2026-11-05T10:00:00Z' }),
  mk({ id: 'a2', site_code: 'S-2', name: 'Survey', criticality: 5, accuracy_class: 'exact_survey', created_at: '2026-11-05T11:00:00Z' }),
  mk({ id: 'a3', site_code: 'S-3', name: 'Minor', criticality: 2, accuracy_class: 'approximate', created_at: '2026-11-05T12:00:00Z' }),
];
const al = computeAlerts(matches, incidents, assets);
const cat = (c: string) => al.filter((x) => x.category === c);
check('two proposed matches raise two alerts (confirmed does not)', cat('PROPOSED_MATCH').length === 2);
check('proposed match on a critical incident is critical severity', cat('PROPOSED_MATCH').find((x) => x.id === 'alert-match-m1')?.severity === 'critical');
check('proposed match on a non-critical incident is high severity', cat('PROPOSED_MATCH').find((x) => x.id === 'alert-match-m3')?.severity === 'high');
check('match alert shows score as a whole percent', cat('PROPOSED_MATCH').find((x) => x.id === 'alert-match-m1')?.title.includes('(90%)') === true);
check('critical and high incidents raise alerts, low does not', cat('CRITICAL_INCIDENT').length === 1 && cat('HIGH_INCIDENT').length === 1);
check('only tier-5 assets that are not exact_survey raise the approximate-location alert', cat('APPROXIMATE_CRITICAL_ASSET').length === 1 && cat('APPROXIMATE_CRITICAL_ASSET')[0].targetId === 'a1');
check('alerts are sorted newest first', al.every((x, i) => i === 0 || new Date(al[i - 1].timestamp).getTime() >= new Date(x.timestamp).getTime()));
check('no data gives no alerts', computeAlerts([], [], []).length === 0);

// ---------------- path tracing ----------------
console.log('Path tracing');
const E = (id: string, s: string, t: string) => ({ id, source: s, target: t });
const edges = [E('e1', 'A', 'B'), E('e2', 'B', 'C'), E('e3', 'C', 'D'), E('e4', 'A', 'D'), E('e5', 'X', 'Y')];
const all = new Set(['A', 'B', 'C', 'D', 'X', 'Y']);
const p1 = shortestPathUndirected(edges, all, 'A', 'D');
check('direct edge beats the longer route', p1.nodes.size === 2 && p1.edges.has('e4') && p1.edges.size === 1);
const p2 = shortestPathUndirected(edges, all, 'D', 'A');
check('path is the same when reversed (edges followed both ways)', p2.nodes.size === 2 && p2.edges.has('e4'));
const p3 = shortestPathUndirected(edges, all, 'B', 'D');
check('multi-hop path found (B to D is 2 hops)', p3.nodes.size === 3 && p3.edges.size === 2);
const p4 = shortestPathUndirected(edges, all, 'A', 'X');
check('disconnected nodes give an empty path', p4.nodes.size === 0 && p4.edges.size === 0);
check('same start and end gives an empty path', shortestPathUndirected(edges, all, 'A', 'A').nodes.size === 0);
check('node outside the allowed set gives an empty path', shortestPathUndirected(edges, new Set(['A', 'B']), 'A', 'D').nodes.size === 0);
check('empty ids give an empty path', shortestPathUndirected(edges, all, '', 'D').nodes.size === 0);
// larger graph: 5,000-node chain finishes quickly and is exact
const chain: Array<{ id: string; source: string; target: string }> = [];
const ids = new Set<string>();
for (let i = 0; i < 5000; i++) { ids.add('n' + i); if (i > 0) chain.push(E('c' + i, 'n' + (i - 1), 'n' + i)); }
const t0 = Date.now();
const pc = shortestPathUndirected(chain, ids, 'n0', 'n4999');
check('5,000-node chain traced exactly in under 2 seconds', pc.nodes.size === 5000 && pc.edges.size === 4999 && Date.now() - t0 < 2000, `${Date.now() - t0} ms`);

// ---------------- GIS source validation ----------------
console.log('GIS source validation');
check('valid https XYZ source passes', validateGisSourceInput({ name: 'Sentinel', protocol: 'XYZ_RASTER', url: 'https://tiles.example.org/{z}/{x}/{y}.png' }) === null);
check('plain http is rejected', validateGisSourceInput({ name: 'Plain', protocol: 'WMS', url: 'http://tiles.example.org/wms' }) !== null);
check('embedded credentials are rejected', validateGisSourceInput({ name: 'Creds', protocol: 'WMS', url: 'https://user:pw@tiles.example.org/wms' }) !== null);
check('unknown protocol is rejected', validateGisSourceInput({ name: 'BadProto', protocol: 'FTP', url: 'https://tiles.example.org/a' }) !== null);
check('whitespace in url is rejected', validateGisSourceInput({ name: 'Space', protocol: 'GeoJSON', url: 'https://tiles.example.org/my file.geojson' }) !== null);
check('empty name is rejected', validateGisSourceInput({ name: '   ', protocol: 'GeoJSON', url: 'https://tiles.example.org/a.geojson' }) !== null);

console.log('\n===============================================');
console.log(`INTELLIGENCE TESTS: ${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
