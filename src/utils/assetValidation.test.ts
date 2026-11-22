/**
 * Project ATLAS: Front-End Validation Test Suite (Stage 2)
 *
 * Verifies:
 * 1. Oversized file (> 5 MB) is rejected.
 * 2. Wrong CRS (e.g. EPSG:3857) is rejected with clear message.
 * 3. Malformed GeoJSON syntax is rejected.
 * 4. Coordinates out of range (lon > 180 or lat > 90) are rejected.
 * 5. Duplicate site codes within payload are rejected.
 * 6. Duplicate site codes against existing workspace assets are rejected.
 * 7. Positive control: valid CSV and valid GeoJSON pass with 0 errors.
 */

import {
  validateCsvAssetFile,
  validateGeoJsonAssetFile,
  validateCrs,
  MAX_FILE_SIZE_BYTES,
} from './assetValidation';

let failedTests = 0;
let passedTests = 0;

function assert(condition: boolean, testName: string, detail?: string) {
  if (condition) {
    console.log(`PASS: ${testName}`);
    passedTests++;
  } else {
    console.error(`FAIL: ${testName} - ${detail || 'Assertion failed'}`);
    failedTests++;
  }
}

console.log('====================================================================');
console.log('PROJECT ATLAS: FRONT-END ASSET IMPORT VALIDATION SUITE');
console.log('====================================================================');

// Test 1: Oversized file check
{
  const dummyContent = 'site_code,name,type\n';
  const oversizedBytes = MAX_FILE_SIZE_BYTES + 1; // 5MB + 1 byte
  const res = validateCsvAssetFile(dummyContent, oversizedBytes, 'EPSG:4326');
  assert(!res.isValid, 'Reject oversized file (> 5MB)');
  assert(
    res.errors.some((e) => e.message.includes('exceeds maximum allowed limit of 5 MB')),
    'Oversized file returns exact error message'
  );
}

// Test 2: Declared CRS enforcement - Reject EPSG:3857, accept EPSG:4326
{
  const crs3857 = validateCrs('EPSG:3857');
  assert(!crs3857.isValid, 'Reject EPSG:3857');
  assert(
    crs3857.error?.includes("Unsupported CRS 'EPSG:3857'") || false,
    'Clear rejection message for unsupported CRS'
  );

  const crs4326 = validateCrs('EPSG:4326');
  assert(crs4326.isValid && crs4326.normalized === 'EPSG:4326', 'Accept EPSG:4326');

  const crsWgs84 = validateCrs('WGS84');
  assert(crsWgs84.isValid && crsWgs84.normalized === 'EPSG:4326', 'Accept WGS84 as EPSG:4326');
}

// Test 3: Malformed GeoJSON syntax
{
  const malformedJson = '{"type": "FeatureCollection", "features": [ {';
  const res = validateGeoJsonAssetFile(malformedJson, 500, 'EPSG:4326');
  assert(!res.isValid, 'Reject malformed GeoJSON JSON syntax');
  assert(
    res.errors.some((e) => e.message.includes('Malformed GeoJSON file')),
    'Malformed JSON error captured'
  );
}

// Test 4: Coordinate out of range
{
  const badCoordsCsv = `site_code,name,type,criticality,owner,accuracy_class,longitude,latitude
STE-BAD-01,Bad Coordinates Site,site,4,Security Corp,exact_survey,195.5,45.0`;

  const res = validateCsvAssetFile(badCoordsCsv, badCoordsCsv.length, 'EPSG:4326');
  assert(!res.isValid, 'Reject coordinate out of range (lon=195.5)');
  assert(
    res.errors.some((e) => e.message.includes('Longitude 195.5 is out of range [-180, 180]')),
    'Coordinate range error specifies bad longitude'
  );

  const badLatCsv = `site_code,name,type,criticality,owner,accuracy_class,longitude,latitude
STE-BAD-02,Bad Lat Site,site,4,Security Corp,exact_survey,10.0,-95.5`;
  const resLat = validateCsvAssetFile(badLatCsv, badLatCsv.length, 'EPSG:4326');
  assert(!resLat.isValid, 'Reject coordinate out of range (lat=-95.5)');
  assert(
    resLat.errors.some((e) => e.message.includes('Latitude -95.5 is out of range [-90, 90]')),
    'Coordinate range error specifies bad latitude'
  );
}

// Test 5: Duplicate site code within payload
{
  const dupCsv = `site_code,name,type,criticality,owner,accuracy_class,longitude,latitude
STE-DUP-01,Site One,site,3,Alpha Ops,exact_survey,10.0,45.0
STE-DUP-01,Site Two Duplicate,site,3,Alpha Ops,exact_survey,10.1,45.1`;

  const res = validateCsvAssetFile(dupCsv, dupCsv.length, 'EPSG:4326');
  assert(!res.isValid, 'Reject duplicate site_code within file payload');
  assert(
    res.errors.some((e) => e.message.includes("Duplicate site_code 'STE-DUP-01'")),
    'Duplicate site code error details code'
  );
}

// Test 6: Duplicate site code against existing workspace
{
  const existingSet = new Set(['STE-EXISTING-99']);
  const csv = `site_code,name,type,criticality,owner,accuracy_class,longitude,latitude
STE-EXISTING-99,Colliding Site,site,3,Alpha Ops,exact_survey,10.0,45.0`;

  const res = validateCsvAssetFile(csv, csv.length, 'EPSG:4326', existingSet);
  assert(!res.isValid, 'Reject site_code that collides with existing workspace');
  assert(
    res.errors.some((e) => e.message.includes("Site code 'STE-EXISTING-99' already exists in this workspace")),
    'Workspace collision error reported'
  );
}

// Test 7: Positive control - Valid CSV
{
  const validCsv = `site_code,name,type,criticality,owner,accuracy_class,longitude,latitude,source
STE-OK-01,London Data Centre,site,5,Alpha Ops,exact_survey,-0.1278,51.5074,Survey 2026
PWR-OK-02,Substation Grid 2,power_feed,4,National Grid,facility_approximate,-0.1300,51.5100,Survey 2026`;

  const res = validateCsvAssetFile(validCsv, validCsv.length, 'EPSG:4326');
  assert(res.isValid, 'Valid CSV passes with 0 errors');
  assert(res.validRows.length === 2, 'Parsed 2 valid rows');
  assert(res.validRows[0].site_code === 'STE-OK-01', 'First row site code correct');
  assert(res.validRows[1].accuracy_class === 'facility_approximate', 'Second row accuracy class preserved');
}

// Test 8: Positive control - Valid GeoJSON with CRS declaration
{
  const validGeoJson = JSON.stringify({
    type: 'FeatureCollection',
    crs: {
      type: 'name',
      properties: { name: 'EPSG:4326' },
    },
    features: [
      {
        type: 'Feature',
        properties: {
          site_code: 'GEO-001',
          name: 'Primary Node A',
          type: 'cloud_region',
          criticality: 5,
          owner: 'Alpha Cloud',
          accuracy_class: 'exact_survey',
        },
        geometry: {
          type: 'Point',
          coordinates: [12.4964, 41.9028],
        },
      },
      {
        type: 'Feature',
        properties: {
          site_code: 'GEO-002',
          name: 'Regional Relay B',
          type: 'fibre_route',
          criticality: 4,
          owner: 'Telecom Partner',
          accuracy_class: 'regional_approximate',
        },
        geometry: {
          type: 'LineString',
          coordinates: [
            [12.4964, 41.9028],
            [12.5100, 41.9100],
          ],
        },
      },
    ],
  });

  const res = validateGeoJsonAssetFile(validGeoJson, validGeoJson.length, 'EPSG:4326');
  assert(res.isValid, 'Valid GeoJSON passes with 0 errors');
  assert(res.validRows.length === 2, 'Extracted 2 valid features');
  assert(res.validRows[1].type === 'fibre_route', 'LineString asset preserved');
  assert(res.validRows[1].accuracy_class === 'regional_approximate', 'Regional approximate accuracy preserved');
}

console.log('====================================================================');
console.log(`TOTAL PASSED: ${passedTests} | TOTAL FAILED: ${failedTests}`);
console.log('====================================================================');

if (failedTests > 0) {
  process.exit(1);
}
