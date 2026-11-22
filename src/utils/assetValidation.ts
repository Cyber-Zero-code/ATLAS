/**
 * Project ATLAS: Asset Import Validation Engine (Stage 2)
 *
 * HARD RULES & SPECIFICATIONS:
 * 1. CSV and GeoJSON only.
 * 2. Maximum file size: 5 MB (5,242,880 bytes).
 * 3. Maximum row count: 10,000 rows.
 * 4. Declared CRS is required: strictly accept only EPSG:4326 in this stage.
 *    Reject any other CRS (e.g., EPSG:3857, NAD83, etc.) with a clear message:
 *    "Unsupported CRS '<NAME>'. Only EPSG:4326 is permitted in this stage. No coordinate conversion allowed."
 * 5. Validate coordinate bounds: Longitude [-180..180], Latitude [-90..90].
 * 6. Validate required fields: site_code, name, owner, type, criticality (1-5), accuracy_class.
 * 7. Validate duplicate site codes within the file and against existing workspace assets.
 * 8. Generate downloadable per-row error report before publishing.
 */

import { AssetType, AccuracyClass } from '../types/atlas';

export const MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024; // 5 MB
export const MAX_ROW_LIMIT = 10000;

export interface ValidationError {
  rowNumber: number;
  siteCode?: string;
  field?: string;
  message: string;
  severity: 'error' | 'warning';
}

export interface ValidatedAssetRow {
  site_code: string;
  name: string;
  type: AssetType;
  criticality: number;
  owner: string;
  accuracy_class: AccuracyClass;
  positional_accuracy_m: number | null;
  identifiers: {
    hostnames: string[];
    ip_addresses: string[];
    cidrs: string[];
    cloud_account_ids: string[];
  };
  geometry: {
    type: string;
    coordinates: any;
  };
  original_geom: {
    type: string;
    coordinates: any;
  };
  source: string;
  confidence: number;
  sharing_policy: string;
}

export interface ValidationResult {
  isValid: boolean;
  totalRows: number;
  validRows: ValidatedAssetRow[];
  errors: ValidationError[];
  declaredCrs: string;
  datasetMetadata: {
    name: string;
    source: string;
    licence: string;
  };
}

const VALID_ASSET_TYPES: AssetType[] = [
  'site',
  'power_feed',
  'fibre_route',
  'cloud_region',
  'service',
];

const VALID_ACCURACY_CLASSES: AccuracyClass[] = [
  'exact_survey',
  'facility_approximate',
  'regional_approximate',
];

/**
 * Normalises and validates a declared CRS identifier.
 * Permitted aliases for EPSG:4326: 'EPSG:4326', 'WGS84', 'URN:OGC:DEF:CRS:OGC:1.3:CRS84', 'CRS84'.
 */
export function validateCrs(rawCrs: string | undefined | null): { isValid: boolean; normalized: string; error?: string } {
  if (!rawCrs || typeof rawCrs !== 'string' || rawCrs.trim() === '') {
    return {
      isValid: false,
      normalized: '',
      error: 'Declared CRS is required. Only EPSG:4326 is permitted in this stage.',
    };
  }

  const clean = rawCrs.trim().toUpperCase();
  const allowed = [
    'EPSG:4326',
    'WGS84',
    'URN:OGC:DEF:CRS:OGC:1.3:CRS84',
    'CRS84',
    'URN:OGC:DEF:CRS:EPSG::4326',
  ];

  if (allowed.includes(clean)) {
    return { isValid: true, normalized: 'EPSG:4326' };
  }

  return {
    isValid: false,
    normalized: rawCrs,
    error: `Unsupported CRS '${rawCrs}'. Only EPSG:4326 is permitted in this stage. No coordinate conversion allowed.`,
  };
}

/**
 * Validates coordinate ranges for any GeoJSON geometry object.
 */
function validateCoordinatesRange(coords: any, geomType: string): string | null {
  if (!coords) return 'Missing coordinates array';

  const checkPair = (pair: any): string | null => {
    if (!Array.isArray(pair) || pair.length < 2) {
      return `Invalid coordinate pair: expected [lon, lat], received ${JSON.stringify(pair)}`;
    }
    const [lon, lat] = pair;
    if (typeof lon !== 'number' || isNaN(lon) || typeof lat !== 'number' || isNaN(lat)) {
      return `Non-numeric coordinate values: [${lon}, ${lat}]`;
    }
    if (lon < -180 || lon > 180) {
      return `Longitude ${lon} is out of range [-180, 180]`;
    }
    if (lat < -90 || lat > 90) {
      return `Latitude ${lat} is out of range [-90, 90]`;
    }
    return null;
  };

  switch (geomType) {
    case 'Point':
      return checkPair(coords);

    case 'MultiPoint':
    case 'LineString': {
      if (!Array.isArray(coords) || coords.length === 0) return 'Empty coordinate array';
      for (const p of coords) {
        const err = checkPair(p);
        if (err) return err;
      }
      return null;
    }

    case 'MultiLineString':
    case 'Polygon': {
      if (!Array.isArray(coords) || coords.length === 0) return 'Empty coordinate array';
      for (const ring of coords) {
        if (!Array.isArray(ring) || ring.length === 0) return 'Empty ring coordinate array';
        for (const p of ring) {
          const err = checkPair(p);
          if (err) return err;
        }
      }
      return null;
    }

    case 'MultiPolygon': {
      if (!Array.isArray(coords) || coords.length === 0) return 'Empty coordinate array';
      for (const poly of coords) {
        if (!Array.isArray(poly) || poly.length === 0) return 'Empty polygon coordinate array';
        for (const ring of poly) {
          if (!Array.isArray(ring) || ring.length === 0) return 'Empty ring coordinate array';
          for (const p of ring) {
            const err = checkPair(p);
            if (err) return err;
          }
        }
      }
      return null;
    }

    default:
      return `Unsupported geometry type: ${geomType}`;
  }
}

/**
 * Simple CSV parser handling quotes and commas
 */
function parseCsvLines(csvText: string): string[][] {
  const lines: string[][] = [];
  const rawLines = csvText.split(/\r?\n/);

  for (let i = 0; i < rawLines.length; i++) {
    const rawLine = rawLines[i].trim();
    if (!rawLine) continue; // skip blank lines

    const row: string[] = [];
    let inQuotes = false;
    let currentCell = '';

    for (let c = 0; c < rawLine.length; c++) {
      const char = rawLine[c];
      if (char === '"') {
        if (inQuotes && rawLine[c + 1] === '"') {
          currentCell += '"';
          c++;
        } else {
          inQuotes = !inQuotes;
        }
      } else if (char === ',' && !inQuotes) {
        row.push(currentCell.trim());
        currentCell = '';
      } else {
        currentCell += char;
      }
    }
    row.push(currentCell.trim());
    lines.push(row);
  }

  return lines;
}

/**
 * Validates and parses raw CSV content
 */
export function validateCsvAssetFile(
  content: string,
  fileSizeBytes: number,
  declaredCrsParam: string,
  existingSiteCodes: Set<string> = new Set()
): ValidationResult {
  const errors: ValidationError[] = [];

  // 1. File size check
  if (fileSizeBytes > MAX_FILE_SIZE_BYTES) {
    errors.push({
      rowNumber: 0,
      message: `File size ${(fileSizeBytes / (1024 * 1024)).toFixed(2)} MB exceeds maximum allowed limit of 5 MB.`,
      severity: 'error',
    });
    return {
      isValid: false,
      totalRows: 0,
      validRows: [],
      errors,
      declaredCrs: declaredCrsParam,
      datasetMetadata: { name: '', source: '', licence: '' },
    };
  }

  // 2. Declared CRS check
  const crsCheck = validateCrs(declaredCrsParam);
  if (!crsCheck.isValid) {
    errors.push({
      rowNumber: 0,
      field: 'declared_crs',
      message: crsCheck.error!,
      severity: 'error',
    });
    return {
      isValid: false,
      totalRows: 0,
      validRows: [],
      errors,
      declaredCrs: declaredCrsParam,
      datasetMetadata: { name: '', source: '', licence: '' },
    };
  }

  // 3. Parse CSV rows
  const parsedRows = parseCsvLines(content);
  if (parsedRows.length <= 1) {
    errors.push({
      rowNumber: 0,
      message: 'CSV file contains no data rows (header only or empty file).',
      severity: 'error',
    });
    return {
      isValid: false,
      totalRows: 0,
      validRows: [],
      errors,
      declaredCrs: crsCheck.normalized,
      datasetMetadata: { name: '', source: '', licence: '' },
    };
  }

  const rawHeaders = parsedRows[0].map((h) => h.toLowerCase().replace(/\s+/g, '_'));
  const headerMap: Record<string, number> = {};
  rawHeaders.forEach((h, idx) => {
    headerMap[h] = idx;
  });

  const getCell = (row: string[], colNames: string[]): string | undefined => {
    for (const name of colNames) {
      if (headerMap[name] !== undefined) {
        return row[headerMap[name]];
      }
    }
    return undefined;
  };

  const dataRows = parsedRows.slice(1);
  const totalRows = dataRows.length;

  if (totalRows > MAX_ROW_LIMIT) {
    errors.push({
      rowNumber: 0,
      message: `Row count (${totalRows}) exceeds maximum limit of ${MAX_ROW_LIMIT} rows.`,
      severity: 'error',
    });
    return {
      isValid: false,
      totalRows,
      validRows: [],
      errors,
      declaredCrs: crsCheck.normalized,
      datasetMetadata: { name: '', source: '', licence: '' },
    };
  }

  const seenSiteCodes = new Set<string>();
  const validRows: ValidatedAssetRow[] = [];

  dataRows.forEach((row, index) => {
    const rowNum = index + 2; // line 1 is header

    const siteCode = getCell(row, ['site_code', 'code', 'site_id', 'id'])?.trim();
    const name = getCell(row, ['name', 'asset_name', 'title'])?.trim();
    const type = (getCell(row, ['type', 'asset_type'])?.toLowerCase().trim() || 'site') as AssetType;
    const rawCrit = getCell(row, ['criticality', 'crit', 'tier']);
    const owner = getCell(row, ['owner', 'responsible', 'operator'])?.trim();
    const accuracyClass = (getCell(row, ['accuracy_class', 'accuracy', 'precision'])?.toLowerCase().trim() ||
      'exact_survey') as AccuracyClass;
    const rawPosAccuracy = getCell(row, ['positional_accuracy_m', 'pos_accuracy']);

    // Coordinates
    const rawLon = getCell(row, ['longitude', 'lon', 'lng', 'x']);
    const rawLat = getCell(row, ['latitude', 'lat', 'y']);

    // Identifiers
    const rawHostnames = getCell(row, ['hostnames', 'hostname']);
    const rawIps = getCell(row, ['ip_addresses', 'ip_address', 'ips', 'ip']);
    const rawCidrs = getCell(row, ['cidrs', 'cidr']);
    const rawCloudAccounts = getCell(row, ['cloud_account_ids', 'cloud_account_id', 'cloud_accounts']);

    const source = getCell(row, ['source'])?.trim() || 'CSV Import Ingest';
    const confidence = parseFloat(getCell(row, ['confidence']) || '1.0');
    const sharingPolicy = getCell(row, ['sharing_policy'])?.trim() || 'internal_only';

    let rowHasError = false;

    // Field: site_code
    if (!siteCode) {
      errors.push({
        rowNumber: rowNum,
        field: 'site_code',
        message: 'Missing required field site_code',
        severity: 'error',
      });
      rowHasError = true;
    } else {
      if (seenSiteCodes.has(siteCode)) {
        errors.push({
          rowNumber: rowNum,
          siteCode,
          field: 'site_code',
          message: `Duplicate site_code '${siteCode}' detected within the import batch.`,
          severity: 'error',
        });
        rowHasError = true;
      } else {
        seenSiteCodes.add(siteCode);
      }

      if (existingSiteCodes.has(siteCode)) {
        errors.push({
          rowNumber: rowNum,
          siteCode,
          field: 'site_code',
          message: `Site code '${siteCode}' already exists in this workspace. Duplicate codes are rejected.`,
          severity: 'error',
        });
        rowHasError = true;
      }
    }

    // Field: name
    if (!name) {
      errors.push({
        rowNumber: rowNum,
        siteCode,
        field: 'name',
        message: 'Missing required field name',
        severity: 'error',
      });
      rowHasError = true;
    }

    // Field: owner
    if (!owner) {
      errors.push({
        rowNumber: rowNum,
        siteCode,
        field: 'owner',
        message: 'Missing required field owner',
        severity: 'error',
      });
      rowHasError = true;
    }

    // Field: type
    if (!VALID_ASSET_TYPES.includes(type)) {
      errors.push({
        rowNumber: rowNum,
        siteCode,
        field: 'type',
        message: `Invalid asset type '${type}'. Must be one of: ${VALID_ASSET_TYPES.join(', ')}`,
        severity: 'error',
      });
      rowHasError = true;
    }

    // Field: criticality
    const criticality = parseInt(rawCrit || '3', 10);
    if (isNaN(criticality) || criticality < 1 || criticality > 5) {
      errors.push({
        rowNumber: rowNum,
        siteCode,
        field: 'criticality',
        message: `Invalid criticality '${rawCrit}'. Must be an integer between 1 and 5.`,
        severity: 'error',
      });
      rowHasError = true;
    }

    // Field: accuracy_class
    if (!VALID_ACCURACY_CLASSES.includes(accuracyClass)) {
      errors.push({
        rowNumber: rowNum,
        siteCode,
        field: 'accuracy_class',
        message: `Invalid accuracy_class '${accuracyClass}'. Must be one of: ${VALID_ACCURACY_CLASSES.join(', ')}`,
        severity: 'error',
      });
      rowHasError = true;
    }

    // Coordinates check
    if (!rawLon || !rawLat) {
      errors.push({
        rowNumber: rowNum,
        siteCode,
        field: 'coordinates',
        message: 'Missing latitude or longitude values',
        severity: 'error',
      });
      rowHasError = true;
    } else {
      const lon = parseFloat(rawLon);
      const lat = parseFloat(rawLat);

      if (isNaN(lon) || isNaN(lat)) {
        errors.push({
          rowNumber: rowNum,
          siteCode,
          field: 'coordinates',
          message: `Non-numeric coordinate values: [${rawLon}, ${rawLat}]`,
          severity: 'error',
        });
        rowHasError = true;
      } else {
        const coordErr = validateCoordinatesRange([lon, lat], 'Point');
        if (coordErr) {
          errors.push({
            rowNumber: rowNum,
            siteCode,
            field: 'coordinates',
            message: coordErr,
            severity: 'error',
          });
          rowHasError = true;
        } else if (!rowHasError) {
          const splitIdentifiers = (raw?: string): string[] => {
            if (!raw) return [];
            return raw
              .split(/[,;|]/)
              .map((s) => s.trim())
              .filter(Boolean);
          };

          const geomObj = {
            type: 'Point',
            coordinates: [lon, lat],
          };

          validRows.push({
            site_code: siteCode!,
            name: name!,
            type,
            criticality,
            owner: owner!,
            accuracy_class: accuracyClass,
            positional_accuracy_m: rawPosAccuracy ? parseFloat(rawPosAccuracy) : null,
            identifiers: {
              hostnames: splitIdentifiers(rawHostnames),
              ip_addresses: splitIdentifiers(rawIps),
              cidrs: splitIdentifiers(rawCidrs),
              cloud_account_ids: splitIdentifiers(rawCloudAccounts),
            },
            geometry: geomObj,
            original_geom: geomObj,
            source,
            confidence: isNaN(confidence) ? 1.0 : confidence,
            sharing_policy: sharingPolicy,
          });
        }
      }
    }
  });

  return {
    isValid: errors.length === 0,
    totalRows,
    validRows: errors.length === 0 ? validRows : [],
    errors,
    declaredCrs: crsCheck.normalized,
    datasetMetadata: {
      name: '',
      source: '',
      licence: '',
    },
  };
}

/**
 * Validates and parses GeoJSON content
 */
export function validateGeoJsonAssetFile(
  content: string,
  fileSizeBytes: number,
  fallbackCrsParam?: string,
  existingSiteCodes: Set<string> = new Set()
): ValidationResult {
  const errors: ValidationError[] = [];

  // 1. File size check
  if (fileSizeBytes > MAX_FILE_SIZE_BYTES) {
    errors.push({
      rowNumber: 0,
      message: `File size ${(fileSizeBytes / (1024 * 1024)).toFixed(2)} MB exceeds maximum allowed limit of 5 MB.`,
      severity: 'error',
    });
    return {
      isValid: false,
      totalRows: 0,
      validRows: [],
      errors,
      declaredCrs: fallbackCrsParam || '',
      datasetMetadata: { name: '', source: '', licence: '' },
    };
  }

  // 2. Parse JSON syntax
  let parsedJson: any;
  try {
    parsedJson = JSON.parse(content);
  } catch (err: any) {
    errors.push({
      rowNumber: 0,
      message: `Malformed GeoJSON file: ${err.message}`,
      severity: 'error',
    });
    return {
      isValid: false,
      totalRows: 0,
      validRows: [],
      errors,
      declaredCrs: fallbackCrsParam || '',
      datasetMetadata: { name: '', source: '', licence: '' },
    };
  }

  // 3. CRS Check
  // GeoJSON crs object: { "type": "name", "properties": { "name": "urn:ogc:def:crs:OGC:1.3:CRS84" } }
  let extractedCrs = fallbackCrsParam;
  if (parsedJson.crs && parsedJson.crs.properties && parsedJson.crs.properties.name) {
    extractedCrs = parsedJson.crs.properties.name;
  }

  const crsCheck = validateCrs(extractedCrs || 'EPSG:4326');
  if (!crsCheck.isValid) {
    errors.push({
      rowNumber: 0,
      field: 'crs',
      message: crsCheck.error!,
      severity: 'error',
    });
    return {
      isValid: false,
      totalRows: 0,
      validRows: [],
      errors,
      declaredCrs: extractedCrs || '',
      datasetMetadata: { name: '', source: '', licence: '' },
    };
  }

  // 4. Extract Features
  let features: any[] = [];
  if (parsedJson.type === 'FeatureCollection' && Array.isArray(parsedJson.features)) {
    features = parsedJson.features;
  } else if (parsedJson.type === 'Feature') {
    features = [parsedJson];
  } else if (Array.isArray(parsedJson)) {
    features = parsedJson;
  } else {
    errors.push({
      rowNumber: 0,
      message: `Invalid GeoJSON structure: expected FeatureCollection or Feature, got ${parsedJson.type || typeof parsedJson}`,
      severity: 'error',
    });
    return {
      isValid: false,
      totalRows: 0,
      validRows: [],
      errors,
      declaredCrs: crsCheck.normalized,
      datasetMetadata: { name: '', source: '', licence: '' },
    };
  }

  const totalRows = features.length;
  if (totalRows === 0) {
    errors.push({
      rowNumber: 0,
      message: 'GeoJSON contains 0 features.',
      severity: 'error',
    });
    return {
      isValid: false,
      totalRows: 0,
      validRows: [],
      errors,
      declaredCrs: crsCheck.normalized,
      datasetMetadata: { name: '', source: '', licence: '' },
    };
  }

  if (totalRows > MAX_ROW_LIMIT) {
    errors.push({
      rowNumber: 0,
      message: `Feature count (${totalRows}) exceeds maximum limit of ${MAX_ROW_LIMIT} rows.`,
      severity: 'error',
    });
    return {
      isValid: false,
      totalRows,
      validRows: [],
      errors,
      declaredCrs: crsCheck.normalized,
      datasetMetadata: { name: '', source: '', licence: '' },
    };
  }

  const seenSiteCodes = new Set<string>();
  const validRows: ValidatedAssetRow[] = [];

  features.forEach((feature, idx) => {
    const rowNum = idx + 1;
    const props = feature.properties || {};
    const geom = feature.geometry;

    const siteCode = (props.site_code || props.code || props.site_id || props.id || feature.id)?.toString().trim();
    const name = (props.name || props.asset_name || props.title)?.toString().trim();
    const type = (props.type || props.asset_type || 'site').toString().toLowerCase().trim() as AssetType;
    const owner = (props.owner || props.operator || props.responsible)?.toString().trim();
    const rawCrit = props.criticality ?? props.crit ?? 3;
    const accuracyClass = (props.accuracy_class || 'exact_survey').toString().toLowerCase().trim() as AccuracyClass;
    const posAccuracy = props.positional_accuracy_m !== undefined ? Number(props.positional_accuracy_m) : null;
    const source = props.source?.toString().trim() || 'GeoJSON Import Ingest';
    const confidence = props.confidence !== undefined ? Number(props.confidence) : 1.0;
    const sharingPolicy = props.sharing_policy?.toString().trim() || 'internal_only';

    let rowHasError = false;

    // Field: site_code
    if (!siteCode) {
      errors.push({
        rowNumber: rowNum,
        field: 'site_code',
        message: 'Missing required property site_code',
        severity: 'error',
      });
      rowHasError = true;
    } else {
      if (seenSiteCodes.has(siteCode)) {
        errors.push({
          rowNumber: rowNum,
          siteCode,
          field: 'site_code',
          message: `Duplicate site_code '${siteCode}' detected within the GeoJSON payload.`,
          severity: 'error',
        });
        rowHasError = true;
      } else {
        seenSiteCodes.add(siteCode);
      }

      if (existingSiteCodes.has(siteCode)) {
        errors.push({
          rowNumber: rowNum,
          siteCode,
          field: 'site_code',
          message: `Site code '${siteCode}' already exists in workspace. Duplicate codes are rejected.`,
          severity: 'error',
        });
        rowHasError = true;
      }
    }

    // Field: name
    if (!name) {
      errors.push({
        rowNumber: rowNum,
        siteCode,
        field: 'name',
        message: 'Missing required property name',
        severity: 'error',
      });
      rowHasError = true;
    }

    // Field: owner
    if (!owner) {
      errors.push({
        rowNumber: rowNum,
        siteCode,
        field: 'owner',
        message: 'Missing required property owner',
        severity: 'error',
      });
      rowHasError = true;
    }

    // Field: type
    if (!VALID_ASSET_TYPES.includes(type)) {
      errors.push({
        rowNumber: rowNum,
        siteCode,
        field: 'type',
        message: `Invalid asset type '${type}'. Must be one of: ${VALID_ASSET_TYPES.join(', ')}`,
        severity: 'error',
      });
      rowHasError = true;
    }

    // Field: criticality
    const criticality = parseInt(rawCrit, 10);
    if (isNaN(criticality) || criticality < 1 || criticality > 5) {
      errors.push({
        rowNumber: rowNum,
        siteCode,
        field: 'criticality',
        message: `Invalid criticality '${rawCrit}'. Must be an integer between 1 and 5.`,
        severity: 'error',
      });
      rowHasError = true;
    }

    // Field: accuracy_class
    if (!VALID_ACCURACY_CLASSES.includes(accuracyClass)) {
      errors.push({
        rowNumber: rowNum,
        siteCode,
        field: 'accuracy_class',
        message: `Invalid accuracy_class '${accuracyClass}'. Must be one of: ${VALID_ACCURACY_CLASSES.join(', ')}`,
        severity: 'error',
      });
      rowHasError = true;
    }

    // Geometry validation
    if (!geom || !geom.type || !geom.coordinates) {
      errors.push({
        rowNumber: rowNum,
        siteCode,
        field: 'geometry',
        message: 'Missing or malformed geometry object',
        severity: 'error',
      });
      rowHasError = true;
    } else {
      const coordErr = validateCoordinatesRange(geom.coordinates, geom.type);
      if (coordErr) {
        errors.push({
          rowNumber: rowNum,
          siteCode,
          field: 'geometry',
          message: coordErr,
          severity: 'error',
        });
        rowHasError = true;
      }
    }

    if (!rowHasError) {
      const identifiers = {
        hostnames: Array.isArray(props.identifiers?.hostnames)
          ? props.identifiers.hostnames
          : Array.isArray(props.hostnames)
          ? props.hostnames
          : [],
        ip_addresses: Array.isArray(props.identifiers?.ip_addresses)
          ? props.identifiers.ip_addresses
          : Array.isArray(props.ip_addresses)
          ? props.ip_addresses
          : [],
        cidrs: Array.isArray(props.identifiers?.cidrs)
          ? props.identifiers.cidrs
          : Array.isArray(props.cidrs)
          ? props.cidrs
          : [],
        cloud_account_ids: Array.isArray(props.identifiers?.cloud_account_ids)
          ? props.identifiers.cloud_account_ids
          : Array.isArray(props.cloud_account_ids)
          ? props.cloud_account_ids
          : [],
      };

      validRows.push({
        site_code: siteCode!,
        name: name!,
        type,
        criticality,
        owner: owner!,
        accuracy_class: accuracyClass,
        positional_accuracy_m: posAccuracy,
        identifiers,
        geometry: geom,
        original_geom: geom,
        source,
        confidence: isNaN(confidence) ? 1.0 : confidence,
        sharing_policy: sharingPolicy,
      });
    }
  });

  return {
    isValid: errors.length === 0,
    totalRows,
    validRows: errors.length === 0 ? validRows : [],
    errors,
    declaredCrs: crsCheck.normalized,
    datasetMetadata: {
      name: parsedJson.name || '',
      source: '',
      licence: '',
    },
  };
}

/**
 * Generates downloadable CSV content of validation errors
 */
export function generateErrorReportCsv(errors: ValidationError[]): string {
  const headers = ['Row Number', 'Site Code', 'Field', 'Severity', 'Error Message'];
  const rows = errors.map((e) => [
    e.rowNumber.toString(),
    `"${(e.siteCode || '').replace(/"/g, '""')}"`,
    `"${(e.field || '').replace(/"/g, '""')}"`,
    e.severity.toUpperCase(),
    `"${e.message.replace(/"/g, '""')}"`,
  ]);

  return [headers.join(','), ...rows.map((r) => r.join(','))].join('\r\n');
}

/**
 * Triggers browser download of error report CSV
 */
export function downloadErrorReport(errors: ValidationError[], filename = 'atlas_import_errors.csv'): void {
  const csvContent = generateErrorReportCsv(errors);
  const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.setAttribute('href', url);
  link.setAttribute('download', filename);
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}
