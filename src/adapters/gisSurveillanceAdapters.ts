/**
 * Project ATLAS — Module C: Geospatial, Elevation & Surveillance Camera Adapters
 *
 * Security & Honesty Rules:
 * - Zero unapproved external basemaps, public tile servers, or silent coordinate
 *   transmissions. Every external source must be explicitly validated and attached
 *   by the operator (`https://`, zero embedded credentials).
 * - Camera gateway adapters (ONVIF, RTSP->WebRTC, RTSP->HLS) explicitly distinguish
 *   registered metadata & FOV visualization from live video playback; disconnected
 *   or unconfigured cameras NEVER show fabricated video streams.
 */

import { supabase } from '../lib/supabase';
import { validateGatewayEndpointUrl } from './gatewayClient';
import type {
  CameraRegistryItem,
  CameraRetentionSetting,
  GisAdapterCatalogEntry,
  GatewayCameraRecord,
} from '../types/atlas';

export const GIS_SOURCE_ADAPTER_CATALOG: GisAdapterCatalogEntry[] = [
  {
    id: 'copernicus_dem',
    label: 'Copernicus DEM (GLO-30)',
    category: 'DEM_ELEVATION',
    protocol: 'WMS',
    status: 'requires_operator_endpoint',
    endpointPlaceholder: 'https://sh.dataspace.copernicus.eu/ogc/wms/<instance-id>?...',
    licenceNote: 'Copernicus Data Space Ecosystem credentials/WMS instance ID managed by operator.',
    capabilityEffect: 'Attaches licensed elevation hillshade/contour overlay to the map.',
  },
  {
    id: 'usgs_3dep',
    label: 'USGS National Map / 3DEP Elevation',
    category: 'DEM_ELEVATION',
    protocol: 'WMS',
    status: 'requires_operator_endpoint',
    endpointPlaceholder: 'https://elevation.nationalmap.gov/arcgis/services/3DEPElevation/ImageServer/WMSServer?...',
    licenceNote: 'Operator-approved WMS/WMTS endpoint required before transmission.',
    capabilityEffect: 'Provides topographic contour/hillshade raster tile layer.',
  },
  {
    id: 'licensed_satellite',
    label: 'Licensed EO / SAR Satellite Imagery',
    category: 'SATELLITE_IMAGERY',
    protocol: 'XYZ_RASTER',
    status: 'requires_operator_endpoint',
    endpointPlaceholder: 'https://imagery.organisation.internal/tiles/{z}/{x}/{y}.png',
    licenceNote: 'Requires enterprise satellite vendor contract & proxy-injected API token.',
    capabilityEffect: 'Enables optical/SAR visual inspection underneath asset vectors.',
  },
  {
    id: 'authorised_indian_gis',
    label: 'Authorised Indian Geospatial Feeds (Bhuvan / SOI OGC)',
    category: 'NATIONAL_GIS',
    protocol: 'WMS',
    status: 'requires_operator_endpoint',
    endpointPlaceholder: 'https://bhuvan-vec1.nrsc.gov.in/bhuvan/wms?...',
    licenceNote: 'Subject to NRSC/SOI dissemination guidelines & operator authorisation.',
    capabilityEffect: 'Overlays authorised regional administrative/terrain layers.',
  },
  {
    id: 'user_geojson',
    label: 'Operator GeoJSON AOI / Incident Overlay',
    category: 'VECTOR_OVERLAY',
    protocol: 'GeoJSON',
    status: 'local_upload_ready',
    endpointPlaceholder: 'https://gis.organisation.internal/aoi/sector.geojson',
    licenceNote: 'Must serve valid RFC 7946 GeoJSON over HTTPS with permissive CORS.',
    capabilityEffect: 'Renders external sector boundaries or incident perimeters directly in MapLibre.',
  },
];

export const CAMERA_GATEWAY_ADAPTERS = [
  {
    protocol: 'ONVIF' as const,
    label: 'ONVIF Profile S / Profile T Gateway Decoder',
    status: 'BOUNDED GATEWAY DECODER (1 FRAME / 5s)',
    requirement: 'Decoded server-side via gateway ffmpeg child process; JPEG frames fetched with AAL2 JWT.',
  },
  {
    protocol: 'RTSP_WEBRTC' as const,
    label: 'RTSP / RTSPS Live Gateway Decoder',
    status: 'BOUNDED GATEWAY DECODER (1 FRAME / 5s)',
    requirement: 'Stream URL & credentials held strictly server-side; max 4 concurrent streams per org.',
  },
  {
    protocol: 'RTSP_HLS' as const,
    label: 'RTSP / HTTPS -> Gateway JPEG Stream Adapter',
    status: 'READY VIA AUTHENTICATED GATEWAY',
    requirement: 'Requires running gateway service + camera legal_basis_ref (or atlas:admin override).',
  },
];

/**
 * Validates browser-direct GIS endpoints (`https://` required, zero embedded `user:pass@` credentials).
 */
export function validateAuthorisedEndpointUrl(rawUrl: string): { valid: boolean; reason?: string } {
  const trimmed = rawUrl.trim();
  if (!trimmed) return { valid: false, reason: 'Endpoint URL is required.' };
  if (!/^https:\/\//i.test(trimmed)) {
    return { valid: false, reason: 'Only HTTPS endpoints (https://) are permitted by security policy.' };
  }
  if (/^https:\/\/[^/?#]*@/i.test(trimmed)) {
    return { valid: false, reason: 'Embedded URL credentials (user:pass@) are prohibited.' };
  }
  if (/([?&])(api_?key|access_?token|auth_?token|auth|token|secret|password|passwd|session_?token|session_?id|bearer|sig|x-amz-signature|x-amz-credential)=/i.test(trimmed)) {
    return { valid: false, reason: 'URL query credentials or API tokens cannot be stored in browser configuration.' };
  }
  if (/#.*(token|key|secret|password|auth)=/i.test(trimmed)) {
    return { valid: false, reason: 'URL fragment credentials or tokens cannot be stored in browser configuration.' };
  }
  try {
    const parsed = new URL(trimmed.replace(/\{[zxy]\}/g, '0'));
    if (parsed.username || parsed.password) {
      return { valid: false, reason: 'Embedded URL credentials (user:pass@) are prohibited.' };
    }
    if (!parsed.hostname || parsed.hostname.length < 3) {
      return { valid: false, reason: 'Endpoint hostname is invalid.' };
    }
  } catch {
    return { valid: false, reason: 'Malformed URL format.' };
  }
  return { valid: true };
}

/**
 * Validates registered camera stream URLs destined for server-side decoding in the gateway.
 * Permits `rtsp://`, `rtsps://`, and `https://`. Credentials are never persisted in browser state/DB.
 */
export function validateCameraStreamUrlForGateway(rawUrl: string): { valid: boolean; reason?: string } {
  const trimmed = (rawUrl || '').trim();
  if (!trimmed || /\s/.test(trimmed)) {
    return { valid: false, reason: 'Camera stream URL must be non-empty without whitespace.' };
  }
  try {
    const parsed = new URL(trimmed);
    if (!['rtsp:', 'rtsps:', 'https:'].includes(parsed.protocol)) {
      return { valid: false, reason: 'Camera stream URL must start with rtsp://, rtsps://, or https://.' };
    }
    const host = parsed.hostname.toLowerCase();
    if (!host || host === '127.0.0.1' || host === 'localhost' || host === '::1' || host === '169.254.169.254') {
      return { valid: false, reason: 'Loopback and cloud metadata camera targets are blocked by gateway policy.' };
    }
    return { valid: true };
  } catch {
    return { valid: false, reason: 'Malformed camera stream URL.' };
  }
}

async function getActiveSessionJwt(): Promise<string> {
  const { data } = await supabase.auth.getSession();
  const token = data?.session?.access_token;
  if (!token) {
    throw new Error('No active authenticated Supabase session found.');
  }
  return token;
}

export async function listGatewayCameras(
  gatewayUrl: string,
  orgId: string
): Promise<{ cameras: GatewayCameraRecord[]; maxConcurrentPerOrg: number }> {
  const gw = validateGatewayEndpointUrl(gatewayUrl);
  if (!gw.valid || !gw.normalized) {
    throw new Error(gw.reason || 'Invalid gateway URL.');
  }
  const jwt = await getActiveSessionJwt();
  const res = await fetch(`${gw.normalized}/api/v1/cameras`, {
    headers: {
      Authorization: `Bearer ${jwt}`,
      'x-atlas-org-id': orgId,
      Accept: 'application/json',
    },
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(data?.error || `Failed to load gateway cameras (HTTP ${res.status}).`);
  }
  return {
    cameras: Array.isArray(data?.cameras) ? (data.cameras as GatewayCameraRecord[]) : [],
    maxConcurrentPerOrg: Number(data?.maxConcurrentPerOrg || 4),
  };
}

export async function registerAndStartGatewayCamera(params: {
  gatewayUrl: string;
  orgId: string;
  camera: CameraRegistryItem;
  streamUrl: string;
  retentionSetting?: CameraRetentionSetting;
  adminAcceptWithoutLegalBasis?: boolean;
}): Promise<GatewayCameraRecord> {
  const gw = validateGatewayEndpointUrl(params.gatewayUrl);
  if (!gw.valid || !gw.normalized) {
    throw new Error(gw.reason || 'Invalid gateway URL.');
  }
  const urlCheck = validateCameraStreamUrlForGateway(params.streamUrl);
  if (!urlCheck.valid) {
    throw new Error(urlCheck.reason || 'Invalid camera stream URL.');
  }
  const jwt = await getActiveSessionJwt();
  const res = await fetch(`${gw.normalized}/api/v1/cameras`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${jwt}`,
      'x-atlas-org-id': params.orgId,
      'Content-Type': 'application/json',
      Accept: 'application/json',
    },
    body: JSON.stringify({
      cameraId: params.camera.id,
      siteId: params.camera.siteId,
      siteCode: params.camera.siteCode,
      cameraCode: params.camera.cameraCode,
      name: params.camera.name,
      protocol: params.camera.protocol,
      streamUrl: params.streamUrl.trim(),
      retentionSetting: params.retentionSetting || params.camera.retentionSetting || 'none',
      legalBasisRef: params.camera.legalBasisRef,
      adminAcceptWithoutLegalBasis: Boolean(params.adminAcceptWithoutLegalBasis),
      autoStart: true,
    }),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok || !data?.camera) {
    throw new Error(data?.error || `Gateway refused camera stream start (HTTP ${res.status}).`);
  }
  return data.camera as GatewayCameraRecord;
}

export async function stopGatewayCamera(params: {
  gatewayUrl: string;
  orgId: string;
  cameraId: string;
}): Promise<GatewayCameraRecord> {
  const gw = validateGatewayEndpointUrl(params.gatewayUrl);
  if (!gw.valid || !gw.normalized) {
    throw new Error(gw.reason || 'Invalid gateway URL.');
  }
  const jwt = await getActiveSessionJwt();
  const res = await fetch(`${gw.normalized}/api/v1/cameras/${encodeURIComponent(params.cameraId)}/stop`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${jwt}`,
      'x-atlas-org-id': params.orgId,
      Accept: 'application/json',
    },
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok || !data?.camera) {
    throw new Error(data?.error || `Failed to stop camera stream (HTTP ${res.status}).`);
  }
  return data.camera as GatewayCameraRecord;
}

export async function fetchGatewayCameraFrameBlob(params: {
  gatewayUrl: string;
  orgId: string;
  cameraId: string;
}): Promise<Blob> {
  const gw = validateGatewayEndpointUrl(params.gatewayUrl);
  if (!gw.valid || !gw.normalized) {
    throw new Error(gw.reason || 'Invalid gateway URL.');
  }
  const jwt = await getActiveSessionJwt();
  const res = await fetch(`${gw.normalized}/api/v1/cameras/${encodeURIComponent(params.cameraId)}/frame`, {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${jwt}`,
      'x-atlas-org-id': params.orgId,
      Accept: 'image/jpeg',
    },
  });
  if (!res.ok) {
    const errJson = await res.json().catch(() => ({}));
    throw new Error(errJson?.error || `Camera frame unavailable (HTTP ${res.status}).`);
  }
  return res.blob();
}

export async function fetchGatewayCameraAnalytics(params: {
  gatewayUrl: string;
  orgId: string;
  cameraId: string;
}): Promise<GatewayCameraRecord> {
  const gw = validateGatewayEndpointUrl(params.gatewayUrl);
  if (!gw.valid || !gw.normalized) {
    throw new Error(gw.reason || 'Invalid gateway URL.');
  }
  const jwt = await getActiveSessionJwt();
  const res = await fetch(`${gw.normalized}/api/v1/cameras/${encodeURIComponent(params.cameraId)}/analytics`, {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${jwt}`,
      'x-atlas-org-id': params.orgId,
      Accept: 'application/json',
    },
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok || !data?.camera) {
    throw new Error(data?.error || `Failed to fetch camera analytics (HTTP ${res.status}).`);
  }
  return data.camera as GatewayCameraRecord;
}

/**
 * Computes GeoJSON FeatureCollection for Camera Markers + Geodesic FOV Cones
 */
export function buildCamerasGeoJson(cameras: CameraRegistryItem[]): {
  type: 'FeatureCollection';
  features: any[];
} {
  const features: any[] = [];
  const toRad = (d: number) => (d * Math.PI) / 180;

  for (const cam of cameras) {
    // Point feature
    features.push({
      type: 'Feature',
      id: `cam-pt-${cam.id}`,
      geometry: { type: 'Point', coordinates: [cam.lng, cam.lat] },
      properties: {
        kind: 'camera_point',
        id: cam.id,
        cameraCode: cam.cameraCode,
        name: cam.name,
        connectionState: cam.connectionState || (cam.endpointUrl ? 'configured' : 'registered'),
        streamStatus: cam.streamStatus,
        protocol: cam.protocol,
      },
    });

    // FOV sector polygon (azimuth clockwise from North = 0 deg)
    const radiusKm = Math.max(0.02, Math.min(5, cam.rangeMeters / 1000));
    const halfFov = Math.max(5, Math.min(90, cam.fovDeg / 2));
    const latRad = toRad(cam.lat);
    const dLatPerKm = 1 / 111.32;
    const dLonPerKm = 1 / (111.32 * Math.max(Math.cos(latRad), 0.12));

    const steps = 16;
    const ring: Array<[number, number]> = [[cam.lng, cam.lat]];
    for (let i = 0; i <= steps; i++) {
      const azimuthDeg = cam.bearingDeg - halfFov + (i / steps) * (halfFov * 2);
      const azRad = toRad(azimuthDeg);
      const dNorthKm = radiusKm * Math.cos(azRad);
      const dEastKm = radiusKm * Math.sin(azRad);
      ring.push([cam.lng + dEastKm * dLonPerKm, cam.lat + dNorthKm * dLatPerKm]);
    }
    ring.push([cam.lng, cam.lat]);

    features.push({
      type: 'Feature',
      id: `cam-fov-${cam.id}`,
      geometry: { type: 'Polygon', coordinates: [ring] },
      properties: {
        kind: 'camera_fov',
        id: cam.id,
        cameraCode: cam.cameraCode,
        connectionState: cam.connectionState || (cam.endpointUrl ? 'configured' : 'registered'),
        streamStatus: cam.streamStatus,
        isCalculatedCoverageEstimate: true,
      },
    });
  }

  return { type: 'FeatureCollection', features };
}
