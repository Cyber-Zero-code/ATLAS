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

import type {
  CameraRegistryItem,
  GisAdapterCatalogEntry,
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
    label: 'ONVIF Profile S / Profile T Metadata & PTZ Adapter',
    status: 'AWAITING AUTHORISED PROXY',
    requirement: 'Requires on-prem ONVIF WS-Security gateway bridge (browser cannot open raw TCP/SOAP ONVIF sockets without TLS bridge).',
  },
  {
    protocol: 'RTSP_WEBRTC' as const,
    label: 'RTSP -> WebRTC Low-Latency Gateway (MediaMTX / Janus)',
    status: 'AWAITING AUTHORISED GATEWAY',
    requirement: 'Requires WHEP/WebRTC HTTPS signalling endpoint on internal/VPN network.',
  },
  {
    protocol: 'RTSP_HLS' as const,
    label: 'RTSP -> HLS (`.m3u8`) Segmented Stream Gateway',
    status: 'READY WHEN ENDPOINT SUPPLIED',
    requirement: 'Requires HTTPS CORS-enabled `.m3u8` stream URL from authorised VMS relay.',
  },
];

/**
 * Validates user-supplied GIS or Camera Gateway endpoints
 * (`https://` required, zero embedded `user:pass@` credentials).
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
