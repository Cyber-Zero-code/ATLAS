-- ============================================================================
-- Project ATLAS - Migration 006: Atomic Asset Import & Map GeoJSON Queries
-- ============================================================================
-- Features:
-- 1. import_assets(p_dataset, p_rows):
--    - Atomic transaction: all rows committed or all rolled back.
--    - Enforces EPSG:4326 CRS, required fields, criticality (1-5), accuracy class,
--      geometry validity (via PostGIS), and duplicate site code detection.
--    - Stores dataset metadata (name, source, licence, declared_crs, validation_report).
--    - Keeps original geometry untouched in original_geom column.
--    - Triggers database audit events on public.assets and public.datasets.
-- 2. get_workspace_assets_geojson(p_org_id, p_type, p_min_criticality):
--    - Returns an optimized GeoJSON FeatureCollection for MapLibre rendering.
--    - Filters by asset type and minimum criticality.
--    - Includes accuracy_class, positional_accuracy_m, identifiers for profile card.
-- ============================================================================

-- 1. Atomic Asset Import Function
CREATE OR REPLACE FUNCTION public.import_assets(
    p_dataset JSONB,
    p_rows JSONB
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_caller UUID := auth.uid();
    v_org_id UUID;
    v_dataset_id UUID := gen_random_uuid();
    v_dataset_name TEXT;
    v_source TEXT;
    v_licence TEXT;
    v_declared_crs TEXT;
    v_correlation_id TEXT;
    v_validation_report JSONB;

    v_row JSONB;
    v_site_code TEXT;
    v_name TEXT;
    v_type TEXT;
    v_criticality INT;
    v_owner TEXT;
    v_accuracy_class TEXT;
    v_pos_accuracy NUMERIC;
    v_identifiers JSONB;
    v_geom_json JSONB;
    v_original_geom JSONB;
    v_geom geometry;
    v_confidence NUMERIC;
    v_sharing_policy TEXT;
    v_asset_id UUID;

    v_seen_codes TEXT[] := ARRAY[]::TEXT[];
    v_count INT := 0;
BEGIN
    -- 1. Security & Authentication Checks
    IF v_caller IS NULL THEN
        RAISE EXCEPTION 'Unauthenticated caller' USING ERRCODE = '42501';
    END IF;

    IF (auth.jwt() ->> 'aal') <> 'aal2' THEN
        RAISE EXCEPTION 'MFA AAL2 required for asset import' USING ERRCODE = '42501';
    END IF;

    -- Extract Dataset Metadata
    v_org_id := (p_dataset->>'org_id')::UUID;
    v_dataset_name := COALESCE(NULLIF(trim(p_dataset->>'name'), ''), 'Unnamed Ingest Batch');
    v_source := COALESCE(NULLIF(trim(p_dataset->>'source'), ''), 'Client Upload Ingest');
    v_licence := COALESCE(NULLIF(trim(p_dataset->>'licence'), ''), 'Proprietary / Authorised');
    v_declared_crs := upper(trim(p_dataset->>'declared_crs'));
    v_correlation_id := COALESCE(NULLIF(trim(p_dataset->>'correlation_id'), ''), gen_random_uuid()::text);
    v_validation_report := COALESCE(p_dataset->'validation_report', '{}'::jsonb);

    IF v_org_id IS NULL THEN
        RAISE EXCEPTION 'Missing target organisation id' USING ERRCODE = '22023';
    END IF;

    -- Verify membership in target organisation
    IF NOT public.user_is_member(v_org_id) THEN
        RAISE EXCEPTION 'Access denied: user % is not a member of organisation %', v_caller, v_org_id
            USING ERRCODE = '42501';
    END IF;

    -- Enforce Declared CRS: Only EPSG:4326 accepted in this stage
    IF v_declared_crs NOT IN ('EPSG:4326', 'WGS84', 'URN:OGC:DEF:CRS:OGC:1.3:CRS84') THEN
        RAISE EXCEPTION 'Unsupported CRS "%". Only EPSG:4326 is permitted in this stage. No coordinate conversion allowed.', v_declared_crs
            USING ERRCODE = '22023';
    END IF;

    -- Verify row count bounds (1 to 10,000)
    IF jsonb_array_length(p_rows) = 0 THEN
        RAISE EXCEPTION 'Cannot publish empty dataset: 0 rows provided' USING ERRCODE = '22023';
    END IF;

    IF jsonb_array_length(p_rows) > 10000 THEN
        RAISE EXCEPTION 'Batch exceeds maximum allowed limit of 10,000 rows (got %)', jsonb_array_length(p_rows)
            USING ERRCODE = '22023';
    END IF;

    -- 2. Create Dataset Record
    INSERT INTO public.datasets (
        id, org_id, name, source, licence, declared_crs, validation_report, row_count, correlation_id
    ) VALUES (
        v_dataset_id, v_org_id, v_dataset_name, v_source, v_licence, 'EPSG:4326', v_validation_report, jsonb_array_length(p_rows), v_correlation_id
    );

    -- 3. Validate & Insert Each Asset Row Atomically
    FOR v_row IN SELECT * FROM jsonb_array_elements(p_rows)
    LOOP
        v_site_code := trim(v_row->>'site_code');
        v_name := trim(v_row->>'name');
        v_type := lower(trim(v_row->>'type'));
        v_criticality := (v_row->>'criticality')::INT;
        v_owner := trim(v_row->>'owner');
        v_accuracy_class := lower(trim(v_row->>'accuracy_class'));
        v_pos_accuracy := (v_row->>'positional_accuracy_m')::NUMERIC;
        v_identifiers := COALESCE(v_row->'identifiers', '{"hostnames":[], "ip_addresses":[], "cidrs":[], "cloud_account_ids":[]}'::jsonb);
        v_geom_json := v_row->'geometry';
        v_original_geom := COALESCE(v_row->'original_geom', v_geom_json);
        v_confidence := COALESCE((v_row->>'confidence')::NUMERIC, 1.0);
        v_sharing_policy := COALESCE(NULLIF(trim(v_row->>'sharing_policy'), ''), 'internal_only');

        -- Required Field Validations
        IF v_site_code IS NULL OR v_site_code = '' THEN
            RAISE EXCEPTION 'Row %: Missing required field site_code', v_count + 1 USING ERRCODE = '23502';
        END IF;

        IF v_name IS NULL OR v_name = '' THEN
            RAISE EXCEPTION 'Row % (site_code %): Missing required field name', v_count + 1, v_site_code USING ERRCODE = '23502';
        END IF;

        IF v_owner IS NULL OR v_owner = '' THEN
            RAISE EXCEPTION 'Row % (site_code %): Missing required field owner', v_count + 1, v_site_code USING ERRCODE = '23502';
        END IF;

        -- Enum Type Validation
        IF v_type NOT IN ('site', 'power_feed', 'fibre_route', 'cloud_region', 'service') THEN
            RAISE EXCEPTION 'Row % (site_code %): Invalid asset type "%". Must be site, power_feed, fibre_route, cloud_region, or service.',
                v_count + 1, v_site_code, v_type USING ERRCODE = '22023';
        END IF;

        -- Criticality Validation (1 to 5)
        IF v_criticality IS NULL OR v_criticality < 1 OR v_criticality > 5 THEN
            RAISE EXCEPTION 'Row % (site_code %): Invalid criticality "%". Must be an integer between 1 and 5.',
                v_count + 1, v_site_code, v_row->>'criticality' USING ERRCODE = '22023';
        END IF;

        -- Accuracy Class Validation
        IF v_accuracy_class NOT IN ('exact_survey', 'facility_approximate', 'regional_approximate') THEN
            RAISE EXCEPTION 'Row % (site_code %): Invalid accuracy_class "%". Must be exact_survey, facility_approximate, or regional_approximate.',
                v_count + 1, v_site_code, v_accuracy_class USING ERRCODE = '22023';
        END IF;

        -- Duplicate Site Code Check within the File
        IF v_site_code = ANY(v_seen_codes) THEN
            RAISE EXCEPTION 'Row %: Duplicate site_code "%" detected within the import payload',
                v_count + 1, v_site_code USING ERRCODE = '23505';
        END IF;
        v_seen_codes := array_append(v_seen_codes, v_site_code);

        -- Duplicate Site Code Check within the Existing Workspace
        IF EXISTS (SELECT 1 FROM public.assets WHERE org_id = v_org_id AND site_code = v_site_code) THEN
            RAISE EXCEPTION 'Row %: Site code "%" already exists in workspace %',
                v_count + 1, v_site_code, v_org_id USING ERRCODE = '23505';
        END IF;

        -- Geometry Validation via PostGIS
        IF v_geom_json IS NULL OR (v_geom_json->>'type') IS NULL THEN
            RAISE EXCEPTION 'Row % (site_code %): Missing GeoJSON geometry object',
                v_count + 1, v_site_code USING ERRCODE = '22023';
        END IF;

        BEGIN
            v_geom := ST_SetSRID(ST_GeomFromGeoJSON(v_geom_json::text), 4326);
        EXCEPTION WHEN OTHERS THEN
            RAISE EXCEPTION 'Row % (site_code %): Malformed GeoJSON geometry: %',
                v_count + 1, v_site_code, SQLERRM USING ERRCODE = '22023';
        END;

        IF v_geom IS NULL OR NOT ST_IsValid(v_geom) THEN
            RAISE EXCEPTION 'Row % (site_code %): PostGIS validation failure: Geometry is invalid (reason: %)',
                v_count + 1, v_site_code, ST_IsValidReason(v_geom) USING ERRCODE = '22023';
        END IF;

        -- Coordinate Bounds Check [-180, 180], [-90, 90]
        IF ST_XMin(v_geom) < -180.0 OR ST_XMax(v_geom) > 180.0 OR
           ST_YMin(v_geom) < -90.0 OR ST_YMax(v_geom) > 90.0 THEN
            RAISE EXCEPTION 'Row % (site_code %): Coordinates out of WGS84 range [-180..180, -90..90]',
                v_count + 1, v_site_code USING ERRCODE = '22023';
        END IF;

        -- Generate ID & Insert
        v_asset_id := gen_random_uuid();

        INSERT INTO public.assets (
            id,
            org_id,
            dataset_id,
            site_code,
            name,
            type,
            criticality,
            owner,
            geom,
            original_geom,
            accuracy_class,
            positional_accuracy_m,
            identifiers,
            source,
            confidence,
            sharing_policy,
            correlation_id
        ) VALUES (
            v_asset_id,
            v_org_id,
            v_dataset_id,
            v_site_code,
            v_name,
            v_type,
            v_criticality,
            v_owner,
            v_geom,
            v_original_geom,
            v_accuracy_class,
            v_pos_accuracy,
            v_identifiers,
            v_source,
            v_confidence,
            v_sharing_policy,
            v_correlation_id
        );

        v_count := v_count + 1;
    END LOOP;

    RETURN jsonb_build_object(
        'success', true,
        'dataset_id', v_dataset_id,
        'dataset_name', v_dataset_name,
        'imported_count', v_count,
        'correlation_id', v_correlation_id
    );
END;
$$;

REVOKE EXECUTE ON FUNCTION public.import_assets(JSONB, JSONB) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.import_assets(JSONB, JSONB) TO authenticated;

-- 2. GeoJSON Query Function for MapLibre
CREATE OR REPLACE FUNCTION public.get_workspace_assets_geojson(
    p_org_id UUID,
    p_type TEXT DEFAULT NULL,
    p_min_criticality INTEGER DEFAULT NULL
)
RETURNS JSONB
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_caller UUID := auth.uid();
    v_geojson JSONB;
BEGIN
    -- Authorisation & AAL2 check
    IF v_caller IS NULL THEN
        RAISE EXCEPTION 'Unauthenticated caller' USING ERRCODE = '42501';
    END IF;

    IF (auth.jwt() ->> 'aal') <> 'aal2' THEN
        RAISE EXCEPTION 'MFA AAL2 required to query map assets' USING ERRCODE = '42501';
    END IF;

    IF NOT public.user_is_member(p_org_id) THEN
        RAISE EXCEPTION 'Access denied: user % is not a member of organisation %', v_caller, p_org_id
            USING ERRCODE = '42501';
    END IF;

    SELECT jsonb_build_object(
        'type', 'FeatureCollection',
        'features', COALESCE(jsonb_agg(
            jsonb_build_object(
                'type', 'Feature',
                'id', a.id,
                'geometry', ST_AsGeoJSON(a.geom)::jsonb,
                'properties', jsonb_build_object(
                    'id', a.id,
                    'site_code', a.site_code,
                    'name', a.name,
                    'type', a.type,
                    'criticality', a.criticality,
                    'owner', a.owner,
                    'accuracy_class', a.accuracy_class,
                    'is_approximate', (a.accuracy_class IN ('facility_approximate', 'regional_approximate')),
                    'positional_accuracy_m', a.positional_accuracy_m,
                    'identifiers', a.identifiers,
                    'source', a.source,
                    'confidence', a.confidence,
                    'sharing_policy', a.sharing_policy,
                    'created_at', a.created_at
                )
            )
        ), '[]'::jsonb)
    ) INTO v_geojson
    FROM public.assets a
    WHERE a.org_id = p_org_id
      AND (p_type IS NULL OR p_type = 'all' OR a.type = p_type)
      AND (p_min_criticality IS NULL OR a.criticality >= p_min_criticality);

    RETURN v_geojson;
END;
$$;

REVOKE EXECUTE ON FUNCTION public.get_workspace_assets_geojson(UUID, TEXT, INTEGER) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.get_workspace_assets_geojson(UUID, TEXT, INTEGER) TO authenticated;
