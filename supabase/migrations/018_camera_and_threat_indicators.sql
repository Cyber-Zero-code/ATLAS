-- ============================================================================
-- Project ATLAS - Migration 018: Camera Registry & External Threat Indicators
-- ============================================================================
-- Defines public.camera_registry and public.external_threat_indicators using
-- the exact structural, RLS, MFA (AAL2), least-privilege, and cryptographic
-- audit ledger conventions established in migrations 001, 002, and 003.
-- ============================================================================

-- 1. Surveillance Camera Metadata Registry
-- Stores operator-registered camera metadata and FOV geometry parameters only.
-- Plain http:// and non-https endpoints are rejected by CHECK constraint.
CREATE TABLE public.camera_registry (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES public.organisations(id) ON DELETE CASCADE,
    camera_code TEXT NOT NULL,
    name TEXT NOT NULL,
    protocol TEXT NOT NULL CHECK (protocol IN ('ONVIF', 'RTSP_WEBRTC', 'RTSP_HLS')),
    lng DOUBLE PRECISION NOT NULL CHECK (lng >= -180.0 AND lng <= 180.0),
    lat DOUBLE PRECISION NOT NULL CHECK (lat >= -90.0 AND lat <= 90.0),
    bearing_deg DOUBLE PRECISION NOT NULL DEFAULT 0 CHECK (bearing_deg >= 0.0 AND bearing_deg <= 360.0),
    fov_deg DOUBLE PRECISION NOT NULL DEFAULT 60 CHECK (fov_deg > 0.0 AND fov_deg <= 180.0),
    range_meters DOUBLE PRECISION NOT NULL DEFAULT 250 CHECK (range_meters > 0.0),
    connection_state TEXT NOT NULL DEFAULT 'registered' CHECK (connection_state IN ('registered', 'configured', 'connected', 'operational')),
    stream_status TEXT NOT NULL DEFAULT 'REGISTERED (METADATA & CALCULATED FOV ESTIMATE ONLY — NOT CONNECTED)',
    endpoint_url TEXT CHECK (endpoint_url IS NULL OR (endpoint_url ~* '^https://' AND endpoint_url !~ '\s')),
    created_by UUID REFERENCES auth.users(id),
    updated_by UUID REFERENCES auth.users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()),
    source TEXT NOT NULL DEFAULT 'Operator Camera Registry',
    confidence NUMERIC CHECK (confidence >= 0.0 AND confidence <= 1.0) DEFAULT 1.0,
    sharing_policy TEXT NOT NULL DEFAULT 'internal_only',
    correlation_id TEXT NOT NULL DEFAULT gen_random_uuid()::text,
    CONSTRAINT uq_camera_registry_org_id UNIQUE (org_id, id),
    CONSTRAINT uq_camera_registry_org_code UNIQUE (org_id, camera_code)
);

CREATE INDEX idx_camera_registry_org ON public.camera_registry(org_id);
CREATE INDEX idx_camera_registry_created ON public.camera_registry(org_id, created_at DESC);

-- 2. External Threat Indicators (Operator-Imported STIX 2.1 / CISA KEV)
-- Imported indicator facts are immutable; analysts may only update verification_status.
CREATE TABLE public.external_threat_indicators (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES public.organisations(id) ON DELETE CASCADE,
    provider_id TEXT NOT NULL CHECK (provider_id IN ('STIX_2_1', 'CISA_KEV', 'MISP', 'TAXII_2_1', 'ALIENVAULT_OTX', 'ABUSE_CH')),
    stix_id TEXT,
    indicator_type TEXT NOT NULL CHECK (indicator_type IN ('ip', 'cidr', 'domain', 'hostname', 'hash', 'certificate', 'malware', 'threat_actor', 'cve')),
    value TEXT NOT NULL,
    source_name TEXT NOT NULL,
    confidence INTEGER NOT NULL DEFAULT 50 CHECK (confidence >= 0 AND confidence <= 100),
    valid_from TIMESTAMPTZ DEFAULT timezone('utc'::text, now()),
    valid_until TIMESTAMPTZ,
    verification_status TEXT NOT NULL DEFAULT 'unverified' CHECK (verification_status IN ('unverified', 'verified_by_analyst', 'false_positive')),
    matched_asset_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
    matched_incident_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
    raw_summary TEXT NOT NULL DEFAULT '',
    imported_by UUID REFERENCES auth.users(id),
    imported_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()),
    source TEXT NOT NULL DEFAULT 'External CTI Import',
    sharing_policy TEXT NOT NULL DEFAULT 'internal_only',
    correlation_id TEXT NOT NULL DEFAULT gen_random_uuid()::text,
    CONSTRAINT uq_external_threat_indicators_org_id UNIQUE (org_id, id),
    CONSTRAINT uq_external_threat_indicators_dedup UNIQUE (org_id, indicator_type, value)
);

CREATE INDEX idx_external_threat_indicators_org ON public.external_threat_indicators(org_id);
CREATE INDEX idx_external_threat_indicators_imported ON public.external_threat_indicators(org_id, imported_at DESC);

-- 3. Enable & Force Row-Level Security (Deny by Default)
ALTER TABLE public.camera_registry ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.camera_registry FORCE ROW LEVEL SECURITY;

ALTER TABLE public.external_threat_indicators ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.external_threat_indicators FORCE ROW LEVEL SECURITY;

-- 4. Mandatory Restrictive MFA AAL2 Policies
CREATE POLICY rst_aal2_camera_registry ON public.camera_registry
    AS RESTRICTIVE FOR ALL TO authenticated
    USING ((auth.jwt() ->> 'aal') = 'aal2')
    WITH CHECK ((auth.jwt() ->> 'aal') = 'aal2');

CREATE POLICY rst_aal2_external_threat_indicators ON public.external_threat_indicators
    AS RESTRICTIVE FOR ALL TO authenticated
    USING ((auth.jwt() ->> 'aal') = 'aal2')
    WITH CHECK ((auth.jwt() ->> 'aal') = 'aal2');

-- 5. Permissive Tenant & Role Policies (Roles from Migration 002: atlas:analyst, atlas:admin)
-- 5.1 camera_registry: members may read; atlas:analyst & atlas:admin may insert/update; only atlas:admin may delete.
CREATE POLICY perm_select_camera_registry ON public.camera_registry
    FOR SELECT TO authenticated
    USING (org_id IN (SELECT public.current_user_org_ids()));

CREATE POLICY perm_insert_camera_registry ON public.camera_registry
    FOR INSERT TO authenticated
    WITH CHECK (
        public.user_has_role(org_id, 'atlas:analyst')
        OR public.user_has_role(org_id, 'atlas:admin')
    );

CREATE POLICY perm_update_camera_registry ON public.camera_registry
    FOR UPDATE TO authenticated
    USING (
        public.user_has_role(org_id, 'atlas:analyst')
        OR public.user_has_role(org_id, 'atlas:admin')
    )
    WITH CHECK (
        public.user_has_role(org_id, 'atlas:analyst')
        OR public.user_has_role(org_id, 'atlas:admin')
    );

CREATE POLICY perm_delete_camera_registry ON public.camera_registry
    FOR DELETE TO authenticated
    USING (public.user_has_role(org_id, 'atlas:admin'));

-- 5.2 external_threat_indicators: members may read; atlas:analyst & atlas:admin may insert/update; only atlas:admin may delete.
CREATE POLICY perm_select_external_threat_indicators ON public.external_threat_indicators
    FOR SELECT TO authenticated
    USING (org_id IN (SELECT public.current_user_org_ids()));

CREATE POLICY perm_insert_external_threat_indicators ON public.external_threat_indicators
    FOR INSERT TO authenticated
    WITH CHECK (
        public.user_has_role(org_id, 'atlas:analyst')
        OR public.user_has_role(org_id, 'atlas:admin')
    );

CREATE POLICY perm_update_external_threat_indicators ON public.external_threat_indicators
    FOR UPDATE TO authenticated
    USING (
        public.user_has_role(org_id, 'atlas:analyst')
        OR public.user_has_role(org_id, 'atlas:admin')
    )
    WITH CHECK (
        public.user_has_role(org_id, 'atlas:analyst')
        OR public.user_has_role(org_id, 'atlas:admin')
    );

CREATE POLICY perm_delete_external_threat_indicators ON public.external_threat_indicators
    FOR DELETE TO authenticated
    USING (public.user_has_role(org_id, 'atlas:admin'));

-- 6. Field-Level Update Guards (Prevent Non-Admin Ownership Tampering & Indicator Fact Mutation)
CREATE OR REPLACE FUNCTION public.enforce_camera_registry_update_rules()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.org_id IS DISTINCT FROM OLD.org_id
       OR NEW.created_by IS DISTINCT FROM OLD.created_by
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'Camera ownership and identity fields (id, org_id, created_by, created_at) cannot be modified.'
            USING ERRCODE = '42501';
    END IF;
    NEW.updated_at := timezone('utc'::text, now());
    RETURN NEW;
END;
$$;

REVOKE EXECUTE ON FUNCTION public.enforce_camera_registry_update_rules() FROM PUBLIC, anon, authenticated;

CREATE TRIGGER trg_camera_registry_guard_update
    BEFORE UPDATE ON public.camera_registry
    FOR EACH ROW EXECUTE FUNCTION public.enforce_camera_registry_update_rules();

CREATE OR REPLACE FUNCTION public.enforce_external_indicator_immutability()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.org_id IS DISTINCT FROM OLD.org_id
       OR NEW.provider_id IS DISTINCT FROM OLD.provider_id
       OR NEW.stix_id IS DISTINCT FROM OLD.stix_id
       OR NEW.indicator_type IS DISTINCT FROM OLD.indicator_type
       OR NEW.value IS DISTINCT FROM OLD.value
       OR NEW.source_name IS DISTINCT FROM OLD.source_name
       OR NEW.confidence IS DISTINCT FROM OLD.confidence
       OR NEW.valid_from IS DISTINCT FROM OLD.valid_from
       OR NEW.valid_until IS DISTINCT FROM OLD.valid_until
       OR NEW.matched_asset_ids IS DISTINCT FROM OLD.matched_asset_ids
       OR NEW.matched_incident_ids IS DISTINCT FROM OLD.matched_incident_ids
       OR NEW.raw_summary IS DISTINCT FROM OLD.raw_summary
       OR NEW.imported_by IS DISTINCT FROM OLD.imported_by
       OR NEW.imported_at IS DISTINCT FROM OLD.imported_at
       OR NEW.source IS DISTINCT FROM OLD.source THEN
        RAISE EXCEPTION 'Imported external threat indicator facts are immutable; only verification_status may be updated.'
            USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END;
$$;

REVOKE EXECUTE ON FUNCTION public.enforce_external_indicator_immutability() FROM PUBLIC, anon, authenticated;

CREATE TRIGGER trg_external_threat_indicators_immutability
    BEFORE UPDATE ON public.external_threat_indicators
    FOR EACH ROW EXECUTE FUNCTION public.enforce_external_indicator_immutability();

-- 7. Cryptographic Audit Ledger Triggers (calling public.internal_append_audit)
CREATE OR REPLACE FUNCTION public.trg_audit_camera_registry_change()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_org_id UUID;
    v_target_id TEXT;
    v_correlation_id TEXT;
    v_details JSONB;
BEGIN
    IF TG_OP = 'DELETE' THEN
        v_org_id := OLD.org_id;
        v_target_id := OLD.id::text;
        v_correlation_id := COALESCE(OLD.correlation_id, 'none');
        v_details := jsonb_build_object(
            'op', 'DELETE',
            'table', TG_TABLE_NAME,
            'old_row', to_jsonb(OLD)
        );
    ELSIF TG_OP = 'INSERT' THEN
        v_org_id := NEW.org_id;
        v_target_id := NEW.id::text;
        v_correlation_id := COALESCE(NEW.correlation_id, 'none');
        v_details := jsonb_build_object(
            'op', 'INSERT',
            'table', TG_TABLE_NAME,
            'new_row', to_jsonb(NEW)
        );
    ELSIF TG_OP = 'UPDATE' THEN
        v_org_id := NEW.org_id;
        v_target_id := NEW.id::text;
        v_correlation_id := COALESCE(NEW.correlation_id, 'none');
        v_details := jsonb_build_object(
            'op', 'UPDATE',
            'table', TG_TABLE_NAME,
            'new_row', to_jsonb(NEW),
            'old_row', to_jsonb(OLD)
        );
    END IF;

    PERFORM public.internal_append_audit(
        v_org_id,
        'CAMERA_' || TG_OP,
        TG_TABLE_NAME,
        v_target_id,
        v_correlation_id,
        v_details
    );

    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    ELSE
        RETURN NEW;
    END IF;
END;
$$;

REVOKE EXECUTE ON FUNCTION public.trg_audit_camera_registry_change() FROM PUBLIC, anon, authenticated;

CREATE TRIGGER trg_audit_camera_registry
    AFTER INSERT OR UPDATE OR DELETE ON public.camera_registry
    FOR EACH ROW EXECUTE FUNCTION public.trg_audit_camera_registry_change();

CREATE TRIGGER trg_audit_external_threat_indicators
    AFTER INSERT OR UPDATE OR DELETE ON public.external_threat_indicators
    FOR EACH ROW EXECUTE FUNCTION public.trg_audit_data_table_change();

-- 8. Least-Privilege Role Grants
REVOKE ALL ON public.camera_registry FROM anon;
REVOKE ALL ON public.external_threat_indicators FROM anon;
REVOKE TRUNCATE, REFERENCES, TRIGGER ON public.camera_registry FROM authenticated;
REVOKE TRUNCATE, REFERENCES, TRIGGER ON public.external_threat_indicators FROM authenticated;
