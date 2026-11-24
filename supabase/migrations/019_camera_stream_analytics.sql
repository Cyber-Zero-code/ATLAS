-- ============================================================================
-- Project ATLAS - Migration 019: Camera Stream Registration, Analytics & Audit
-- ============================================================================
-- Implements ADR 010 (Amended) and ADR 006 (Amended):
-- - Extends public.camera_registry with site reference, RTSP stream URL support,
--   retention policy (default 'none'), legal_basis_ref, admin override fields,
--   and 'offline' connection state.
-- - Adds public.camera_biometric_identities and public.camera_analytics_events
--   with composite (org_id, id) keys, composite foreign keys, FORCE RLS,
--   mandatory AAL2 restrictive policies, and cryptographic audit triggers.
-- - Extends public.log_event() action allowlist for live frame views,
--   retention frame deletions, legal-basis admin overrides, and person alerts.
-- ============================================================================

-- 1. Extend camera_registry with stream URL, site, retention, and legal basis metadata
ALTER TABLE public.camera_registry
    DROP CONSTRAINT camera_registry_endpoint_url_check,
    DROP CONSTRAINT camera_registry_connection_state_check,
    ADD COLUMN site_id UUID,
    ADD COLUMN site_code TEXT,
    ADD COLUMN retention_setting TEXT NOT NULL DEFAULT 'none'
        CHECK (retention_setting IN ('none', '1h', '24h', '7d', '30d')),
    ADD COLUMN legal_basis_ref TEXT,
    ADD COLUMN admin_no_legal_basis_accepted BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN admin_no_legal_basis_accepted_by UUID REFERENCES auth.users(id),
    ADD COLUMN admin_no_legal_basis_accepted_at TIMESTAMPTZ,
    ADD COLUMN last_stream_error TEXT,
    ADD CONSTRAINT fk_camera_registry_site_asset
        FOREIGN KEY (org_id, site_id) REFERENCES public.assets(org_id, id) ON DELETE SET NULL,
    ADD CONSTRAINT camera_registry_endpoint_url_check
        CHECK (endpoint_url IS NULL OR (endpoint_url ~* '^(https?|rtsps?)://' AND endpoint_url !~ '\s')),
    ADD CONSTRAINT camera_registry_connection_state_check
        CHECK (connection_state IN ('registered', 'configured', 'connected', 'operational', 'offline'));

-- Enforce admin-only acceptance when activating without a legal_basis_ref
CREATE OR REPLACE FUNCTION public.enforce_camera_legal_basis_governance()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_has_legal_basis BOOLEAN := COALESCE(btrim(NEW.legal_basis_ref), '') <> '';
    v_is_activating BOOLEAN := NEW.connection_state IN ('connected', 'operational');
BEGIN
    -- Prevent non-admin users from setting or altering admin_no_legal_basis_accepted
    IF NEW.admin_no_legal_basis_accepted IS DISTINCT FROM COALESCE(OLD.admin_no_legal_basis_accepted, false)
       AND NEW.admin_no_legal_basis_accepted = true THEN
        IF NOT public.user_has_role(NEW.org_id, 'atlas:admin') THEN
            RAISE EXCEPTION 'Only an atlas:admin may accept activating a camera without a legal_basis_ref.'
                USING ERRCODE = '42501';
        END IF;
        NEW.admin_no_legal_basis_accepted_by := auth.uid();
        NEW.admin_no_legal_basis_accepted_at := timezone('utc'::text, now());
    END IF;

    IF v_is_activating AND NOT v_has_legal_basis AND NOT NEW.admin_no_legal_basis_accepted THEN
        RAISE EXCEPTION 'Cannot activate camera stream without a legal_basis_ref unless explicitly accepted by an atlas:admin.'
            USING ERRCODE = '22023';
    END IF;

    RETURN NEW;
END;
$$;

REVOKE EXECUTE ON FUNCTION public.enforce_camera_legal_basis_governance() FROM PUBLIC, anon, authenticated;

CREATE TRIGGER trg_camera_legal_basis_insert_update
    BEFORE INSERT OR UPDATE ON public.camera_registry
    FOR EACH ROW EXECUTE FUNCTION public.enforce_camera_legal_basis_governance();

-- 2. Enrolled Biometric Identities (Per-Org Restricted Watchlist / Gallery)
CREATE TABLE public.camera_biometric_identities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES public.organisations(id) ON DELETE CASCADE,
    person_label TEXT NOT NULL,
    person_ref TEXT NOT NULL,
    embedding_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    legal_basis_ref TEXT,
    created_by UUID REFERENCES auth.users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()),
    source TEXT NOT NULL DEFAULT 'Authorised Site Biometric Registry',
    confidence NUMERIC CHECK (confidence >= 0.0 AND confidence <= 1.0) DEFAULT 1.0,
    sharing_policy TEXT NOT NULL DEFAULT 'internal_only',
    correlation_id TEXT NOT NULL DEFAULT gen_random_uuid()::text,
    CONSTRAINT uq_camera_biometric_identities_org_id UNIQUE (org_id, id),
    CONSTRAINT uq_camera_biometric_identities_org_ref UNIQUE (org_id, person_ref)
);

CREATE INDEX idx_camera_biometric_identities_org ON public.camera_biometric_identities(org_id);

-- 3. Camera Analytics, Cross-Camera Tracking & Person-Identifying Alert Events
CREATE TABLE public.camera_analytics_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES public.organisations(id) ON DELETE CASCADE,
    camera_id UUID NOT NULL,
    event_kind TEXT NOT NULL CHECK (
        event_kind IN (
            'face_detection',
            'face_recognition',
            'person_detection',
            'cross_camera_track',
            'person_alert'
        )
    ),
    track_id TEXT,
    identity_id UUID,
    person_label TEXT,
    person_count INTEGER NOT NULL DEFAULT 0 CHECK (person_count >= 0),
    confidence NUMERIC NOT NULL DEFAULT 0.0 CHECK (confidence >= 0.0 AND confidence <= 1.0),
    bounding_box JSONB NOT NULL DEFAULT '{}'::jsonb,
    alert_triggered BOOLEAN NOT NULL DEFAULT false,
    alert_reason TEXT,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()),
    retention_expires_at TIMESTAMPTZ,
    created_by UUID REFERENCES auth.users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()),
    source TEXT NOT NULL DEFAULT 'Gateway Vision Analytics',
    sharing_policy TEXT NOT NULL DEFAULT 'internal_only',
    correlation_id TEXT NOT NULL DEFAULT gen_random_uuid()::text,
    CONSTRAINT uq_camera_analytics_events_org_id UNIQUE (org_id, id),
    CONSTRAINT fk_camera_analytics_camera
        FOREIGN KEY (org_id, camera_id) REFERENCES public.camera_registry(org_id, id) ON DELETE CASCADE,
    CONSTRAINT fk_camera_analytics_identity
        FOREIGN KEY (org_id, identity_id) REFERENCES public.camera_biometric_identities(org_id, id) ON DELETE SET NULL
);

CREATE INDEX idx_camera_analytics_events_org_time ON public.camera_analytics_events(org_id, observed_at DESC);
CREATE INDEX idx_camera_analytics_events_track ON public.camera_analytics_events(org_id, track_id);

-- 4. Enable & Force Row-Level Security + Mandatory AAL2 Policies
ALTER TABLE public.camera_biometric_identities ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.camera_biometric_identities FORCE ROW LEVEL SECURITY;

ALTER TABLE public.camera_analytics_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.camera_analytics_events FORCE ROW LEVEL SECURITY;

CREATE POLICY rst_aal2_camera_biometric_identities ON public.camera_biometric_identities
    AS RESTRICTIVE FOR ALL TO authenticated
    USING ((auth.jwt() ->> 'aal') = 'aal2')
    WITH CHECK ((auth.jwt() ->> 'aal') = 'aal2');

CREATE POLICY rst_aal2_camera_analytics_events ON public.camera_analytics_events
    AS RESTRICTIVE FOR ALL TO authenticated
    USING ((auth.jwt() ->> 'aal') = 'aal2')
    WITH CHECK ((auth.jwt() ->> 'aal') = 'aal2');

CREATE POLICY perm_select_camera_biometric_identities ON public.camera_biometric_identities
    FOR SELECT TO authenticated
    USING (org_id IN (SELECT public.current_user_org_ids()));

CREATE POLICY perm_insert_camera_biometric_identities ON public.camera_biometric_identities
    FOR INSERT TO authenticated
    WITH CHECK (
        public.user_has_role(org_id, 'atlas:analyst')
        OR public.user_has_role(org_id, 'atlas:admin')
    );

CREATE POLICY perm_update_camera_biometric_identities ON public.camera_biometric_identities
    FOR UPDATE TO authenticated
    USING (
        public.user_has_role(org_id, 'atlas:analyst')
        OR public.user_has_role(org_id, 'atlas:admin')
    )
    WITH CHECK (
        public.user_has_role(org_id, 'atlas:analyst')
        OR public.user_has_role(org_id, 'atlas:admin')
    );

CREATE POLICY perm_delete_camera_biometric_identities ON public.camera_biometric_identities
    FOR DELETE TO authenticated
    USING (public.user_has_role(org_id, 'atlas:admin'));

CREATE POLICY perm_select_camera_analytics_events ON public.camera_analytics_events
    FOR SELECT TO authenticated
    USING (org_id IN (SELECT public.current_user_org_ids()));

CREATE POLICY perm_insert_camera_analytics_events ON public.camera_analytics_events
    FOR INSERT TO authenticated
    WITH CHECK (
        public.user_has_role(org_id, 'atlas:analyst')
        OR public.user_has_role(org_id, 'atlas:admin')
    );

CREATE POLICY perm_delete_camera_analytics_events ON public.camera_analytics_events
    FOR DELETE TO authenticated
    USING (public.user_has_role(org_id, 'atlas:admin'));

-- 5. Audit Triggers calling public.internal_append_audit
CREATE TRIGGER trg_audit_camera_biometric_identities
    AFTER INSERT OR UPDATE OR DELETE ON public.camera_biometric_identities
    FOR EACH ROW EXECUTE FUNCTION public.trg_audit_data_table_change();

CREATE TRIGGER trg_audit_camera_analytics_events
    AFTER INSERT OR DELETE ON public.camera_analytics_events
    FOR EACH ROW EXECUTE FUNCTION public.trg_audit_data_table_change();

-- 6. Least-Privilege Role Grants
REVOKE ALL ON public.camera_biometric_identities FROM anon;
REVOKE ALL ON public.camera_analytics_events FROM anon;
REVOKE TRUNCATE, REFERENCES, TRIGGER ON public.camera_biometric_identities FROM authenticated;
REVOKE TRUNCATE, REFERENCES, TRIGGER ON public.camera_analytics_events FROM authenticated;

-- 7. Extend log_event() Allowlist for Camera Frame Views, Retention Deletions, Legal Overrides & Alerts
CREATE OR REPLACE FUNCTION public.log_event(
    p_org_id UUID,
    p_action TEXT,
    p_target_type TEXT,
    p_target_id TEXT,
    p_correlation_id TEXT,
    p_details JSONB
)
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_caller UUID := auth.uid();
    v_role TEXT;
    v_allowed TEXT[] := ARRAY[
        'SIGN_IN',
        'SIGN_OUT',
        'VIEW',
        'EXPORT',
        'APPROVAL',
        'VERIFY_AUDIT_CHAIN',
        'CAMERA_FRAME_VIEW',
        'CAMERA_RETENTION_DELETE',
        'CAMERA_LEGAL_OVERRIDE',
        'CAMERA_PERSON_ALERT'
    ];
BEGIN
    IF v_caller IS NULL THEN
        RAISE EXCEPTION 'Unauthenticated callers cannot log audit events' USING ERRCODE = '42501';
    END IF;

    IF COALESCE(auth.jwt() ->> 'aal', '') <> 'aal2' THEN
        RAISE EXCEPTION 'MFA (aal2) required to log audit events' USING ERRCODE = '42501';
    END IF;

    SELECT role INTO v_role
    FROM public.memberships
    WHERE user_id = v_caller AND org_id = p_org_id;

    IF v_role IS NULL THEN
        RAISE EXCEPTION 'Access denied: user % is not a member of organisation %', v_caller, p_org_id
            USING ERRCODE = '42501';
    END IF;

    IF p_action IS NULL OR NOT (p_action = ANY (v_allowed)) THEN
        RAISE EXCEPTION 'Action "%" is not allowed through log_event()', p_action USING ERRCODE = '22023';
    END IF;

    IF p_details IS NOT NULL AND octet_length(p_details::text) > 8192 THEN
        RAISE EXCEPTION 'details payload too large (max 8192 bytes)' USING ERRCODE = '22023';
    END IF;

    RETURN public.internal_append_audit(
        p_org_id, p_action, p_target_type, p_target_id, p_correlation_id, p_details, v_caller, v_role
    );
END;
$$;

REVOKE EXECUTE ON FUNCTION public.log_event(UUID, TEXT, TEXT, TEXT, TEXT, JSONB) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.log_event(UUID, TEXT, TEXT, TEXT, TEXT, JSONB) TO authenticated;
