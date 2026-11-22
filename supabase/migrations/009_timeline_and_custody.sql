-- ============================================================================
-- Project ATLAS - Migration 009: Incident Timeline & Evidence Custody
-- ============================================================================
-- 1. get_incident_timeline(p_incident_id UUID):
--    - SECURITY INVOKER: Enforces RLS and tenant isolation.
--    - Aggregates read-only chronological history from public.audit_events
--      covering: INGEST, MATCH_DECISIONS, VIEWS, EXPORTS, EVIDENCE_UPLOAD, CUSTODY.
-- 2. record_evidence(...):
--    - SECURITY INVOKER: Registers uploaded evidence metadata in public.evidence.
--    - Atomically creates initial 'INTAKE' custody event in public.custody_events.
-- 3. record_custody_event(...):
--    - Appends a custody audit log (e.g., 'VERIFY_HASH', 'ACCESS').
--    - Custody history is strictly append-only.
-- ============================================================================

-- 1. Read-Only Incident Timeline Function
CREATE OR REPLACE FUNCTION public.get_incident_timeline(
    p_incident_id UUID
)
RETURNS TABLE (
    event_id UUID,
    seq BIGINT,
    "timestamp" TIMESTAMPTZ,
    action TEXT,
    actor_id UUID,
    actor_role TEXT,
    target_type TEXT,
    target_id TEXT,
    payload_hash TEXT,
    prev_hash TEXT,
    record_hash TEXT,
    details JSONB
)
LANGUAGE plpgsql
STABLE
SECURITY INVOKER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_org_id UUID;
BEGIN
    -- Verify caller access to the incident via RLS
    SELECT inc.org_id INTO v_org_id
    FROM public.incidents inc
    WHERE inc.id = p_incident_id;

    IF v_org_id IS NULL THEN
        RAISE EXCEPTION 'Access denied: incident % not found or not accessible', p_incident_id
            USING ERRCODE = '42501';
    END IF;

    RETURN QUERY
    SELECT 
        ae.id AS event_id,
        ae.seq,
        ae.timestamp,
        ae.action,
        ae.actor_id,
        ae.actor_role,
        ae.target_type,
        ae.target_id,
        ae.payload_hash,
        ae.prev_hash,
        ae.record_hash,
        ae.details
    FROM public.audit_events ae
    WHERE ae.org_id = v_org_id
      AND (
        -- The incident row itself (audit trigger labels rows with the table name)
        (ae.target_type = 'incidents' AND ae.target_id = p_incident_id::text)
        OR
        -- Match proposals and decisions for this incident
        (ae.target_type = 'asset_matches'
           AND (ae.details->'new_row'->>'incident_id' = p_incident_id::text
                OR ae.details->'old_row'->>'incident_id' = p_incident_id::text))
        OR
        -- Evidence attached to this incident
        (ae.target_type = 'evidence'
           AND upper(coalesce(ae.details->'new_row'->>'target_type', ae.details->'old_row'->>'target_type')) = 'INCIDENT'
           AND coalesce(ae.details->'new_row'->>'target_id', ae.details->'old_row'->>'target_id') = p_incident_id::text)
        OR
        -- Custody events of that evidence
        (ae.target_type = 'custody_events'
           AND coalesce(ae.details->'new_row'->>'evidence_id', ae.details->'old_row'->>'evidence_id') IN (
                SELECT ev.id::text FROM public.evidence ev
                WHERE ev.org_id = v_org_id AND upper(ev.target_type) = 'INCIDENT' AND ev.target_id = p_incident_id))
      )
    ORDER BY ae.seq ASC;
END;
$$;

REVOKE EXECUTE ON FUNCTION public.get_incident_timeline(UUID) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.get_incident_timeline(UUID) TO authenticated;

-- 2. Evidence Registration Function
CREATE OR REPLACE FUNCTION public.record_evidence(
    p_org_id UUID,
    p_target_type TEXT,
    p_target_id UUID,
    p_file_name TEXT,
    p_file_path TEXT,
    p_file_size_bytes BIGINT,
    p_mime_type TEXT,
    p_sha256 TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_caller UUID := auth.uid();
    v_evidence_id UUID := gen_random_uuid();
    v_custody_id UUID := gen_random_uuid();
    v_sanitized_name TEXT;
    v_correlation_id TEXT := gen_random_uuid()::text;
BEGIN
    IF v_caller IS NULL THEN
        RAISE EXCEPTION 'Unauthenticated caller' USING ERRCODE = '42501';
    END IF;

    IF (auth.jwt() ->> 'aal') <> 'aal2' THEN
        RAISE EXCEPTION 'MFA AAL2 required for evidence intake' USING ERRCODE = '42501';
    END IF;

    IF NOT public.user_is_member(p_org_id) THEN
        RAISE EXCEPTION 'Access denied: user % is not a member of organisation %', v_caller, p_org_id
            USING ERRCODE = '42501';
    END IF;

    -- Validate SHA-256 hex format (64 lowercase hex characters)
    IF p_sha256 !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'Malformed SHA-256 hash digest "%". Expected 64 hex characters.', p_sha256
            USING ERRCODE = '22023';
    END IF;

    -- Enforce file size limit (Max 50 MB)
    IF p_file_size_bytes > 52428800 THEN
        RAISE EXCEPTION 'File size % exceeds maximum allowed limit of 50 MB', p_file_size_bytes
            USING ERRCODE = '22023';
    END IF;

    -- Sanitize file name
    v_sanitized_name := regexp_replace(p_file_name, '[^a-zA-Z0-9._-]', '_', 'g');

    -- Insert into public.evidence
    INSERT INTO public.evidence (
        id,
        org_id,
        target_type,
        target_id,
        file_name,
        file_path,
        file_size_bytes,
        mime_type,
        sha256,
        uploader_id,
        source,
        created_at,
        confidence,
        sharing_policy,
        correlation_id
    ) VALUES (
        v_evidence_id,
        p_org_id,
        p_target_type,
        p_target_id,
        v_sanitized_name,
        p_file_path,
        p_file_size_bytes,
        p_mime_type,
        lower(p_sha256),
        v_caller,
        'Analyst Evidence Locker',
        timezone('utc'::text, now()),
        1.0,
        'internal_only',
        v_correlation_id
    );

    -- Insert initial INTAKE custody event
    INSERT INTO public.custody_events (
        id,
        org_id,
        evidence_id,
        event_type,
        actor_id,
        sha256_verified,
        details,
        source,
        created_at,
        confidence,
        sharing_policy,
        correlation_id
    ) VALUES (
        v_custody_id,
        p_org_id,
        v_evidence_id,
        'INTAKE',
        v_caller,
        lower(p_sha256),
        jsonb_build_object(
            'event', 'INITIAL_INTAKE_VERIFIED',
            'file_name', v_sanitized_name,
            'file_size_bytes', p_file_size_bytes,
            'mime_type', p_mime_type,
            'target_type', p_target_type,
            'target_id', p_target_id
        ),
        'Evidence Management',
        timezone('utc'::text, now()),
        1.0,
        'internal_only',
        v_correlation_id
    );

    RETURN jsonb_build_object(
        'success', true,
        'evidence_id', v_evidence_id,
        'custody_id', v_custody_id,
        'sha256', lower(p_sha256),
        'file_name', v_sanitized_name
    );
END;
$$;

REVOKE EXECUTE ON FUNCTION public.record_evidence(UUID, TEXT, UUID, TEXT, TEXT, BIGINT, TEXT, TEXT) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.record_evidence(UUID, TEXT, UUID, TEXT, TEXT, BIGINT, TEXT, TEXT) TO authenticated;

-- 3. Append-Only Custody Verification Function
CREATE OR REPLACE FUNCTION public.record_custody_event(
    p_evidence_id UUID,
    p_event_type TEXT,
    p_sha256_verified TEXT,
    p_details JSONB DEFAULT '{}'::jsonb
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_caller UUID := auth.uid();
    v_org_id UUID;
    v_expected_hash TEXT;
    v_custody_id UUID := gen_random_uuid();
    v_correlation_id TEXT := gen_random_uuid()::text;
    v_is_intact BOOLEAN;
BEGIN
    IF v_caller IS NULL THEN
        RAISE EXCEPTION 'Unauthenticated caller' USING ERRCODE = '42501';
    END IF;

    IF (auth.jwt() ->> 'aal') <> 'aal2' THEN
        RAISE EXCEPTION 'MFA AAL2 required for custody verification' USING ERRCODE = '42501';
    END IF;

    SELECT ev.org_id, ev.sha256
    INTO v_org_id, v_expected_hash
    FROM public.evidence ev
    WHERE ev.id = p_evidence_id;

    IF v_org_id IS NULL THEN
        RAISE EXCEPTION 'Evidence record % not found or not accessible', p_evidence_id
            USING ERRCODE = '02000';
    END IF;

    IF p_event_type NOT IN ('INTAKE', 'VERIFY_HASH', 'ACCESS', 'TRANSFERRED', 'RETENTION_FLAG') THEN
        RAISE EXCEPTION 'Invalid custody event_type "%"', p_event_type
            USING ERRCODE = '22023';
    END IF;

    v_is_intact := (lower(p_sha256_verified) = v_expected_hash);

    -- Insert into append-only custody_events
    INSERT INTO public.custody_events (
        id,
        org_id,
        evidence_id,
        event_type,
        actor_id,
        sha256_verified,
        details,
        source,
        created_at,
        confidence,
        sharing_policy,
        correlation_id
    ) VALUES (
        v_custody_id,
        v_org_id,
        p_evidence_id,
        p_event_type,
        v_caller,
        lower(p_sha256_verified),
        COALESCE(p_details, '{}'::jsonb) || jsonb_build_object(
            'hash_matches_recorded', v_is_intact,
            'expected_hash', v_expected_hash,
            'verified_hash', lower(p_sha256_verified)
        ),
        'Evidence Management Verification',
        timezone('utc'::text, now()),
        1.0,
        'internal_only',
        v_correlation_id
    );

    RETURN jsonb_build_object(
        'success', true,
        'custody_id', v_custody_id,
        'evidence_id', p_evidence_id,
        'is_intact', v_is_intact,
        'expected_hash', v_expected_hash,
        'verified_hash', lower(p_sha256_verified)
    );
END;
$$;

REVOKE EXECUTE ON FUNCTION public.record_custody_event(UUID, TEXT, TEXT, JSONB) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.record_custody_event(UUID, TEXT, TEXT, JSONB) TO authenticated;
