-- ============================================================================
-- Project ATLAS - Migration 011: Harden record_evidence()
-- Closes: evidence could be registered against a non-existent or other-organisation
-- target, an unknown target type, or a storage path outside the organisation's folder.
-- Safe to run more than once.
-- ============================================================================
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

    -- Evidence must be registered against a known kind of target that exists in THIS organisation
    IF upper(p_target_type) NOT IN ('INCIDENT', 'ASSET') THEN
        RAISE EXCEPTION 'Unsupported evidence target type "%"', p_target_type USING ERRCODE = '22023';
    END IF;
    IF upper(p_target_type) = 'INCIDENT' AND NOT EXISTS (
        SELECT 1 FROM public.incidents i WHERE i.org_id = p_org_id AND i.id = p_target_id) THEN
        RAISE EXCEPTION 'Incident % not found in this organisation', p_target_id USING ERRCODE = '22023';
    END IF;
    IF upper(p_target_type) = 'ASSET' AND NOT EXISTS (
        SELECT 1 FROM public.assets a WHERE a.org_id = p_org_id AND a.id = p_target_id) THEN
        RAISE EXCEPTION 'Asset % not found in this organisation', p_target_id USING ERRCODE = '22023';
    END IF;

    -- The stored object must live inside this organisation's own storage folder
    IF p_file_path IS NULL OR left(p_file_path, length(p_org_id::text) + 1) <> p_org_id::text || '/'
       OR p_file_path LIKE '%..%' THEN
        RAISE EXCEPTION 'file_path must be inside the organisation folder %/', p_org_id USING ERRCODE = '22023';
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
