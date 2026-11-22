-- ============================================================================
-- Project ATLAS - Migration 010: Harden log_event()
-- Problems closed:
--  1. log_event is SECURITY DEFINER, so it skipped the aal2 (MFA) policies. It now requires aal2 itself.
--  2. It accepted any action text, so a member could write entries that look like system events
--     (e.g. "incidents_INSERT" or "EXPORT_APPROVED"). It now accepts only a fixed list of client-reported actions.
--  3. Unbounded details payload. Now limited to 8 KB.
-- Safe to run more than once.
-- ============================================================================
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
    -- Only these client-reported actions may be written through this function.
    v_allowed TEXT[] := ARRAY['SIGN_IN','SIGN_OUT','VIEW','EXPORT','APPROVAL','VERIFY_AUDIT_CHAIN'];
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
