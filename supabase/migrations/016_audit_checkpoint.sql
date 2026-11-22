-- ============================================================================
-- Project ATLAS - Migration 016: audit checkpoints (detects removal of the newest audit rows)
-- A hash chain proves that rows were not edited and that no row was removed from the middle.
-- It cannot, on its own, show that the newest rows were cut off the end, because a shorter chain
-- is still a valid chain. A checkpoint fixes that: an administrator records the chain head
-- (sequence number and record hash) somewhere outside the database, and later checks the live
-- chain against it. Rows removed from the end then show up as a missing or different anchor row.
--   * audit_checkpoint(org)            admin + MFA. Appends an AUDIT_CHECKPOINT event and returns its
--                                      seq and record_hash. Store those two values outside ATLAS.
--   * verify_audit_chain_against(org, seq, hash)  any member. Runs the full chain check, then checks
--                                      that row <seq> exists and has exactly that hash.
-- Safe to run more than once.
-- ============================================================================

CREATE OR REPLACE FUNCTION public.audit_checkpoint(p_org_id UUID)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_caller UUID := auth.uid();
    v_role TEXT;
    v_seq BIGINT;
    v_hash TEXT;
    v_ts TIMESTAMPTZ;
BEGIN
    IF v_caller IS NULL THEN
        RAISE EXCEPTION 'Unauthenticated caller' USING ERRCODE = '42501';
    END IF;
    IF COALESCE(auth.jwt() ->> 'aal', '') <> 'aal2' THEN
        RAISE EXCEPTION 'MFA (aal2) required' USING ERRCODE = '42501';
    END IF;
    SELECT role INTO v_role FROM public.memberships WHERE user_id = v_caller AND org_id = p_org_id;
    IF v_role IS DISTINCT FROM 'atlas:admin' THEN
        RAISE EXCEPTION 'Only an administrator of this organisation can record an audit checkpoint' USING ERRCODE = '42501';
    END IF;

    PERFORM public.internal_append_audit(
        p_org_id, 'AUDIT_CHECKPOINT', 'audit_chain', p_org_id::text,
        'cid-audit-checkpoint-' || gen_random_uuid()::text, '{}'::jsonb, v_caller, v_role);

    SELECT a.seq, a.record_hash, a.timestamp INTO v_seq, v_hash, v_ts
    FROM public.audit_events a
    WHERE a.org_id = p_org_id AND a.action = 'AUDIT_CHECKPOINT' AND a.actor_id = v_caller
    ORDER BY a.seq DESC LIMIT 1;

    RETURN jsonb_build_object('org_id', p_org_id, 'seq', v_seq, 'record_hash', v_hash, 'recorded_at', v_ts,
        'note', 'Store seq and record_hash outside ATLAS (for example in your own ticketing or vault). They let you detect removal of the newest audit rows later.');
END;
$$;
REVOKE EXECUTE ON FUNCTION public.audit_checkpoint(UUID) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.audit_checkpoint(UUID) TO authenticated;

CREATE OR REPLACE FUNCTION public.verify_audit_chain_against(p_org_id UUID, p_seq BIGINT, p_record_hash TEXT)
RETURNS TABLE (is_valid BOOLEAN, first_bad_seq BIGINT, reason TEXT, total_verified BIGINT)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_ok BOOLEAN;
    v_bad BIGINT;
    v_why TEXT;
    v_total BIGINT;
    v_stored TEXT;
BEGIN
    IF auth.uid() IS NULL OR NOT public.user_is_member(p_org_id) THEN
        RAISE EXCEPTION 'Access denied' USING ERRCODE = '42501';
    END IF;
    IF p_seq IS NULL OR p_seq < 1 OR p_record_hash IS NULL OR p_record_hash !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'A checkpoint needs a sequence number of 1 or more and a 64-character lowercase hex hash' USING ERRCODE = '22023';
    END IF;

    SELECT c.is_valid, c.first_bad_seq, c.reason, c.total_verified INTO v_ok, v_bad, v_why, v_total
    FROM public.verify_audit_chain(p_org_id) c;
    IF NOT v_ok THEN
        RETURN QUERY SELECT v_ok, v_bad, v_why, v_total;
        RETURN;
    END IF;

    SELECT a.record_hash INTO v_stored FROM public.audit_events a WHERE a.org_id = p_org_id AND a.seq = p_seq;
    IF v_stored IS NULL THEN
        RETURN QUERY SELECT false, p_seq,
            format('Checkpoint row %s is missing: the chain now ends at %s. Newest rows were removed.', p_seq, v_total), v_total;
    ELSIF v_stored <> lower(p_record_hash) THEN
        RETURN QUERY SELECT false, p_seq, format('Checkpoint row %s exists but its hash differs from the stored checkpoint.', p_seq), v_total;
    ELSE
        RETURN QUERY SELECT true, NULL::BIGINT,
            format('Chain verified and matches the checkpoint at sequence %s.', p_seq), v_total;
    END IF;
END;
$$;
REVOKE EXECUTE ON FUNCTION public.verify_audit_chain_against(UUID, BIGINT, TEXT) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.verify_audit_chain_against(UUID, BIGINT, TEXT) TO authenticated;
