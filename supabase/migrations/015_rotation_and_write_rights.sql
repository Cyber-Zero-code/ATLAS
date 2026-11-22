-- ============================================================================
-- Project ATLAS - Migration 015: ingest key rotation, and removal of unused write rights
-- 1. Key rotation. rotate_ingest_key() issues a new key and lets the old one keep working for a
--    short, bounded grace window (0 to 1440 minutes) so a sender can switch over without losing
--    messages. After the window the old key is refused. Admin only, MFA (aal2) required.
--    The old key can still be revoked immediately with revoke_ingest_key().
-- 2. Write rights that no policy ever allowed are removed from the authenticated role, so the
--    table grant and the row policy agree. (Rows were already protected by RLS and triggers; this
--    removes the unused rights so a future policy mistake cannot open them.)
-- Safe to run more than once.
-- ============================================================================

ALTER TABLE public.ingest_keys ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;

-- A key is usable while it is active and has not passed its expiry
CREATE OR REPLACE FUNCTION public.verify_ingest_signature(p_org_id UUID, p_payload JSONB)
RETURNS BOOLEAN
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_secret TEXT;
    v_key_id TEXT := p_payload->>'key_id';
    v_sig TEXT := lower(COALESCE(p_payload->>'signature', ''));
    v_expected TEXT;
BEGIN
    IF auth.uid() IS NULL OR NOT public.user_is_member(p_org_id) THEN
        RAISE EXCEPTION 'Access denied' USING ERRCODE = '42501';
    END IF;
    IF v_key_id IS NULL OR v_sig !~ '^[0-9a-f]{64}$' THEN
        RETURN FALSE;
    END IF;

    SELECT k.secret INTO v_secret
    FROM public.ingest_keys k
    WHERE k.org_id = p_org_id AND k.key_id = v_key_id AND k.status = 'active'
      AND (k.expires_at IS NULL OR k.expires_at > clock_timestamp());
    IF v_secret IS NULL THEN
        RETURN FALSE;
    END IF;

    v_expected := encode(
        extensions.hmac(
            convert_to(public.ingest_signing_string(p_org_id, p_payload), 'UTF8'),
            convert_to(v_secret, 'UTF8'),
            'sha256'),
        'hex');

    RETURN extensions.digest(v_expected, 'sha256') = extensions.digest(v_sig, 'sha256');
END;
$$;
REVOKE EXECUTE ON FUNCTION public.verify_ingest_signature(UUID, JSONB) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.verify_ingest_signature(UUID, JSONB) TO authenticated;

-- Listing now shows the expiry. The secret is still never returned.
DROP FUNCTION IF EXISTS public.list_ingest_keys(UUID);
CREATE FUNCTION public.list_ingest_keys(p_org_id UUID)
RETURNS TABLE (key_id TEXT, status TEXT, created_at TIMESTAMPTZ, revoked_at TIMESTAMPTZ, expires_at TIMESTAMPTZ)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
BEGIN
    IF auth.uid() IS NULL OR COALESCE(auth.jwt() ->> 'aal', '') <> 'aal2' OR NOT public.user_is_member(p_org_id) THEN
        RAISE EXCEPTION 'Access denied' USING ERRCODE = '42501';
    END IF;
    RETURN QUERY
        SELECT k.key_id, k.status, k.created_at, k.revoked_at, k.expires_at
        FROM public.ingest_keys k
        WHERE k.org_id = p_org_id
        ORDER BY k.created_at DESC;
END;
$$;
REVOKE EXECUTE ON FUNCTION public.list_ingest_keys(UUID) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.list_ingest_keys(UUID) TO authenticated;

-- Rotation
CREATE OR REPLACE FUNCTION public.rotate_ingest_key(p_org_id UUID, p_old_key_id TEXT, p_grace_minutes INT DEFAULT 60)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_caller UUID := auth.uid();
    v_role TEXT;
    v_new_id TEXT;
    v_secret TEXT;
    v_expires TIMESTAMPTZ;
    v_rows INT;
BEGIN
    IF v_caller IS NULL THEN
        RAISE EXCEPTION 'Unauthenticated caller' USING ERRCODE = '42501';
    END IF;
    IF COALESCE(auth.jwt() ->> 'aal', '') <> 'aal2' THEN
        RAISE EXCEPTION 'MFA (aal2) required' USING ERRCODE = '42501';
    END IF;
    SELECT role INTO v_role FROM public.memberships WHERE user_id = v_caller AND org_id = p_org_id;
    IF v_role IS DISTINCT FROM 'atlas:admin' THEN
        RAISE EXCEPTION 'Only an administrator of this organisation can rotate ingest keys' USING ERRCODE = '42501';
    END IF;
    IF p_grace_minutes IS NULL OR p_grace_minutes < 0 OR p_grace_minutes > 1440 THEN
        RAISE EXCEPTION 'Grace period must be between 0 and 1440 minutes' USING ERRCODE = '22023';
    END IF;

    v_expires := clock_timestamp() + make_interval(mins => p_grace_minutes);
    UPDATE public.ingest_keys
    SET expires_at = v_expires
    WHERE org_id = p_org_id AND key_id = p_old_key_id AND status = 'active'
      AND (expires_at IS NULL OR expires_at > v_expires);
    GET DIAGNOSTICS v_rows = ROW_COUNT;
    IF v_rows = 0 THEN
        RAISE EXCEPTION 'No active key % in this organisation (or it already expires sooner)', p_old_key_id USING ERRCODE = '02000';
    END IF;

    v_new_id := 'k_' || encode(gen_random_bytes(4), 'hex');
    v_secret := encode(gen_random_bytes(32), 'hex');
    INSERT INTO public.ingest_keys (org_id, key_id, secret, created_by) VALUES (p_org_id, v_new_id, v_secret, v_caller);

    PERFORM public.internal_append_audit(
        p_org_id, 'INGEST_KEY_ROTATED', 'ingest_key', v_new_id,
        'cid-ingest-key-' || v_new_id,
        jsonb_build_object('new_key_id', v_new_id, 'old_key_id', p_old_key_id,
                           'old_key_expires_at', v_expires, 'grace_minutes', p_grace_minutes),
        v_caller, v_role);

    RETURN jsonb_build_object('key_id', v_new_id, 'secret', v_secret, 'old_key_id', p_old_key_id,
        'old_key_expires_at', v_expires,
        'note', 'The new secret is shown once. The old key stops working at the time shown.');
END;
$$;
REVOKE EXECUTE ON FUNCTION public.rotate_ingest_key(UUID, TEXT, INT) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.rotate_ingest_key(UUID, TEXT, INT) TO authenticated;

-- ---- Unused write rights --------------------------------------------------
REVOKE DELETE ON public.asset_matches FROM authenticated;
REVOKE UPDATE, DELETE ON public.custody_events FROM authenticated;
REVOKE UPDATE, DELETE ON public.evidence FROM authenticated;
REVOKE UPDATE, DELETE ON public.incidents FROM authenticated;
REVOKE INSERT, UPDATE, DELETE ON public.organisations FROM authenticated;
REVOKE INSERT, DELETE ON public.scoring_config FROM authenticated;
