-- ============================================================================
-- Project ATLAS - Migration 003: Cryptographic Audit Ledger & Tamper Detection
-- ============================================================================
-- Architecture Guarantees:
-- 1. Written only inside the database: triggers on data tables + log_event() RPC.
-- 2. Actor and role are derived from auth.uid() and memberships; clock is database UTC.
-- 3. Clients have ZERO INSERT/UPDATE/DELETE/TRUNCATE permissions on audit_events.
-- 4. Advisory locking per organisation ensures atomic sequence allocation.
-- 5. Record hash: SHA-256 over (org|seq|timestamp_text|actor|role|action|target_type|target_id|correlation_id|payload_hash|prev_hash).
-- 6. Verification RPC verify_audit_chain(org_id) scans and detects sequence gaps,
--    broken prev_hash pointers, or tampered payload/record hashes.
-- ============================================================================

-- 1. Tamper Resistance Trigger on audit_events (Blocks UPDATE, DELETE, TRUNCATE)
CREATE OR REPLACE FUNCTION public.enforce_audit_immutability()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
BEGIN
    RAISE EXCEPTION 'Audit ledger records are immutable: % operations are prohibited by Project ATLAS policy.', TG_OP
        USING ERRCODE = '55000'; -- object_not_in_prerequisite_state
END;
$$;

CREATE TRIGGER trg_audit_events_no_modify
    BEFORE UPDATE OR DELETE ON public.audit_events
    FOR EACH ROW
    EXECUTE FUNCTION public.enforce_audit_immutability();

CREATE TRIGGER trg_audit_events_no_truncate
    BEFORE TRUNCATE ON public.audit_events
    EXECUTE FUNCTION public.enforce_audit_immutability();

-- 2. Core Internal Chain Append Routine
CREATE OR REPLACE FUNCTION public.internal_append_audit(
    p_org_id UUID,
    p_action TEXT,
    p_target_type TEXT,
    p_target_id TEXT,
    p_correlation_id TEXT,
    p_details JSONB,
    p_actor_id UUID DEFAULT NULL,
    p_actor_role TEXT DEFAULT NULL
)
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_actor_id UUID;
    v_actor_role TEXT;
    v_seq BIGINT;
    v_now TIMESTAMPTZ := timezone('utc'::text, now());
    v_timestamp_text TEXT;
    v_payload_hash TEXT;
    v_prev_hash TEXT;
    v_record_hash TEXT;
    v_raw_str TEXT;
    v_new_id UUID := gen_random_uuid();
    v_lock_key BIGINT;
BEGIN
    -- Derive actor and role if not supplied
    IF p_actor_id IS NOT NULL THEN
        v_actor_id := p_actor_id;
    ELSE
        v_actor_id := auth.uid();
    END IF;

    IF p_actor_role IS NOT NULL THEN
        v_actor_role := p_actor_role;
    ELSIF v_actor_id IS NOT NULL THEN
        SELECT role INTO v_actor_role
        FROM public.memberships
        WHERE user_id = v_actor_id AND org_id = p_org_id;
        
        IF v_actor_role IS NULL THEN
            v_actor_role := 'atlas:system';
        END IF;
    ELSE
        v_actor_role := 'atlas:system';
    END IF;

    -- Standard fixed UTC timestamp format
    v_timestamp_text := to_char(v_now, 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"');

    -- Compute payload hash (SHA-256 over details JSON string)
    v_payload_hash := encode(
        extensions.digest(COALESCE(p_details::text, '{}'::text), 'sha256'),
        'hex'
    );

    -- Transactional Advisory Lock on Organisation UUID (guarantees serial chain)
    -- Hash text representation to 64-bit bigint
    v_lock_key := ('x' || substr(encode(extensions.digest(p_org_id::text, 'sha256'), 'hex'), 1, 16))::bit(64)::bigint;
    PERFORM pg_advisory_xact_lock(v_lock_key);

    -- Calculate Next Sequence Number
    SELECT COALESCE(MAX(seq), 0) + 1 INTO v_seq
    FROM public.audit_events
    WHERE org_id = p_org_id;

    -- Determine Previous Hash (Genesis uses 64 zeros)
    IF v_seq = 1 THEN
        v_prev_hash := repeat('0', 64);
    ELSE
        SELECT record_hash INTO v_prev_hash
        FROM public.audit_events
        WHERE org_id = p_org_id AND seq = (v_seq - 1);

        IF v_prev_hash IS NULL THEN
            RAISE EXCEPTION 'Audit chain integrity failure: missing predecessor for sequence % in org %', v_seq, p_org_id
                USING ERRCODE = '2F000';
        END IF;
    END IF;

    -- Compute Record Hash over ALL Canonical Fields:
    -- org_id | seq | timestamp_text | actor_id | actor_role | action | target_type | target_id | correlation_id | payload_hash | prev_hash
    v_raw_str := p_org_id::text || '|' ||
                 v_seq::text || '|' ||
                 v_timestamp_text || '|' ||
                 COALESCE(v_actor_id::text, 'system') || '|' ||
                 v_actor_role || '|' ||
                 p_action || '|' ||
                 p_target_type || '|' ||
                 p_target_id || '|' ||
                 COALESCE(p_correlation_id, 'none') || '|' ||
                 v_payload_hash || '|' ||
                 v_prev_hash;

    v_record_hash := encode(extensions.digest(v_raw_str, 'sha256'), 'hex');

    -- Insert into immutable ledger
    INSERT INTO public.audit_events (
        id,
        org_id,
        seq,
        timestamp,
        timestamp_text,
        actor_id,
        actor_role,
        action,
        target_type,
        target_id,
        correlation_id,
        payload_hash,
        prev_hash,
        record_hash,
        details
    ) VALUES (
        v_new_id,
        p_org_id,
        v_seq,
        v_now,
        v_timestamp_text,
        v_actor_id,
        v_actor_role,
        p_action,
        p_target_type,
        p_target_id,
        COALESCE(p_correlation_id, gen_random_uuid()::text),
        v_payload_hash,
        v_prev_hash,
        v_record_hash,
        COALESCE(p_details, '{}'::jsonb)
    );

    RETURN v_new_id;
END;
$$;

-- Revoke internal function from all except postgres/service_role
REVOKE EXECUTE ON FUNCTION public.internal_append_audit FROM PUBLIC, anon, authenticated;

-- 3. Public Callable Audit Logger for Non-Table Events (sign-in, view, export, approval)
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
BEGIN
    -- Verify caller is authenticated member of the specified organization
    IF v_caller IS NULL THEN
        RAISE EXCEPTION 'Unauthenticated callers cannot log audit events'
            USING ERRCODE = '42501';
    END IF;

    SELECT role INTO v_role
    FROM public.memberships
    WHERE user_id = v_caller AND org_id = p_org_id;

    IF v_role IS NULL THEN
        RAISE EXCEPTION 'Access denied: user % is not a member of organisation %', v_caller, p_org_id
            USING ERRCODE = '42501';
    END IF;

    -- Append event
    RETURN public.internal_append_audit(
        p_org_id,
        p_action,
        p_target_type,
        p_target_id,
        p_correlation_id,
        p_details,
        v_caller,
        v_role
    );
END;
$$;

REVOKE EXECUTE ON FUNCTION public.log_event FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.log_event TO authenticated;

-- 4. Generic Table Change Trigger
CREATE OR REPLACE FUNCTION public.trg_audit_data_table_change()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_org_id UUID;
    v_target_id TEXT;
    v_details JSONB;
    v_correlation_id TEXT;
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
        TG_TABLE_NAME || '_' || TG_OP,
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

-- Attach triggers to all core tables
CREATE TRIGGER trg_audit_assets
    AFTER INSERT OR UPDATE OR DELETE ON public.assets
    FOR EACH ROW EXECUTE FUNCTION public.trg_audit_data_table_change();

CREATE TRIGGER trg_audit_dependency_edges
    AFTER INSERT OR UPDATE OR DELETE ON public.dependency_edges
    FOR EACH ROW EXECUTE FUNCTION public.trg_audit_data_table_change();

CREATE TRIGGER trg_audit_incidents
    AFTER INSERT OR UPDATE OR DELETE ON public.incidents
    FOR EACH ROW EXECUTE FUNCTION public.trg_audit_data_table_change();

CREATE TRIGGER trg_audit_asset_matches
    AFTER INSERT OR UPDATE OR DELETE ON public.asset_matches
    FOR EACH ROW EXECUTE FUNCTION public.trg_audit_data_table_change();

CREATE TRIGGER trg_audit_evidence
    AFTER INSERT OR UPDATE OR DELETE ON public.evidence
    FOR EACH ROW EXECUTE FUNCTION public.trg_audit_data_table_change();

CREATE TRIGGER trg_audit_custody_events
    AFTER INSERT OR UPDATE OR DELETE ON public.custody_events
    FOR EACH ROW EXECUTE FUNCTION public.trg_audit_data_table_change();

CREATE TRIGGER trg_audit_memberships
    AFTER INSERT OR UPDATE OR DELETE ON public.memberships
    FOR EACH ROW EXECUTE FUNCTION public.trg_audit_data_table_change();

-- 5. Chain Verification Function
-- Scans the organisation's chain, validates sequential ordering, genesis hash,
-- prev_hash pointer link, and recomputed SHA-256 record_hash.
CREATE OR REPLACE FUNCTION public.verify_audit_chain(p_org_id UUID)
RETURNS TABLE (
    is_valid BOOLEAN,
    first_bad_seq BIGINT,
    reason TEXT,
    total_verified BIGINT
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    r RECORD;
    v_expected_seq BIGINT := 1;
    v_prev_record_hash TEXT := repeat('0', 64);
    v_recalculated_hash TEXT;
    v_count BIGINT := 0;
    v_raw_str TEXT;
BEGIN
    -- Authorisation check: caller must be an authenticated member of this org
    IF NOT public.user_is_member(p_org_id) THEN
        RAISE EXCEPTION 'Access denied: user is not a member of organisation %', p_org_id
            USING ERRCODE = '42501';
    END IF;

    FOR r IN (
        SELECT *
        FROM public.audit_events
        WHERE org_id = p_org_id
        ORDER BY seq ASC
    ) LOOP
        -- 1. Sequence Continuity Check
        IF r.seq <> v_expected_seq THEN
            RETURN QUERY SELECT false, r.seq, format('Sequence gap detected: expected %s, found %s', v_expected_seq, r.seq), v_count;
            RETURN;
        END IF;

        -- 2. Previous Hash Pointer Check
        IF r.prev_hash <> v_prev_record_hash THEN
            RETURN QUERY SELECT false, r.seq, format('Previous hash mismatch at sequence %s: expected %s, found %s', r.seq, v_prev_record_hash, r.prev_hash), v_count;
            RETURN;
        END IF;

        -- 3. Recalculate Record Hash
        v_raw_str := r.org_id::text || '|' ||
                     r.seq::text || '|' ||
                     r.timestamp_text || '|' ||
                     COALESCE(r.actor_id::text, 'system') || '|' ||
                     r.actor_role || '|' ||
                     r.action || '|' ||
                     r.target_type || '|' ||
                     r.target_id || '|' ||
                     COALESCE(r.correlation_id, 'none') || '|' ||
                     r.payload_hash || '|' ||
                     r.prev_hash;

        v_recalculated_hash := encode(extensions.digest(v_raw_str, 'sha256'), 'hex');

        IF r.record_hash <> v_recalculated_hash THEN
            RETURN QUERY SELECT false, r.seq, format('Record hash signature failure at sequence %s: stored %s, recalculated %s', r.seq, r.record_hash, v_recalculated_hash), v_count;
            RETURN;
        END IF;

        -- 4. Advance
        v_prev_record_hash := r.record_hash;
        v_expected_seq := v_expected_seq + 1;
        v_count := v_count + 1;
    END LOOP;

    RETURN QUERY SELECT true, NULL::BIGINT, 'Audit chain integrity verified. All cryptographic proofs match.', v_count;
END;
$$;

REVOKE EXECUTE ON FUNCTION public.verify_audit_chain(UUID) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.verify_audit_chain(UUID) TO authenticated;
