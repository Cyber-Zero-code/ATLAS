-- ============================================================================
-- Project ATLAS - Migration 013: Signed incident intake
-- Incident messages must now carry key_id and signature: an HMAC-SHA256 (hex) over a fixed
-- signing string, made with a secret that belongs to the organisation. Unsigned, tampered,
-- wrong-organisation and revoked-key messages are refused with SQLSTATE 42501.
--   * Secrets live in public.ingest_keys, which no client role can read (RLS forced, no policies, no grants).
--   * Admins create and revoke keys; the secret is shown once at creation.
--   * Key creation and revocation are audited WITHOUT the secret.
--   * sent_at is inside the signature, so the 10-minute replay window cannot be stretched.
-- Signing string v1 (lines joined with a line feed; every string value is JSON-quoted):
--   atlas-ingest-v1 / org_id / key_id / schema_version / event_id / event_type / severity / observed_at /
--   sent_at / confidence (raw number text, or empty) / correlation_id / source / then the five signal
--   lists (site_codes, hostnames, ips, cidrs, cloud_account_ids), each as a JSON array sorted bytewise.
-- Safe to run more than once.
-- ============================================================================

CREATE TABLE IF NOT EXISTS public.ingest_keys (
    org_id      UUID        NOT NULL REFERENCES public.organisations(id) ON DELETE CASCADE,
    key_id      TEXT        NOT NULL CHECK (key_id ~ '^k_[0-9a-f]{8}$'),
    secret      TEXT        NOT NULL CHECK (length(secret) >= 32),
    status      TEXT        NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    created_by  UUID        NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()),
    revoked_at  TIMESTAMPTZ,
    PRIMARY KEY (org_id, key_id)
);
ALTER TABLE public.ingest_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ingest_keys FORCE ROW LEVEL SECURITY;
-- No policies on purpose: deny by default. Only the SECURITY DEFINER functions below can touch it.
REVOKE ALL ON public.ingest_keys FROM PUBLIC, anon, authenticated;

-- Signing string (no secret involved; safe to expose)
CREATE OR REPLACE FUNCTION public.ingest_signing_string(p_org_id UUID, p_payload JSONB)
RETURNS TEXT
LANGUAGE plpgsql
IMMUTABLE
SECURITY INVOKER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_lines TEXT[];
    v_k TEXT;
    v_list TEXT;
    v_signals JSONB := COALESCE(p_payload->'signals', '{}'::jsonb);
BEGIN
    v_lines := ARRAY[
        'atlas-ingest-v1',
        'org_id=' || to_json(p_org_id::text)::text,
        'key_id=' || to_json(COALESCE(p_payload->>'key_id', ''))::text
    ];
    FOREACH v_k IN ARRAY ARRAY['schema_version','event_id','event_type','severity','observed_at','sent_at'] LOOP
        v_lines := v_lines || (v_k || '=' || to_json(COALESCE(p_payload->>v_k, ''))::text);
    END LOOP;
    v_lines := v_lines || ('confidence=' || COALESCE(p_payload->>'confidence', ''));
    v_lines := v_lines || ('correlation_id=' || to_json(COALESCE(p_payload->>'correlation_id', ''))::text);
    v_lines := v_lines || ('source=' || to_json(COALESCE(p_payload->>'source', ''))::text);
    FOREACH v_k IN ARRAY ARRAY['site_codes','hostnames','ips','cidrs','cloud_account_ids'] LOOP
        IF v_signals ? v_k AND jsonb_typeof(v_signals->v_k) <> 'array' THEN
            RAISE EXCEPTION 'Signal list "%" must be a JSON array', v_k USING ERRCODE = '22023';
        END IF;
        SELECT COALESCE(string_agg(to_json(e)::text, ',' ORDER BY e COLLATE "C"), '') INTO v_list
        FROM jsonb_array_elements_text(COALESCE(v_signals->v_k, '[]'::jsonb)) AS e;
        v_lines := v_lines || (v_k || '=[' || v_list || ']');
    END LOOP;
    RETURN array_to_string(v_lines, E'\n');
END;
$$;
REVOKE EXECUTE ON FUNCTION public.ingest_signing_string(UUID, JSONB) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.ingest_signing_string(UUID, JSONB) TO authenticated;

-- Verification: reads the secret, so it is SECURITY DEFINER; it checks membership itself.
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
    WHERE k.org_id = p_org_id AND k.key_id = v_key_id AND k.status = 'active';
    IF v_secret IS NULL THEN
        RETURN FALSE;
    END IF;

    v_expected := encode(
        extensions.hmac(
            convert_to(public.ingest_signing_string(p_org_id, p_payload), 'UTF8'),
            convert_to(v_secret, 'UTF8'),
            'sha256'),
        'hex');

    -- Compare digests of both values so the comparison does not stop at the first differing character.
    RETURN extensions.digest(v_expected, 'sha256') = extensions.digest(v_sig, 'sha256');
END;
$$;
REVOKE EXECUTE ON FUNCTION public.verify_ingest_signature(UUID, JSONB) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.verify_ingest_signature(UUID, JSONB) TO authenticated;

-- Key management (admins only, MFA required)
CREATE OR REPLACE FUNCTION public.create_ingest_key(p_org_id UUID)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_caller UUID := auth.uid();
    v_role TEXT;
    v_key_id TEXT;
    v_secret TEXT;
BEGIN
    IF v_caller IS NULL THEN
        RAISE EXCEPTION 'Unauthenticated caller' USING ERRCODE = '42501';
    END IF;
    IF COALESCE(auth.jwt() ->> 'aal', '') <> 'aal2' THEN
        RAISE EXCEPTION 'MFA (aal2) required' USING ERRCODE = '42501';
    END IF;
    SELECT role INTO v_role FROM public.memberships WHERE user_id = v_caller AND org_id = p_org_id;
    IF v_role IS DISTINCT FROM 'atlas:admin' THEN
        RAISE EXCEPTION 'Only an administrator of this organisation can create ingest keys' USING ERRCODE = '42501';
    END IF;

    v_key_id := 'k_' || encode(gen_random_bytes(4), 'hex');
    v_secret := encode(gen_random_bytes(32), 'hex');
    INSERT INTO public.ingest_keys (org_id, key_id, secret, created_by) VALUES (p_org_id, v_key_id, v_secret, v_caller);

    PERFORM public.internal_append_audit(
        p_org_id, 'INGEST_KEY_CREATED', 'ingest_key', v_key_id,
        'cid-ingest-key-' || v_key_id, jsonb_build_object('key_id', v_key_id), v_caller, v_role);

    RETURN jsonb_build_object('key_id', v_key_id, 'secret', v_secret,
        'note', 'The secret is shown once. Store it in the sender; ATLAS cannot show it again.');
END;
$$;
REVOKE EXECUTE ON FUNCTION public.create_ingest_key(UUID) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.create_ingest_key(UUID) TO authenticated;

CREATE OR REPLACE FUNCTION public.revoke_ingest_key(p_org_id UUID, p_key_id TEXT)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_caller UUID := auth.uid();
    v_role TEXT;
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
        RAISE EXCEPTION 'Only an administrator of this organisation can revoke ingest keys' USING ERRCODE = '42501';
    END IF;

    UPDATE public.ingest_keys
    SET status = 'revoked', revoked_at = timezone('utc'::text, now())
    WHERE org_id = p_org_id AND key_id = p_key_id AND status = 'active';
    GET DIAGNOSTICS v_rows = ROW_COUNT;
    IF v_rows = 0 THEN
        RAISE EXCEPTION 'No active key % in this organisation', p_key_id USING ERRCODE = '02000';
    END IF;

    PERFORM public.internal_append_audit(
        p_org_id, 'INGEST_KEY_REVOKED', 'ingest_key', p_key_id,
        'cid-ingest-key-' || p_key_id, jsonb_build_object('key_id', p_key_id), v_caller, v_role);

    RETURN jsonb_build_object('key_id', p_key_id, 'status', 'revoked');
END;
$$;
REVOKE EXECUTE ON FUNCTION public.revoke_ingest_key(UUID, TEXT) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.revoke_ingest_key(UUID, TEXT) TO authenticated;

-- Listing never returns the secret
CREATE OR REPLACE FUNCTION public.list_ingest_keys(p_org_id UUID)
RETURNS TABLE (key_id TEXT, status TEXT, created_at TIMESTAMPTZ, revoked_at TIMESTAMPTZ)
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
        SELECT k.key_id, k.status, k.created_at, k.revoked_at
        FROM public.ingest_keys k
        WHERE k.org_id = p_org_id
        ORDER BY k.created_at DESC;
END;
$$;
REVOKE EXECUTE ON FUNCTION public.list_ingest_keys(UUID) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.list_ingest_keys(UUID) TO authenticated;

-- ingest_incident now verifies the signature (replaces the 008 version)
CREATE OR REPLACE FUNCTION public.ingest_incident(
    p_payload JSONB
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_caller UUID := auth.uid();
    v_org_id UUID;
    v_schema_version TEXT;
    v_event_id TEXT;
    v_event_type TEXT;
    v_severity TEXT;
    v_observed_at TIMESTAMPTZ;
    v_sent_at TIMESTAMPTZ;
    v_confidence NUMERIC;
    v_signals JSONB;
    v_correlation_id TEXT;
    v_source TEXT;

    v_existing_id UUID;
    v_incident_id UUID;
    v_key TEXT;
    v_match_count INT;

    -- Allowlisted Event Types
    c_allowed_event_types TEXT[] := ARRAY[
        'OT_DISRUPTION',
        'RANSOMWARE',
        'PHYSICAL_INTRUSION',
        'TELEMETRY_ANOMALY',
        'POWER_GRID_VOLTAGE_SAG',
        'COMMUNICATION_LINK_FAILURE',
        'SCADA_UNAUTHORIZED_COMMAND',
        'DENIAL_OF_SERVICE',
        'DATA_EXFILTRATION',
        'UNAUTHORIZED_ACCESS'
    ];

    -- Allowlisted Top-Level Payload Keys
    c_allowed_payload_keys TEXT[] := ARRAY[
        'schema_version',
        'event_id',
        'event_type',
        'severity',
        'observed_at',
        'sent_at',
        'confidence',
        'signals',
        'correlation_id',
        'org_id',
        'source',
        'key_id',
        'signature'
    ];

    -- Allowlisted Signals Keys
    c_allowed_signal_keys TEXT[] := ARRAY[
        'site_codes',
        'hostnames',
        'ips',
        'cidrs',
        'cloud_account_ids'
    ];
BEGIN
    -- 1. Authentication & MFA Check
    IF v_caller IS NULL THEN
        RAISE EXCEPTION 'Unauthenticated caller' USING ERRCODE = '42501';
    END IF;

    IF (auth.jwt() ->> 'aal') <> 'aal2' THEN
        RAISE EXCEPTION 'MFA AAL2 required for incident intake' USING ERRCODE = '42501';
    END IF;

    -- 2. Reject Unknown Top-Level Fields in Payload
    FOR v_key IN SELECT jsonb_object_keys(p_payload)
    LOOP
        IF NOT (v_key = ANY(c_allowed_payload_keys)) THEN
            RAISE EXCEPTION 'Unknown field in incident payload: "%"', v_key USING ERRCODE = '22023';
        END IF;
    END LOOP;

    -- 3. Extract & Validate Required Fields
    v_schema_version := trim(p_payload->>'schema_version');
    IF v_schema_version IS NULL OR v_schema_version <> '1.0' THEN
        RAISE EXCEPTION 'Invalid schema_version "%". Expected "1.0"', COALESCE(v_schema_version, 'null')
            USING ERRCODE = '22023';
    END IF;

    v_event_id := trim(p_payload->>'event_id');
    IF v_event_id IS NULL OR v_event_id = '' THEN
        RAISE EXCEPTION 'Missing required field event_id' USING ERRCODE = '22023';
    END IF;

    v_event_type := upper(trim(p_payload->>'event_type'));
    IF v_event_type IS NULL OR NOT (v_event_type = ANY(c_allowed_event_types)) THEN
        RAISE EXCEPTION 'Event type "%" is not in allowlist. Allowed: %', 
            COALESCE(v_event_type, 'null'), array_to_string(c_allowed_event_types, ', ')
            USING ERRCODE = '22023';
    END IF;

    v_severity := lower(trim(p_payload->>'severity'));
    IF v_severity NOT IN ('low', 'medium', 'high', 'critical') THEN
        RAISE EXCEPTION 'Invalid severity "%". Must be low, medium, high, or critical', COALESCE(v_severity, 'null')
            USING ERRCODE = '22023';
    END IF;

    -- Timestamp checks
    BEGIN
        v_observed_at := (p_payload->>'observed_at')::TIMESTAMPTZ;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION 'Malformed observed_at timestamp: %', p_payload->>'observed_at' USING ERRCODE = '22023';
    END;
    IF v_observed_at IS NULL THEN
        RAISE EXCEPTION 'Missing required field observed_at' USING ERRCODE = '22023';
    END IF;

    BEGIN
        v_sent_at := (p_payload->>'sent_at')::TIMESTAMPTZ;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION 'Malformed sent_at timestamp: %', p_payload->>'sent_at' USING ERRCODE = '22023';
    END;
    IF v_sent_at IS NULL THEN
        RAISE EXCEPTION 'Missing required field sent_at' USING ERRCODE = '22023';
    END IF;

    -- Replay Protection: Reject sent_at older than 10 minutes
    IF (now() - v_sent_at) > INTERVAL '10 minutes' THEN
        RAISE EXCEPTION 'Replay rejected: sent_at is older than 10 minutes (% seconds old)',
            EXTRACT(EPOCH FROM (now() - v_sent_at)) USING ERRCODE = '22023';
    END IF;

    -- Confidence check (sender estimate of telemetry reality, NOT attribution)
    v_confidence := COALESCE((p_payload->>'confidence')::NUMERIC, 1.0);
    IF v_confidence < 0.0 OR v_confidence > 1.0 THEN
        RAISE EXCEPTION 'Confidence % is out of range [0.0..1.0]', v_confidence USING ERRCODE = '22023';
    END IF;

    -- Signals validation
    v_signals := COALESCE(p_payload->'signals', '{}'::jsonb);
    IF jsonb_typeof(v_signals) <> 'object' THEN
        RAISE EXCEPTION 'Signals field must be a JSON object' USING ERRCODE = '22023';
    END IF;

    -- Reject Unknown Fields in Signals
    FOR v_key IN SELECT jsonb_object_keys(v_signals)
    LOOP
        IF NOT (v_key = ANY(c_allowed_signal_keys)) THEN
            RAISE EXCEPTION 'Unknown field in signals: "%". Allowed signal keys: %',
                v_key, array_to_string(c_allowed_signal_keys, ', ') USING ERRCODE = '22023';
        END IF;
    END LOOP;

    -- Organisation Resolution & Membership Check
    IF (p_payload->>'org_id') IS NOT NULL THEN
        v_org_id := (p_payload->>'org_id')::UUID;
    ELSE
        -- Default to caller's first active organisation membership
        SELECT org_id INTO v_org_id
        FROM public.memberships
        WHERE user_id = v_caller
        ORDER BY created_at ASC
        LIMIT 1;
    END IF;

    IF v_org_id IS NULL OR NOT public.user_is_member(v_org_id) THEN
        RAISE EXCEPTION 'Access denied: caller % is not a member of organisation %', v_caller, v_org_id
            USING ERRCODE = '42501';
    END IF;

    -- Signature check (migration 013): the message must be signed with an ACTIVE ingest key of THIS organisation.
    IF NOT public.verify_ingest_signature(v_org_id, p_payload) THEN
        RAISE EXCEPTION 'Invalid or missing ingest signature for organisation %', v_org_id USING ERRCODE = '42501';
    END IF;

    v_source := COALESCE(NULLIF(trim(p_payload->>'source'), ''), 'CyberShield X (CSX) Ingest');
    v_correlation_id := COALESCE(NULLIF(trim(p_payload->>'correlation_id'), ''), gen_random_uuid()::text);

    -- 4. Idempotency Check: Duplicate event_id is a safe no-op returning the original record
    SELECT inc.id INTO v_existing_id
    FROM public.incidents inc
    WHERE inc.org_id = v_org_id AND inc.event_id = v_event_id;

    IF v_existing_id IS NOT NULL THEN
        SELECT COUNT(*) INTO v_match_count
        FROM public.asset_matches
        WHERE org_id = v_org_id AND incident_id = v_existing_id;

        RETURN jsonb_build_object(
            'success', true,
            'idempotent', true,
            'incident_id', v_existing_id,
            'event_id', v_event_id,
            'matches_count', v_match_count,
            'message', 'Idempotent no-op: incident with event_id already recorded'
        );
    END IF;

    -- 5. Insert New Incident Record
    v_incident_id := gen_random_uuid();

    INSERT INTO public.incidents (
        id,
        org_id,
        event_id,
        schema_version,
        event_type,
        severity,
        observed_at,
        sent_at,
        signals,
        source,
        created_at,
        confidence,
        sharing_policy,
        correlation_id
    ) VALUES (
        v_incident_id,
        v_org_id,
        v_event_id,
        '1.0',
        v_event_type,
        v_severity,
        v_observed_at,
        v_sent_at,
        v_signals,
        v_source,
        timezone('utc'::text, now()),
        v_confidence,
        'internal_only',
        v_correlation_id
    );

    -- 6. Trigger Matching Engine in SQL
    v_match_count := public.match_incident_to_assets(v_org_id, v_incident_id);

    RETURN jsonb_build_object(
        'success', true,
        'idempotent', false,
        'incident_id', v_incident_id,
        'event_id', v_event_id,
        'matches_count', v_match_count,
        'correlation_id', v_correlation_id
    );
END;
$$;
REVOKE EXECUTE ON FUNCTION public.ingest_incident(JSONB) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.ingest_incident(JSONB) TO authenticated;
