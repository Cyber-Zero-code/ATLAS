-- ============================================================================
-- Project ATLAS - Migration 008: Incident Ingest Contract & Rule-Based Matching
-- ============================================================================
-- CONTRACT (CyberShield X / CSX Ingest Interface):
-- 1. ingest_incident(p_payload JSONB):
--    - SECURITY INVOKER: Runs under the caller's JWT & RLS permissions.
--    - Validates schema_version "1.0", event_id, event_type (allowlist), severity,
--      observed_at, sent_at, confidence, signals, and correlation_id.
--    - Rejects unknown or malformed fields with clear SQLSTATE 22023 errors.
--    - Rejects sent_at timestamps older than 10 minutes (replay window protection).
--    - Duplicate event_id is an idempotent safe no-op returning the original record.
--    - NOTE ON SIGNATURE VERIFICATION:
--        Cryptographic signature verification of the CSX sender payload is
--        deferred to Stage 5 / Pre-pilot. Current intake validates schema integrity,
--        field allowlist, and timestamp replay freshness (10-minute window).
--    - NOTE ON CONFIDENCE DEFINITION:
--        Confidence represents the sender's estimate that the telemetry reflects
--        a real physical or cyber event. It is strictly a measure of telemetry
--        signal fidelity, NOT attribution of any person, threat group, or actor.
--
-- MATCHING ENGINE:
-- 2. Rules executed in deterministic priority order:
--    Rule 1: exact site code (Score: 1.00 -> auto)
--    Rule 2: exact hostname (Score: 0.95 -> auto)
--    Rule 3: exact IP address (Score: 0.95 -> auto)
--    Rule 4: CIDR containment (Score: 0.85 -> proposed, needs analyst confirmation)
--    Rule 5: cloud account id (Score: 0.90 -> auto)
--    Rule 6: fuzzy hostname via pg_trgm (Score: similarity, <0.90 -> proposed)
--    - Matches >= 0.90 are 'auto'; matches < 0.90 are 'proposed'.
--    - Analysts confirm or reject proposals, permanently stored as labelled data.
-- ============================================================================

-- Ensure pg_trgm extension is installed in extensions schema
CREATE EXTENSION IF NOT EXISTS pg_trgm WITH SCHEMA extensions;
GRANT USAGE ON SCHEMA extensions TO postgres, anon, authenticated, service_role;

-- Ensure sent_at column exists on public.incidents
ALTER TABLE public.incidents ADD COLUMN IF NOT EXISTS sent_at TIMESTAMPTZ;

-- 1. Helper Function: Validate and Match Incident to Assets
CREATE OR REPLACE FUNCTION public.match_incident_to_assets(
    p_org_id UUID,
    p_incident_id UUID
)
RETURNS INTEGER
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_signals JSONB;
    v_site_codes TEXT[];
    v_hostnames TEXT[];
    v_ips TEXT[];
    v_cidrs TEXT[];
    v_cloud_accounts TEXT[];
    v_match_count INT := 0;
    v_correlation_id TEXT;
    v_source TEXT;
BEGIN
    -- Retrieve incident signals
    SELECT inc.signals, inc.correlation_id, inc.source
    INTO v_signals, v_correlation_id, v_source
    FROM public.incidents inc
    WHERE inc.org_id = p_org_id AND inc.id = p_incident_id;

    IF v_signals IS NULL THEN
        RETURN 0;
    END IF;

    -- Extract signal arrays
    SELECT ARRAY(SELECT jsonb_array_elements_text(COALESCE(v_signals->'site_codes', '[]'::jsonb))) INTO v_site_codes;
    SELECT ARRAY(SELECT lower(jsonb_array_elements_text(COALESCE(v_signals->'hostnames', '[]'::jsonb)))) INTO v_hostnames;
    SELECT ARRAY(SELECT jsonb_array_elements_text(COALESCE(v_signals->'ips', '[]'::jsonb))) INTO v_ips;
    SELECT ARRAY(SELECT jsonb_array_elements_text(COALESCE(v_signals->'cidrs', '[]'::jsonb))) INTO v_cidrs;
    SELECT ARRAY(SELECT jsonb_array_elements_text(COALESCE(v_signals->'cloud_account_ids', '[]'::jsonb))) INTO v_cloud_accounts;

    -- ------------------------------------------------------------------------
    -- RULE 1: Exact Site Code Match (Score: 1.00 -> auto)
    -- ------------------------------------------------------------------------
    IF array_length(v_site_codes, 1) > 0 THEN
        INSERT INTO public.asset_matches (
            org_id, incident_id, asset_id, rule_fired, score, status, source, confidence, correlation_id
        )
        SELECT 
            p_org_id,
            p_incident_id,
            a.id,
            'exact_site_code',
            1.00,
            'auto',
            v_source,
            1.00,
            v_correlation_id
        FROM public.assets a
        WHERE a.org_id = p_org_id
          AND a.site_code = ANY(v_site_codes)
        ON CONFLICT (org_id, incident_id, asset_id, rule_fired) DO NOTHING;
    END IF;

    -- ------------------------------------------------------------------------
    -- RULE 2: Exact Hostname Match (Score: 0.95 -> auto)
    -- ------------------------------------------------------------------------
    IF array_length(v_hostnames, 1) > 0 THEN
        INSERT INTO public.asset_matches (
            org_id, incident_id, asset_id, rule_fired, score, status, source, confidence, correlation_id
        )
        SELECT DISTINCT
            p_org_id,
            p_incident_id,
            a.id,
            'exact_hostname',
            0.95,
            'auto',
            v_source,
            0.95,
            v_correlation_id
        FROM public.assets a,
             jsonb_array_elements_text(COALESCE(a.identifiers->'hostnames', '[]'::jsonb)) h
        WHERE a.org_id = p_org_id
          AND lower(h) = ANY(v_hostnames)
        ON CONFLICT (org_id, incident_id, asset_id, rule_fired) DO NOTHING;
    END IF;

    -- ------------------------------------------------------------------------
    -- RULE 3: Exact IP Address Match (Score: 0.95 -> auto)
    -- ------------------------------------------------------------------------
    IF array_length(v_ips, 1) > 0 THEN
        INSERT INTO public.asset_matches (
            org_id, incident_id, asset_id, rule_fired, score, status, source, confidence, correlation_id
        )
        SELECT DISTINCT
            p_org_id,
            p_incident_id,
            a.id,
            'exact_ip',
            0.95,
            'auto',
            v_source,
            0.95,
            v_correlation_id
        FROM public.assets a,
             jsonb_array_elements_text(COALESCE(a.identifiers->'ip_addresses', '[]'::jsonb)) ip
        WHERE a.org_id = p_org_id
          AND ip = ANY(v_ips)
        ON CONFLICT (org_id, incident_id, asset_id, rule_fired) DO NOTHING;
    END IF;

    -- ------------------------------------------------------------------------
    -- RULE 4: CIDR Containment Match (Score: 0.85 -> proposed, needs review)
    -- ------------------------------------------------------------------------
    IF array_length(v_ips, 1) > 0 OR array_length(v_cidrs, 1) > 0 THEN
        INSERT INTO public.asset_matches (
            org_id, incident_id, asset_id, rule_fired, score, status, source, confidence, correlation_id
        )
        SELECT DISTINCT
            p_org_id,
            p_incident_id,
            a.id,
            'cidr_containment',
            0.85,
            'proposed', -- < 0.90 requires analyst confirmation
            v_source,
            0.85,
            v_correlation_id
        FROM public.assets a
        WHERE a.org_id = p_org_id
          AND (
            -- Case A: Signal IP inside Asset CIDR
            EXISTS (
                SELECT 1
                FROM unnest(v_ips) s_ip,
                     jsonb_array_elements_text(COALESCE(a.identifiers->'cidrs', '[]'::jsonb)) a_cidr
                WHERE s_ip ~ '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'
                  AND a_cidr ~ '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$'
                  AND (s_ip::inet <<= a_cidr::inet)
            )
            OR
            -- Case B: Asset IP inside Signal CIDR
            EXISTS (
                SELECT 1
                FROM unnest(v_cidrs) s_cidr,
                     jsonb_array_elements_text(COALESCE(a.identifiers->'ip_addresses', '[]'::jsonb)) a_ip
                WHERE s_cidr ~ '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$'
                  AND a_ip ~ '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'
                  AND (a_ip::inet <<= s_cidr::inet)
            )
          )
        ON CONFLICT (org_id, incident_id, asset_id, rule_fired) DO NOTHING;
    END IF;

    -- ------------------------------------------------------------------------
    -- RULE 5: Cloud Account ID Match (Score: 0.90 -> auto)
    -- ------------------------------------------------------------------------
    IF array_length(v_cloud_accounts, 1) > 0 THEN
        INSERT INTO public.asset_matches (
            org_id, incident_id, asset_id, rule_fired, score, status, source, confidence, correlation_id
        )
        SELECT DISTINCT
            p_org_id,
            p_incident_id,
            a.id,
            'cloud_account_id',
            0.90,
            'auto',
            v_source,
            0.90,
            v_correlation_id
        FROM public.assets a,
             jsonb_array_elements_text(COALESCE(a.identifiers->'cloud_account_ids', '[]'::jsonb)) acc
        WHERE a.org_id = p_org_id
          AND acc = ANY(v_cloud_accounts)
        ON CONFLICT (org_id, incident_id, asset_id, rule_fired) DO NOTHING;
    END IF;

    -- ------------------------------------------------------------------------
    -- RULE 6: Fuzzy Hostname Match via pg_trgm (Score: similarity, <0.90 -> proposed)
    -- ------------------------------------------------------------------------
    IF array_length(v_hostnames, 1) > 0 THEN
        INSERT INTO public.asset_matches (
            org_id, incident_id, asset_id, rule_fired, score, status, source, confidence, correlation_id
        )
        SELECT 
            p_org_id,
            p_incident_id,
            sub.asset_id,
            'fuzzy_hostname',
            sub.max_similarity,
            CASE WHEN sub.max_similarity >= 0.90 THEN 'auto' ELSE 'proposed' END,
            v_source,
            sub.max_similarity,
            v_correlation_id
        FROM (
            SELECT 
                a.id AS asset_id,
                ROUND(MAX(similarity(lower(h), sig_h))::numeric, 2) AS max_similarity
            FROM public.assets a,
                 jsonb_array_elements_text(COALESCE(a.identifiers->'hostnames', '[]'::jsonb)) h,
                 unnest(v_hostnames) sig_h
            WHERE a.org_id = p_org_id
              AND lower(h) <> sig_h -- Exclude exact match (handled in Rule 2)
              AND similarity(lower(h), sig_h) >= 0.50
            GROUP BY a.id
        ) sub
        ON CONFLICT (org_id, incident_id, asset_id, rule_fired) DO NOTHING;
    END IF;

    SELECT COUNT(*) INTO v_match_count
    FROM public.asset_matches
    WHERE org_id = p_org_id AND incident_id = p_incident_id;

    RETURN v_match_count;
END;
$$;

REVOKE EXECUTE ON FUNCTION public.match_incident_to_assets(UUID, UUID) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.match_incident_to_assets(UUID, UUID) TO authenticated;

-- 2. Core Intake Contract Function: ingest_incident(payload)
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
        'source'
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

-- 3. Analyst Match Decision Functions (Confirm & Reject Labels)
CREATE OR REPLACE FUNCTION public.confirm_asset_match(
    p_match_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_caller UUID := auth.uid();
    v_org_id UUID;
    v_asset_id UUID;
    v_incident_id UUID;
    v_score NUMERIC;
    v_rule TEXT;
BEGIN
    IF v_caller IS NULL THEN
        RAISE EXCEPTION 'Unauthenticated caller' USING ERRCODE = '42501';
    END IF;

    SELECT org_id, asset_id, incident_id, score, rule_fired
    INTO v_org_id, v_asset_id, v_incident_id, v_score, v_rule
    FROM public.asset_matches
    WHERE id = p_match_id;

    IF v_org_id IS NULL THEN
        RAISE EXCEPTION 'Asset match % not found', p_match_id USING ERRCODE = '02000';
    END IF;

    UPDATE public.asset_matches
    SET status = 'confirmed',
        decided_by = v_caller,
        decided_at = timezone('utc'::text, now())
    WHERE id = p_match_id;

    RETURN jsonb_build_object(
        'success', true,
        'match_id', p_match_id,
        'status', 'confirmed',
        'decided_by', v_caller
    );
END;
$$;

REVOKE EXECUTE ON FUNCTION public.confirm_asset_match(UUID) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.confirm_asset_match(UUID) TO authenticated;

CREATE OR REPLACE FUNCTION public.reject_asset_match(
    p_match_id UUID,
    p_reason TEXT DEFAULT 'Analyst rejected proposal'
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_caller UUID := auth.uid();
    v_org_id UUID;
BEGIN
    IF v_caller IS NULL THEN
        RAISE EXCEPTION 'Unauthenticated caller' USING ERRCODE = '42501';
    END IF;

    SELECT org_id INTO v_org_id
    FROM public.asset_matches
    WHERE id = p_match_id;

    IF v_org_id IS NULL THEN
        RAISE EXCEPTION 'Asset match % not found', p_match_id USING ERRCODE = '02000';
    END IF;

    UPDATE public.asset_matches
    SET status = 'rejected',
        decided_by = v_caller,
        decided_at = timezone('utc'::text, now())
    WHERE id = p_match_id;

    RETURN jsonb_build_object(
        'success', true,
        'match_id', p_match_id,
        'status', 'rejected',
        'reason', p_reason,
        'decided_by', v_caller
    );
END;
$$;

REVOKE EXECUTE ON FUNCTION public.reject_asset_match(UUID, TEXT) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.reject_asset_match(UUID, TEXT) TO authenticated;
