-- ============================================================================
-- Project ATLAS - Migration 005: Synthetic Seed Data
-- ============================================================================
-- 1. Creates two fictional security firms and two client workspaces:
--    - Firm A: Aegis Cyber-Physical Advisory Ltd (AEGIS-HQ)
--      Client A: Sector 9 Municipal Water Authority (S9-WATER)
--    - Firm B: Vanguard Resilience Partners (VANGUARD-HQ)
--      Client B: Archipelago Energy Transmission Co (ARCH-ENERGY)
-- 2. Seeds standard baseline scoring configs (explicitly labelled 'uncalibrated').
-- 3. Genesis cryptographic audit record for each organisation.
-- 4. Binds your authenticated user to Firm A and Client A as atlas:admin.
-- ============================================================================

DO $$
DECLARE
    -- ========================================================================
    -- >>> EDIT THIS ONCE: YOUR SUPABASE AUTH USER EMAIL <<<
    -- Replace the email below with the email address you use to sign in.
    -- ========================================================================
    c_user_email CONSTANT TEXT := 'teambuilderspvt@gmail.com';
    -- ========================================================================

    -- Fixed Deterministic UUIDs for Seed Workspaces
    v_firm_a_id   UUID := '11111111-1111-4111-a111-111111111111';
    v_client_a_id UUID := '11111111-2222-4111-a111-222222222222';
    v_firm_b_id   UUID := '22222222-1111-4222-b222-111111111111';
    v_client_b_id UUID := '22222222-2222-4222-b222-222222222222';

    v_user_id UUID;
BEGIN
    -- 1. Insert Firm A and Client A
    INSERT INTO public.organisations (id, name, code, kind, parent_firm_id, source, sharing_policy, correlation_id)
    VALUES 
        (v_firm_a_id, 'Aegis Cyber-Physical Advisory Ltd', 'AEGIS-HQ', 'firm', NULL, 'Stage 1 Seed', 'internal_only', 'cid-seed-firm-a')
    ON CONFLICT (code) DO UPDATE 
    SET name = EXCLUDED.name;

    INSERT INTO public.organisations (id, name, code, kind, parent_firm_id, source, sharing_policy, correlation_id)
    VALUES 
        (v_client_a_id, 'Sector 9 Municipal Water Authority', 'S9-WATER', 'client', v_firm_a_id, 'Stage 1 Seed', 'internal_only', 'cid-seed-client-a')
    ON CONFLICT (code) DO UPDATE 
    SET name = EXCLUDED.name, parent_firm_id = EXCLUDED.parent_firm_id;

    -- 2. Insert Firm B and Client B
    INSERT INTO public.organisations (id, name, code, kind, parent_firm_id, source, sharing_policy, correlation_id)
    VALUES 
        (v_firm_b_id, 'Vanguard Resilience Partners', 'VANGUARD-HQ', 'firm', NULL, 'Stage 1 Seed', 'internal_only', 'cid-seed-firm-b')
    ON CONFLICT (code) DO UPDATE 
    SET name = EXCLUDED.name;

    INSERT INTO public.organisations (id, name, code, kind, parent_firm_id, source, sharing_policy, correlation_id)
    VALUES 
        (v_client_b_id, 'Archipelago Energy Transmission Co', 'ARCH-ENERGY', 'client', v_firm_b_id, 'Stage 1 Seed', 'internal_only', 'cid-seed-client-b')
    ON CONFLICT (code) DO UPDATE 
    SET name = EXCLUDED.name, parent_firm_id = EXCLUDED.parent_firm_id;

    -- 3. Seed Baseline Scoring Config (Every entry labelled 'uncalibrated')
    INSERT INTO public.scoring_config (org_id, config_key, weight, scale, calibration_status, description, source, correlation_id)
    VALUES
        (v_firm_a_id, 'weight_impact', 0.40, 1.0, 'uncalibrated', 'Uncalibrated baseline weight for consequence impact factor', 'Stage 1 Seed', 'cid-seed-cfg'),
        (v_firm_a_id, 'weight_exposure', 0.35, 1.0, 'uncalibrated', 'Uncalibrated baseline weight for exposure reachability', 'Stage 1 Seed', 'cid-seed-cfg'),
        (v_firm_a_id, 'weight_likelihood', 0.25, 1.0, 'uncalibrated', 'Uncalibrated baseline weight for telemetry signal likelihood', 'Stage 1 Seed', 'cid-seed-cfg'),
        (v_client_a_id, 'weight_impact', 0.50, 1.0, 'uncalibrated', 'Uncalibrated water utility impact weight', 'Stage 1 Seed', 'cid-seed-cfg'),
        (v_client_a_id, 'weight_exposure', 0.30, 1.0, 'uncalibrated', 'Uncalibrated water utility exposure weight', 'Stage 1 Seed', 'cid-seed-cfg'),
        (v_client_a_id, 'weight_likelihood', 0.20, 1.0, 'uncalibrated', 'Uncalibrated water utility likelihood weight', 'Stage 1 Seed', 'cid-seed-cfg'),
        (v_firm_b_id, 'weight_impact', 0.45, 1.0, 'uncalibrated', 'Uncalibrated baseline weight for energy grid impact', 'Stage 1 Seed', 'cid-seed-cfg'),
        (v_client_b_id, 'weight_impact', 0.45, 1.0, 'uncalibrated', 'Uncalibrated baseline weight for energy grid impact', 'Stage 1 Seed', 'cid-seed-cfg')
    ON CONFLICT (org_id, config_key) DO NOTHING;

    -- 4. Initial Genesis Audit Event for each organisation (if empty)
    IF NOT EXISTS (SELECT 1 FROM public.audit_events WHERE org_id = v_firm_a_id) THEN
        PERFORM public.internal_append_audit(
            v_firm_a_id,
            'ORGANISATION_GENESIS',
            'ORGANISATION',
            v_firm_a_id::text,
            'cid-genesis-firm-a',
            jsonb_build_object('genesis', true, 'org_code', 'AEGIS-HQ', 'kind', 'firm')
        );
    END IF;

    IF NOT EXISTS (SELECT 1 FROM public.audit_events WHERE org_id = v_client_a_id) THEN
        PERFORM public.internal_append_audit(
            v_client_a_id,
            'ORGANISATION_GENESIS',
            'ORGANISATION',
            v_client_a_id::text,
            'cid-genesis-client-a',
            jsonb_build_object('genesis', true, 'org_code', 'S9-WATER', 'kind', 'client')
        );
    END IF;

    IF NOT EXISTS (SELECT 1 FROM public.audit_events WHERE org_id = v_firm_b_id) THEN
        PERFORM public.internal_append_audit(
            v_firm_b_id,
            'ORGANISATION_GENESIS',
            'ORGANISATION',
            v_firm_b_id::text,
            'cid-genesis-firm-b',
            jsonb_build_object('genesis', true, 'org_code', 'VANGUARD-HQ', 'kind', 'firm')
        );
    END IF;

    IF NOT EXISTS (SELECT 1 FROM public.audit_events WHERE org_id = v_client_b_id) THEN
        PERFORM public.internal_append_audit(
            v_client_b_id,
            'ORGANISATION_GENESIS',
            'ORGANISATION',
            v_client_b_id::text,
            'cid-genesis-client-b',
            jsonb_build_object('genesis', true, 'org_code', 'ARCH-ENERGY', 'kind', 'client')
        );
    END IF;

    -- 5. Membership Assignment for the Configured User Email
    SELECT id INTO v_user_id FROM auth.users WHERE email = c_user_email LIMIT 1;
    IF v_user_id IS NOT NULL THEN
        -- Grant atlas:admin membership in Firm A and Client A
        INSERT INTO public.memberships (user_id, org_id, role, source, correlation_id)
        VALUES 
            (v_user_id, v_firm_a_id, 'atlas:admin', 'Stage 1 Seed', 'cid-seed-mem'),
            (v_user_id, v_client_a_id, 'atlas:admin', 'Stage 1 Seed', 'cid-seed-mem')
        ON CONFLICT (user_id, org_id) DO NOTHING;
        
        RAISE NOTICE 'Assigned user % (%) as atlas:admin to Firm A and Client A', c_user_email, v_user_id;
    ELSE
        RAISE NOTICE 'User email % not found in auth.users yet. Create user via Sign Up, then re-run migration 005 or insert membership manually.', c_user_email;
    END IF;

END $$;
