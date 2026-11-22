-- ============================================================================
-- Project ATLAS: Stage 1 Behavioural Security Test Suite
-- ============================================================================
-- Enforces:
-- 1. Positive controls (user reads own records with expected counts)
-- 2. Zero cross-tenant reads across all tables and RPCs
-- 3. Cross-tenant writes fail with exact SQLSTATE (42501 or 23503)
-- 4. Composite keys physically block references to another organisation's rows
-- 5. Analyst cannot delete restricted rows (0 rows affected, asset persists)
-- 6. Forged audit inserts fail; audit UPDATE, DELETE and TRUNCATE fail with 55000
-- 7. aal1 and anon sessions read zero rows
-- 8. Superuser tampering is detected by verify_audit_chain(org_id)
-- 
-- Single transaction execution ending with intentional ROLLBACK (leaves 0 artifacts).
-- Raises exception immediately if any check fails.
-- ============================================================================

DO $$
DECLARE
    -- Tenant UUIDs
    v_org_a UUID := 'a0000000-0000-0000-0000-000000000001';
    v_org_b UUID := 'b0000000-0000-0000-0000-000000000002';

    -- User UUIDs
    v_admin_a   UUID := 'a0000000-1111-0000-0000-000000000001';
    v_analyst_a UUID := 'a0000000-2222-0000-0000-000000000002';
    v_admin_b   UUID := 'b0000000-1111-0000-0000-000000000001';

    -- Entity UUIDs
    v_asset_a1 UUID := 'a0000000-aaaa-0000-0000-000000000001';
    v_asset_a2 UUID := 'a0000000-aaaa-0000-0000-000000000002';
    v_asset_b1 UUID := 'b0000000-bbbb-0000-0000-000000000001';

    v_inc_a UUID := 'a0000000-cccc-0000-0000-000000000001';
    v_inc_b UUID := 'b0000000-cccc-0000-0000-000000000001';

    v_count INT;
    v_rows_affected INT;
    v_sqlstate TEXT;
    v_sqlerrm TEXT;
    v_verify_record RECORD;
BEGIN
    RAISE NOTICE '====================================================================';
    RAISE NOTICE 'PROJECT ATLAS: RUNNING STAGE 1 BEHAVIOURAL SECURITY SUITE';
    RAISE NOTICE '====================================================================';

    -- ------------------------------------------------------------------------
    -- SETUP TEST FIXTURES (Running as postgres superuser)
    -- ------------------------------------------------------------------------
    -- 1. Create auth users
    INSERT INTO auth.users (id, email, raw_user_meta_data)
    VALUES 
        (v_admin_a, 'admin_a@atlas.test', '{"role":"admin"}'::jsonb),
        (v_analyst_a, 'analyst_a@atlas.test', '{"role":"analyst"}'::jsonb),
        (v_admin_b, 'admin_b@atlas.test', '{"role":"admin"}'::jsonb)
    ON CONFLICT (id) DO NOTHING;

    -- 2. Create organisations
    INSERT INTO public.organisations (id, name, code, kind, source, correlation_id)
    VALUES 
        (v_org_a, 'Alpha Defence Firm', 'ALPHA-FIRMA', 'firm', 'Security Suite', 'cid-test-a'),
        (v_org_b, 'Beta Security Firm', 'BETA-FIRMB', 'firm', 'Security Suite', 'cid-test-b')
    ON CONFLICT (code) DO NOTHING;

    -- 3. Create memberships
    INSERT INTO public.memberships (user_id, org_id, role, source, correlation_id)
    VALUES 
        (v_admin_a, v_org_a, 'atlas:admin', 'Security Suite', 'cid-test'),
        (v_analyst_a, v_org_a, 'atlas:analyst', 'Security Suite', 'cid-test'),
        (v_admin_b, v_org_b, 'atlas:admin', 'Security Suite', 'cid-test')
    ON CONFLICT (user_id, org_id) DO NOTHING;

    -- 4. Create sample assets
    INSERT INTO public.assets (id, org_id, site_code, name, type, criticality, owner, accuracy_class, source, correlation_id)
    VALUES 
        (v_asset_a1, v_org_a, 'STE-A1', 'Substation North A', 'power_feed', 5, 'Alpha Grid', 'exact_survey', 'Test', 'cid-test'),
        (v_asset_a2, v_org_a, 'STE-A2', 'Pumping Station A', 'site', 4, 'Alpha Water', 'facility_approximate', 'Test', 'cid-test'),
        (v_asset_b1, v_org_b, 'STE-B1', 'Substation West B', 'power_feed', 5, 'Beta Power', 'exact_survey', 'Test', 'cid-test')
    ON CONFLICT (org_id, id) DO NOTHING;

    -- 5. Create incidents
    INSERT INTO public.incidents (id, org_id, event_id, event_type, severity, observed_at, source, correlation_id)
    VALUES 
        (v_inc_a, v_org_a, 'EVT-A-001', 'OT_DISRUPTION', 'critical', now(), 'CSX-Test', 'cid-test'),
        (v_inc_b, v_org_b, 'EVT-B-001', 'RANSOMWARE', 'high', now(), 'CSX-Test', 'cid-test')
    ON CONFLICT (org_id, id) DO NOTHING;

    -- ------------------------------------------------------------------------
    -- TEST 1: POSITIVE CONTROL (User A sees own rows with AAL2)
    -- ------------------------------------------------------------------------
    SET LOCAL ROLE authenticated;
    EXECUTE format('SET LOCAL request.jwt.claims = ''{"sub": "%s", "role": "authenticated", "aal": "aal2"}''', v_admin_a);

    SELECT COUNT(*) INTO v_count FROM public.organisations WHERE id = v_org_a;
    IF v_count = 1 THEN
        RAISE NOTICE 'PASS: Test 1 [Positive Control - User A reads own organisation]';
    ELSE
        RAISE EXCEPTION 'FAIL: Test 1 [Positive Control failed: expected 1 organisation, found %]', v_count;
    END IF;

    SELECT COUNT(*) INTO v_count FROM public.assets WHERE org_id = v_org_a;
    IF v_count >= 2 THEN
        RAISE NOTICE 'PASS: Test 1b [Positive Control - User A reads own assets (count=%)]', v_count;
    ELSE
        RAISE EXCEPTION 'FAIL: Test 1b [Positive Control failed: expected >= 2 assets, found %]', v_count;
    END IF;

    -- ------------------------------------------------------------------------
    -- TEST 2: ZERO CROSS-TENANT READS (User A queries Org B)
    -- ------------------------------------------------------------------------
    SELECT COUNT(*) INTO v_count FROM public.organisations WHERE id = v_org_b;
    IF v_count = 0 THEN
        RAISE NOTICE 'PASS: Test 2a [Zero Cross-Tenant Read - organisations]';
    ELSE
        RAISE EXCEPTION 'FAIL: Test 2a [Cross-Tenant Read Leak in organisations: found % rows]', v_count;
    END IF;

    SELECT COUNT(*) INTO v_count FROM public.assets WHERE org_id = v_org_b;
    IF v_count = 0 THEN
        RAISE NOTICE 'PASS: Test 2b [Zero Cross-Tenant Read - assets]';
    ELSE
        RAISE EXCEPTION 'FAIL: Test 2b [Cross-Tenant Read Leak in assets: found % rows]', v_count;
    END IF;

    SELECT COUNT(*) INTO v_count FROM public.incidents WHERE org_id = v_org_b;
    IF v_count = 0 THEN
        RAISE NOTICE 'PASS: Test 2c [Zero Cross-Tenant Read - incidents]';
    ELSE
        RAISE EXCEPTION 'FAIL: Test 2c [Cross-Tenant Read Leak in incidents: found % rows]', v_count;
    END IF;

    SELECT COUNT(*) INTO v_count FROM public.audit_events WHERE org_id = v_org_b;
    IF v_count = 0 THEN
        RAISE NOTICE 'PASS: Test 2d [Zero Cross-Tenant Read - audit_events]';
    ELSE
        RAISE EXCEPTION 'FAIL: Test 2d [Cross-Tenant Read Leak in audit_events: found % rows]', v_count;
    END IF;

    -- ------------------------------------------------------------------------
    -- TEST 3: RPC CROSS-TENANT AUTHORISATION (verify_audit_chain)
    -- ------------------------------------------------------------------------
    BEGIN
        PERFORM public.verify_audit_chain(v_org_b);
        RAISE EXCEPTION 'FAIL: Test 3 [verify_audit_chain allowed cross-tenant execution without error]';
    EXCEPTION WHEN OTHERS THEN
        GET STACKED DIAGNOSTICS v_sqlstate = RETURNED_SQLSTATE, v_sqlerrm = MESSAGE_TEXT;
        IF v_sqlstate = '42501' THEN
            RAISE NOTICE 'PASS: Test 3 [verify_audit_chain rejected cross-tenant execution with exact SQLSTATE 42501: %]', v_sqlerrm;
        ELSE
            RAISE EXCEPTION 'FAIL: Test 3 [Unexpected SQLSTATE: expected 42501, got % (%)]', v_sqlstate, v_sqlerrm;
        END IF;
    END;

    -- ------------------------------------------------------------------------
    -- TEST 4: CROSS-TENANT WRITES FAIL WITH EXACT SQLSTATE 42501
    -- ------------------------------------------------------------------------
    -- 4a. Cross-tenant INSERT into assets
    BEGIN
        INSERT INTO public.assets (org_id, site_code, name, type, criticality, owner, accuracy_class, source, correlation_id)
        VALUES (v_org_b, 'X-ROGUE', 'Rogue Cross-Tenant Asset', 'site', 1, 'Infiltrator', 'exact_survey', 'Hack', 'cid-x');
        RAISE EXCEPTION 'FAIL: Test 4a [Cross-tenant asset INSERT succeeded unexpectedly]';
    EXCEPTION WHEN OTHERS THEN
        GET STACKED DIAGNOSTICS v_sqlstate = RETURNED_SQLSTATE, v_sqlerrm = MESSAGE_TEXT;
        IF v_sqlstate = '42501' THEN
            RAISE NOTICE 'PASS: Test 4a [Cross-tenant asset INSERT rejected with exact SQLSTATE 42501]';
        ELSE
            RAISE EXCEPTION 'FAIL: Test 4a [Expected SQLSTATE 42501, got % (%)]', v_sqlstate, v_sqlerrm;
        END IF;
    END;

    -- 4b. Cross-tenant UPDATE
    UPDATE public.assets SET name = 'Tampered' WHERE id = v_asset_b1;
    GET DIAGNOSTICS v_rows_affected = ROW_COUNT;
    IF v_rows_affected = 0 THEN
        RAISE NOTICE 'PASS: Test 4b [Cross-tenant UPDATE affected 0 rows]';
    ELSE
        RAISE EXCEPTION 'FAIL: Test 4b [Cross-tenant UPDATE modified % rows]', v_rows_affected;
    END IF;

    -- 4c. Cross-tenant DELETE
    DELETE FROM public.assets WHERE id = v_asset_b1;
    GET DIAGNOSTICS v_rows_affected = ROW_COUNT;
    IF v_rows_affected = 0 THEN
        RAISE NOTICE 'PASS: Test 4c [Cross-tenant DELETE affected 0 rows]';
    ELSE
        RAISE EXCEPTION 'FAIL: Test 4c [Cross-tenant DELETE removed % rows]', v_rows_affected;
    END IF;

    -- ------------------------------------------------------------------------
    -- TEST 5: COMPOSITE KEYS BLOCK CROSS-TENANT RELATIONAL REFERENCES
    -- (Foreign key engine rejects referencing an asset from another organisation)
    -- ------------------------------------------------------------------------
    SET LOCAL ROLE postgres; -- Execute as superuser to test database engine constraint
    BEGIN
        INSERT INTO public.dependency_edges (
            org_id, from_asset_id, to_asset_id, relation_type, criticality, source, correlation_id
        ) VALUES (
            v_org_a, v_asset_a1, v_asset_b1, 'powers', 5, 'Security Test', 'cid-fk-test'
        );
        RAISE EXCEPTION 'FAIL: Test 5 [Composite FK failed to reject cross-tenant edge reference]';
    EXCEPTION WHEN OTHERS THEN
        GET STACKED DIAGNOSTICS v_sqlstate = RETURNED_SQLSTATE, v_sqlerrm = MESSAGE_TEXT;
        IF v_sqlstate = '23503' THEN
            RAISE NOTICE 'PASS: Test 5 [Composite FK rejected cross-tenant reference with exact SQLSTATE 23503: %]', v_sqlerrm;
        ELSE
            RAISE EXCEPTION 'FAIL: Test 5 [Expected SQLSTATE 23503 foreign_key_violation, got % (%)]', v_sqlstate, v_sqlerrm;
        END IF;
    END;

    -- ------------------------------------------------------------------------
    -- TEST 6: ROLE ENFORCEMENT (Analyst cannot DELETE assets, Admin can)
    -- ------------------------------------------------------------------------
    -- 6a. Switch to Analyst in Org A
    SET LOCAL ROLE authenticated;
    EXECUTE format('SET LOCAL request.jwt.claims = ''{"sub": "%s", "role": "authenticated", "aal": "aal2"}''', v_analyst_a);

    DELETE FROM public.assets WHERE id = v_asset_a2;
    GET DIAGNOSTICS v_rows_affected = ROW_COUNT;
    IF v_rows_affected = 0 THEN
        RAISE NOTICE 'PASS: Test 6a [Analyst DELETE asset affected 0 rows]';
    ELSE
        RAISE EXCEPTION 'FAIL: Test 6a [Analyst was able to DELETE asset (% rows affected)]', v_rows_affected;
    END IF;

    -- Verify row still exists
    SELECT COUNT(*) INTO v_count FROM public.assets WHERE id = v_asset_a2;
    IF v_count = 1 THEN
        RAISE NOTICE 'PASS: Test 6b [Asset persists after analyst deletion attempt]';
    ELSE
        RAISE EXCEPTION 'FAIL: Test 6b [Asset was removed]';
    END IF;

    -- 6b. Switch to Admin in Org A -> Delete succeeds
    EXECUTE format('SET LOCAL request.jwt.claims = ''{"sub": "%s", "role": "authenticated", "aal": "aal2"}''', v_admin_a);
    DELETE FROM public.assets WHERE id = v_asset_a2;
    GET DIAGNOSTICS v_rows_affected = ROW_COUNT;
    IF v_rows_affected = 1 THEN
        RAISE NOTICE 'PASS: Test 6c [Admin DELETE asset successfully removed 1 row]';
    ELSE
        RAISE EXCEPTION 'FAIL: Test 6c [Admin DELETE asset failed, rows affected: %]', v_rows_affected;
    END IF;

    -- ------------------------------------------------------------------------
    -- TEST 7: AUDIT IMMUTABILITY & TAMPER PREVENTION TRIGGERS
    -- ------------------------------------------------------------------------
    -- 7a. Forged direct INSERT into audit_events by client
    BEGIN
        INSERT INTO public.audit_events (
            org_id, seq, timestamp, timestamp_text, actor_id, actor_role, action, target_type, target_id,
            correlation_id, payload_hash, prev_hash, record_hash
        ) VALUES (
            v_org_a, 999, now(), '2026-01-01T00:00:00.000000Z', v_admin_a, 'atlas:admin', 'FORGED', 'NONE', '0',
            'cid', repeat('a', 64), repeat('0', 64), repeat('f', 64)
        );
        RAISE EXCEPTION 'FAIL: Test 7a [Client direct INSERT into audit_events succeeded unexpectedly]';
    EXCEPTION WHEN OTHERS THEN
        GET STACKED DIAGNOSTICS v_sqlstate = RETURNED_SQLSTATE;
        IF v_sqlstate = '42501' THEN
            RAISE NOTICE 'PASS: Test 7a [Direct client audit INSERT rejected by RLS (SQLSTATE 42501)]';
        ELSE
            RAISE EXCEPTION 'FAIL: Test 7a [Expected SQLSTATE 42501, got %]', v_sqlstate;
        END IF;
    END;

    -- 7b. UPDATE on audit_events (Trigger enforce_audit_immutability)
    SET LOCAL ROLE postgres; -- Superuser attempt
    BEGIN
        UPDATE public.audit_events SET action = 'ALTERED' WHERE org_id = v_org_a;
        RAISE EXCEPTION 'FAIL: Test 7b [UPDATE audit_events succeeded unexpectedly]';
    EXCEPTION WHEN OTHERS THEN
        GET STACKED DIAGNOSTICS v_sqlstate = RETURNED_SQLSTATE, v_sqlerrm = MESSAGE_TEXT;
        IF v_sqlstate = '55000' AND v_sqlerrm LIKE '%Audit ledger records are immutable%' THEN
            RAISE NOTICE 'PASS: Test 7b [UPDATE audit_events blocked with exact SQLSTATE 55000: %]', v_sqlerrm;
        ELSE
            RAISE EXCEPTION 'FAIL: Test 7b [Expected SQLSTATE 55000 with exact message, got % (%)]', v_sqlstate, v_sqlerrm;
        END IF;
    END;

    -- 7c. DELETE on audit_events
    BEGIN
        DELETE FROM public.audit_events WHERE org_id = v_org_a;
        RAISE EXCEPTION 'FAIL: Test 7c [DELETE audit_events succeeded unexpectedly]';
    EXCEPTION WHEN OTHERS THEN
        GET STACKED DIAGNOSTICS v_sqlstate = RETURNED_SQLSTATE, v_sqlerrm = MESSAGE_TEXT;
        IF v_sqlstate = '55000' AND v_sqlerrm LIKE '%Audit ledger records are immutable%' THEN
            RAISE NOTICE 'PASS: Test 7c [DELETE audit_events blocked with exact SQLSTATE 55000: %]', v_sqlerrm;
        ELSE
            RAISE EXCEPTION 'FAIL: Test 7c [Expected SQLSTATE 55000 with exact message, got % (%)]', v_sqlstate, v_sqlerrm;
        END IF;
    END;

    -- ------------------------------------------------------------------------
    -- TEST 8: MANDATORY MFA (aal1 sessions read 0 rows)
    -- ------------------------------------------------------------------------
    SET LOCAL ROLE authenticated;
    EXECUTE format('SET LOCAL request.jwt.claims = ''{"sub": "%s", "role": "authenticated", "aal": "aal1"}''', v_admin_a);

    SELECT COUNT(*) INTO v_count FROM public.organisations;
    IF v_count = 0 THEN
        RAISE NOTICE 'PASS: Test 8a [aal1 session reads 0 rows in organisations]';
    ELSE
        RAISE EXCEPTION 'FAIL: Test 8a [aal1 session leaked % rows in organisations]', v_count;
    END IF;

    SELECT COUNT(*) INTO v_count FROM public.assets;
    IF v_count = 0 THEN
        RAISE NOTICE 'PASS: Test 8b [aal1 session reads 0 rows in assets]';
    ELSE
        RAISE EXCEPTION 'FAIL: Test 8b [aal1 session leaked % rows in assets]', v_count;
    END IF;

    -- ------------------------------------------------------------------------
    -- TEST 9: ANON ROLE READS 0 ROWS EVERYWHERE
    -- ------------------------------------------------------------------------
    SET LOCAL ROLE anon;
    SET LOCAL request.jwt.claims = '{"role": "anon", "aal": "aal1"}';

    -- After migration 014 anon holds no table rights at all, so the strongest outcome is a privilege error (42501).
    -- Zero rows is also acceptable; anything else (rows returned, or a different error) fails.
    BEGIN
        SELECT COUNT(*) INTO v_count FROM public.organisations;
        IF v_count = 0 THEN
            RAISE NOTICE 'PASS: Test 9a [anon role reads 0 rows in organisations]';
        ELSE
            RAISE EXCEPTION 'FAIL: Test 9a [anon role leaked % rows in organisations]', v_count;
        END IF;
    EXCEPTION WHEN OTHERS THEN
        GET STACKED DIAGNOSTICS v_sqlstate = RETURNED_SQLSTATE, v_sqlerrm = MESSAGE_TEXT;
        IF v_sqlstate = '42501' THEN
            RAISE NOTICE 'PASS: Test 9a [anon role has no access to organisations (42501)]';
        ELSE
            RAISE EXCEPTION '%', v_sqlerrm;
        END IF;
    END;

    BEGIN
        SELECT COUNT(*) INTO v_count FROM public.audit_events;
        IF v_count = 0 THEN
            RAISE NOTICE 'PASS: Test 9b [anon role reads 0 rows in audit_events]';
        ELSE
            RAISE EXCEPTION 'FAIL: Test 9b [anon role leaked % rows in audit_events]', v_count;
        END IF;
    EXCEPTION WHEN OTHERS THEN
        GET STACKED DIAGNOSTICS v_sqlstate = RETURNED_SQLSTATE, v_sqlerrm = MESSAGE_TEXT;
        IF v_sqlstate = '42501' THEN
            RAISE NOTICE 'PASS: Test 9b [anon role has no access to audit_events (42501)]';
        ELSE
            RAISE EXCEPTION '%', v_sqlerrm;
        END IF;
    END;

    -- ------------------------------------------------------------------------
    -- TEST 10: CRYPTOGRAPHIC CHAIN TAMPER DETECTION
    -- ------------------------------------------------------------------------
    -- 10a. Verify untampered chain is valid
    SET LOCAL ROLE authenticated;
    EXECUTE format('SET LOCAL request.jwt.claims = ''{"sub": "%s", "role": "authenticated", "aal": "aal2"}''', v_admin_a);

    SELECT * INTO v_verify_record FROM public.verify_audit_chain(v_org_a);
    IF v_verify_record.is_valid THEN
        RAISE NOTICE 'PASS: Test 10a [verify_audit_chain confirms untampered chain: total_verified=%]', v_verify_record.total_verified;
    ELSE
        RAISE EXCEPTION 'FAIL: Test 10a [Unexpected verification failure on clean chain: %]', v_verify_record.reason;
    END IF;

    -- 10b. Tamper with a row as superuser (disable triggers temporarily to simulate raw database tampering)
    SET LOCAL ROLE postgres;
    ALTER TABLE public.audit_events DISABLE TRIGGER trg_audit_events_no_modify;

    UPDATE public.audit_events
    SET payload_hash = repeat('e', 64)
    WHERE org_id = v_org_a AND seq = 1;

    ALTER TABLE public.audit_events ENABLE TRIGGER trg_audit_events_no_modify;

    -- 10c. Run verify_audit_chain -> Must detect tampering at seq 1
    SET LOCAL ROLE authenticated;
    EXECUTE format('SET LOCAL request.jwt.claims = ''{"sub": "%s", "role": "authenticated", "aal": "aal2"}''', v_admin_a);

    SELECT * INTO v_verify_record FROM public.verify_audit_chain(v_org_a);
    IF NOT v_verify_record.is_valid AND v_verify_record.first_bad_seq = 1 AND v_verify_record.reason LIKE '%Record hash signature failure%' THEN
        RAISE NOTICE 'PASS: Test 10b [verify_audit_chain correctly caught tampered sequence %: %]', v_verify_record.first_bad_seq, v_verify_record.reason;
    ELSE
        RAISE EXCEPTION 'FAIL: Test 10b [Tampering was not detected as expected. is_valid=%, reason=%]', v_verify_record.is_valid, v_verify_record.reason;
    END IF;

    -- ------------------------------------------------------------------------
    -- TEST 11: ATOMIC ASSET IMPORT (import_assets RPC)
    -- ------------------------------------------------------------------------
    -- 11a. Atomic rollback on partial failure (Batch has 1 valid and 1 invalid row)
    SET LOCAL ROLE authenticated;
    EXECUTE format('SET LOCAL request.jwt.claims = ''{"sub": "%s", "role": "authenticated", "aal": "aal2"}''', v_analyst_a);

    BEGIN
        PERFORM public.import_assets(
            jsonb_build_object(
                'org_id', v_org_a,
                'name', 'Bad Batch Test',
                'source', 'Test Suite',
                'licence', 'Proprietary',
                'declared_crs', 'EPSG:4326'
            ),
            jsonb_build_array(
                jsonb_build_object(
                    'site_code', 'STE-FAIL-VALID',
                    'name', 'Valid Part of Batch',
                    'type', 'site',
                    'criticality', 3,
                    'owner', 'Alpha Ops',
                    'accuracy_class', 'exact_survey',
                    'geometry', '{"type": "Point", "coordinates": [-0.12, 51.50]}'::jsonb
                ),
                jsonb_build_object(
                    'site_code', 'STE-FAIL-INVALID',
                    'name', 'Invalid Geometry Coords',
                    'type', 'site',
                    'criticality', 3,
                    'owner', 'Alpha Ops',
                    'accuracy_class', 'exact_survey',
                    'geometry', '{"type": "Point", "coordinates": [250.0, 51.50]}'::jsonb -- Longitude out of bounds
                )
            )
        );
        RAISE EXCEPTION 'FAIL: Test 11a [import_assets succeeded unexpectedly on invalid coordinates]';
    EXCEPTION WHEN OTHERS THEN
        GET STACKED DIAGNOSTICS v_sqlstate = RETURNED_SQLSTATE, v_sqlerrm = MESSAGE_TEXT;
        IF v_sqlstate = '22023' AND v_sqlerrm LIKE '%Coordinates out of WGS84 range%' THEN
            RAISE NOTICE 'PASS: Test 11a [import_assets rejected invalid row with SQLSTATE 22023: %]', v_sqlerrm;
        ELSE
            RAISE EXCEPTION 'FAIL: Test 11a [Expected 22023 coordinate error, got % (%)]', v_sqlstate, v_sqlerrm;
        END IF;
    END;

    -- Verify that the first valid row was NOT committed (Atomic Rollback)
    SELECT COUNT(*) INTO v_count FROM public.assets WHERE org_id = v_org_a AND site_code = 'STE-FAIL-VALID';
    IF v_count = 0 THEN
        RAISE NOTICE 'PASS: Test 11b [Atomic import rollback confirmed: 0 rows leaked from failed batch]';
    ELSE
        RAISE EXCEPTION 'FAIL: Test 11b [Atomicity failure: valid row from failed batch was committed!]';
    END IF;

    -- ------------------------------------------------------------------------
    -- TEST 12: CROSS-TENANT IMPORT DENIAL
    -- User A attempts to publish an asset batch into Org B
    -- ------------------------------------------------------------------------
    BEGIN
        PERFORM public.import_assets(
            jsonb_build_object(
                'org_id', v_org_b,
                'name', 'Cross Tenant Hack',
                'source', 'Infiltrator',
                'licence', 'None',
                'declared_crs', 'EPSG:4326'
            ),
            jsonb_build_array(
                jsonb_build_object(
                    'site_code', 'STE-X-01',
                    'name', 'Cross Infiltrator',
                    'type', 'site',
                    'criticality', 1,
                    'owner', 'Rogue',
                    'accuracy_class', 'exact_survey',
                    'geometry', '{"type": "Point", "coordinates": [0.0, 0.0]}'::jsonb
                )
            )
        );
        RAISE EXCEPTION 'FAIL: Test 12 [Cross-tenant import_assets succeeded unexpectedly]';
    EXCEPTION WHEN OTHERS THEN
        GET STACKED DIAGNOSTICS v_sqlstate = RETURNED_SQLSTATE, v_sqlerrm = MESSAGE_TEXT;
        IF v_sqlstate = '42501' THEN
            RAISE NOTICE 'PASS: Test 12 [Cross-tenant import_assets denied with exact SQLSTATE 42501: %]', v_sqlerrm;
        ELSE
            RAISE EXCEPTION 'FAIL: Test 12 [Expected SQLSTATE 42501, got % (%)]', v_sqlstate, v_sqlerrm;
        END IF;
    END;

    -- ------------------------------------------------------------------------
    -- TEST 13: CRS ENFORCEMENT & ROW LIMITS (Reject non-EPSG:4326 in SQL)
    -- ------------------------------------------------------------------------
    BEGIN
        PERFORM public.import_assets(
            jsonb_build_object(
                'org_id', v_org_a,
                'name', 'Wrong CRS Test',
                'declared_crs', 'EPSG:3857'
            ),
            jsonb_build_array(
                jsonb_build_object(
                    'site_code', 'STE-3857',
                    'name', 'Web Mercator Site',
                    'type', 'site',
                    'criticality', 3,
                    'owner', 'Alpha Ops',
                    'accuracy_class', 'exact_survey',
                    'geometry', '{"type": "Point", "coordinates": [0.0, 0.0]}'::jsonb
                )
            )
        );
        RAISE EXCEPTION 'FAIL: Test 13 [import_assets accepted EPSG:3857 unexpectedly]';
    EXCEPTION WHEN OTHERS THEN
        GET STACKED DIAGNOSTICS v_sqlstate = RETURNED_SQLSTATE, v_sqlerrm = MESSAGE_TEXT;
        IF v_sqlstate = '22023' AND v_sqlerrm LIKE '%Unsupported CRS%' THEN
            RAISE NOTICE 'PASS: Test 13 [import_assets rejected non-EPSG:4326 CRS with SQLSTATE 22023: %]', v_sqlerrm;
        ELSE
            RAISE EXCEPTION 'FAIL: Test 13 [Expected 22023 CRS rejection, got % (%)]', v_sqlstate, v_sqlerrm;
        END IF;
    END;

    -- ------------------------------------------------------------------------
    -- TEST 14: ANALYST CAN INSERT ASSETS VIA RPC BUT CANNOT DELETE
    -- ------------------------------------------------------------------------
    -- 14a. Analyst successfully imports valid asset batch
    PERFORM public.import_assets(
        jsonb_build_object(
            'org_id', v_org_a,
            'name', 'Analyst Stage 2 Ingest Batch',
            'source', 'OT Resilience Assessment',
            'licence', 'Proprietary',
            'declared_crs', 'EPSG:4326'
        ),
        jsonb_build_array(
            jsonb_build_object(
                'site_code', 'STE-ANALYST-01',
                'name', 'Analyst Approved Site',
                'type', 'site',
                'criticality', 4,
                'owner', 'Alpha Ops',
                'accuracy_class', 'exact_survey',
                'geometry', '{"type": "Point", "coordinates": [-0.1278, 51.5074]}'::jsonb
            ),
            jsonb_build_object(
                'site_code', 'PWR-ANALYST-02',
                'name', 'Analyst Approximate Feed',
                'type', 'power_feed',
                'criticality', 5,
                'owner', 'Regional Grid',
                'accuracy_class', 'facility_approximate',
                'positional_accuracy_m', 150,
                'geometry', '{"type": "Point", "coordinates": [-0.1300, 51.5100]}'::jsonb
            )
        )
    );

    SELECT COUNT(*) INTO v_count FROM public.assets WHERE org_id = v_org_a AND site_code = 'STE-ANALYST-01';
    IF v_count = 1 THEN
        RAISE NOTICE 'PASS: Test 14a [Analyst successfully imported asset batch via import_assets]';
    ELSE
        RAISE EXCEPTION 'FAIL: Test 14a [Analyst import failed to persist asset]';
    END IF;

    -- 14b. Analyst attempts DELETE on the newly imported asset -> Denied
    DELETE FROM public.assets WHERE org_id = v_org_a AND site_code = 'STE-ANALYST-01';
    GET DIAGNOSTICS v_rows_affected = ROW_COUNT;
    IF v_rows_affected = 0 THEN
        RAISE NOTICE 'PASS: Test 14b [Analyst cannot DELETE imported asset (0 rows affected)]';
    ELSE
        RAISE EXCEPTION 'FAIL: Test 14b [Analyst was able to DELETE asset (% rows affected)]', v_rows_affected;
    END IF;

    -- 14c. GeoJSON map query returns the new assets with accuracy flag
    DECLARE
        v_map_geojson JSONB;
    BEGIN
        v_map_geojson := public.get_workspace_assets_geojson(v_org_a, 'all', 1);
        IF (v_map_geojson->>'type') = 'FeatureCollection' AND jsonb_array_length(v_map_geojson->'features') >= 2 THEN
            RAISE NOTICE 'PASS: Test 14c [get_workspace_assets_geojson returns FeatureCollection for workspace with count=%]',
                jsonb_array_length(v_map_geojson->'features');
        ELSE
            RAISE EXCEPTION 'FAIL: Test 14c [get_workspace_assets_geojson failed or returned unexpected payload: %]', v_map_geojson;
        END IF;
    END;

    -- ------------------------------------------------------------------------
    -- TEST 15: CROSS-ORGANISATION EDGE CANNOT BE CREATED AT DATABASE LEVEL
    -- ------------------------------------------------------------------------
    -- Attempting to insert an edge from Org A to an asset in Org B
    BEGIN
        INSERT INTO public.dependency_edges (
            org_id, from_asset_id, to_asset_id, relation_type, criticality, source, correlation_id
        ) VALUES (
            v_org_a, v_asset_a1, v_asset_b1, 'powers', 5, 'Security Test', 'cid-cross-edge'
        );
        RAISE EXCEPTION 'FAIL: Test 15 [Cross-organisation dependency edge succeeded unexpectedly]';
    EXCEPTION WHEN OTHERS THEN
        GET STACKED DIAGNOSTICS v_sqlstate = RETURNED_SQLSTATE, v_sqlerrm = MESSAGE_TEXT;
        IF v_sqlstate = '23503' THEN
            RAISE NOTICE 'PASS: Test 15 [Cross-organisation edge rejected by composite FK with SQLSTATE 23503: %]', v_sqlerrm;
        ELSE
            RAISE EXCEPTION 'FAIL: Test 15 [Expected SQLSTATE 23503 foreign key violation, got % (%)]', v_sqlstate, v_sqlerrm;
        END IF;
    END;

    -- ------------------------------------------------------------------------
    -- TEST 16: FIXED TEST GRAPH & HAND-COMPUTED EXPECTED OUTPUT FOR blast_radius
    -- ------------------------------------------------------------------------
    DECLARE
        v_test_root UUID := 'a0000000-1111-1111-0000-000000000001';
        v_test_dc   UUID := 'a0000000-1111-1111-0000-000000000002';
        v_test_svc1 UUID := 'a0000000-1111-1111-0000-000000000003';
        v_test_svc2 UUID := 'a0000000-1111-1111-0000-000000000004';
        v_test_svc3 UUID := 'a0000000-1111-1111-0000-000000000005';
        v_test_inc  UUID := 'a0000000-1111-1111-0000-000000000009';
        v_br_row RECORD;
        v_run1_json JSONB;
        v_run2_json JSONB;
    BEGIN
        -- 1. Insert fixed test graph assets in Org A
        -- Total services in Org A for this test = 3 (v_test_svc1, v_test_svc2, v_test_svc3)
        INSERT INTO public.assets (id, org_id, site_code, name, type, criticality, owner, accuracy_class, source, correlation_id)
        VALUES
            (v_test_root, v_org_a, 'TEST-ROOT', 'Root Substation Alpha', 'power_feed', 5, 'Grid Ops', 'exact_survey', 'Fixed Graph', 'cid-test'),
            (v_test_dc,   v_org_a, 'TEST-DC',   'Data Centre Beta',    'site',       4, 'Cloud Ops', 'exact_survey', 'Fixed Graph', 'cid-test'),
            (v_test_svc1, v_org_a, 'TEST-SVC1', 'Telemetry API',       'service',    5, 'Sec Ops',   'exact_survey', 'Fixed Graph', 'cid-test'),
            (v_test_svc2, v_org_a, 'TEST-SVC2', 'Billing Database',    'service',    3, 'Fin Ops',   'facility_approximate', 'Fixed Graph', 'cid-test'),
            (v_test_svc3, v_org_a, 'TEST-SVC3', 'Unreachable Backup',  'service',    2, 'IT Ops',    'exact_survey', 'Fixed Graph', 'cid-test')
        ON CONFLICT (org_id, id) DO NOTHING;

        -- 2. Insert directed edges (impact flows provider -> consumer)
        -- root -(powers)-> dc -(hosts)-> svc1, dc -(hosts)-> svc2
        INSERT INTO public.dependency_edges (org_id, from_asset_id, to_asset_id, relation_type, criticality, source, correlation_id)
        VALUES
            (v_org_a, v_test_root, v_test_dc, 'powers', 5, 'Fixed Graph', 'cid-test'),
            (v_org_a, v_test_dc, v_test_svc1, 'hosts',  5, 'Fixed Graph', 'cid-test'),
            (v_org_a, v_test_dc, v_test_svc2, 'hosts',  4, 'Fixed Graph', 'cid-test')
        ON CONFLICT (org_id, from_asset_id, to_asset_id, relation_type) DO NOTHING;

        -- 3. Insert incident and confirmed root match
        INSERT INTO public.incidents (id, org_id, event_id, event_type, severity, observed_at, source, correlation_id)
        VALUES
            (v_test_inc, v_org_a, 'EVT-BR-TEST', 'PHYSICAL_INTRUSION', 'critical', now(), 'Security Suite', 'cid-test')
        ON CONFLICT (org_id, id) DO NOTHING;

        INSERT INTO public.asset_matches (org_id, incident_id, asset_id, rule_fired, score, status, source, confidence, correlation_id)
        VALUES
            (v_org_a, v_test_inc, v_test_root, 'exact_site_code', 1.0, 'confirmed', 'Security Suite', 1.0, 'cid-test')
        ON CONFLICT (org_id, incident_id, asset_id, rule_fired) DO NOTHING;

        -- 4. Execute blast_radius as authenticated AAL2 user in Org A
        SET LOCAL ROLE authenticated;
        EXECUTE format('SET LOCAL request.jwt.claims = ''{"sub": "%s", "role": "authenticated", "aal": "aal2"}''', v_admin_a);

        -- Hand-computed checks on Root Asset (v_test_root):
        -- Reachable services downstream: TEST-SVC1 and TEST-SVC2 (2 services)
        -- Total workspace services = 3 (TEST-SVC1, TEST-SVC2, TEST-SVC3)
        -- Factor r = 2/3 = 0.6667
        -- Factor c = 5/5 = 1.0000
        -- Impact I = 1.0000 * 0.6667 = 0.6667
        -- Exposure E = 0.80
        -- Likelihood L = 0.90
        -- Priority = 0.6667 * 0.80 * 0.90 = 0.4800
        SELECT * INTO v_br_row FROM public.blast_radius(v_test_inc) WHERE asset_id = v_test_root;
        IF v_br_row.asset_id IS NOT NULL AND v_br_row.c = 1.0000 AND v_br_row.r = 0.6667 AND v_br_row.priority = 0.4800 THEN
            RAISE NOTICE 'PASS: Test 16a [Hand-computed factors verified on Root Asset: c=%, r=%, I=%, Priority=%]',
                v_br_row.c, v_br_row.r, v_br_row.i_factor, v_br_row.priority;
        ELSE
            RAISE EXCEPTION 'FAIL: Test 16a [Hand-computed factor mismatch on Root Asset: got c=%, r=%, Priority=% (expected c=1.0000, r=0.6667, Priority=0.4800)]',
                v_br_row.c, v_br_row.r, v_br_row.priority;
        END IF;

        -- Hand-computed checks on Data Centre (v_test_dc):
        -- Reachable services downstream: 2 services
        -- Factor r = 2/3 = 0.6667
        -- Factor c = 4/5 = 0.8000
        -- Impact I = 0.8000 * 0.6667 = 0.5333
        -- Exposure E = 0.80
        -- Likelihood L = 0.90 * 0.85 = 0.7650
        -- Priority = 0.5333 * 0.80 * 0.7650 = 0.3264
        SELECT * INTO v_br_row FROM public.blast_radius(v_test_inc) WHERE asset_id = v_test_dc;
        IF v_br_row.asset_id IS NOT NULL AND v_br_row.c = 0.8000 AND v_br_row.r = 0.6667 AND v_br_row.priority = 0.3264 THEN
            RAISE NOTICE 'PASS: Test 16b [Hand-computed factors verified on Intermediate DC: c=%, r=%, I=%, Priority=%]',
                v_br_row.c, v_br_row.r, v_br_row.i_factor, v_br_row.priority;
        ELSE
            RAISE EXCEPTION 'FAIL: Test 16b [Hand-computed factor mismatch on DC: got c=%, r=%, Priority=% (expected c=0.8000, r=0.6667, Priority=0.3264)]',
                v_br_row.c, v_br_row.r, v_br_row.priority;
        END IF;

        -- --------------------------------------------------------------------
        -- TEST 17: DETERMINISM (Running twice gives identical output)
        -- --------------------------------------------------------------------
        SELECT jsonb_agg(row_to_json(b)) INTO v_run1_json FROM public.blast_radius(v_test_inc) b;
        SELECT jsonb_agg(row_to_json(b)) INTO v_run2_json FROM public.blast_radius(v_test_inc) b;

        IF v_run1_json = v_run2_json THEN
            RAISE NOTICE 'PASS: Test 17 [Determinism verified: blast_radius run 1 and run 2 produced 100%% identical JSON payload]';
        ELSE
            RAISE EXCEPTION 'FAIL: Test 17 [Nondeterministic blast radius output detected between runs]';
        END IF;

        -- --------------------------------------------------------------------
        -- TEST 18: CROSS-TENANT CALL TO blast_radius IS DENIED
        -- --------------------------------------------------------------------
        -- User A attempts to call blast_radius on Org B's incident
        BEGIN
            PERFORM public.blast_radius(v_inc_b);
            RAISE EXCEPTION 'FAIL: Test 18 [blast_radius succeeded on cross-tenant incident unexpectedly]';
        EXCEPTION WHEN OTHERS THEN
            GET STACKED DIAGNOSTICS v_sqlstate = RETURNED_SQLSTATE, v_sqlerrm = MESSAGE_TEXT;
            IF v_sqlstate = '42501' THEN
                RAISE NOTICE 'PASS: Test 18 [Cross-tenant blast_radius denied with exact SQLSTATE 42501: %]', v_sqlerrm;
            ELSE
                RAISE EXCEPTION 'FAIL: Test 18 [Expected SQLSTATE 42501, got % (%)]', v_sqlstate, v_sqlerrm;
            END IF;
        END;
    END;

    -- ------------------------------------------------------------------------
    -- TEST 19: INCIDENT INGEST IDEMPOTENCY
    -- ------------------------------------------------------------------------
    DECLARE
        v_ingest_res1 JSONB;
        v_ingest_res2 JSONB;
        v_inc_count INT;
        v_ingest_key JSONB;
    BEGIN
        -- Test helpers (live only in this session). They sign payloads the way a real sender must.
        RESET ROLE;
        EXECUTE $q$
            CREATE FUNCTION pg_temp.atlas_sign_with(p_org UUID, p JSONB, p_key TEXT, p_secret TEXT) RETURNS JSONB
            LANGUAGE sql AS $f$
                SELECT (p || jsonb_build_object('key_id', p_key)) || jsonb_build_object('signature',
                    encode(extensions.hmac(public.ingest_signing_string(p_org, p || jsonb_build_object('key_id', p_key)), p_secret, 'sha256'), 'hex'))
            $f$
        $q$;
        EXECUTE $q$
            CREATE FUNCTION pg_temp.atlas_ingest(p JSONB) RETURNS JSONB
            LANGUAGE sql AS $f$
                SELECT public.ingest_incident(pg_temp.atlas_sign_with(
                    COALESCE((p->>'org_id')::uuid, 'a0000000-0000-0000-0000-000000000001'::uuid), p,
                    current_setting('atlas_test.key_id'), current_setting('atlas_test.secret')))
            $f$
        $q$;

        SET LOCAL ROLE authenticated;
        EXECUTE format('SET LOCAL request.jwt.claims = ''{"sub": "%s", "role": "authenticated", "aal": "aal2"}''', v_admin_a);

        -- An administrator creates the organisation's ingest key through the real function
        v_ingest_key := public.create_ingest_key(v_org_a);
        PERFORM set_config('atlas_test.key_id', v_ingest_key->>'key_id', true);
        PERFORM set_config('atlas_test.secret', v_ingest_key->>'secret', true);

        -- Ingest incident first time
        v_ingest_res1 := pg_temp.atlas_ingest(
            jsonb_build_object(
                'schema_version', '1.0',
                'event_id', 'EVT-IDEMP-001',
                'event_type', 'OT_DISRUPTION',
                'severity', 'critical',
                'observed_at', now()::text,
                'sent_at', now()::text,
                'confidence', 0.95,
                'signals', jsonb_build_object(
                    'site_codes', jsonb_build_array('STE-A1'),
                    'hostnames', '[]'::jsonb,
                    'ips', '[]'::jsonb,
                    'cidrs', '[]'::jsonb,
                    'cloud_account_ids', '[]'::jsonb
                ),
                'org_id', v_org_a,
                'source', 'Security Suite Test'
            )
        );

        IF (v_ingest_res1->>'success')::boolean = true AND (v_ingest_res1->>'idempotent')::boolean = false THEN
            RAISE NOTICE 'PASS: Test 19a [First ingest succeeded: incident_id=%]', v_ingest_res1->>'incident_id';
        ELSE
            RAISE EXCEPTION 'FAIL: Test 19a [Initial ingest failed: %]', v_ingest_res1;
        END IF;

        -- Ingest second time with exact same event_id -> Must be a safe idempotent no-op
        v_ingest_res2 := pg_temp.atlas_ingest(
            jsonb_build_object(
                'schema_version', '1.0',
                'event_id', 'EVT-IDEMP-001',
                'event_type', 'OT_DISRUPTION',
                'severity', 'critical',
                'observed_at', now()::text,
                'sent_at', now()::text,
                'confidence', 0.95,
                'signals', jsonb_build_object('site_codes', jsonb_build_array('STE-A1')),
                'org_id', v_org_a,
                'source', 'Security Suite Test'
            )
        );

        IF (v_ingest_res2->>'success')::boolean = true AND (v_ingest_res2->>'idempotent')::boolean = true AND
           (v_ingest_res2->>'incident_id') = (v_ingest_res1->>'incident_id') THEN
            RAISE NOTICE 'PASS: Test 19b [Idempotent replay detected and returned original incident record safely]';
        ELSE
            RAISE EXCEPTION 'FAIL: Test 19b [Idempotency failed: %]', v_ingest_res2;
        END IF;

        -- Ensure exactly 1 row was stored in public.incidents
        SELECT COUNT(*) INTO v_inc_count FROM public.incidents WHERE org_id = v_org_a AND event_id = 'EVT-IDEMP-001';
        IF v_inc_count = 1 THEN
            RAISE NOTICE 'PASS: Test 19c [Database row count verified: exactly 1 incident record exists]';
        ELSE
            RAISE EXCEPTION 'FAIL: Test 19c [Duplicate incident row leaked in database: count=%]', v_inc_count;
        END IF;
    END;

    -- ------------------------------------------------------------------------
    -- TEST 20: REPLAY REJECTION (sent_at older than 10 minutes)
    -- ------------------------------------------------------------------------
    BEGIN
        SET LOCAL ROLE authenticated;
        EXECUTE format('SET LOCAL request.jwt.claims = ''{"sub": "%s", "role": "authenticated", "aal": "aal2"}''', v_admin_a);

        PERFORM pg_temp.atlas_ingest(
            jsonb_build_object(
                'schema_version', '1.0',
                'event_id', 'EVT-STALE-REPLAY',
                'event_type', 'OT_DISRUPTION',
                'severity', 'high',
                'observed_at', (now() - INTERVAL '20 minutes')::text,
                'sent_at', (now() - INTERVAL '15 minutes')::text, -- Stale timestamp (> 10 minutes)
                'confidence', 0.90,
                'signals', '{}'::jsonb,
                'org_id', v_org_a
            )
        );
        RAISE EXCEPTION 'FAIL: Test 20 [Stale replay payload accepted unexpectedly]';
    EXCEPTION WHEN OTHERS THEN
        GET STACKED DIAGNOSTICS v_sqlstate = RETURNED_SQLSTATE, v_sqlerrm = MESSAGE_TEXT;
        IF v_sqlstate = '22023' AND v_sqlerrm LIKE '%Replay rejected: sent_at is older than 10 minutes%' THEN
            RAISE NOTICE 'PASS: Test 20 [Stale payload rejected by 10-minute replay window: %]', v_sqlerrm;
        ELSE
            RAISE EXCEPTION 'FAIL: Test 20 [Expected 22023 replay rejection, got % (%)]', v_sqlstate, v_sqlerrm;
        END IF;
    END;

    -- ------------------------------------------------------------------------
    -- TEST 21: UNKNOWN-FIELD REJECTION
    -- ------------------------------------------------------------------------
    -- 21a. Unknown top-level field
    BEGIN
        PERFORM pg_temp.atlas_ingest(
            jsonb_build_object(
                'schema_version', '1.0',
                'event_id', 'EVT-UNKNOWN-FLD',
                'event_type', 'OT_DISRUPTION',
                'severity', 'high',
                'observed_at', now()::text,
                'sent_at', now()::text,
                'confidence', 0.90,
                'unauthorized_field', 'injection_attempt',
                'org_id', v_org_a
            )
        );
        RAISE EXCEPTION 'FAIL: Test 21a [Unknown payload field was accepted unexpectedly]';
    EXCEPTION WHEN OTHERS THEN
        GET STACKED DIAGNOSTICS v_sqlstate = RETURNED_SQLSTATE, v_sqlerrm = MESSAGE_TEXT;
        IF v_sqlstate = '22023' AND v_sqlerrm LIKE '%Unknown field in incident payload%' THEN
            RAISE NOTICE 'PASS: Test 21a [Unknown top-level field rejected with SQLSTATE 22023: %]', v_sqlerrm;
        ELSE
            RAISE EXCEPTION 'FAIL: Test 21a [Expected 22023 unknown field error, got % (%)]', v_sqlstate, v_sqlerrm;
        END IF;
    END;

    -- 21b. Unknown signal key
    BEGIN
        PERFORM pg_temp.atlas_ingest(
            jsonb_build_object(
                'schema_version', '1.0',
                'event_id', 'EVT-UNKNOWN-SIG',
                'event_type', 'OT_DISRUPTION',
                'severity', 'high',
                'observed_at', now()::text,
                'sent_at', now()::text,
                'confidence', 0.90,
                'signals', jsonb_build_object('unauthorized_signal_field', 'malformed_data'),
                'org_id', v_org_a
            )
        );
        RAISE EXCEPTION 'FAIL: Test 21b [Unknown signal key was accepted unexpectedly]';
    EXCEPTION WHEN OTHERS THEN
        GET STACKED DIAGNOSTICS v_sqlstate = RETURNED_SQLSTATE, v_sqlerrm = MESSAGE_TEXT;
        IF v_sqlstate = '22023' AND v_sqlerrm LIKE '%Unknown field in signals%' THEN
            RAISE NOTICE 'PASS: Test 21b [Unknown signal key rejected with SQLSTATE 22023: %]', v_sqlerrm;
        ELSE
            RAISE EXCEPTION 'FAIL: Test 21b [Expected 22023 signal key error, got % (%)]', v_sqlstate, v_sqlerrm;
        END IF;
    END;

    -- ------------------------------------------------------------------------
    -- TEST 22: MATCHING RULES IN ORDER & 0.90 THRESHOLD (AUTO VS PROPOSED)
    -- ------------------------------------------------------------------------
    DECLARE
        v_asset_r1 UUID := 'a0000000-8888-0000-0000-000000000001';
        v_asset_r2 UUID := 'a0000000-8888-0000-0000-000000000002';
        v_asset_r3 UUID := 'a0000000-8888-0000-0000-000000000003';
        v_asset_r4 UUID := 'a0000000-8888-0000-0000-000000000004';
        v_asset_r5 UUID := 'a0000000-8888-0000-0000-000000000005';
        v_asset_r6 UUID := 'a0000000-8888-0000-0000-000000000006';
        v_rule_inc_id UUID;
        v_rule_match RECORD;
        v_decision_res JSONB;
        v_ingest_res1 JSONB;
    BEGIN
        -- 1. Create target assets with distinct identifiers
        INSERT INTO public.assets (id, org_id, site_code, name, type, criticality, owner, accuracy_class, identifiers, source, correlation_id)
        VALUES
            (v_asset_r1, v_org_a, 'RULE-SITE-01', 'Rule Site Code Asset', 'site', 4, 'Alpha Ops', 'exact_survey', '{}'::jsonb, 'Test', 'cid-test'),
            (v_asset_r2, v_org_a, 'RULE-HOST-02', 'Rule Exact Host Asset', 'site', 4, 'Alpha Ops', 'exact_survey', '{"hostnames": ["scada-master.grid.internal"]}'::jsonb, 'Test', 'cid-test'),
            (v_asset_r3, v_org_a, 'RULE-IP-03',   'Rule Exact IP Asset',   'site', 4, 'Alpha Ops', 'exact_survey', '{"ip_addresses": ["192.168.10.42"]}'::jsonb, 'Test', 'cid-test'),
            (v_asset_r4, v_org_a, 'RULE-CIDR-04', 'Rule CIDR Asset',       'site', 4, 'Alpha Ops', 'exact_survey', '{"cidrs": ["10.200.0.0/16"]}'::jsonb, 'Test', 'cid-test'),
            (v_asset_r5, v_org_a, 'RULE-CLD-05',  'Rule Cloud Acc Asset',  'cloud_region', 4, 'Alpha Ops', 'exact_survey', '{"cloud_account_ids": ["aws-acc-112233"]}'::jsonb, 'Test', 'cid-test'),
            (v_asset_r6, v_org_a, 'RULE-FUZ-06',  'Rule Fuzzy Host Asset', 'site', 4, 'Alpha Ops', 'exact_survey', '{"hostnames": ["substation-scada-relay-north"]}'::jsonb, 'Test', 'cid-test')
        ON CONFLICT (org_id, id) DO NOTHING;

        -- 2. Ingest telemetry matching all 6 rules
        v_ingest_res1 := pg_temp.atlas_ingest(
            jsonb_build_object(
                'schema_version', '1.0',
                'event_id', 'EVT-RULE-EVAL-001',
                'event_type', 'TELEMETRY_ANOMALY',
                'severity', 'critical',
                'observed_at', now()::text,
                'sent_at', now()::text,
                'confidence', 0.95,
                'signals', jsonb_build_object(
                    'site_codes', jsonb_build_array('RULE-SITE-01'),
                    'hostnames', jsonb_build_array('scada-master.grid.internal', 'substn-scada-relay-nrth'), -- exact + typo for fuzzy
                    'ips', jsonb_build_array('192.168.10.42', '10.200.5.15'), -- exact IP + IP inside CIDR 10.200.0.0/16
                    'cidrs', '[]'::jsonb,
                    'cloud_account_ids', jsonb_build_array('aws-acc-112233')
                ),
                'org_id', v_org_a,
                'source', 'Rule Engine Tester'
            )
        );

        v_rule_inc_id := (v_ingest_res1->>'incident_id')::UUID;

        -- Verify Rule 1: exact_site_code (Score: 1.00 -> auto)
        SELECT * INTO v_rule_match FROM public.asset_matches WHERE incident_id = v_rule_inc_id AND rule_fired = 'exact_site_code';
        IF v_rule_match.score = 1.00 AND v_rule_match.status = 'auto' THEN
            RAISE NOTICE 'PASS: Test 22a [Rule 1 exact_site_code verified: score=1.00, status=auto]';
        ELSE
            RAISE EXCEPTION 'FAIL: Test 22a [exact_site_code mismatch: score=%, status=%]', v_rule_match.score, v_rule_match.status;
        END IF;

        -- Verify Rule 2: exact_hostname (Score: 0.95 -> auto)
        SELECT * INTO v_rule_match FROM public.asset_matches WHERE incident_id = v_rule_inc_id AND rule_fired = 'exact_hostname';
        IF v_rule_match.score = 0.95 AND v_rule_match.status = 'auto' THEN
            RAISE NOTICE 'PASS: Test 22b [Rule 2 exact_hostname verified: score=0.95, status=auto]';
        ELSE
            RAISE EXCEPTION 'FAIL: Test 22b [exact_hostname mismatch: score=%, status=%]', v_rule_match.score, v_rule_match.status;
        END IF;

        -- Verify Rule 3: exact_ip (Score: 0.95 -> auto)
        SELECT * INTO v_rule_match FROM public.asset_matches WHERE incident_id = v_rule_inc_id AND rule_fired = 'exact_ip';
        IF v_rule_match.score = 0.95 AND v_rule_match.status = 'auto' THEN
            RAISE NOTICE 'PASS: Test 22c [Rule 3 exact_ip verified: score=0.95, status=auto]';
        ELSE
            RAISE EXCEPTION 'FAIL: Test 22c [exact_ip mismatch: score=%, status=%]', v_rule_match.score, v_rule_match.status;
        END IF;

        -- Verify Rule 4: cidr_containment (Score: 0.85 -> proposed < 0.90)
        SELECT * INTO v_rule_match FROM public.asset_matches WHERE incident_id = v_rule_inc_id AND rule_fired = 'cidr_containment';
        IF v_rule_match.score = 0.85 AND v_rule_match.status = 'proposed' THEN
            RAISE NOTICE 'PASS: Test 22d [Rule 4 cidr_containment verified: score=0.85, status=proposed (needs confirmation)]';
        ELSE
            RAISE EXCEPTION 'FAIL: Test 22d [cidr_containment mismatch: score=%, status=%]', v_rule_match.score, v_rule_match.status;
        END IF;

        -- Verify Rule 5: cloud_account_id (Score: 0.90 -> auto)
        SELECT * INTO v_rule_match FROM public.asset_matches WHERE incident_id = v_rule_inc_id AND rule_fired = 'cloud_account_id';
        IF v_rule_match.score = 0.90 AND v_rule_match.status = 'auto' THEN
            RAISE NOTICE 'PASS: Test 22e [Rule 5 cloud_account_id verified: score=0.90, status=auto]';
        ELSE
            RAISE EXCEPTION 'FAIL: Test 22e [cloud_account_id mismatch: score=%, status=%]', v_rule_match.score, v_rule_match.status;
        END IF;

        -- Verify Rule 6: fuzzy_hostname (Score < 0.90 -> proposed)
        SELECT * INTO v_rule_match FROM public.asset_matches WHERE incident_id = v_rule_inc_id AND rule_fired = 'fuzzy_hostname';
        IF v_rule_match.status = 'proposed' AND v_rule_match.score < 0.90 THEN
            RAISE NOTICE 'PASS: Test 22f [Rule 6 fuzzy_hostname verified: score=%, status=proposed]', v_rule_match.score;
        ELSE
            RAISE EXCEPTION 'FAIL: Test 22f [fuzzy_hostname mismatch: score=%, status=%]', v_rule_match.score, v_rule_match.status;
        END IF;

        -- 3. Analyst Confirms the Proposed CIDR Match -> Labelled Data Stored
        SELECT * INTO v_rule_match FROM public.asset_matches WHERE incident_id = v_rule_inc_id AND rule_fired = 'cidr_containment';
        v_decision_res := public.confirm_asset_match(v_rule_match.id);
        IF (v_decision_res->>'success')::boolean = true AND (v_decision_res->>'status') = 'confirmed' THEN
            RAISE NOTICE 'PASS: Test 22g [Analyst confirmed proposal: status updated to confirmed in database]';
        ELSE
            RAISE EXCEPTION 'FAIL: Test 22g [confirm_asset_match failed: %]', v_decision_res;
        END IF;

        -- 4. Analyst Rejects the Proposed Fuzzy Match -> Labelled Data Stored
        SELECT * INTO v_rule_match FROM public.asset_matches WHERE incident_id = v_rule_inc_id AND rule_fired = 'fuzzy_hostname';
        v_decision_res := public.reject_asset_match(v_rule_match.id, 'Spurious fuzzy string similarity');
        IF (v_decision_res->>'success')::boolean = true AND (v_decision_res->>'status') = 'rejected' THEN
            RAISE NOTICE 'PASS: Test 22h [Analyst rejected proposal: status updated to rejected in database with reason]';
        ELSE
            RAISE EXCEPTION 'FAIL: Test 22h [reject_asset_match failed: %]', v_decision_res;
        END IF;
    END;

    -- ------------------------------------------------------------------------
    -- TEST 23: STAGE 5 EVIDENCE CUSTODY & CROSS-TENANT ISOLATION
    -- ------------------------------------------------------------------------
    DECLARE
        v_ev_res JSONB;
        v_evidence_id UUID;
        v_custody_res JSONB;
        v_test_sha256 TEXT := 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'; -- NIST vector 'abc'
        v_tampered_sha256 TEXT := 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ae'; -- 1 bit altered
        v_ev_count INT;
        v_timeline_count INT;
    BEGIN
        -- 1. Admin A registers genuine evidence in Org A
        SET LOCAL ROLE authenticated;
        EXECUTE format('SET LOCAL request.jwt.claims = ''{"sub": "%s", "role": "authenticated", "aal": "aal2"}''', v_admin_a);

        v_ev_res := public.record_evidence(
            v_org_a,
            'INCIDENT',
            v_inc_a,
            'scada_pcap_capture_20261109.pcap',
            v_org_a::text || '/1700000000_scada_pcap_capture_20261109.pcap',
            1048576,
            'application/vnd.tcpdump.pcap',
            v_test_sha256
        );

        IF (v_ev_res->>'success')::boolean = true THEN
            v_evidence_id := (v_ev_res->>'evidence_id')::UUID;
            RAISE NOTICE 'PASS: Test 23a [record_evidence registered evidence and initial INTAKE custody event]';
        ELSE
            RAISE EXCEPTION 'FAIL: Test 23a [record_evidence failed: %]', v_ev_res;
        END IF;

        -- 2. Positive Control: User A can read own evidence and custody events
        SELECT COUNT(*) INTO v_ev_count FROM public.evidence WHERE id = v_evidence_id;
        IF v_ev_count = 1 THEN
            RAISE NOTICE 'PASS: Test 23b [User A reads own evidence row (count=1)]';
        ELSE
            RAISE EXCEPTION 'FAIL: Test 23b [User A could not read registered evidence row, count=%]', v_ev_count;
        END IF;

        SELECT COUNT(*) INTO v_ev_count FROM public.custody_events WHERE evidence_id = v_evidence_id;
        IF v_ev_count = 1 THEN
            RAISE NOTICE 'PASS: Test 23c [User A reads initial INTAKE custody event]';
        ELSE
            RAISE EXCEPTION 'FAIL: Test 23c [Initial custody event missing, count=%]', v_ev_count;
        END IF;

        -- 3. Switch to User B in Org B: Zero cross-tenant evidence reads
        EXECUTE format('SET LOCAL request.jwt.claims = ''{"sub": "%s", "role": "authenticated", "aal": "aal2"}''', v_admin_b);

        SELECT COUNT(*) INTO v_ev_count FROM public.evidence WHERE id = v_evidence_id;
        IF v_ev_count = 0 THEN
            RAISE NOTICE 'PASS: Test 23d [Zero cross-tenant read on evidence table for Org B]';
        ELSE
            RAISE EXCEPTION 'FAIL: Test 23d [Cross-tenant leak: User B read % evidence rows of Org A]', v_ev_count;
        END IF;

        SELECT COUNT(*) INTO v_ev_count FROM public.custody_events WHERE evidence_id = v_evidence_id;
        IF v_ev_count = 0 THEN
            RAISE NOTICE 'PASS: Test 23e [Zero cross-tenant read on custody_events table for Org B]';
        ELSE
            RAISE EXCEPTION 'FAIL: Test 23e [Cross-tenant leak: User B read % custody events of Org A]', v_ev_count;
        END IF;

        -- 4. Cross-tenant evidence write denial (User B attempts to record evidence into Org A)
        BEGIN
            PERFORM public.record_evidence(
                v_org_a,
                'INCIDENT',
                v_inc_a,
                'unauthorized_cross_tenant.log',
                v_org_a::text || '/bad.log',
                1024,
                'text/plain',
                v_test_sha256
            );
            RAISE EXCEPTION 'FAIL: Test 23f [Cross-tenant record_evidence succeeded unexpectedly]';
        EXCEPTION WHEN OTHERS THEN
            GET STACKED DIAGNOSTICS v_sqlstate = RETURNED_SQLSTATE, v_sqlerrm = MESSAGE_TEXT;
            IF v_sqlstate = '42501' THEN
                RAISE NOTICE 'PASS: Test 23f [Cross-tenant record_evidence rejected with SQLSTATE 42501: %]', v_sqlerrm;
            ELSE
                RAISE EXCEPTION 'FAIL: Test 23f [Expected SQLSTATE 42501, got % (%)]', v_sqlstate, v_sqlerrm;
            END IF;
        END;

        -- 5. Cross-tenant custody event logging denial (User B attempts to append custody log to Org A's evidence)
        BEGIN
            PERFORM public.record_custody_event(
                v_evidence_id,
                'VERIFY_HASH',
                v_test_sha256
            );
            RAISE EXCEPTION 'FAIL: Test 23g [Cross-tenant record_custody_event succeeded unexpectedly]';
        EXCEPTION WHEN OTHERS THEN
            GET STACKED DIAGNOSTICS v_sqlstate = RETURNED_SQLSTATE, v_sqlerrm = MESSAGE_TEXT;
            IF v_sqlstate = '02000' THEN
                RAISE NOTICE 'PASS: Test 23g [Cross-tenant record_custody_event rejected with SQLSTATE 02000: %]', v_sqlerrm;
            ELSE
                RAISE EXCEPTION 'FAIL: Test 23g [Expected SQLSTATE 02000, got % (%)]', v_sqlstate, v_sqlerrm;
            END IF;
        END;

        -- --------------------------------------------------------------------
        -- TEST 24: STAGE 5 TAMPER DETECTION & TIMELINE AUDIT AGGREGATION
        -- --------------------------------------------------------------------
        -- Switch back to User A
        EXECUTE format('SET LOCAL request.jwt.claims = ''{"sub": "%s", "role": "authenticated", "aal": "aal2"}''', v_admin_a);

        -- 24a. Legitimate re-hash verification -> is_intact = true
        v_custody_res := public.record_custody_event(
            v_evidence_id,
            'VERIFY_HASH',
            v_test_sha256,
            '{"verified_by": "analyst_workstation"}'::jsonb
        );

        IF (v_custody_res->>'is_intact')::boolean = true THEN
            RAISE NOTICE 'PASS: Test 24a [Intact custody verification confirmed matching SHA-256]';
        ELSE
            RAISE EXCEPTION 'FAIL: Test 24a [Legitimate hash verification reported mismatch: %]', v_custody_res;
        END IF;

        -- 24b. Tampered re-hash verification -> is_intact = false
        v_custody_res := public.record_custody_event(
            v_evidence_id,
            'VERIFY_HASH',
            v_tampered_sha256,
            '{"verified_by": "automated_integrity_scanner"}'::jsonb
        );

        IF (v_custody_res->>'is_intact')::boolean = false THEN
            RAISE NOTICE 'PASS: Test 24b [Tamper detection successfully detected altered SHA-256 digest]';
        ELSE
            RAISE EXCEPTION 'FAIL: Test 24b [Tamper detection failed to detect altered hash: %]', v_custody_res;
        END IF;

        -- 24c. Incident Timeline Read via get_incident_timeline()
        SELECT COUNT(*) INTO v_timeline_count
        FROM public.get_incident_timeline(v_inc_a);

        IF v_timeline_count >= 1 THEN
            RAISE NOTICE 'PASS: Test 24c [get_incident_timeline returned % chronological audit events for incident]', v_timeline_count;
        ELSE
            RAISE EXCEPTION 'FAIL: Test 24c [get_incident_timeline returned 0 events for valid incident]';
        END IF;

        -- 24d. Cross-tenant get_incident_timeline denial
        EXECUTE format('SET LOCAL request.jwt.claims = ''{"sub": "%s", "role": "authenticated", "aal": "aal2"}''', v_admin_b);

        BEGIN
            PERFORM * FROM public.get_incident_timeline(v_inc_a);
            RAISE EXCEPTION 'FAIL: Test 24d [Cross-tenant get_incident_timeline succeeded unexpectedly]';
        EXCEPTION WHEN OTHERS THEN
            GET STACKED DIAGNOSTICS v_sqlstate = RETURNED_SQLSTATE, v_sqlerrm = MESSAGE_TEXT;
            IF v_sqlstate = '42501' THEN
                RAISE NOTICE 'PASS: Test 24d [Cross-tenant get_incident_timeline rejected with SQLSTATE 42501: %]', v_sqlerrm;
            ELSE
                RAISE EXCEPTION 'FAIL: Test 24d [Expected SQLSTATE 42501, got % (%)]', v_sqlstate, v_sqlerrm;
            END IF;
        END;
    END;

    -- ------------------------------------------------------------------------
    -- TEST 25: HARDENING CHECKS ADDED AFTER DELIBERATE-BREAK REVIEW
    -- (each one targets a break the suite originally failed to detect)
    -- ------------------------------------------------------------------------
    RESET ROLE;

    -- 25a. Every ordinary table in public has RLS enabled AND forced
    DECLARE
        v_bad TEXT;
    BEGIN
        SELECT string_agg(c.relname, ', ') INTO v_bad
        FROM pg_class c
        WHERE c.relnamespace = 'public'::regnamespace
          AND c.relkind IN ('r', 'p')
          AND NOT (c.relrowsecurity AND c.relforcerowsecurity)
          AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.objid = c.oid AND d.deptype = 'e'); -- skip extension-owned (e.g. spatial_ref_sys)
        IF v_bad IS NULL THEN
            RAISE NOTICE 'PASS: Test 25a [RLS is enabled and forced on every public table]';
        ELSE
            RAISE EXCEPTION 'FAIL: Test 25a [RLS not enabled+forced on: %]', v_bad;
        END IF;
    END;

    -- 25b. Composite FK also blocks a cross-tenant FROM asset
    BEGIN
        INSERT INTO public.dependency_edges (
            org_id, from_asset_id, to_asset_id, relation_type, criticality, source, correlation_id
        ) VALUES (
            v_org_a, v_asset_b1, v_asset_a1, 'powers', 5, 'Security Test', 'cid-fk-test-from'
        );
        RAISE EXCEPTION 'FAIL: Test 25b [Composite FK accepted a cross-tenant from_asset]';
    EXCEPTION WHEN OTHERS THEN
        GET STACKED DIAGNOSTICS v_sqlstate = RETURNED_SQLSTATE, v_sqlerrm = MESSAGE_TEXT;
        IF v_sqlstate = '23503' THEN
            RAISE NOTICE 'PASS: Test 25b [Cross-tenant from_asset rejected with SQLSTATE 23503]';
        ELSE
            RAISE EXCEPTION 'FAIL: Test 25b [Expected 23503, got % (%)]', v_sqlstate, v_sqlerrm;
        END IF;
    END;

    -- 25c. TRUNCATE of the audit ledger is blocked by trigger, even for the superuser
    BEGIN
        TRUNCATE public.audit_events;
        RAISE EXCEPTION 'FAIL: Test 25c [TRUNCATE audit_events succeeded]';
    EXCEPTION WHEN OTHERS THEN
        GET STACKED DIAGNOSTICS v_sqlstate = RETURNED_SQLSTATE, v_sqlerrm = MESSAGE_TEXT;
        IF v_sqlstate = '55000' THEN
            RAISE NOTICE 'PASS: Test 25c [TRUNCATE audit_events blocked with SQLSTATE 55000]';
        ELSE
            RAISE EXCEPTION 'FAIL: Test 25c [Expected 55000, got % (%)]', v_sqlstate, v_sqlerrm;
        END IF;
    END;

    -- ------------------------------------------------------------------------
    -- TEST 26: log_event() HARDENING (migration 010)
    -- ------------------------------------------------------------------------
    DECLARE
        v_log_id UUID;
        v_actor_ok BOOLEAN;
    BEGIN
        SET LOCAL ROLE authenticated;

        -- 26a. aal1 session is refused
        EXECUTE format('SET LOCAL request.jwt.claims = ''{"sub": "%s", "role": "authenticated", "aal": "aal1"}''', v_admin_a);
        BEGIN
            PERFORM public.log_event(v_org_a, 'VIEW', 'incidents', 'x', 'cid-26a', '{}'::jsonb);
            RAISE EXCEPTION 'FAIL: Test 26a [log_event accepted an aal1 session]';
        EXCEPTION WHEN OTHERS THEN
            GET STACKED DIAGNOSTICS v_sqlstate = RETURNED_SQLSTATE, v_sqlerrm = MESSAGE_TEXT;
            IF v_sqlstate = '42501' THEN
                RAISE NOTICE 'PASS: Test 26a [log_event rejects aal1 with SQLSTATE 42501]';
            ELSE
                RAISE EXCEPTION 'FAIL: Test 26a [Expected 42501, got % (%)]', v_sqlstate, v_sqlerrm;
            END IF;
        END;

        EXECUTE format('SET LOCAL request.jwt.claims = ''{"sub": "%s", "role": "authenticated", "aal": "aal2"}''', v_admin_a);

        -- 26b. Action that imitates a system event is refused
        BEGIN
            PERFORM public.log_event(v_org_a, 'incidents_INSERT', 'incidents', 'x', 'cid-26b', '{}'::jsonb);
            RAISE EXCEPTION 'FAIL: Test 26b [log_event accepted a forged system action]';
        EXCEPTION WHEN OTHERS THEN
            GET STACKED DIAGNOSTICS v_sqlstate = RETURNED_SQLSTATE, v_sqlerrm = MESSAGE_TEXT;
            IF v_sqlstate = '22023' THEN
                RAISE NOTICE 'PASS: Test 26b [log_event rejects non-allowlisted action with SQLSTATE 22023]';
            ELSE
                RAISE EXCEPTION 'FAIL: Test 26b [Expected 22023, got % (%)]', v_sqlstate, v_sqlerrm;
            END IF;
        END;

        -- 26c. Positive control: allowed action by a member succeeds and records the caller as actor
        v_log_id := public.log_event(v_org_a, 'VIEW', 'incidents', 'x', 'cid-26c', '{}'::jsonb);
        RESET ROLE;
        SELECT (actor_id = v_admin_a AND action = 'VIEW') INTO v_actor_ok FROM public.audit_events WHERE id = v_log_id;
        IF COALESCE(v_actor_ok, false) THEN
            RAISE NOTICE 'PASS: Test 26c [Allowed log_event written with actor taken from auth.uid()]';
        ELSE
            RAISE EXCEPTION 'FAIL: Test 26c [Allowed log_event not recorded correctly]';
        END IF;

        -- 26d. Non-member of the target organisation is refused
        SET LOCAL ROLE authenticated;
        EXECUTE format('SET LOCAL request.jwt.claims = ''{"sub": "%s", "role": "authenticated", "aal": "aal2"}''', v_admin_b);
        BEGIN
            PERFORM public.log_event(v_org_a, 'VIEW', 'incidents', 'x', 'cid-26d', '{}'::jsonb);
            RAISE EXCEPTION 'FAIL: Test 26d [Cross-tenant log_event succeeded]';
        EXCEPTION WHEN OTHERS THEN
            GET STACKED DIAGNOSTICS v_sqlstate = RETURNED_SQLSTATE, v_sqlerrm = MESSAGE_TEXT;
            IF v_sqlstate = '42501' THEN
                RAISE NOTICE 'PASS: Test 26d [Cross-tenant log_event rejected with SQLSTATE 42501]';
            ELSE
                RAISE EXCEPTION 'FAIL: Test 26d [Expected 42501, got % (%)]', v_sqlstate, v_sqlerrm;
            END IF;
        END;
        RESET ROLE;
    END;

    -- ------------------------------------------------------------------------
    -- TEST 27: record_evidence() VALIDATION (migration 011)
    -- ------------------------------------------------------------------------
    DECLARE
        v_ev JSONB;
    BEGIN
        SET LOCAL ROLE authenticated;
        EXECUTE format('SET LOCAL request.jwt.claims = ''{"sub": "%s", "role": "authenticated", "aal": "aal2"}''', v_analyst_a);

        -- 27a. Positive control: valid registration inside own folder, own incident
        v_ev := public.record_evidence(v_org_a, 'INCIDENT', v_inc_a, 'ok.txt',
                    v_org_a::text || '/1700000000_ok.txt', 10, 'text/plain', repeat('a', 64));
        IF (v_ev->>'evidence_id') IS NOT NULL THEN
            RAISE NOTICE 'PASS: Test 27a [Valid evidence registration succeeds]';
        ELSE
            RAISE EXCEPTION 'FAIL: Test 27a [Valid registration returned %]', v_ev;
        END IF;

        -- 27b. Storage path in another organisation's folder is refused
        BEGIN
            PERFORM public.record_evidence(v_org_a, 'INCIDENT', v_inc_a, 'x.txt',
                        v_org_b::text || '/1700000000_x.txt', 10, 'text/plain', repeat('b', 64));
            RAISE EXCEPTION 'FAIL: Test 27b [Evidence accepted a foreign storage path]';
        EXCEPTION WHEN OTHERS THEN
            GET STACKED DIAGNOSTICS v_sqlstate = RETURNED_SQLSTATE, v_sqlerrm = MESSAGE_TEXT;
            IF v_sqlstate = '22023' THEN
                RAISE NOTICE 'PASS: Test 27b [Foreign storage path rejected with SQLSTATE 22023]';
            ELSE
                RAISE EXCEPTION 'FAIL: Test 27b [Expected 22023, got % (%)]', v_sqlstate, v_sqlerrm;
            END IF;
        END;

        -- 27c. Target incident belonging to another organisation is refused
        BEGIN
            PERFORM public.record_evidence(v_org_a, 'INCIDENT', v_inc_b, 'y.txt',
                        v_org_a::text || '/1700000001_y.txt', 10, 'text/plain', repeat('c', 64));
            RAISE EXCEPTION 'FAIL: Test 27c [Evidence accepted another organisation''s incident]';
        EXCEPTION WHEN OTHERS THEN
            GET STACKED DIAGNOSTICS v_sqlstate = RETURNED_SQLSTATE, v_sqlerrm = MESSAGE_TEXT;
            IF v_sqlstate = '22023' THEN
                RAISE NOTICE 'PASS: Test 27c [Cross-tenant evidence target rejected with SQLSTATE 22023]';
            ELSE
                RAISE EXCEPTION 'FAIL: Test 27c [Expected 22023, got % (%)]', v_sqlstate, v_sqlerrm;
            END IF;
        END;

        -- 27d. Unknown target type is refused
        BEGIN
            PERFORM public.record_evidence(v_org_a, 'SOMETHING', v_inc_a, 'z.txt',
                        v_org_a::text || '/1700000002_z.txt', 10, 'text/plain', repeat('d', 64));
            RAISE EXCEPTION 'FAIL: Test 27d [Evidence accepted an unknown target type]';
        EXCEPTION WHEN OTHERS THEN
            GET STACKED DIAGNOSTICS v_sqlstate = RETURNED_SQLSTATE, v_sqlerrm = MESSAGE_TEXT;
            IF v_sqlstate = '22023' THEN
                RAISE NOTICE 'PASS: Test 27d [Unknown evidence target type rejected with SQLSTATE 22023]';
            ELSE
                RAISE EXCEPTION 'FAIL: Test 27d [Expected 22023, got % (%)]', v_sqlstate, v_sqlerrm;
            END IF;
        END;
        RESET ROLE;
    END;

    -- ------------------------------------------------------------------------
    -- TEST 28: STORAGE CLEANUP RULE (migration 012)
    -- ------------------------------------------------------------------------
    DECLARE
        v_del INT;
    BEGIN
        RESET ROLE;
        INSERT INTO storage.objects (bucket_id, name, owner_id, created_at) VALUES
            ('evidence', v_org_a::text || '/1700000100_unreg.txt',  v_analyst_a::text, now()),
            ('evidence', v_org_a::text || '/1700000000_ok.txt',     v_analyst_a::text, now()),   -- registered in test 27a
            ('evidence', v_org_a::text || '/1700000200_other.txt',  v_admin_a::text,   now()),
            ('evidence', v_org_a::text || '/1700000300_old.txt',    v_analyst_a::text, now() - interval '1 hour'),
            ('evidence', v_org_b::text || '/1700000400_foreign.txt', v_analyst_a::text, now());

        -- The Storage API sets this flag when it deletes objects; without it Supabase refuses any SQL delete.
        -- Setting it here lets the test exercise OUR policy, which is what decides which rows may go.
        PERFORM set_config('storage.allow_delete_query', 'true', true);

        SET LOCAL ROLE authenticated;
        EXECUTE format('SET LOCAL request.jwt.claims = ''{"sub": "%s", "role": "authenticated", "aal": "aal2"}''', v_analyst_a);

        -- 28a. Positive control: own, recent, unregistered object can be removed
        DELETE FROM storage.objects WHERE name = v_org_a::text || '/1700000100_unreg.txt';
        GET DIAGNOSTICS v_del = ROW_COUNT;
        IF v_del = 1 THEN RAISE NOTICE 'PASS: Test 28a [Unregistered own upload can be removed]';
        ELSE RAISE EXCEPTION 'FAIL: Test 28a [Expected 1 row deleted, got %]', v_del; END IF;

        -- 28b. Registered evidence file cannot be removed
        DELETE FROM storage.objects WHERE name = v_org_a::text || '/1700000000_ok.txt';
        GET DIAGNOSTICS v_del = ROW_COUNT;
        IF v_del = 0 THEN RAISE NOTICE 'PASS: Test 28b [Registered evidence object cannot be removed]';
        ELSE RAISE EXCEPTION 'FAIL: Test 28b [Registered evidence object was deleted (% rows)]', v_del; END IF;

        -- 28c. Another user's upload cannot be removed
        DELETE FROM storage.objects WHERE name = v_org_a::text || '/1700000200_other.txt';
        GET DIAGNOSTICS v_del = ROW_COUNT;
        IF v_del = 0 THEN RAISE NOTICE 'PASS: Test 28c [Another user''s upload cannot be removed]';
        ELSE RAISE EXCEPTION 'FAIL: Test 28c [Deleted another user''s object (% rows)]', v_del; END IF;

        -- 28d. An old object (older than 15 minutes) cannot be removed
        DELETE FROM storage.objects WHERE name = v_org_a::text || '/1700000300_old.txt';
        GET DIAGNOSTICS v_del = ROW_COUNT;
        IF v_del = 0 THEN RAISE NOTICE 'PASS: Test 28d [Object older than 15 minutes cannot be removed]';
        ELSE RAISE EXCEPTION 'FAIL: Test 28d [Deleted an old object (% rows)]', v_del; END IF;

        -- 28e. Another organisation's folder cannot be touched
        DELETE FROM storage.objects WHERE name = v_org_b::text || '/1700000400_foreign.txt';
        GET DIAGNOSTICS v_del = ROW_COUNT;
        IF v_del = 0 THEN RAISE NOTICE 'PASS: Test 28e [Other organisation''s folder cannot be touched]';
        ELSE RAISE EXCEPTION 'FAIL: Test 28e [Deleted a cross-tenant object (% rows)]', v_del; END IF;

        -- 28f. aal1 session cannot delete even an eligible object
        RESET ROLE;
        INSERT INTO storage.objects (bucket_id, name, owner_id, created_at)
            VALUES ('evidence', v_org_a::text || '/1700000500_aal1.txt', v_analyst_a::text, now());
        SET LOCAL ROLE authenticated;
        EXECUTE format('SET LOCAL request.jwt.claims = ''{"sub": "%s", "role": "authenticated", "aal": "aal1"}''', v_analyst_a);
        DELETE FROM storage.objects WHERE name = v_org_a::text || '/1700000500_aal1.txt';
        GET DIAGNOSTICS v_del = ROW_COUNT;
        IF v_del = 0 THEN RAISE NOTICE 'PASS: Test 28f [aal1 session cannot delete storage objects]';
        ELSE RAISE EXCEPTION 'FAIL: Test 28f [aal1 session deleted an object (% rows)]', v_del; END IF;
        RESET ROLE;
    END;

    -- ------------------------------------------------------------------------
    -- TEST 29: SIGNED INCIDENT INTAKE (migration 013)
    -- ------------------------------------------------------------------------
    DECLARE
        v_base JSONB;
        v_k_main TEXT := current_setting('atlas_test.key_id');
        v_s_main TEXT := current_setting('atlas_test.secret');
        v_now_txt TEXT := to_char(now() AT TIME ZONE 'utc', 'YYYY-MM-DD"T"HH24:MI:SS"Z"');
        v_res JSONB;
        v_k2 JSONB;
        v_kb JSONB;
        v_leak INT;
        v_ss TEXT;
        v_expected_ss TEXT := E'atlas-ingest-v1\norg_id="a0000000-0000-0000-0000-000000000001"\nkey_id="k_test0001"\nschema_version="1.0"\nevent_id="EVT-VEC-001"\nevent_type="RANSOMWARE"\nseverity="high"\nobserved_at="2026-01-01T00:00:00Z"\nsent_at="2026-01-01T00:00:05Z"\nconfidence=0.9\ncorrelation_id="cid-vec"\nsource=""\nsite_codes=[]\nhostnames=["a.example.test","b.example.test"]\nips=["10.0.0.1"]\ncidrs=[]\ncloud_account_ids=[]';
    BEGIN
        RESET ROLE;
        v_base := jsonb_build_object(
            'schema_version', '1.0', 'event_type', 'RANSOMWARE', 'severity', 'high',
            'observed_at', v_now_txt, 'sent_at', v_now_txt, 'org_id', v_org_a,
            'signals', jsonb_build_object('hostnames', jsonb_build_array('sig-test.example.test')));

        -- 29a. Reference vector: signing string and HMAC match values computed independently (Python)
        v_ss := public.ingest_signing_string('a0000000-0000-0000-0000-000000000001'::uuid, jsonb_build_object(
            'key_id', 'k_test0001', 'schema_version', '1.0', 'event_id', 'EVT-VEC-001', 'event_type', 'RANSOMWARE',
            'severity', 'high', 'observed_at', '2026-01-01T00:00:00Z', 'sent_at', '2026-01-01T00:00:05Z',
            'confidence', 0.9, 'correlation_id', 'cid-vec',
            'signals', jsonb_build_object('hostnames', jsonb_build_array('b.example.test', 'a.example.test'), 'ips', jsonb_build_array('10.0.0.1'))));
        IF v_ss = v_expected_ss
           AND encode(extensions.hmac(v_ss, 'test-secret-0123456789abcdef', 'sha256'), 'hex') = '611621ffcbeafcf64cb6f5bf36523a27cd4a1564462a4e31f90bf08a99123c60' THEN
            RAISE NOTICE 'PASS: Test 29a [Signing string and HMAC match the independent reference vector]';
        ELSE
            RAISE EXCEPTION 'FAIL: Test 29a [Reference vector mismatch: %]', v_ss;
        END IF;

        SET LOCAL ROLE authenticated;
        EXECUTE format('SET LOCAL request.jwt.claims = ''{"sub": "%s", "role": "authenticated", "aal": "aal2"}''', v_admin_a);

        -- 29b. Positive control: correctly signed message is accepted
        v_res := public.ingest_incident(pg_temp.atlas_sign_with(v_org_a, v_base || '{"event_id":"EVT-SIG-OK"}'::jsonb, v_k_main, v_s_main));
        IF (v_res->>'success')::boolean THEN RAISE NOTICE 'PASS: Test 29b [Correctly signed message accepted]';
        ELSE RAISE EXCEPTION 'FAIL: Test 29b [Signed message not accepted: %]', v_res; END IF;

        -- 29c. Unsigned message refused
        BEGIN
            PERFORM public.ingest_incident(v_base || '{"event_id":"EVT-SIG-UNSIGNED"}'::jsonb);
            RAISE EXCEPTION 'FAIL: Test 29c [Unsigned message accepted]';
        EXCEPTION WHEN OTHERS THEN
            GET STACKED DIAGNOSTICS v_sqlstate = RETURNED_SQLSTATE, v_sqlerrm = MESSAGE_TEXT;
            IF v_sqlstate = '42501' THEN RAISE NOTICE 'PASS: Test 29c [Unsigned message refused with SQLSTATE 42501]';
            ELSE RAISE EXCEPTION 'FAIL: Test 29c [Expected 42501, got % (%)]', v_sqlstate, v_sqlerrm; END IF;
        END;

        -- 29d. Message changed after signing (severity) refused
        BEGIN
            PERFORM public.ingest_incident(
                pg_temp.atlas_sign_with(v_org_a, v_base || '{"event_id":"EVT-SIG-T1"}'::jsonb, v_k_main, v_s_main) || '{"severity":"low"}'::jsonb);
            RAISE EXCEPTION 'FAIL: Test 29d [Tampered severity accepted]';
        EXCEPTION WHEN OTHERS THEN
            GET STACKED DIAGNOSTICS v_sqlstate = RETURNED_SQLSTATE, v_sqlerrm = MESSAGE_TEXT;
            IF v_sqlstate = '42501' THEN RAISE NOTICE 'PASS: Test 29d [Tampered severity refused with SQLSTATE 42501]';
            ELSE RAISE EXCEPTION 'FAIL: Test 29d [Expected 42501, got % (%)]', v_sqlstate, v_sqlerrm; END IF;
        END;

        -- 29e. Extra signal added after signing refused
        BEGIN
            PERFORM public.ingest_incident(
                pg_temp.atlas_sign_with(v_org_a, v_base || '{"event_id":"EVT-SIG-T2"}'::jsonb, v_k_main, v_s_main)
                || jsonb_build_object('signals', jsonb_build_object('hostnames', jsonb_build_array('sig-test.example.test', 'extra.example.test'))));
            RAISE EXCEPTION 'FAIL: Test 29e [Tampered signals accepted]';
        EXCEPTION WHEN OTHERS THEN
            GET STACKED DIAGNOSTICS v_sqlstate = RETURNED_SQLSTATE, v_sqlerrm = MESSAGE_TEXT;
            IF v_sqlstate = '42501' THEN RAISE NOTICE 'PASS: Test 29e [Tampered signals refused with SQLSTATE 42501]';
            ELSE RAISE EXCEPTION 'FAIL: Test 29e [Expected 42501, got % (%)]', v_sqlstate, v_sqlerrm; END IF;
        END;

        -- 29f. Signed with the wrong secret refused
        BEGIN
            PERFORM public.ingest_incident(
                pg_temp.atlas_sign_with(v_org_a, v_base || '{"event_id":"EVT-SIG-WS"}'::jsonb, v_k_main, 'not-the-real-secret-not-the-real-secret'));
            RAISE EXCEPTION 'FAIL: Test 29f [Wrong-secret signature accepted]';
        EXCEPTION WHEN OTHERS THEN
            GET STACKED DIAGNOSTICS v_sqlstate = RETURNED_SQLSTATE, v_sqlerrm = MESSAGE_TEXT;
            IF v_sqlstate = '42501' THEN RAISE NOTICE 'PASS: Test 29f [Wrong secret refused with SQLSTATE 42501]';
            ELSE RAISE EXCEPTION 'FAIL: Test 29f [Expected 42501, got % (%)]', v_sqlstate, v_sqlerrm; END IF;
        END;

        -- 29g. Another organisation's key cannot sign for this organisation
        EXECUTE format('SET LOCAL request.jwt.claims = ''{"sub": "%s", "role": "authenticated", "aal": "aal2"}''', v_admin_b);
        v_kb := public.create_ingest_key(v_org_b);
        EXECUTE format('SET LOCAL request.jwt.claims = ''{"sub": "%s", "role": "authenticated", "aal": "aal2"}''', v_admin_a);
        BEGIN
            PERFORM public.ingest_incident(
                pg_temp.atlas_sign_with(v_org_a, v_base || '{"event_id":"EVT-SIG-XORG"}'::jsonb, v_kb->>'key_id', v_kb->>'secret'));
            RAISE EXCEPTION 'FAIL: Test 29g [Other organisation''s key accepted]';
        EXCEPTION WHEN OTHERS THEN
            GET STACKED DIAGNOSTICS v_sqlstate = RETURNED_SQLSTATE, v_sqlerrm = MESSAGE_TEXT;
            IF v_sqlstate = '42501' THEN RAISE NOTICE 'PASS: Test 29g [Cross-organisation key refused with SQLSTATE 42501]';
            ELSE RAISE EXCEPTION 'FAIL: Test 29g [Expected 42501, got % (%)]', v_sqlstate, v_sqlerrm; END IF;
        END;

        -- 29h. A revoked key stops working (positive control first: the new key works)
        v_k2 := public.create_ingest_key(v_org_a);
        v_res := public.ingest_incident(pg_temp.atlas_sign_with(v_org_a, v_base || '{"event_id":"EVT-SIG-K2A"}'::jsonb, v_k2->>'key_id', v_k2->>'secret'));
        IF NOT (v_res->>'success')::boolean THEN RAISE EXCEPTION 'FAIL: Test 29h [New key did not work: %]', v_res; END IF;
        PERFORM public.revoke_ingest_key(v_org_a, v_k2->>'key_id');
        BEGIN
            PERFORM public.ingest_incident(pg_temp.atlas_sign_with(v_org_a, v_base || '{"event_id":"EVT-SIG-K2B"}'::jsonb, v_k2->>'key_id', v_k2->>'secret'));
            RAISE EXCEPTION 'FAIL: Test 29h [Revoked key accepted]';
        EXCEPTION WHEN OTHERS THEN
            GET STACKED DIAGNOSTICS v_sqlstate = RETURNED_SQLSTATE, v_sqlerrm = MESSAGE_TEXT;
            IF v_sqlstate = '42501' THEN RAISE NOTICE 'PASS: Test 29h [Revoked key refused with SQLSTATE 42501]';
            ELSE RAISE EXCEPTION 'FAIL: Test 29h [Expected 42501, got % (%)]', v_sqlstate, v_sqlerrm; END IF;
        END;

        -- 29i. An analyst cannot create or revoke keys
        EXECUTE format('SET LOCAL request.jwt.claims = ''{"sub": "%s", "role": "authenticated", "aal": "aal2"}''', v_analyst_a);
        BEGIN
            PERFORM public.create_ingest_key(v_org_a);
            RAISE EXCEPTION 'FAIL: Test 29i [Analyst created an ingest key]';
        EXCEPTION WHEN OTHERS THEN
            GET STACKED DIAGNOSTICS v_sqlstate = RETURNED_SQLSTATE, v_sqlerrm = MESSAGE_TEXT;
            IF v_sqlstate = '42501' THEN RAISE NOTICE 'PASS: Test 29i [Analyst cannot create keys (42501)]';
            ELSE RAISE EXCEPTION 'FAIL: Test 29i [Expected 42501, got % (%)]', v_sqlstate, v_sqlerrm; END IF;
        END;
        BEGIN
            PERFORM public.revoke_ingest_key(v_org_a, v_k_main);
            RAISE EXCEPTION 'FAIL: Test 29i2 [Analyst revoked an ingest key]';
        EXCEPTION WHEN OTHERS THEN
            GET STACKED DIAGNOSTICS v_sqlstate = RETURNED_SQLSTATE, v_sqlerrm = MESSAGE_TEXT;
            IF v_sqlstate = '42501' THEN RAISE NOTICE 'PASS: Test 29i2 [Analyst cannot revoke keys (42501)]';
            ELSE RAISE EXCEPTION 'FAIL: Test 29i2 [Expected 42501, got % (%)]', v_sqlstate, v_sqlerrm; END IF;
        END;

        -- 29j. No client role can read the secrets table
        BEGIN
            PERFORM * FROM public.ingest_keys;
            RAISE EXCEPTION 'FAIL: Test 29j [authenticated could read ingest_keys]';
        EXCEPTION WHEN OTHERS THEN
            GET STACKED DIAGNOSTICS v_sqlstate = RETURNED_SQLSTATE, v_sqlerrm = MESSAGE_TEXT;
            IF v_sqlstate = '42501' THEN RAISE NOTICE 'PASS: Test 29j [ingest_keys unreadable by clients (42501)]';
            ELSE RAISE EXCEPTION 'FAIL: Test 29j [Expected 42501, got % (%)]', v_sqlstate, v_sqlerrm; END IF;
        END;

        -- 29k. aal1 session cannot create a key
        EXECUTE format('SET LOCAL request.jwt.claims = ''{"sub": "%s", "role": "authenticated", "aal": "aal1"}''', v_admin_a);
        BEGIN
            PERFORM public.create_ingest_key(v_org_a);
            RAISE EXCEPTION 'FAIL: Test 29k [aal1 session created a key]';
        EXCEPTION WHEN OTHERS THEN
            GET STACKED DIAGNOSTICS v_sqlstate = RETURNED_SQLSTATE, v_sqlerrm = MESSAGE_TEXT;
            IF v_sqlstate = '42501' THEN RAISE NOTICE 'PASS: Test 29k [aal1 cannot create keys (42501)]';
            ELSE RAISE EXCEPTION 'FAIL: Test 29k [Expected 42501, got % (%)]', v_sqlstate, v_sqlerrm; END IF;
        END;

        -- 29l. Key events are audited and the audit never contains a secret
        RESET ROLE;
        SELECT count(*) INTO v_leak FROM public.audit_events
         WHERE position(v_s_main IN details::text) > 0 OR position(v_k2->>'secret' IN details::text) > 0 OR position(v_kb->>'secret' IN details::text) > 0;
        IF v_leak = 0
           AND (SELECT count(*) FROM public.audit_events WHERE org_id = v_org_a AND action = 'INGEST_KEY_CREATED') >= 2
           AND (SELECT count(*) FROM public.audit_events WHERE org_id = v_org_a AND action = 'INGEST_KEY_REVOKED') = 1 THEN
            RAISE NOTICE 'PASS: Test 29l [Key creation and revocation audited; no secret in the audit log]';
        ELSE
            RAISE EXCEPTION 'FAIL: Test 29l [Audit missing key events or a secret leaked (leaks=%)]', v_leak;
        END IF;
    END;

    -- ------------------------------------------------------------------------
    -- TEST 30: LEAST-PRIVILEGE GRANTS (migration 014)
    -- ------------------------------------------------------------------------
    DECLARE
        v_bad TEXT;
    BEGIN
        RESET ROLE;

        -- 30a. anon holds no rights on any public table
        SELECT string_agg(c.relname, ', ') INTO v_bad
        FROM pg_class c
        WHERE c.relnamespace = 'public'::regnamespace AND c.relkind IN ('r', 'p')
          AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.objid = c.oid AND d.deptype = 'e') -- skip extension-owned tables (PostGIS spatial_ref_sys)
          AND (has_table_privilege('anon', c.oid, 'SELECT') OR has_table_privilege('anon', c.oid, 'INSERT')
               OR has_table_privilege('anon', c.oid, 'UPDATE') OR has_table_privilege('anon', c.oid, 'DELETE')
               OR has_table_privilege('anon', c.oid, 'TRUNCATE'));
        IF v_bad IS NULL THEN RAISE NOTICE 'PASS: Test 30a [anon has no rights on any public table]';
        ELSE RAISE EXCEPTION 'FAIL: Test 30a [anon still has rights on: %]', v_bad; END IF;

        -- 30b. authenticated has no TRUNCATE, REFERENCES or TRIGGER on any public table
        SELECT string_agg(c.relname, ', ') INTO v_bad
        FROM pg_class c
        WHERE c.relnamespace = 'public'::regnamespace AND c.relkind IN ('r', 'p')
          AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.objid = c.oid AND d.deptype = 'e') -- skip extension-owned tables (PostGIS spatial_ref_sys)
          AND (has_table_privilege('authenticated', c.oid, 'TRUNCATE') OR has_table_privilege('authenticated', c.oid, 'REFERENCES')
               OR has_table_privilege('authenticated', c.oid, 'TRIGGER'));
        IF v_bad IS NULL THEN RAISE NOTICE 'PASS: Test 30b [authenticated has no TRUNCATE/REFERENCES/TRIGGER on public tables]';
        ELSE RAISE EXCEPTION 'FAIL: Test 30b [authenticated still has such rights on: %]', v_bad; END IF;

        -- 30c. authenticated cannot write audit_events at privilege level (read only)
        IF NOT (has_table_privilege('authenticated', 'public.audit_events', 'INSERT')
             OR has_table_privilege('authenticated', 'public.audit_events', 'UPDATE')
             OR has_table_privilege('authenticated', 'public.audit_events', 'DELETE'))
           AND has_table_privilege('authenticated', 'public.audit_events', 'SELECT') THEN
            RAISE NOTICE 'PASS: Test 30c [authenticated can read but not write audit_events]';
        ELSE
            RAISE EXCEPTION 'FAIL: Test 30c [authenticated has write rights on audit_events, or lost read]';
        END IF;

        -- 30d. Behavioural: an authenticated MFA session cannot TRUNCATE a data table (SQLSTATE 42501)
        SET LOCAL ROLE authenticated;
        EXECUTE format('SET LOCAL request.jwt.claims = ''{"sub": "%s", "role": "authenticated", "aal": "aal2"}''', v_admin_a);
        BEGIN
            TRUNCATE public.assets;
            RAISE EXCEPTION 'FAIL: Test 30d [authenticated TRUNCATE of assets succeeded]';
        EXCEPTION WHEN OTHERS THEN
            GET STACKED DIAGNOSTICS v_sqlstate = RETURNED_SQLSTATE, v_sqlerrm = MESSAGE_TEXT;
            IF v_sqlstate = '42501' THEN RAISE NOTICE 'PASS: Test 30d [authenticated TRUNCATE refused with SQLSTATE 42501]';
            ELSE RAISE EXCEPTION 'FAIL: Test 30d [Expected 42501, got % (%)]', v_sqlstate, v_sqlerrm; END IF;
        END;
        RESET ROLE;

        -- 30e. Trigger functions cannot be executed by clients
        IF NOT has_function_privilege('anon', 'public.trg_audit_data_table_change()'::regprocedure, 'EXECUTE')
           AND NOT has_function_privilege('authenticated', 'public.enforce_audit_immutability()'::regprocedure, 'EXECUTE') THEN
            RAISE NOTICE 'PASS: Test 30e [Audit trigger functions are not executable by clients]';
        ELSE
            RAISE EXCEPTION 'FAIL: Test 30e [A client role can execute an audit trigger function]';
        END IF;
    END;

    -- ------------------------------------------------------------------------
    -- TEST 31: KEY ROTATION AND REMOVED WRITE RIGHTS (migration 015)
    -- ------------------------------------------------------------------------
    DECLARE
        v_b JSONB;
        v_now2 TEXT := to_char(now() AT TIME ZONE 'utc', 'YYYY-MM-DD"T"HH24:MI:SS"Z"');
        v_old JSONB;
        v_new JSONB;
        v_r JSONB;
        v_cnt INT;
        v_n INT;
    BEGIN
        RESET ROLE;
        v_b := jsonb_build_object(
            'schema_version', '1.0', 'event_type', 'RANSOMWARE', 'severity', 'high',
            'observed_at', v_now2, 'sent_at', v_now2, 'org_id', v_org_a,
            'signals', jsonb_build_object('hostnames', jsonb_build_array('rot-test.example.test')));
        SET LOCAL ROLE authenticated;
        EXECUTE format('SET LOCAL request.jwt.claims = ''{"sub": "%s", "role": "authenticated", "aal": "aal2"}''', v_admin_a);

        -- 31a. Rotation: the new key works, the old key works inside the grace window
        v_old := public.create_ingest_key(v_org_a);
        v_new := public.rotate_ingest_key(v_org_a, v_old->>'key_id', 30);
        IF (v_new->>'key_id') IS NULL OR (v_new->>'key_id') = (v_old->>'key_id') THEN
            RAISE EXCEPTION 'FAIL: Test 31a [Rotation did not issue a new key: %]', v_new;
        END IF;
        v_r := public.ingest_incident(pg_temp.atlas_sign_with(v_org_a, v_b || '{"event_id":"EVT-ROT-NEW"}'::jsonb, v_new->>'key_id', v_new->>'secret'));
        IF NOT (v_r->>'success')::boolean THEN RAISE EXCEPTION 'FAIL: Test 31a [New key refused: %]', v_r; END IF;
        v_r := public.ingest_incident(pg_temp.atlas_sign_with(v_org_a, v_b || '{"event_id":"EVT-ROT-OLD1"}'::jsonb, v_old->>'key_id', v_old->>'secret'));
        IF NOT (v_r->>'success')::boolean THEN RAISE EXCEPTION 'FAIL: Test 31a [Old key refused inside grace window: %]', v_r; END IF;
        RAISE NOTICE 'PASS: Test 31a [Rotation issues a new key; old key still works inside the grace window]';

        -- 31b. After the grace window the old key is refused; the new key still works
        RESET ROLE;
        UPDATE public.ingest_keys SET expires_at = clock_timestamp() - interval '1 second'
            WHERE org_id = v_org_a AND key_id = v_old->>'key_id';
        SET LOCAL ROLE authenticated;
        EXECUTE format('SET LOCAL request.jwt.claims = ''{"sub": "%s", "role": "authenticated", "aal": "aal2"}''', v_admin_a);
        BEGIN
            PERFORM public.ingest_incident(pg_temp.atlas_sign_with(v_org_a, v_b || '{"event_id":"EVT-ROT-OLD2"}'::jsonb, v_old->>'key_id', v_old->>'secret'));
            RAISE EXCEPTION 'FAIL: Test 31b [Expired key accepted]';
        EXCEPTION WHEN OTHERS THEN
            GET STACKED DIAGNOSTICS v_sqlstate = RETURNED_SQLSTATE, v_sqlerrm = MESSAGE_TEXT;
            IF v_sqlstate = '42501' THEN RAISE NOTICE 'PASS: Test 31b [Expired key refused with SQLSTATE 42501]';
            ELSE RAISE EXCEPTION 'FAIL: Test 31b [Expected 42501, got % (%)]', v_sqlstate, v_sqlerrm; END IF;
        END;
        v_r := public.ingest_incident(pg_temp.atlas_sign_with(v_org_a, v_b || '{"event_id":"EVT-ROT-NEW2"}'::jsonb, v_new->>'key_id', v_new->>'secret'));
        IF NOT (v_r->>'success')::boolean THEN RAISE EXCEPTION 'FAIL: Test 31b [New key stopped working: %]', v_r; END IF;

        -- 31c. Grace period is bounded
        BEGIN
            PERFORM public.rotate_ingest_key(v_org_a, v_new->>'key_id', 1441);
            RAISE EXCEPTION 'FAIL: Test 31c [Grace period above 1440 accepted]';
        EXCEPTION WHEN OTHERS THEN
            GET STACKED DIAGNOSTICS v_sqlstate = RETURNED_SQLSTATE, v_sqlerrm = MESSAGE_TEXT;
            IF v_sqlstate = '22023' THEN RAISE NOTICE 'PASS: Test 31c [Out-of-range grace period refused (22023)]';
            ELSE RAISE EXCEPTION 'FAIL: Test 31c [Expected 22023, got % (%)]', v_sqlstate, v_sqlerrm; END IF;
        END;

        -- 31d. A rotation cannot lengthen an old key's life: rotating an already-expiring key with a longer window is refused
        BEGIN
            PERFORM public.rotate_ingest_key(v_org_a, v_old->>'key_id', 1000);
            RAISE EXCEPTION 'FAIL: Test 31d [Rotation of an expired key accepted]';
        EXCEPTION WHEN OTHERS THEN
            GET STACKED DIAGNOSTICS v_sqlstate = RETURNED_SQLSTATE, v_sqlerrm = MESSAGE_TEXT;
            IF v_sqlstate = '02000' THEN RAISE NOTICE 'PASS: Test 31d [Expired key cannot be re-extended by rotation (02000)]';
            ELSE RAISE EXCEPTION 'FAIL: Test 31d [Expected 02000, got % (%)]', v_sqlstate, v_sqlerrm; END IF;
        END;

        -- 31e. Analysts and aal1 sessions cannot rotate
        EXECUTE format('SET LOCAL request.jwt.claims = ''{"sub": "%s", "role": "authenticated", "aal": "aal2"}''', v_analyst_a);
        BEGIN
            PERFORM public.rotate_ingest_key(v_org_a, v_new->>'key_id', 10);
            RAISE EXCEPTION 'FAIL: Test 31e [Analyst rotated a key]';
        EXCEPTION WHEN OTHERS THEN
            GET STACKED DIAGNOSTICS v_sqlstate = RETURNED_SQLSTATE, v_sqlerrm = MESSAGE_TEXT;
            IF v_sqlstate = '42501' THEN RAISE NOTICE 'PASS: Test 31e [Analyst cannot rotate keys (42501)]';
            ELSE RAISE EXCEPTION 'FAIL: Test 31e [Expected 42501, got % (%)]', v_sqlstate, v_sqlerrm; END IF;
        END;
        EXECUTE format('SET LOCAL request.jwt.claims = ''{"sub": "%s", "role": "authenticated", "aal": "aal1"}''', v_admin_a);
        BEGIN
            PERFORM public.rotate_ingest_key(v_org_a, v_new->>'key_id', 10);
            RAISE EXCEPTION 'FAIL: Test 31e2 [aal1 session rotated a key]';
        EXCEPTION WHEN OTHERS THEN
            GET STACKED DIAGNOSTICS v_sqlstate = RETURNED_SQLSTATE, v_sqlerrm = MESSAGE_TEXT;
            IF v_sqlstate = '42501' THEN RAISE NOTICE 'PASS: Test 31e2 [aal1 session cannot rotate keys (42501)]';
            ELSE RAISE EXCEPTION 'FAIL: Test 31e2 [Expected 42501, got % (%)]', v_sqlstate, v_sqlerrm; END IF;
        END;

        -- 31f. Audit records the rotation, and no secret appears in the ledger
        RESET ROLE;
        SELECT count(*) INTO v_cnt FROM public.audit_events
            WHERE org_id = v_org_a AND action = 'INGEST_KEY_ROTATED'
              AND details->>'old_key_id' = v_old->>'key_id' AND details->>'new_key_id' = v_new->>'key_id';
        SELECT count(*) INTO v_n FROM public.audit_events
            WHERE org_id = v_org_a AND (details::text LIKE '%' || (v_new->>'secret') || '%' OR details::text LIKE '%' || (v_old->>'secret') || '%');
        IF v_cnt = 1 AND v_n = 0 THEN RAISE NOTICE 'PASS: Test 31f [Rotation audited; no secret in the ledger]';
        ELSE RAISE EXCEPTION 'FAIL: Test 31f [Audit rows=%, secret leaks=%]', v_cnt, v_n; END IF;

        -- 31g. Rights with no matching policy are gone; rights that are used remain
        IF has_table_privilege('authenticated', 'public.incidents', 'UPDATE')
           OR has_table_privilege('authenticated', 'public.incidents', 'DELETE')
           OR has_table_privilege('authenticated', 'public.evidence', 'UPDATE')
           OR has_table_privilege('authenticated', 'public.evidence', 'DELETE')
           OR has_table_privilege('authenticated', 'public.custody_events', 'UPDATE')
           OR has_table_privilege('authenticated', 'public.custody_events', 'DELETE')
           OR has_table_privilege('authenticated', 'public.asset_matches', 'DELETE')
           OR has_table_privilege('authenticated', 'public.organisations', 'INSERT')
           OR has_table_privilege('authenticated', 'public.organisations', 'UPDATE')
           OR has_table_privilege('authenticated', 'public.organisations', 'DELETE')
           OR has_table_privilege('authenticated', 'public.scoring_config', 'INSERT')
           OR has_table_privilege('authenticated', 'public.scoring_config', 'DELETE') THEN
            RAISE EXCEPTION 'FAIL: Test 31g [authenticated still holds a right that no policy allows]';
        END IF;
        IF NOT (has_table_privilege('authenticated', 'public.incidents', 'SELECT')
                AND has_table_privilege('authenticated', 'public.incidents', 'INSERT')
                AND has_table_privilege('authenticated', 'public.evidence', 'INSERT')
                AND has_table_privilege('authenticated', 'public.assets', 'UPDATE')
                AND has_table_privilege('authenticated', 'public.assets', 'DELETE')
                AND has_table_privilege('authenticated', 'public.asset_matches', 'UPDATE')
                AND has_table_privilege('authenticated', 'public.scoring_config', 'UPDATE')) THEN
            RAISE EXCEPTION 'FAIL: Test 31g [authenticated lost a right that the app uses]';
        END IF;
        RAISE NOTICE 'PASS: Test 31g [Unused write rights removed; used rights intact]';

        -- 31h. Behaviour: an admin session now gets a permission error (not just zero rows) on UPDATE incidents
        SET LOCAL ROLE authenticated;
        EXECUTE format('SET LOCAL request.jwt.claims = ''{"sub": "%s", "role": "authenticated", "aal": "aal2"}''', v_admin_a);
        BEGIN
            UPDATE public.incidents SET severity = 'low' WHERE org_id = v_org_a;
            RAISE EXCEPTION 'FAIL: Test 31h [Admin UPDATE on incidents did not error]';
        EXCEPTION WHEN OTHERS THEN
            GET STACKED DIAGNOSTICS v_sqlstate = RETURNED_SQLSTATE, v_sqlerrm = MESSAGE_TEXT;
            IF v_sqlstate = '42501' THEN RAISE NOTICE 'PASS: Test 31h [UPDATE on incidents refused with 42501]';
            ELSE RAISE EXCEPTION 'FAIL: Test 31h [Expected 42501, got % (%)]', v_sqlstate, v_sqlerrm; END IF;
        END;
        RESET ROLE;
    END;

    -- ------------------------------------------------------------------------
    -- TEST 32: AUDIT CHECKPOINTS (migration 016)
    -- ------------------------------------------------------------------------
    DECLARE
        v_cp JSONB;
        v_vr RECORD;
        v_before BIGINT;
        v_max BIGINT;
    BEGIN
        RESET ROLE;
        SET LOCAL ROLE authenticated;
        EXECUTE format('SET LOCAL request.jwt.claims = ''{"sub": "%s", "role": "authenticated", "aal": "aal2"}''', v_admin_b);

        -- 32a. An admin records a checkpoint; the live chain matches it
        v_cp := public.audit_checkpoint(v_org_b);
        SELECT * INTO v_vr FROM public.verify_audit_chain_against(v_org_b, (v_cp->>'seq')::bigint, v_cp->>'record_hash');
        IF v_vr.is_valid THEN RAISE NOTICE 'PASS: Test 32a [Checkpoint recorded and verified: %]', v_vr.reason;
        ELSE RAISE EXCEPTION 'FAIL: Test 32a [Fresh checkpoint did not verify: %]', v_vr.reason; END IF;

        -- 32b. New audit rows after the checkpoint do not break it
        PERFORM public.log_event(v_org_b, 'VIEW', 'dashboard', 'after-checkpoint', 'cid-after-cp', '{}'::jsonb);
        SELECT * INTO v_vr FROM public.verify_audit_chain_against(v_org_b, (v_cp->>'seq')::bigint, v_cp->>'record_hash');
        IF v_vr.is_valid THEN RAISE NOTICE 'PASS: Test 32b [Checkpoint still holds after later audit rows]';
        ELSE RAISE EXCEPTION 'FAIL: Test 32b [Checkpoint broke after later rows: %]', v_vr.reason; END IF;

        -- 32c. A wrong hash for a real sequence number is reported
        SELECT * INTO v_vr FROM public.verify_audit_chain_against(v_org_b, (v_cp->>'seq')::bigint, repeat('a', 64));
        IF NOT v_vr.is_valid AND v_vr.first_bad_seq = (v_cp->>'seq')::bigint THEN RAISE NOTICE 'PASS: Test 32c [Wrong checkpoint hash reported]';
        ELSE RAISE EXCEPTION 'FAIL: Test 32c [Wrong hash accepted or no sequence reported: valid=% reason=%]', v_vr.is_valid, v_vr.reason; END IF;

        -- 32d. Malformed checkpoint input is refused
        BEGIN
            PERFORM * FROM public.verify_audit_chain_against(v_org_b, 0, 'xyz');
            RAISE EXCEPTION 'FAIL: Test 32d [Malformed checkpoint accepted]';
        EXCEPTION WHEN OTHERS THEN
            GET STACKED DIAGNOSTICS v_sqlstate = RETURNED_SQLSTATE, v_sqlerrm = MESSAGE_TEXT;
            IF v_sqlstate = '22023' THEN RAISE NOTICE 'PASS: Test 32d [Malformed checkpoint refused (22023)]';
            ELSE RAISE EXCEPTION 'FAIL: Test 32d [Expected 22023, got % (%)]', v_sqlstate, v_sqlerrm; END IF;
        END;

        -- 32e. An analyst (of org A) cannot record a checkpoint; analyst-level callers are not admins record a checkpoint, aal1 sessions cannot either
        EXECUTE format('SET LOCAL request.jwt.claims = ''{"sub": "%s", "role": "authenticated", "aal": "aal2"}''', v_analyst_a);
        BEGIN
            PERFORM public.audit_checkpoint(v_org_a);
            RAISE EXCEPTION 'FAIL: Test 32e [Analyst recorded a checkpoint]';
        EXCEPTION WHEN OTHERS THEN
            GET STACKED DIAGNOSTICS v_sqlstate = RETURNED_SQLSTATE, v_sqlerrm = MESSAGE_TEXT;
            IF v_sqlstate = '42501' THEN RAISE NOTICE 'PASS: Test 32e [Analyst cannot record a checkpoint (42501)]';
            ELSE RAISE EXCEPTION 'FAIL: Test 32e [Expected 42501, got % (%)]', v_sqlstate, v_sqlerrm; END IF;
        END;
        EXECUTE format('SET LOCAL request.jwt.claims = ''{"sub": "%s", "role": "authenticated", "aal": "aal1"}''', v_admin_b);
        BEGIN
            PERFORM public.audit_checkpoint(v_org_b);
            RAISE EXCEPTION 'FAIL: Test 32e2 [aal1 session recorded a checkpoint]';
        EXCEPTION WHEN OTHERS THEN
            GET STACKED DIAGNOSTICS v_sqlstate = RETURNED_SQLSTATE, v_sqlerrm = MESSAGE_TEXT;
            IF v_sqlstate = '42501' THEN RAISE NOTICE 'PASS: Test 32e2 [aal1 session cannot record a checkpoint (42501)]';
            ELSE RAISE EXCEPTION 'FAIL: Test 32e2 [Expected 42501, got % (%)]', v_sqlstate, v_sqlerrm; END IF;
        END;

        -- 32f. A member of another organisation cannot check this chain
        EXECUTE format('SET LOCAL request.jwt.claims = ''{"sub": "%s", "role": "authenticated", "aal": "aal2"}''', v_admin_a);
        BEGIN
            PERFORM * FROM public.verify_audit_chain_against(v_org_b, (v_cp->>'seq')::bigint, v_cp->>'record_hash');
            RAISE EXCEPTION 'FAIL: Test 32f [Cross-tenant checkpoint check accepted]';
        EXCEPTION WHEN OTHERS THEN
            GET STACKED DIAGNOSTICS v_sqlstate = RETURNED_SQLSTATE, v_sqlerrm = MESSAGE_TEXT;
            IF v_sqlstate = '42501' THEN RAISE NOTICE 'PASS: Test 32f [Other organisation refused (42501)]';
            ELSE RAISE EXCEPTION 'FAIL: Test 32f [Expected 42501, got % (%)]', v_sqlstate, v_sqlerrm; END IF;
        END;

        -- 32g. Removing the newest rows (done as the table owner, bypassing the immutability trigger) goes
        --      undetected by the plain chain check but is caught by the checkpoint.
        RESET ROLE;
        SELECT max(seq) INTO v_before FROM public.audit_events WHERE org_id = v_org_b;
        ALTER TABLE public.audit_events DISABLE TRIGGER USER;
        DELETE FROM public.audit_events WHERE org_id = v_org_b AND seq >= (v_cp->>'seq')::bigint;
        ALTER TABLE public.audit_events ENABLE TRIGGER USER;
        SELECT max(seq) INTO v_max FROM public.audit_events WHERE org_id = v_org_b;
        SET LOCAL ROLE authenticated;
        EXECUTE format('SET LOCAL request.jwt.claims = ''{"sub": "%s", "role": "authenticated", "aal": "aal2"}''', v_admin_b);
        SELECT * INTO v_vr FROM public.verify_audit_chain(v_org_b);
        IF NOT v_vr.is_valid THEN
            RAISE EXCEPTION 'FAIL: Test 32g [Precondition: tail truncation was expected to leave a valid plain chain, got %]', v_vr.reason;
        END IF;
        SELECT * INTO v_vr FROM public.verify_audit_chain_against(v_org_b, (v_cp->>'seq')::bigint, v_cp->>'record_hash');
        IF NOT v_vr.is_valid AND v_max < v_before THEN
            RAISE NOTICE 'PASS: Test 32g [Tail removal (% rows) passes the plain chain check but fails the checkpoint: %]', v_before - v_max, v_vr.reason;
        ELSE
            RAISE EXCEPTION 'FAIL: Test 32g [Tail removal not caught by checkpoint (valid=%, before=%, after=%)]', v_vr.is_valid, v_before, v_max;
        END IF;
        RESET ROLE;
    END;

    -- ------------------------------------------------------------------------
    -- TEST 33: blast_radius SCALES WITH THE GRAPH, NOT THE NUMBER OF PATHS (migration 017)
    -- A lattice of 7 layers x 10 assets, each layer fully connected to the next, has 10^6 distinct
    -- 6-hop paths from one root. Path enumeration cannot finish this inside the time limit.
    -- ------------------------------------------------------------------------
    DECLARE
        v_inc_lat UUID := 'a0000000-cccc-0000-0000-0000000000f1';
        v_n INT;
        v_maxhop INT;
        v_bad INT;
    BEGIN
        RESET ROLE;
        INSERT INTO public.assets (org_id, site_code, name, type, criticality, owner, accuracy_class, source)
        SELECT v_org_a, 'LAT-' || l || '-' || i, 'Lattice ' || l || '.' || i, 'service', 3, 'suite', 'facility_approximate', 'suite'
        FROM generate_series(0, 6) l, generate_series(0, 9) i;
        INSERT INTO public.dependency_edges (org_id, from_asset_id, to_asset_id, relation_type, criticality, source)
        SELECT v_org_a, f.id, t.id, 'powers', 3, 'suite'
        FROM public.assets f
        JOIN public.assets t ON t.org_id = f.org_id
         AND split_part(t.site_code, '-', 2)::int = split_part(f.site_code, '-', 2)::int + 1
        WHERE f.org_id = v_org_a AND f.site_code LIKE 'LAT-%' AND t.site_code LIKE 'LAT-%';
        INSERT INTO public.incidents (id, org_id, event_id, event_type, severity, observed_at, source)
            VALUES (v_inc_lat, v_org_a, 'LAT-1', 'RANSOMWARE', 'high', now(), 'suite');
        INSERT INTO public.asset_matches (org_id, incident_id, asset_id, rule_fired, score, status, source)
        SELECT v_org_a, v_inc_lat, id, 'suite', 1.0, 'auto', 'suite'
        FROM public.assets WHERE org_id = v_org_a AND site_code = 'LAT-0-0';

        SET LOCAL ROLE authenticated;
        EXECUTE format('SET LOCAL request.jwt.claims = ''{"sub": "%s", "role": "authenticated", "aal": "aal2"}''', v_admin_a);
        SET LOCAL statement_timeout = '10s';
        SELECT count(*), max(hop_depth) INTO v_n, v_maxhop FROM public.blast_radius(v_inc_lat);
        SELECT count(*) INTO v_bad FROM public.blast_radius(v_inc_lat) b
            WHERE b.hop_depth <> split_part(b.site_code, '-', 2)::int;
        SET LOCAL statement_timeout = 0;
        IF v_n = 61 AND v_maxhop = 6 AND v_bad = 0 THEN
            RAISE NOTICE 'PASS: Test 33 [Lattice with 10^6 paths resolved in time: % assets, deepest hop %, every asset at its shortest distance]', v_n, v_maxhop;
        ELSE
            RAISE EXCEPTION 'FAIL: Test 33 [Expected 61 assets, depth 6, all at shortest distance; got rows=%, depth=%, wrong_depth=%]', v_n, v_maxhop, v_bad;
        END IF;
        RESET ROLE;
    END;

    -- ------------------------------------------------------------------------
    -- TEST 36: camera registry (migration 018)
    -- ------------------------------------------------------------------------
    DECLARE
        v_cam_id UUID;
        v_n INT;
    BEGIN
        SET LOCAL ROLE authenticated;
        EXECUTE format('SET LOCAL request.jwt.claims = ''{"sub": "%s", "role": "authenticated", "aal": "aal2"}''', v_analyst_a);

        -- 36a. An analyst can register a camera in their own org
        INSERT INTO public.camera_registry (org_id, camera_code, name, protocol, lng, lat, bearing_deg, fov_deg, range_meters, created_by, updated_by)
            VALUES (v_org_a, 'CAM-01', 'Gate Camera', 'RTSP_HLS', 10.21, 50.11, 90, 60, 80, v_analyst_a, v_analyst_a)
            RETURNING id INTO v_cam_id;
        RAISE NOTICE 'PASS: Test 36a [Analyst registered a camera in their own org]';

        -- 36b. A plain http endpoint is refused
        BEGIN
            INSERT INTO public.camera_registry (org_id, camera_code, name, protocol, lng, lat, endpoint_url, created_by, updated_by)
                VALUES (v_org_a, 'CAM-02', 'Bad', 'RTSP_HLS', 10.21, 50.11, 'http://cam.example.org/stream.m3u8', v_analyst_a, v_analyst_a);
            RAISE EXCEPTION 'FAIL: Test 36b [http:// camera endpoint accepted]';
        EXCEPTION WHEN OTHERS THEN
            GET STACKED DIAGNOSTICS v_sqlstate = RETURNED_SQLSTATE, v_sqlerrm = MESSAGE_TEXT;
            IF v_sqlstate <> '23514' THEN RAISE EXCEPTION 'FAIL: Test 36b [expected 23514, got % (%)]', v_sqlstate, v_sqlerrm; END IF;
        END;
        RAISE NOTICE 'PASS: Test 36b [Plain http camera endpoint refused by a check constraint]';

        -- 36c. Another org cannot read, update or delete it; an analyst cannot delete it either
        RESET ROLE;
        SELECT count(*) INTO v_n FROM public.camera_registry WHERE org_id = v_org_a AND id = v_cam_id;
        IF v_n <> 1 THEN RAISE EXCEPTION 'FAIL: Test 36c [camera row missing after insert]'; END IF;

        SET LOCAL ROLE authenticated;
        EXECUTE format('SET LOCAL request.jwt.claims = ''{"sub": "%s", "role": "authenticated", "aal": "aal2"}''', v_admin_b);
        SELECT count(*) INTO v_n FROM public.camera_registry WHERE id = v_cam_id;
        IF v_n <> 0 THEN RAISE EXCEPTION 'FAIL: Test 36c [another org can read this camera]'; END IF;
        DELETE FROM public.camera_registry WHERE id = v_cam_id;
        GET DIAGNOSTICS v_rows_affected = ROW_COUNT;
        IF v_rows_affected <> 0 THEN RAISE EXCEPTION 'FAIL: Test 36c [another org''s admin deleted % row(s) of this camera]', v_rows_affected; END IF;
        RESET ROLE;
        SELECT count(*) INTO v_n FROM public.camera_registry WHERE id = v_cam_id;
        IF v_n <> 1 THEN RAISE EXCEPTION 'FAIL: Test 36c [camera row gone after another org''s admin attempted delete]'; END IF;

        SET LOCAL ROLE authenticated;
        EXECUTE format('SET LOCAL request.jwt.claims = ''{"sub": "%s", "role": "authenticated", "aal": "aal2"}''', v_analyst_a);
        DELETE FROM public.camera_registry WHERE id = v_cam_id;
        GET DIAGNOSTICS v_rows_affected = ROW_COUNT;
        IF v_rows_affected <> 0 THEN RAISE EXCEPTION 'FAIL: Test 36c [analyst deleted % camera row(s) (should be admin-only)]', v_rows_affected; END IF;
        RESET ROLE;
        SELECT count(*) INTO v_n FROM public.camera_registry WHERE id = v_cam_id;
        IF v_n <> 1 THEN RAISE EXCEPTION 'FAIL: Test 36c [camera row gone after analyst attempted delete]'; END IF;
        RAISE NOTICE 'PASS: Test 36c [Camera is invisible to another org; only an admin of the owning org may delete it]';

        -- 36d. The owning org's admin can delete it, and the delete is audited
        EXECUTE format('SET LOCAL request.jwt.claims = ''{"sub": "%s", "role": "authenticated", "aal": "aal2"}''', v_admin_a);
        DELETE FROM public.camera_registry WHERE id = v_cam_id;
        RESET ROLE;
        SELECT count(*) INTO v_n FROM public.audit_events WHERE org_id = v_org_a AND action = 'CAMERA_DELETE' AND target_id = v_cam_id::text;
        IF v_n < 1 THEN RAISE EXCEPTION 'FAIL: Test 36d [camera delete was not audited]'; END IF;
        RAISE NOTICE 'PASS: Test 36d [Owning org admin deleted the camera; deletion is in the audit ledger]';
    END;

    -- ------------------------------------------------------------------------
    -- TEST 37: external threat indicators (migration 018)
    -- ------------------------------------------------------------------------
    DECLARE
        v_eti_id UUID;
        v_n INT;
    BEGIN
        SET LOCAL ROLE authenticated;
        EXECUTE format('SET LOCAL request.jwt.claims = ''{"sub": "%s", "role": "authenticated", "aal": "aal2"}''', v_analyst_a);

        -- 37a. An analyst imports an indicator into their own org
        INSERT INTO public.external_threat_indicators (org_id, provider_id, indicator_type, value, source_name, confidence, imported_by)
            VALUES (v_org_a, 'CISA_KEV', 'cve', 'CVE-2026-0001', 'CISA KEV (Test Vendor)', 95, v_analyst_a)
            RETURNING id INTO v_eti_id;
        RAISE NOTICE 'PASS: Test 37a [Analyst imported an external indicator into their own org]';

        -- 37b. The analyst can mark it verified, but cannot change the imported value or type
        UPDATE public.external_threat_indicators SET verification_status = 'verified_by_analyst' WHERE id = v_eti_id;
        BEGIN
            UPDATE public.external_threat_indicators SET value = 'CVE-9999-9999' WHERE id = v_eti_id;
            RAISE EXCEPTION 'FAIL: Test 37b [Imported indicator value was changed]';
        EXCEPTION WHEN OTHERS THEN
            GET STACKED DIAGNOSTICS v_sqlstate = RETURNED_SQLSTATE, v_sqlerrm = MESSAGE_TEXT;
            IF v_sqlstate <> '42501' THEN RAISE EXCEPTION 'FAIL: Test 37b [expected 42501, got % (%)]', v_sqlstate, v_sqlerrm; END IF;
        END;
        RAISE NOTICE 'PASS: Test 37b [Verification status can be set; the imported fact itself cannot be changed]';

        -- 37c. Duplicate (same org, type and value) is refused; another org cannot see it
        BEGIN
            INSERT INTO public.external_threat_indicators (org_id, provider_id, indicator_type, value, source_name, imported_by)
                VALUES (v_org_a, 'CISA_KEV', 'cve', 'CVE-2026-0001', 'dup', v_analyst_a);
            RAISE EXCEPTION 'FAIL: Test 37c [Duplicate indicator accepted]';
        EXCEPTION WHEN OTHERS THEN
            GET STACKED DIAGNOSTICS v_sqlstate = RETURNED_SQLSTATE, v_sqlerrm = MESSAGE_TEXT;
            IF v_sqlstate <> '23505' THEN RAISE EXCEPTION 'FAIL: Test 37c [expected 23505, got % (%)]', v_sqlstate, v_sqlerrm; END IF;
        END;
        EXECUTE format('SET LOCAL request.jwt.claims = ''{"sub": "%s", "role": "authenticated", "aal": "aal2"}''', v_admin_b);
        SELECT count(*) INTO v_n FROM public.external_threat_indicators WHERE id = v_eti_id;
        IF v_n <> 0 THEN RAISE EXCEPTION 'FAIL: Test 37c [another org can read this indicator]'; END IF;
        RAISE NOTICE 'PASS: Test 37c [Duplicate (org, type, value) refused; another org cannot see the indicator]';
        RESET ROLE;
    END;

    -- ------------------------------------------------------------------------
    -- TEST 38: CROSS-TENANT WRITES, AAL1 GATE & ROLE MATRIX FOR CAMERA & CTI
    -- ------------------------------------------------------------------------
    DECLARE
        v_cam_cross UUID;
        v_eti_cross UUID;
        v_n INT;
    BEGIN
        -- Seed Org A rows for cross-tenant mutation checks
        SET LOCAL ROLE authenticated;
        EXECUTE format('SET LOCAL request.jwt.claims = ''{"sub": "%s", "role": "authenticated", "aal": "aal2"}''', v_analyst_a);

        INSERT INTO public.camera_registry (org_id, camera_code, name, protocol, lng, lat, created_by, updated_by)
            VALUES (v_org_a, 'CAM-XT-01', 'Cross-Tenant Target', 'ONVIF', 77.209, 28.613, v_analyst_a, v_analyst_a)
            RETURNING id INTO v_cam_cross;

        -- Analyst can update non-admin camera fields, but cannot alter org_id
        UPDATE public.camera_registry SET name = 'Cross-Tenant Target Renamed', fov_deg = 75 WHERE id = v_cam_cross;
        BEGIN
            UPDATE public.camera_registry SET org_id = v_org_b WHERE id = v_cam_cross;
            RAISE EXCEPTION 'FAIL: Test 38a [Analyst modified camera org_id]';
        EXCEPTION WHEN OTHERS THEN
            GET STACKED DIAGNOSTICS v_sqlstate = RETURNED_SQLSTATE, v_sqlerrm = MESSAGE_TEXT;
            IF v_sqlstate <> '42501' THEN RAISE EXCEPTION 'FAIL: Test 38a [expected 42501, got % (%)]', v_sqlstate, v_sqlerrm; END IF;
        END;
        RAISE NOTICE 'PASS: Test 38a [Analyst updated non-admin camera fields; org_id tampering rejected (42501)]';

        INSERT INTO public.external_threat_indicators (org_id, provider_id, indicator_type, value, source_name, confidence, imported_by)
            VALUES (v_org_a, 'STIX_2_1', 'ip', '198.51.100.44', 'STIX Test', 80, v_analyst_a)
            RETURNING id INTO v_eti_cross;

        -- 38b. Cross-tenant INSERT by Org B admin into Org A must fail with 42501 on both tables
        EXECUTE format('SET LOCAL request.jwt.claims = ''{"sub": "%s", "role": "authenticated", "aal": "aal2"}''', v_admin_b);
        BEGIN
            INSERT INTO public.camera_registry (org_id, camera_code, name, protocol, lng, lat, created_by, updated_by)
                VALUES (v_org_a, 'CAM-ROGUE', 'Rogue Cam', 'ONVIF', 0, 0, v_admin_b, v_admin_b);
            RAISE EXCEPTION 'FAIL: Test 38b [Cross-tenant camera_registry INSERT succeeded]';
        EXCEPTION WHEN OTHERS THEN
            GET STACKED DIAGNOSTICS v_sqlstate = RETURNED_SQLSTATE, v_sqlerrm = MESSAGE_TEXT;
            IF v_sqlstate <> '42501' THEN RAISE EXCEPTION 'FAIL: Test 38b [expected 42501, got % (%)]', v_sqlstate, v_sqlerrm; END IF;
        END;

        BEGIN
            INSERT INTO public.external_threat_indicators (org_id, provider_id, indicator_type, value, source_name, imported_by)
                VALUES (v_org_a, 'STIX_2_1', 'ip', '198.51.100.99', 'Rogue CTI', v_admin_b);
            RAISE EXCEPTION 'FAIL: Test 38b2 [Cross-tenant external_threat_indicators INSERT succeeded]';
        EXCEPTION WHEN OTHERS THEN
            GET STACKED DIAGNOSTICS v_sqlstate = RETURNED_SQLSTATE, v_sqlerrm = MESSAGE_TEXT;
            IF v_sqlstate <> '42501' THEN RAISE EXCEPTION 'FAIL: Test 38b2 [expected 42501, got % (%)]', v_sqlstate, v_sqlerrm; END IF;
        END;
        RAISE NOTICE 'PASS: Test 38b [Cross-tenant INSERTs into camera_registry and external_threat_indicators rejected (42501)]';

        -- 38c. Cross-tenant UPDATE and DELETE by Org B admin affect 0 rows on both tables
        UPDATE public.camera_registry SET name = 'Tampered Cam' WHERE id = v_cam_cross;
        GET DIAGNOSTICS v_rows_affected = ROW_COUNT;
        IF v_rows_affected <> 0 THEN RAISE EXCEPTION 'FAIL: Test 38c [Cross-tenant camera UPDATE modified % rows]', v_rows_affected; END IF;

        UPDATE public.external_threat_indicators SET verification_status = 'false_positive' WHERE id = v_eti_cross;
        GET DIAGNOSTICS v_rows_affected = ROW_COUNT;
        IF v_rows_affected <> 0 THEN RAISE EXCEPTION 'FAIL: Test 38c [Cross-tenant indicator UPDATE modified % rows]', v_rows_affected; END IF;

        DELETE FROM public.external_threat_indicators WHERE id = v_eti_cross;
        GET DIAGNOSTICS v_rows_affected = ROW_COUNT;
        IF v_rows_affected <> 0 THEN RAISE EXCEPTION 'FAIL: Test 38c [Cross-tenant indicator DELETE removed % rows]', v_rows_affected; END IF;
        RAISE NOTICE 'PASS: Test 38c [Cross-tenant UPDATE/DELETE affected 0 rows on camera_registry and external_threat_indicators]';

        -- 38d. Analyst cannot delete external_threat_indicators; owning Admin can and is audited
        EXECUTE format('SET LOCAL request.jwt.claims = ''{"sub": "%s", "role": "authenticated", "aal": "aal2"}''', v_analyst_a);
        DELETE FROM public.external_threat_indicators WHERE id = v_eti_cross;
        GET DIAGNOSTICS v_rows_affected = ROW_COUNT;
        IF v_rows_affected <> 0 THEN RAISE EXCEPTION 'FAIL: Test 38d [Analyst deleted % indicator row(s)]', v_rows_affected; END IF;

        EXECUTE format('SET LOCAL request.jwt.claims = ''{"sub": "%s", "role": "authenticated", "aal": "aal2"}''', v_admin_a);
        DELETE FROM public.external_threat_indicators WHERE id = v_eti_cross;
        GET DIAGNOSTICS v_rows_affected = ROW_COUNT;
        IF v_rows_affected <> 1 THEN RAISE EXCEPTION 'FAIL: Test 38d [Owning admin indicator DELETE affected % rows]', v_rows_affected; END IF;
        RESET ROLE;
        SELECT count(*) INTO v_n FROM public.audit_events
            WHERE org_id = v_org_a AND action = 'external_threat_indicators_DELETE' AND target_id = v_eti_cross::text;
        IF v_n < 1 THEN RAISE EXCEPTION 'FAIL: Test 38d [External indicator deletion was not audited]'; END IF;
        RAISE NOTICE 'PASS: Test 38d [Analyst cannot delete indicators; owning admin delete succeeded and audited]';

        -- 38e. AAL1 session reads 0 rows from both tables
        SET LOCAL ROLE authenticated;
        EXECUTE format('SET LOCAL request.jwt.claims = ''{"sub": "%s", "role": "authenticated", "aal": "aal1"}''', v_admin_a);
        SELECT count(*) INTO v_n FROM public.camera_registry;
        IF v_n <> 0 THEN RAISE EXCEPTION 'FAIL: Test 38e [aal1 session leaked % camera rows]', v_n; END IF;
        SELECT count(*) INTO v_n FROM public.external_threat_indicators;
        IF v_n <> 0 THEN RAISE EXCEPTION 'FAIL: Test 38e [aal1 session leaked % indicator rows]', v_n; END IF;
        RAISE NOTICE 'PASS: Test 38e [aal1 session reads 0 rows in camera_registry and external_threat_indicators]';
        RESET ROLE;
    END;

    RAISE NOTICE '====================================================================';
    RAISE NOTICE 'ALL SECURITY CHECKS PASSED SUCCESSFULLY. ROLLING BACK TRANSACTION.';
    RAISE NOTICE '====================================================================';

    -- Intentional rollback to keep database clean
    RAISE EXCEPTION 'INTENTIONAL_ROLLBACK_AFTER_ALL_TESTS_PASS'
        USING ERRCODE = 'P0001';
EXCEPTION
    WHEN SQLSTATE 'P0001' THEN
        IF SQLERRM = 'INTENTIONAL_ROLLBACK_AFTER_ALL_TESTS_PASS' THEN
            RAISE NOTICE 'Transaction rolled back safely. Zero test artifacts committed.';
        ELSE
            RAISE;  -- any other failure must stay a failure
        END IF;
END $$;

