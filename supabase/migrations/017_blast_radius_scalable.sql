-- ============================================================================
-- Project ATLAS - Migration 017: blast_radius no longer enumerates every path
-- The 007 version followed every simple path up to 6 hops, twice (once to reach assets and once per
-- reached asset to count downstream services). On a graph with about 8 dependencies per asset, five
-- matched assets did not finish within 90 seconds. This version visits each asset once, at its
-- shortest distance, so the work grows with the size of the graph, not with the number of paths.
-- The columns returned, the shortest-path rule, the tie-break (lowest array of asset IDs) and the
-- scoring formulas are unchanged. When two dependencies of different types join the same pair of assets,
-- the one with the alphabetically first relation type is now chosen, so the result is repeatable
-- (the old version picked either one). It is still SECURITY INVOKER, so row-level security still applies.
-- Safe to run more than once.
-- ============================================================================

CREATE OR REPLACE FUNCTION public.internal_reachable_service_count(p_org_id UUID, p_start UUID, p_max_depth INT DEFAULT 6)
RETURNS INT
LANGUAGE plpgsql
STABLE
SECURITY INVOKER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_visited UUID[] := ARRAY[p_start];
    v_frontier UUID[] := ARRAY[p_start];
    v_next UUID[];
    v_depth INT := 0;
BEGIN
    WHILE v_depth < p_max_depth AND cardinality(v_frontier) > 0 LOOP
        SELECT COALESCE(array_agg(q.nid), '{}') INTO v_next
        FROM (
            SELECT e.to_asset_id AS nid
            FROM public.dependency_edges e
            WHERE e.org_id = p_org_id
              AND e.from_asset_id = ANY(v_frontier)
            EXCEPT
            SELECT unnest(v_visited)
        ) q;
        v_visited := v_visited || v_next;
        v_frontier := v_next;
        v_depth := v_depth + 1;
    END LOOP;
    RETURN (SELECT COUNT(*) FROM public.assets a
            WHERE a.org_id = p_org_id AND a.id = ANY(v_visited) AND a.type = 'service')::INT;
END;
$$;
REVOKE EXECUTE ON FUNCTION public.internal_reachable_service_count(UUID, UUID, INT) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.internal_reachable_service_count(UUID, UUID, INT) TO authenticated;

CREATE OR REPLACE FUNCTION public.blast_radius(p_incident_id UUID)
RETURNS TABLE (
    asset_id UUID,
    site_code TEXT,
    name TEXT,
    type TEXT,
    criticality INTEGER,
    accuracy_class TEXT,
    hop_depth INTEGER,
    c NUMERIC,
    r NUMERIC,
    i_factor NUMERIC,
    exposure NUMERIC,
    likelihood NUMERIC,
    calibration_status TEXT,
    priority NUMERIC,
    range_low NUMERIC,
    range_high NUMERIC,
    path JSONB,
    root_asset_id UUID,
    match_id UUID,
    match_status TEXT,
    match_confidence NUMERIC
)
LANGUAGE plpgsql
STABLE
SECURITY INVOKER
SET search_path = public, extensions, pg_temp
AS $$
#variable_conflict use_column
DECLARE
    v_org_id UUID;
    v_total_services INT;
    v_default_exposure NUMERIC := 0.80;
    v_default_likelihood NUMERIC := 0.90;
    v_decay_rate NUMERIC := 0.85;
    v_frontier JSONB;
    v_next JSONB;
    v_all JSONB := '[]'::jsonb;
    v_seen UUID[] := '{}';
    v_depth INT := 0;
BEGIN
    -- 1. Identify incident and verify tenant access via RLS (SECURITY INVOKER)
    SELECT inc.org_id INTO v_org_id
    FROM public.incidents inc
    WHERE inc.id = p_incident_id;

    IF v_org_id IS NULL THEN
        RAISE EXCEPTION 'Access denied or incident % not found in accessible organisation', p_incident_id
            USING ERRCODE = '42501';
    END IF;

    -- 2. Retrieve uncalibrated scoring config if defined for this organisation
    SELECT COALESCE(
        (SELECT weight FROM public.scoring_config WHERE org_id = v_org_id AND config_key IN ('exposure', 'weight_exposure') LIMIT 1),
        0.80
    ) INTO v_default_exposure;

    SELECT COALESCE(
        (SELECT weight FROM public.scoring_config WHERE org_id = v_org_id AND config_key IN ('likelihood', 'weight_likelihood') LIMIT 1),
        0.90
    ) INTO v_default_likelihood;

    -- 3. Calculate total service assets in the workspace
    SELECT COUNT(*) INTO v_total_services
    FROM public.assets
    WHERE org_id = v_org_id AND type = 'service';


    -- 4. Level-by-level traversal. Each asset is visited once, at its shortest distance (maximum 6 hops),
    --    which keeps the work proportional to the size of the graph rather than to the number of paths.
    --    Ties between equal-length paths are broken by the lowest array of asset IDs, as before.
    SELECT COALESCE(jsonb_agg(to_jsonb(r0)), '[]'::jsonb) INTO v_frontier
    FROM (
        SELECT DISTINCT ON (m.asset_id)
            m.asset_id AS n_asset,
            ARRAY[m.asset_id] AS n_path,
            ARRAY['root'::TEXT] AS n_rels,
            m.asset_id AS n_root,
            m.id AS n_match,
            m.status AS n_status,
            m.confidence AS n_conf,
            0 AS n_depth
        FROM public.asset_matches m
        WHERE m.incident_id = p_incident_id
          AND m.status IN ('auto', 'confirmed')
        ORDER BY m.asset_id, m.id
    ) r0;

    v_all := v_frontier;
    SELECT COALESCE(array_agg((x ->> 'n_asset')::uuid), '{}') INTO v_seen FROM jsonb_array_elements(v_frontier) x;

    WHILE v_depth < 6 AND jsonb_array_length(v_frontier) > 0 LOOP
        SELECT COALESCE(jsonb_agg(to_jsonb(nx)), '[]'::jsonb) INTO v_next
        FROM (
            SELECT DISTINCT ON (e.to_asset_id)
                e.to_asset_id AS n_asset,
                t.n_path || e.to_asset_id AS n_path,
                t.n_rels || e.relation_type AS n_rels,
                t.n_root,
                t.n_match,
                t.n_status,
                t.n_conf,
                v_depth + 1 AS n_depth
            FROM jsonb_to_recordset(v_frontier)
                 AS t(n_asset uuid, n_path uuid[], n_rels text[], n_root uuid, n_match uuid, n_status text, n_conf numeric, n_depth int)
            JOIN public.dependency_edges e
              ON e.org_id = v_org_id
             AND e.from_asset_id = t.n_asset
            WHERE NOT (e.to_asset_id = ANY(v_seen))
            ORDER BY e.to_asset_id, (t.n_path || e.to_asset_id), (t.n_rels || e.relation_type)
        ) nx;

        v_depth := v_depth + 1;
        EXIT WHEN jsonb_array_length(v_next) = 0;
        SELECT v_seen || COALESCE(array_agg((x ->> 'n_asset')::uuid), '{}') INTO v_seen FROM jsonb_array_elements(v_next) x;
        v_all := v_all || v_next;
        v_frontier := v_next;
    END LOOP;

    RETURN QUERY
    WITH deduped_paths AS (
        SELECT
            t.n_asset AS current_asset_id,
            t.n_depth AS hop_depth,
            t.n_path AS path_asset_ids,
            t.n_rels AS path_relations,
            t.n_root AS root_asset_id,
            t.n_match AS match_id,
            t.n_status AS match_status,
            t.n_conf AS match_confidence
        FROM jsonb_to_recordset(v_all)
             AS t(n_asset uuid, n_path uuid[], n_rels text[], n_root uuid, n_match uuid, n_status text, n_conf numeric, n_depth int)
    ),
    -- MATERIALIZED so the per-asset count runs once per reached asset, not once per output column
    downstream_reach AS MATERIALIZED (
        SELECT dp.current_asset_id,
               public.internal_reachable_service_count(v_org_id, dp.current_asset_id, 6) AS reachable_services_count
        FROM deduped_paths dp
    )
    SELECT 
        a.id AS asset_id,
        a.site_code,
        a.name,
        a.type,
        a.criticality,
        a.accuracy_class,
        dp.hop_depth,
        -- Factor c = criticality / 5.0
        ROUND(a.criticality::NUMERIC / 5.0, 4) AS c,
        -- Factor r = reachable downstream services / total workspace services
        ROUND(
            CASE 
                WHEN v_total_services > 0 THEN dr.reachable_services_count::NUMERIC / v_total_services::NUMERIC
                ELSE 0.0
            END, 
            4
        ) AS r,
        -- Impact I = c * r
        ROUND((a.criticality::NUMERIC / 5.0) * (
            CASE 
                WHEN v_total_services > 0 THEN dr.reachable_services_count::NUMERIC / v_total_services::NUMERIC
                ELSE 0.0
            END
        ), 4) AS i_factor,
        -- Exposure E from scoring_config (uncalibrated)
        v_default_exposure AS exposure,
        -- Likelihood L from scoring_config with hop decay (uncalibrated)
        ROUND(v_default_likelihood * (v_decay_rate ^ dp.hop_depth), 4) AS likelihood,
        'uncalibrated'::TEXT AS calibration_status,
        -- Priority = I * E * L
        ROUND(
            ((a.criticality::NUMERIC / 5.0) * (
                CASE 
                    WHEN v_total_services > 0 THEN dr.reachable_services_count::NUMERIC / v_total_services::NUMERIC
                    ELSE 0.0
                END
            )) * v_default_exposure * (v_default_likelihood * (v_decay_rate ^ dp.hop_depth)),
            4
        ) AS priority,
        -- Range low (widened by match confidence and accuracy class, NEVER changes point estimate)
        GREATEST(0.0, ROUND(
            (((a.criticality::NUMERIC / 5.0) * (
                CASE 
                    WHEN v_total_services > 0 THEN dr.reachable_services_count::NUMERIC / v_total_services::NUMERIC
                    ELSE 0.0
                END
            )) * v_default_exposure * (v_default_likelihood * (v_decay_rate ^ dp.hop_depth))) * (
                1.0 - LEAST(0.60, (1.0 - dp.match_confidence) * 0.5 + 
                    CASE 
                        WHEN a.accuracy_class = 'exact_survey' THEN 0.05
                        WHEN a.accuracy_class = 'facility_approximate' THEN 0.15
                        ELSE 0.30
                    END
                )
            ),
            4
        )) AS range_low,
        -- Range high
        LEAST(1.0, ROUND(
            (((a.criticality::NUMERIC / 5.0) * (
                CASE 
                    WHEN v_total_services > 0 THEN dr.reachable_services_count::NUMERIC / v_total_services::NUMERIC
                    ELSE 0.0
                END
            )) * v_default_exposure * (v_default_likelihood * (v_decay_rate ^ dp.hop_depth))) * (
                1.0 + LEAST(0.60, (1.0 - dp.match_confidence) * 0.5 + 
                    CASE 
                        WHEN a.accuracy_class = 'exact_survey' THEN 0.05
                        WHEN a.accuracy_class = 'facility_approximate' THEN 0.15
                        ELSE 0.30
                    END
                )
            ),
            4
        )) AS range_high,
        -- Path formatted as JSON array of {asset_id, relation_type}
        (
            SELECT jsonb_agg(jsonb_build_object(
                'asset_id', p_id,
                'relation_type', dp.path_relations[idx]
            ))
            FROM unnest(dp.path_asset_ids) WITH ORDINALITY AS u(p_id, idx)
        ) AS path,
        dp.root_asset_id,
        dp.match_id,
        dp.match_status,
        dp.match_confidence
    FROM deduped_paths dp
    JOIN public.assets a ON a.org_id = v_org_id AND a.id = dp.current_asset_id
    JOIN downstream_reach dr ON dr.current_asset_id = dp.current_asset_id
    ORDER BY priority DESC, dp.hop_depth ASC, dp.path_asset_ids ASC;
END;
$$;

REVOKE EXECUTE ON FUNCTION public.blast_radius(UUID) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.blast_radius(UUID) TO authenticated;
