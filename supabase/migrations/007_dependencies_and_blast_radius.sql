-- ============================================================================
-- Project ATLAS - Migration 007: Dependency Graph & Deterministic Blast Radius
-- ============================================================================
-- 1. blast_radius(incident_id UUID):
--    - SECURITY INVOKER: Runs with caller privileges, fully adhering to RLS.
--    - Follows edges from provider (from_asset_id) to consumer (to_asset_id).
--    - Starts strictly from 'auto' and 'confirmed' matches in public.asset_matches.
--    - Maximum traversal depth: 6 hops.
--    - Cycle guard: Prevents infinite loops using path arrays.
--    - Keeps shortest path per asset; breaks ties by lowest array of asset IDs.
--    - Factors:
--        c = criticality / 5.0
--        r = share of workspace's service assets reachable downstream
--        I = c * r
--        E (exposure) and L (likelihood) from scoring_config (labelled 'uncalibrated')
--        Priority = I * E * L
--        Uncertainty range [low, high] widened by match confidence and accuracy class
--        (point estimate is NEVER changed).
--    - Path returned as JSONB array of {asset_id, relation_type}.
-- 2. check_dependency_cycle(p_org_id, p_from_asset_id, p_to_asset_id):
--    - Detects whether an edge from provider to consumer creates a circular graph.
-- ============================================================================

-- 1. Deterministic Blast Radius Function (SECURITY INVOKER)
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

    RETURN QUERY
    WITH RECURSIVE
    -- Seed from auto and confirmed matches only
    root_matches AS (
        SELECT 
            m.id AS match_id,
            m.asset_id AS root_asset_id,
            m.status AS match_status,
            m.confidence AS match_confidence,
            m.org_id
        FROM public.asset_matches m
        WHERE m.incident_id = p_incident_id
          AND m.status IN ('auto', 'confirmed')
    ),
    -- Recursive traversal following provider -> consumer (from_asset -> to_asset)
    traversal AS (
        -- Base case: Root matched assets (hop_depth = 0)
        SELECT 
            rm.root_asset_id AS current_asset_id,
            0 AS hop_depth,
            ARRAY[rm.root_asset_id] AS path_asset_ids,
            ARRAY['root'::TEXT] AS path_relations,
            rm.root_asset_id,
            rm.match_id,
            rm.match_status,
            rm.match_confidence
        FROM root_matches rm

        UNION ALL

        -- Recursive step: Follow dependency edges from_asset -> to_asset
        SELECT 
            e.to_asset_id AS current_asset_id,
            t.hop_depth + 1 AS hop_depth,
            t.path_asset_ids || e.to_asset_id AS path_asset_ids,
            t.path_relations || e.relation_type AS path_relations,
            t.root_asset_id,
            t.match_id,
            t.match_status,
            t.match_confidence
        FROM traversal t
        JOIN public.dependency_edges e 
          ON e.org_id = v_org_id 
         AND e.from_asset_id = t.current_asset_id
        WHERE t.hop_depth < 6
          -- Cycle guard: target asset must not already be in the traversal path
          AND NOT (e.to_asset_id = ANY(t.path_asset_ids))
    ),
    -- Keep the shortest path per asset; break depth ties deterministically by lowest array of asset IDs
    deduped_paths AS (
        SELECT DISTINCT ON (t.current_asset_id)
            t.current_asset_id,
            t.hop_depth,
            t.path_asset_ids,
            t.path_relations,
            t.root_asset_id,
            t.match_id,
            t.match_status,
            t.match_confidence
        FROM traversal t
        ORDER BY t.current_asset_id, t.hop_depth ASC, t.path_asset_ids ASC
    ),
    -- Calculate downstream reachable service assets for each reached asset
    downstream_reach AS (
        SELECT 
            dp.current_asset_id,
            COUNT(DISTINCT reachable.to_asset_id) AS reachable_services_count
        FROM deduped_paths dp
        LEFT JOIN LATERAL (
            -- Sub-traversal to find all services downstream of dp.current_asset_id
            WITH RECURSIVE down_services AS (
                SELECT dp.current_asset_id AS node_id, ARRAY[dp.current_asset_id] AS visited, 0 AS depth
                UNION ALL
                SELECT e2.to_asset_id, ds.visited || e2.to_asset_id, ds.depth + 1
                FROM down_services ds
                JOIN public.dependency_edges e2 ON e2.org_id = v_org_id AND e2.from_asset_id = ds.node_id
                WHERE ds.depth < 6 AND NOT (e2.to_asset_id = ANY(ds.visited))
            )
            SELECT DISTINCT ds.node_id AS to_asset_id
            FROM down_services ds
            JOIN public.assets sa ON sa.org_id = v_org_id AND sa.id = ds.node_id AND sa.type = 'service'
        ) reachable ON TRUE
        GROUP BY dp.current_asset_id
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

-- 2. Cycle Detection Query Function (SECURITY INVOKER)
CREATE OR REPLACE FUNCTION public.check_dependency_cycle(
    p_org_id UUID,
    p_from_asset_id UUID,
    p_to_asset_id UUID
)
RETURNS BOOLEAN
LANGUAGE plpgsql
STABLE
SECURITY INVOKER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_found BOOLEAN := false;
BEGIN
    IF p_from_asset_id = p_to_asset_id THEN
        RETURN true;
    END IF;

    WITH RECURSIVE downstream AS (
        SELECT to_asset_id AS node_id, ARRAY[to_asset_id] AS path, 1 AS depth
        FROM public.dependency_edges
        WHERE org_id = p_org_id AND from_asset_id = p_to_asset_id

        UNION ALL

        SELECT e.to_asset_id, d.path || e.to_asset_id, d.depth + 1
        FROM downstream d
        JOIN public.dependency_edges e ON e.org_id = p_org_id AND e.from_asset_id = d.node_id
        WHERE d.depth < 10 AND NOT (e.to_asset_id = ANY(d.path))
    )
    SELECT EXISTS (
        SELECT 1 FROM downstream WHERE node_id = p_from_asset_id
    ) INTO v_found;

    RETURN v_found;
END;
$$;

REVOKE EXECUTE ON FUNCTION public.check_dependency_cycle(UUID, UUID, UUID) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.check_dependency_cycle(UUID, UUID, UUID) TO authenticated;
