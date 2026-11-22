-- ============================================================================
-- Project ATLAS - Migration 002: Row-Level Security & Role-Based Permissions
-- ============================================================================
-- Strict Enforcement:
-- 1. RLS is ENABLED and FORCED on every table (deny by default).
-- 2. Caller organizations are derived strictly from `public.memberships` via `auth.uid()`.
-- 3. MFA AAL2 claim `(auth.jwt() ->> 'aal') = 'aal2'` is enforced via RESTRICTIVE policies.
-- 4. Role matrix:
--    - atlas:analyst: SELECT workspace; INSERT/UPDATE assets, edges, incidents;
--                     review matches; upload evidence.
--    - atlas:admin:   Everything analyst can, PLUS DELETE assets & edges, manage memberships.
--    - Immutability:   NOBODY can UPDATE or DELETE incidents, evidence, custody_events,
--                     or audit_events. Confirmed matches cannot be modified.
-- ============================================================================

-- 1. Helper Functions (SECURITY DEFINER with explicit search_path)
CREATE OR REPLACE FUNCTION public.current_user_org_ids()
RETURNS SETOF UUID
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
    SELECT org_id 
    FROM public.memberships 
    WHERE user_id = auth.uid();
$$;

CREATE OR REPLACE FUNCTION public.user_has_role(p_org_id UUID, p_role TEXT)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
    SELECT EXISTS (
        SELECT 1 
        FROM public.memberships 
        WHERE user_id = auth.uid() 
          AND org_id = p_org_id 
          AND role = p_role
    );
$$;

CREATE OR REPLACE FUNCTION public.user_is_member(p_org_id UUID)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
    SELECT EXISTS (
        SELECT 1 
        FROM public.memberships 
        WHERE user_id = auth.uid() 
          AND org_id = p_org_id
    );
$$;

-- Revoke all function privileges from PUBLIC and anon; grant authenticated only
REVOKE EXECUTE ON FUNCTION public.current_user_org_ids() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.current_user_org_ids() TO authenticated;

REVOKE EXECUTE ON FUNCTION public.user_has_role(UUID, TEXT) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.user_has_role(UUID, TEXT) TO authenticated;

REVOKE EXECUTE ON FUNCTION public.user_is_member(UUID) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.user_is_member(UUID) TO authenticated;

-- ============================================================================
-- 2. ENABLE & FORCE RLS ON ALL TABLES
-- ============================================================================
ALTER TABLE public.organisations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.organisations FORCE ROW LEVEL SECURITY;

ALTER TABLE public.memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.memberships FORCE ROW LEVEL SECURITY;

ALTER TABLE public.datasets ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.datasets FORCE ROW LEVEL SECURITY;

ALTER TABLE public.assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.assets FORCE ROW LEVEL SECURITY;

ALTER TABLE public.dependency_edges ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.dependency_edges FORCE ROW LEVEL SECURITY;

ALTER TABLE public.incidents ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.incidents FORCE ROW LEVEL SECURITY;

ALTER TABLE public.asset_matches ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.asset_matches FORCE ROW LEVEL SECURITY;

ALTER TABLE public.evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.evidence FORCE ROW LEVEL SECURITY;

ALTER TABLE public.custody_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.custody_events FORCE ROW LEVEL SECURITY;

ALTER TABLE public.scoring_config ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scoring_config FORCE ROW LEVEL SECURITY;

ALTER TABLE public.audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_events FORCE ROW LEVEL SECURITY;

-- ============================================================================
-- 3. MANDATORY RESTRICTIVE MFA AAL2 POLICIES
-- An aal1 or unauthenticated session reads/writes 0 rows across every table.
-- ============================================================================
CREATE POLICY rst_aal2_organisations ON public.organisations
    AS RESTRICTIVE FOR ALL TO authenticated
    USING ((auth.jwt() ->> 'aal') = 'aal2')
    WITH CHECK ((auth.jwt() ->> 'aal') = 'aal2');

CREATE POLICY rst_aal2_memberships ON public.memberships
    AS RESTRICTIVE FOR ALL TO authenticated
    USING ((auth.jwt() ->> 'aal') = 'aal2')
    WITH CHECK ((auth.jwt() ->> 'aal') = 'aal2');

CREATE POLICY rst_aal2_datasets ON public.datasets
    AS RESTRICTIVE FOR ALL TO authenticated
    USING ((auth.jwt() ->> 'aal') = 'aal2')
    WITH CHECK ((auth.jwt() ->> 'aal') = 'aal2');

CREATE POLICY rst_aal2_assets ON public.assets
    AS RESTRICTIVE FOR ALL TO authenticated
    USING ((auth.jwt() ->> 'aal') = 'aal2')
    WITH CHECK ((auth.jwt() ->> 'aal') = 'aal2');

CREATE POLICY rst_aal2_dependency_edges ON public.dependency_edges
    AS RESTRICTIVE FOR ALL TO authenticated
    USING ((auth.jwt() ->> 'aal') = 'aal2')
    WITH CHECK ((auth.jwt() ->> 'aal') = 'aal2');

CREATE POLICY rst_aal2_incidents ON public.incidents
    AS RESTRICTIVE FOR ALL TO authenticated
    USING ((auth.jwt() ->> 'aal') = 'aal2')
    WITH CHECK ((auth.jwt() ->> 'aal') = 'aal2');

CREATE POLICY rst_aal2_asset_matches ON public.asset_matches
    AS RESTRICTIVE FOR ALL TO authenticated
    USING ((auth.jwt() ->> 'aal') = 'aal2')
    WITH CHECK ((auth.jwt() ->> 'aal') = 'aal2');

CREATE POLICY rst_aal2_evidence ON public.evidence
    AS RESTRICTIVE FOR ALL TO authenticated
    USING ((auth.jwt() ->> 'aal') = 'aal2')
    WITH CHECK ((auth.jwt() ->> 'aal') = 'aal2');

CREATE POLICY rst_aal2_custody_events ON public.custody_events
    AS RESTRICTIVE FOR ALL TO authenticated
    USING ((auth.jwt() ->> 'aal') = 'aal2')
    WITH CHECK ((auth.jwt() ->> 'aal') = 'aal2');

CREATE POLICY rst_aal2_scoring_config ON public.scoring_config
    AS RESTRICTIVE FOR ALL TO authenticated
    USING ((auth.jwt() ->> 'aal') = 'aal2')
    WITH CHECK ((auth.jwt() ->> 'aal') = 'aal2');

CREATE POLICY rst_aal2_audit_events ON public.audit_events
    AS RESTRICTIVE FOR ALL TO authenticated
    USING ((auth.jwt() ->> 'aal') = 'aal2')
    WITH CHECK ((auth.jwt() ->> 'aal') = 'aal2');

-- ============================================================================
-- 4. PERMISSIVE TENANT & ROLE POLICIES
-- ============================================================================

-- 4.1 Organisations
CREATE POLICY perm_select_organisations ON public.organisations
    FOR SELECT TO authenticated
    USING (id IN (SELECT public.current_user_org_ids()));

-- 4.2 Memberships
CREATE POLICY perm_select_memberships ON public.memberships
    FOR SELECT TO authenticated
    USING (org_id IN (SELECT public.current_user_org_ids()));

CREATE POLICY perm_insert_memberships ON public.memberships
    FOR INSERT TO authenticated
    WITH CHECK (public.user_has_role(org_id, 'atlas:admin'));

CREATE POLICY perm_update_memberships ON public.memberships
    FOR UPDATE TO authenticated
    USING (public.user_has_role(org_id, 'atlas:admin'))
    WITH CHECK (public.user_has_role(org_id, 'atlas:admin'));

CREATE POLICY perm_delete_memberships ON public.memberships
    FOR DELETE TO authenticated
    USING (public.user_has_role(org_id, 'atlas:admin'));

-- 4.3 Datasets
CREATE POLICY perm_select_datasets ON public.datasets
    FOR SELECT TO authenticated
    USING (org_id IN (SELECT public.current_user_org_ids()));

CREATE POLICY perm_insert_datasets ON public.datasets
    FOR INSERT TO authenticated
    WITH CHECK (public.user_is_member(org_id));

CREATE POLICY perm_update_datasets ON public.datasets
    FOR UPDATE TO authenticated
    USING (public.user_is_member(org_id))
    WITH CHECK (public.user_is_member(org_id));

CREATE POLICY perm_delete_datasets ON public.datasets
    FOR DELETE TO authenticated
    USING (public.user_has_role(org_id, 'atlas:admin'));

-- 4.4 Assets
-- Analysts may SELECT, INSERT, UPDATE. ONLY Admin may DELETE.
CREATE POLICY perm_select_assets ON public.assets
    FOR SELECT TO authenticated
    USING (org_id IN (SELECT public.current_user_org_ids()));

CREATE POLICY perm_insert_assets ON public.assets
    FOR INSERT TO authenticated
    WITH CHECK (public.user_is_member(org_id));

CREATE POLICY perm_update_assets ON public.assets
    FOR UPDATE TO authenticated
    USING (public.user_is_member(org_id))
    WITH CHECK (public.user_is_member(org_id));

CREATE POLICY perm_delete_assets ON public.assets
    FOR DELETE TO authenticated
    USING (public.user_has_role(org_id, 'atlas:admin'));

-- 4.5 Dependency Edges
-- Analysts may SELECT, INSERT, UPDATE. ONLY Admin may DELETE.
CREATE POLICY perm_select_dependency_edges ON public.dependency_edges
    FOR SELECT TO authenticated
    USING (org_id IN (SELECT public.current_user_org_ids()));

CREATE POLICY perm_insert_dependency_edges ON public.dependency_edges
    FOR INSERT TO authenticated
    WITH CHECK (public.user_is_member(org_id));

CREATE POLICY perm_update_dependency_edges ON public.dependency_edges
    FOR UPDATE TO authenticated
    USING (public.user_is_member(org_id))
    WITH CHECK (public.user_is_member(org_id));

CREATE POLICY perm_delete_dependency_edges ON public.dependency_edges
    FOR DELETE TO authenticated
    USING (public.user_has_role(org_id, 'atlas:admin'));

-- 4.6 Incidents
-- Incidents are append-only: SELECT & INSERT allowed. UPDATE and DELETE denied to all.
CREATE POLICY perm_select_incidents ON public.incidents
    FOR SELECT TO authenticated
    USING (org_id IN (SELECT public.current_user_org_ids()));

CREATE POLICY perm_insert_incidents ON public.incidents
    FOR INSERT TO authenticated
    WITH CHECK (public.user_is_member(org_id));

-- 4.7 Asset Matches
-- Analysts and Admins may review proposed/auto matches. Confirmed matches are locked.
CREATE POLICY perm_select_asset_matches ON public.asset_matches
    FOR SELECT TO authenticated
    USING (org_id IN (SELECT public.current_user_org_ids()));

CREATE POLICY perm_insert_asset_matches ON public.asset_matches
    FOR INSERT TO authenticated
    WITH CHECK (public.user_is_member(org_id));

CREATE POLICY perm_update_asset_matches ON public.asset_matches
    FOR UPDATE TO authenticated
    USING (
        public.user_is_member(org_id) 
        AND status IN ('auto', 'proposed')
    )
    WITH CHECK (
        public.user_is_member(org_id)
    );

-- 4.8 Evidence
-- Append-only: SELECT and INSERT permitted. UPDATE and DELETE denied to all.
CREATE POLICY perm_select_evidence ON public.evidence
    FOR SELECT TO authenticated
    USING (org_id IN (SELECT public.current_user_org_ids()));

CREATE POLICY perm_insert_evidence ON public.evidence
    FOR INSERT TO authenticated
    WITH CHECK (public.user_is_member(org_id));

-- 4.9 Custody Events
-- Append-only: SELECT and INSERT permitted. UPDATE and DELETE denied to all.
CREATE POLICY perm_select_custody_events ON public.custody_events
    FOR SELECT TO authenticated
    USING (org_id IN (SELECT public.current_user_org_ids()));

CREATE POLICY perm_insert_custody_events ON public.custody_events
    FOR INSERT TO authenticated
    WITH CHECK (public.user_is_member(org_id));

-- 4.10 Scoring Config
CREATE POLICY perm_select_scoring_config ON public.scoring_config
    FOR SELECT TO authenticated
    USING (org_id IN (SELECT public.current_user_org_ids()));

CREATE POLICY perm_update_scoring_config ON public.scoring_config
    FOR UPDATE TO authenticated
    USING (public.user_has_role(org_id, 'atlas:admin'))
    WITH CHECK (public.user_has_role(org_id, 'atlas:admin'));

-- 4.11 Audit Events
-- Read-only to authenticated workspace members.
-- Writes happen exclusively via database triggers and log_event() RPC.
CREATE POLICY perm_select_audit_events ON public.audit_events
    FOR SELECT TO authenticated
    USING (org_id IN (SELECT public.current_user_org_ids()));
