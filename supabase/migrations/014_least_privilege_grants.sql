-- ============================================================================
-- Project ATLAS - Migration 014: least-privilege table and function grants
-- Supabase gives the anon and authenticated roles broad default rights on every new public table.
-- Row-level security limits which ROWS they reach, but some rights bypass it (TRUNCATE) and some
-- are simply unnecessary. This migration removes them so each layer stands on its own:
--   * anon: no rights at all on public tables (it has no policies; signing in is required).
--   * authenticated: no TRUNCATE, REFERENCES or TRIGGER on any public table.
--   * authenticated: no INSERT, UPDATE or DELETE on audit_events (rows come only from triggers and
--     the SECURITY DEFINER audit functions; clients may read, subject to RLS).
--   * Trigger functions are not executable by anon or PUBLIC.
--   * Future tables in public start without these rights (default privileges).
-- Safe to run more than once.
-- ============================================================================
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM anon;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM anon;
REVOKE TRUNCATE, REFERENCES, TRIGGER ON ALL TABLES IN SCHEMA public FROM authenticated;
REVOKE INSERT, UPDATE, DELETE ON public.audit_events FROM authenticated;

REVOKE EXECUTE ON FUNCTION public.enforce_audit_immutability() FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.trg_audit_data_table_change() FROM PUBLIC, anon, authenticated;

ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM anon;
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE TRUNCATE, REFERENCES, TRIGGER ON TABLES FROM authenticated;
