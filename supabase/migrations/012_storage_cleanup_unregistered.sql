-- ============================================================================
-- Project ATLAS - Migration 012: allow cleanup of UNREGISTERED evidence uploads only
-- Problem: if an upload succeeds but registering the evidence record fails, the file stays in
-- storage and the app could not remove it (storage had no delete rule at all).
-- Rule added: the uploader may delete an object from their own organisation folder only if
--   * it is in the 'evidence' bucket and the folder is an organisation they belong to,
--   * they uploaded it, it is under 15 minutes old, and
--   * NO evidence record points at it.
-- Registered evidence stays undeletable. The MFA (aal2) restrictive policy from 004 still applies.
-- Note: Supabase records the uploader in storage.objects.owner_id (text). If that column is
-- missing on your project the script stops with a clear message; tell the developer.
-- Safe to run more than once.
-- ============================================================================
DO $mig$
DECLARE
    v_owner_col TEXT;
BEGIN
    SELECT column_name INTO v_owner_col
    FROM information_schema.columns
    WHERE table_schema = 'storage' AND table_name = 'objects' AND column_name = 'owner_id';

    IF v_owner_col IS NULL THEN
        RAISE EXCEPTION 'storage.objects.owner_id not found; cannot scope cleanup to the uploader' USING ERRCODE = '42703';
    END IF;

    EXECUTE 'DROP POLICY IF EXISTS evidence_delete_unregistered_own ON storage.objects';
    EXECUTE $p$
        CREATE POLICY evidence_delete_unregistered_own ON storage.objects
            FOR DELETE TO authenticated
            USING (
                bucket_id = 'evidence'
                AND owner_id = auth.uid()::text
                AND created_at > (now() - interval '15 minutes')
                AND (
                    CASE
                        WHEN name ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/'
                        THEN split_part(name, '/', 1)::uuid IN (SELECT public.current_user_org_ids())
                        ELSE false
                    END
                )
                AND NOT EXISTS (
                    SELECT 1 FROM public.evidence e WHERE e.file_path = storage.objects.name
                )
            )
    $p$;
END
$mig$;
