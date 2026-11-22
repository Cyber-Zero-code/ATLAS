-- ============================================================================
-- Project ATLAS - Migration 004: Private Evidence Storage Bucket & Isolation
-- ============================================================================
-- Storage Isolation Rules:
-- 1. Private bucket 'evidence' (public = false).
-- 2. Objects must be nested under their organisation id folder: `<org_id>/...`
-- 3. Caller must be an authenticated member of the target organisation.
-- 4. Mandatory MFA AAL2: (auth.jwt() ->> 'aal') = 'aal2'.
-- 5. Append-only: SELECT and INSERT permitted. UPDATE and DELETE denied.
-- 6. Plain INSERT into storage.buckets: fails loudly if bucket already exists.
-- ============================================================================

-- 1. Evidence Storage Bucket Creation
-- Plain INSERT: fails loudly if the bucket already exists.
INSERT INTO storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
VALUES (
    'evidence',
    'evidence',
    false,
    52428800, -- 50 MB per object limit
    ARRAY[
        'application/json',
        'text/csv',
        'text/plain',
        'application/pdf',
        'application/vnd.tcpdump.pcap',
        'application/octet-stream',
        'image/png',
        'image/jpeg',
        'text/yaml',
        'application/x-yaml'
    ]::text[]
);

-- 2. Storage Policies on storage.objects
-- Plain CREATE POLICY: fails loudly if policy already exists.
CREATE POLICY "evidence_aal2_restrictive" ON storage.objects
    AS RESTRICTIVE FOR ALL TO authenticated
    USING ((auth.jwt() ->> 'aal') = 'aal2')
    WITH CHECK ((auth.jwt() ->> 'aal') = 'aal2');

CREATE POLICY "evidence_select_tenant_folder" ON storage.objects
    FOR SELECT TO authenticated
    USING (
        bucket_id = 'evidence'
        AND (
            CASE 
                WHEN name ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/'
                THEN split_part(name, '/', 1)::uuid IN (SELECT public.current_user_org_ids())
                ELSE false
            END
        )
    );

CREATE POLICY "evidence_insert_tenant_folder" ON storage.objects
    FOR INSERT TO authenticated
    WITH CHECK (
        bucket_id = 'evidence'
        AND (
            CASE 
                WHEN name ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/'
                THEN split_part(name, '/', 1)::uuid IN (SELECT public.current_user_org_ids())
                ELSE false
            END
        )
    );
