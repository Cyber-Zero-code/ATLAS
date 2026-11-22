-- ============================================================================
-- Project ATLAS - Migration 001: Schema, Extensions, and Core Data Model
-- ============================================================================
-- 1. PostGIS is installed in the `public` schema.
-- 2. pgcrypto is loaded (location to be confirmed by user).
-- 3. Plain CREATE used for all tables and indexes (no IF NOT EXISTS) so any stale
--    or conflicting objects fail loudly during migration execution.
-- 4. Every org-owned table enforces composite uniqueness (org_id, id) and
--    composite foreign keys (org_id, parent_id) to physically prohibit cross-org
--    relational references at the database engine level.
-- ============================================================================

-- 1. Extensions
-- PostGIS is installed in public schema
CREATE EXTENSION IF NOT EXISTS postgis WITH SCHEMA public;

-- pgcrypto (temporary schema location pending user confirmation)
CREATE SCHEMA IF NOT EXISTS extensions;
CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA extensions;
GRANT USAGE ON SCHEMA extensions TO postgres, anon, authenticated, service_role;

-- 2. Organizations Table
-- Plain CREATE TABLE: fails loudly if table already exists.
-- Strictly NO 'domain' column: memberships are NEVER granted automatically from email domains.
CREATE TABLE public.organisations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    code TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL CHECK (kind IN ('standalone', 'firm', 'client')),
    parent_firm_id UUID REFERENCES public.organisations(id) ON DELETE RESTRICT,
    source TEXT NOT NULL DEFAULT 'System Provisioning',
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()),
    confidence NUMERIC CHECK (confidence >= 0.0 AND confidence <= 1.0) DEFAULT 1.0,
    sharing_policy TEXT NOT NULL DEFAULT 'internal_only',
    correlation_id TEXT NOT NULL DEFAULT gen_random_uuid()::text,
    CONSTRAINT chk_org_parent_firm CHECK (
        (kind = 'client' AND parent_firm_id IS NOT NULL) OR
        (kind IN ('standalone', 'firm') AND parent_firm_id IS NULL)
    )
);

CREATE INDEX idx_organisations_code ON public.organisations(code);
CREATE INDEX idx_organisations_parent ON public.organisations(parent_firm_id);

-- 3. Memberships Table
-- Firm users access client workspaces ONLY through explicit membership rows.
CREATE TABLE public.memberships (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    org_id UUID NOT NULL REFERENCES public.organisations(id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK (role IN ('atlas:admin', 'atlas:analyst')),
    source TEXT NOT NULL DEFAULT 'Admin Direct Assignment',
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()),
    confidence NUMERIC CHECK (confidence >= 0.0 AND confidence <= 1.0) DEFAULT 1.0,
    sharing_policy TEXT NOT NULL DEFAULT 'internal_only',
    correlation_id TEXT NOT NULL DEFAULT gen_random_uuid()::text,
    CONSTRAINT uq_memberships_user_org UNIQUE (user_id, org_id),
    CONSTRAINT uq_memberships_org_id UNIQUE (org_id, id)
);

CREATE INDEX idx_memberships_user ON public.memberships(user_id);
CREATE INDEX idx_memberships_org ON public.memberships(org_id);

-- 4. Datasets Table
CREATE TABLE public.datasets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES public.organisations(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    source TEXT NOT NULL,
    licence TEXT NOT NULL DEFAULT 'Proprietary / Synthetic',
    declared_crs TEXT NOT NULL DEFAULT 'EPSG:4326',
    validation_report JSONB NOT NULL DEFAULT '{}'::jsonb,
    row_count INTEGER NOT NULL DEFAULT 0 CHECK (row_count >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()),
    confidence NUMERIC CHECK (confidence >= 0.0 AND confidence <= 1.0) DEFAULT 1.0,
    sharing_policy TEXT NOT NULL DEFAULT 'internal_only',
    correlation_id TEXT NOT NULL DEFAULT gen_random_uuid()::text,
    CONSTRAINT uq_datasets_org_id UNIQUE (org_id, id)
);

CREATE INDEX idx_datasets_org ON public.datasets(org_id);

-- 5. Assets Table
-- PostGIS geometry type in public schema
CREATE TABLE public.assets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES public.organisations(id) ON DELETE CASCADE,
    dataset_id UUID,
    site_code TEXT NOT NULL,
    name TEXT NOT NULL,
    type TEXT NOT NULL CHECK (type IN ('site', 'power_feed', 'fibre_route', 'cloud_region', 'service')),
    criticality INTEGER NOT NULL CHECK (criticality >= 1 AND criticality <= 5),
    owner TEXT NOT NULL,
    geom geometry(Geometry, 4326),
    original_geom JSONB,
    accuracy_class TEXT NOT NULL CHECK (accuracy_class IN ('exact_survey', 'facility_approximate', 'regional_approximate')),
    positional_accuracy_m NUMERIC CHECK (positional_accuracy_m >= 0),
    identifiers JSONB NOT NULL DEFAULT '{"hostnames": [], "ip_addresses": [], "cidrs": [], "cloud_account_ids": []}'::jsonb,
    source TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()),
    confidence NUMERIC CHECK (confidence >= 0.0 AND confidence <= 1.0) DEFAULT 1.0,
    sharing_policy TEXT NOT NULL DEFAULT 'internal_only',
    correlation_id TEXT NOT NULL DEFAULT gen_random_uuid()::text,
    CONSTRAINT fk_assets_dataset FOREIGN KEY (org_id, dataset_id) REFERENCES public.datasets(org_id, id) ON DELETE SET NULL,
    CONSTRAINT uq_assets_org_id UNIQUE (org_id, id),
    CONSTRAINT uq_assets_org_site_code UNIQUE (org_id, site_code)
);

CREATE INDEX idx_assets_org ON public.assets(org_id);
CREATE INDEX idx_assets_type ON public.assets(type);
CREATE INDEX idx_assets_geom ON public.assets USING GIST(geom);

-- 6. Dependency Edges Table
-- from_asset is provider (upstream), to_asset is consumer (impacted); impact flows from -> to.
CREATE TABLE public.dependency_edges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES public.organisations(id) ON DELETE CASCADE,
    from_asset_id UUID NOT NULL,
    to_asset_id UUID NOT NULL,
    relation_type TEXT NOT NULL CHECK (relation_type IN ('powers', 'hosts', 'connects_to', 'supplies', 'monitors', 'cools')),
    criticality INTEGER NOT NULL CHECK (criticality >= 1 AND criticality <= 5),
    valid_from TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()),
    valid_to TIMESTAMPTZ,
    source TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()),
    confidence NUMERIC CHECK (confidence >= 0.0 AND confidence <= 1.0) DEFAULT 1.0,
    sharing_policy TEXT NOT NULL DEFAULT 'internal_only',
    correlation_id TEXT NOT NULL DEFAULT gen_random_uuid()::text,
    CONSTRAINT chk_dep_no_self_edge CHECK (from_asset_id <> to_asset_id),
    CONSTRAINT fk_dep_from_asset FOREIGN KEY (org_id, from_asset_id) REFERENCES public.assets(org_id, id) ON DELETE CASCADE,
    CONSTRAINT fk_dep_to_asset FOREIGN KEY (org_id, to_asset_id) REFERENCES public.assets(org_id, id) ON DELETE CASCADE,
    CONSTRAINT uq_dependency_edges_org_id UNIQUE (org_id, id),
    CONSTRAINT uq_dependency_edges_pair UNIQUE (org_id, from_asset_id, to_asset_id, relation_type)
);

CREATE INDEX idx_dep_edges_org ON public.dependency_edges(org_id);
CREATE INDEX idx_dep_edges_from ON public.dependency_edges(from_asset_id);
CREATE INDEX idx_dep_edges_to ON public.dependency_edges(to_asset_id);

-- 7. Incidents Table
CREATE TABLE public.incidents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES public.organisations(id) ON DELETE CASCADE,
    event_id TEXT NOT NULL,
    schema_version TEXT NOT NULL DEFAULT '1.0',
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    observed_at TIMESTAMPTZ NOT NULL,
    signals JSONB NOT NULL DEFAULT '{}'::jsonb,
    source TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()),
    confidence NUMERIC CHECK (confidence >= 0.0 AND confidence <= 1.0) DEFAULT 1.0,
    sharing_policy TEXT NOT NULL DEFAULT 'internal_only',
    correlation_id TEXT NOT NULL DEFAULT gen_random_uuid()::text,
    CONSTRAINT uq_incidents_org_id UNIQUE (org_id, id),
    CONSTRAINT uq_incidents_idempotency UNIQUE (org_id, source, event_id)
);

CREATE INDEX idx_incidents_org ON public.incidents(org_id);
CREATE INDEX idx_incidents_event ON public.incidents(event_id);

-- 8. Asset Matches Table
CREATE TABLE public.asset_matches (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES public.organisations(id) ON DELETE CASCADE,
    incident_id UUID NOT NULL,
    asset_id UUID NOT NULL,
    rule_fired TEXT NOT NULL,
    score NUMERIC NOT NULL CHECK (score >= 0.0 AND score <= 1.0),
    status TEXT NOT NULL CHECK (status IN ('auto', 'proposed', 'confirmed', 'rejected')),
    decided_by UUID REFERENCES auth.users(id),
    decided_at TIMESTAMPTZ,
    source TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()),
    confidence NUMERIC CHECK (confidence >= 0.0 AND confidence <= 1.0) DEFAULT 1.0,
    sharing_policy TEXT NOT NULL DEFAULT 'internal_only',
    correlation_id TEXT NOT NULL DEFAULT gen_random_uuid()::text,
    CONSTRAINT fk_matches_incident FOREIGN KEY (org_id, incident_id) REFERENCES public.incidents(org_id, id) ON DELETE CASCADE,
    CONSTRAINT fk_matches_asset FOREIGN KEY (org_id, asset_id) REFERENCES public.assets(org_id, id) ON DELETE CASCADE,
    CONSTRAINT uq_asset_matches_org_id UNIQUE (org_id, id),
    CONSTRAINT uq_asset_matches_rule UNIQUE (org_id, incident_id, asset_id, rule_fired)
);

CREATE INDEX idx_asset_matches_org ON public.asset_matches(org_id);
CREATE INDEX idx_asset_matches_incident ON public.asset_matches(incident_id);
CREATE INDEX idx_asset_matches_asset ON public.asset_matches(asset_id);

-- 9. Evidence Table
CREATE TABLE public.evidence (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES public.organisations(id) ON DELETE CASCADE,
    target_type TEXT NOT NULL,
    target_id UUID NOT NULL,
    file_name TEXT NOT NULL,
    file_path TEXT NOT NULL,
    file_size_bytes BIGINT NOT NULL CHECK (file_size_bytes >= 0),
    mime_type TEXT NOT NULL,
    sha256 TEXT NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    uploader_id UUID NOT NULL REFERENCES auth.users(id),
    source TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()),
    confidence NUMERIC CHECK (confidence >= 0.0 AND confidence <= 1.0) DEFAULT 1.0,
    sharing_policy TEXT NOT NULL DEFAULT 'internal_only',
    correlation_id TEXT NOT NULL DEFAULT gen_random_uuid()::text,
    CONSTRAINT uq_evidence_org_id UNIQUE (org_id, id)
);

CREATE INDEX idx_evidence_org ON public.evidence(org_id);
CREATE INDEX idx_evidence_target ON public.evidence(target_type, target_id);

-- 10. Custody Events Table
-- Custody history is append-only.
CREATE TABLE public.custody_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES public.organisations(id) ON DELETE CASCADE,
    evidence_id UUID NOT NULL,
    event_type TEXT NOT NULL CHECK (event_type IN ('INTAKE', 'VERIFY_HASH', 'ACCESS', 'TRANSFERRED', 'RETENTION_FLAG')),
    actor_id UUID NOT NULL REFERENCES auth.users(id),
    sha256_verified TEXT NOT NULL CHECK (sha256_verified ~ '^[0-9a-f]{64}$'),
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    source TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()),
    confidence NUMERIC CHECK (confidence >= 0.0 AND confidence <= 1.0) DEFAULT 1.0,
    sharing_policy TEXT NOT NULL DEFAULT 'internal_only',
    correlation_id TEXT NOT NULL DEFAULT gen_random_uuid()::text,
    CONSTRAINT fk_custody_evidence FOREIGN KEY (org_id, evidence_id) REFERENCES public.evidence(org_id, id) ON DELETE CASCADE,
    CONSTRAINT uq_custody_events_org_id UNIQUE (org_id, id)
);

CREATE INDEX idx_custody_events_org ON public.custody_events(org_id);
CREATE INDEX idx_custody_events_evidence ON public.custody_events(evidence_id);

-- 11. Scoring Config Table
-- Holds weights and scales; every value must be labelled 'uncalibrated'.
CREATE TABLE public.scoring_config (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES public.organisations(id) ON DELETE CASCADE,
    config_key TEXT NOT NULL,
    weight NUMERIC NOT NULL,
    scale NUMERIC NOT NULL,
    calibration_status TEXT NOT NULL DEFAULT 'uncalibrated' CHECK (calibration_status = 'uncalibrated'),
    description TEXT NOT NULL,
    source TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()),
    confidence NUMERIC CHECK (confidence >= 0.0 AND confidence <= 1.0) DEFAULT 1.0,
    sharing_policy TEXT NOT NULL DEFAULT 'internal_only',
    correlation_id TEXT NOT NULL DEFAULT gen_random_uuid()::text,
    CONSTRAINT uq_scoring_config_org_id UNIQUE (org_id, id),
    CONSTRAINT uq_scoring_config_key UNIQUE (org_id, config_key)
);

CREATE INDEX idx_scoring_config_org ON public.scoring_config(org_id);

-- 12. Audit Events Table
-- Append-only cryptographic hash chain per organisation.
CREATE TABLE public.audit_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES public.organisations(id) ON DELETE CASCADE,
    seq BIGINT NOT NULL CHECK (seq >= 1),
    timestamp TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()),
    timestamp_text TEXT NOT NULL,
    actor_id UUID REFERENCES auth.users(id),
    actor_role TEXT NOT NULL,
    action TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT NOT NULL,
    correlation_id TEXT NOT NULL,
    payload_hash TEXT NOT NULL CHECK (payload_hash ~ '^[0-9a-f]{64}$'),
    prev_hash TEXT NOT NULL CHECK (prev_hash ~ '^[0-9a-f]{64}$'),
    record_hash TEXT NOT NULL CHECK (record_hash ~ '^[0-9a-f]{64}$'),
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    CONSTRAINT uq_audit_events_org_seq UNIQUE (org_id, seq),
    CONSTRAINT uq_audit_events_org_id UNIQUE (org_id, id)
);

CREATE INDEX idx_audit_events_org ON public.audit_events(org_id);
CREATE INDEX idx_audit_events_org_seq ON public.audit_events(org_id, seq);
