# Project ATLAS: Cyber-Physical Risk Intelligence

ATLAS is a proprietary cyber-physical risk intelligence platform built for private security service firms (managed security providers, incident-response, and OT-resilience consultancies) serving multiple client organisations.

When a cyber incident occurs, ATLAS answers: **which physical sites, services, and operational dependencies are exposed, what should we act on first, and how sure are we?**

ATLAS deterministically links an authorised asset-and-dependency graph to incidents on a map, calculates a deterministic blast radius, and tracks all actions in a cryptographically verifiable audit chain and evidence custody locker.

---

## Architecture & Security Principles

1. **Database as Single Source of Truth**:
   - Single PostgreSQL database with **PostGIS in the `public` schema** (used unqualified: `geometry`, `ST_*`).
   - **`pgcrypto` in the `extensions` schema**: its cryptographic routines are called schema-qualified (`extensions.digest`, `extensions.hmac`), and every `SECURITY DEFINER` function enforces an explicit `search_path = public, extensions, pg_temp`.
   - Migrations 001 to 003 use **plain `CREATE`** for tables, indexes, policies, and triggers (never `IF NOT EXISTS` or silent trigger drops), so any stale or conflicting objects fail loudly instead of being silently kept.
   - Row-Level Security (RLS) is enabled and forced on 100% of tables (`FORCE ROW LEVEL SECURITY`).
   - Every read and write query is executed by Supabase client credentials with `aal = 'aal2'`.
   - Zero in-memory stores, zero mock data arrays, zero persona switchers.
   - Startup schema verification fails loudly if expected tables or columns are missing.

2. **Composite Keys & Relational Tenant Isolation**:
   - Every tenant table enforces uniqueness on `(org_id, id)`.
   - Child tables reference parents using composite foreign keys `(org_id, parent_id) REFERENCES parent_table(org_id, id)`.
   - Physically blocks cross-tenant relationships at the PostgreSQL relational engine level.
   - Organisations table contains strictly no `domain` column; workspace access is NEVER granted automatically from email domains.

3. **Cryptographic Audit Ledger & Web Crypto Evidence Locker**:
   - Every data table mutation triggers `internal_append_audit()` inside an advisory lock transaction, computing SHA-256 record hashes over `(org_id, seq, timestamp, actor, action, target, payload_hash, prev_hash)`.
   - `enforce_audit_immutability()` triggers block all `UPDATE`, `DELETE`, and `TRUNCATE` operations (SQLSTATE `55000`).
   - Browser hashing uses standard Web Crypto (`crypto.subtle.digest`) exclusively, verified against NIST / RFC 6234 standard test vectors.
   - Uploaded evidence files are hashed in-browser before upload, verified immediately after storage upload, and can be re-hashed on demand with append-only custody logging.

---

## 1. Migration Run Order (Supabase SQL Editor)

Run all migration scripts in `supabase/migrations/` sequentially:

1. `001_schema_and_extensions.sql` — Extensions setup (`pgcrypto` in `extensions`, PostGIS in `public`), plain `CREATE TABLE` and `CREATE INDEX` (no `IF NOT EXISTS`), unqualified `geometry`, composite primary/foreign keys.
2. `002_rls_policies_and_roles.sql` — RLS policies, RBAC roles (`atlas:admin`, `atlas:analyst`), mandatory AAL2 MFA checks.
3. `003_audit.sql` — Plain `CREATE TRIGGER` (no silent drops), schema-qualified `extensions.digest`, `SET search_path = public, extensions, pg_temp`, `verify_audit_chain()` RPC.
4. `003b_fix_core_function_names.sql` — Patch removing erroneous `extensions.` qualifier from core PostgreSQL functions (`encode`, `gen_random_uuid`).
5. `004_storage.sql` — Private `evidence` storage bucket with plain `INSERT INTO storage.buckets` (fails if bucket exists, 50MB limit, allowed MIME types) and path isolation (`<org_id>/...`).
6. `005_synthetic_seed.sql` — Single `c_user_email` constant at the top of the file to bind your authenticated user to Firm A and Client A as `atlas:admin`.
7. `006_asset_import_and_map.sql` — Atomic `import_assets(dataset, rows)` function using unqualified PostGIS `geometry` & `ST_*`, GeoJSON asset queries.
8. `007_dependencies_and_blast_radius.sql` — Dependency edges, cycle check, deterministic BFS `blast_radius(incident_id)` function.
9. `008_incident_intake_and_matching.sql` — `ingest_incident()` RPC (CyberShield X contract), 6 matching rules, confirmation/rejection RPCs.
10. `009_timeline_and_custody.sql` — Read-only `get_incident_timeline()`, `record_evidence()`, and append-only `record_custody_event()`.
11. `010_harden_log_event.sql` — Enforces AAL2 MFA, action allowlist, and 8 KB payload cap on `log_event()`.
12. `011_harden_record_evidence.sql` — Locks down evidence storage paths and target validation.
13. `012_storage_cleanup_unregistered.sql` — Permits uploader cleanup only of unregistered failed uploads within a short window.
14. `013_signed_incident_intake.sql` — Enforces HMAC-SHA256 signed incident payloads (`ingest_keys`, `create_ingest_key`, `revoke_ingest_key`, `list_ingest_keys`).
15. `014_least_privilege_grants.sql` — Revokes `anon` table/sequence access and unnecessary `authenticated` privileges.
16. `015_rotation_and_write_rights.sql` — Adds `rotate_ingest_key()` with bounded grace periods (`expires_at`) and revokes unused table write privileges.
17. `016_audit_checkpoint.sql` — Adds `audit_checkpoint()` and `verify_audit_chain_against()` to detect tail truncation.
18. `017_blast_radius_scalable.sql` — Rewrites `blast_radius()` using level-by-level BFS with shortest-path deduplication.
19. `018_camera_and_threat_indicators.sql` — Adds `camera_registry` and `external_threat_indicators` tables with composite org keys, AAL2 RLS policies, RBAC guards, and audit triggers.

---

## 2. 10-Minute Demonstration Script

Follow this step-by-step walkthrough to test the full lifecycle of Project ATLAS:

### Step 1: Sign In with MFA (AAL2)
1. Open the application in your browser.
2. Enter your credentials (`admin@aegis.test` or your Supabase user).
3. The app prompts for TOTP MFA. Scan the QR code or enter your 6-digit authenticator code.
4. Once verified to `aal2`, access is granted to the workspace shell.

### Step 2: Atomic Asset Import (EPSG:4326)
1. Click the **Import** tab in the top navigation bar.
2. Select or drop a CSV or GeoJSON asset file (e.g. `tests/fixtures/valid_assets.geojson`).
3. Notice browser validation checks: coordinate range, CRS (only EPSG:4326 accepted), required fields, and site code uniqueness.
4. Review the per-row validation table. Click **Publish to Workspace**.
5. The `import_assets()` SQL function executes atomically: all rows succeed or none are committed.

### Step 3: Interactive Map Visualization
1. Click the **Map** tab.
2. Observe assets rendered on a neutral vector canvas with custom vector layers (no third-party tile servers or external API keys).
3. Criticality and type filters dynamically filter assets.
4. Notice **approximate points** (such as regional SCADA feeds) are rendered with dashed **accuracy halos** and clearly labeled "approximate".
5. Click an asset pin to open its profile drawer (site code, criticality, accuracy class, hostnames, and IP addresses).

### Step 4: Manage Dependencies & Guard Against Cycles
1. Click the **Dependencies** tab.
2. In the dependency editor, select an upstream provider asset and downstream consumer asset.
3. Select the relation type (e.g., `powers`, `cools`, `connects_to`).
4. Attempt to create a cyclical loop (A &rarr; B &rarr; A): notice the cycle detection alert warns of graph circularity.
5. Click **Create Dependency Edge**: the relationship is saved and audited.

### Step 5: Send a Mock Cyber Incident (CyberShield X Contract)
1. Click the **Intake** tab.
2. In the **Mock CSX Sender** panel, select a synthetic incident payload (e.g., `OT_DISRUPTION` targeting SCADA networks).
3. Inspect the payload contract: schema version `1.0`, event ID, severity, signals (`hostnames`, `ips`, `cidrs`, `site_codes`, `cloud_account_ids`).
4. Click **Dispatch Ingest Incident**:
   - The `ingest_incident()` SQL function enforces strict validation, rejects unknown fields, and rejects stale timestamps (&gt;10 min).
   - Replaying the same payload demonstrates safe idempotency.

### Step 6: Review & Confirm Asset Matches
1. Scroll down to the **Incident Intake & Signal Match Engine** list.
2. Select the ingested incident to view matching results:
   - Matches scored &ge; 0.90 (exact site code, exact hostname, exact IP, cloud account) are marked `AUTO`.
   - Matches scored &lt; 0.90 (CIDR containment, fuzzy hostname) are marked `PROPOSED`.
3. As an analyst, click **Confirm Match** on a proposed CIDR match, or **Reject** with a recorded rationale.
4. Decisions are committed to `public.asset_matches` as labeled training data and audited.

### Step 7: Deterministic Blast Radius Calculation
1. Click the **Blast Radius** tab.
2. Select the active incident:
   - The `blast_radius()` SQL function traverses downstream provider-to-consumer edges up to depth 6.
   - Computes deterministic factors: $c = \text{criticality} / 5$, $r = \text{reachable share}$, $I = c \times r$, priority $= I \times E \times L$.
   - Displayed range `[low, high]` widens based on asset accuracy class and confidence.
   - Point estimates are labeled with an uncalibrated notice.
   - Inspect the exact dependency path linking the cyber incident root to downstream physical assets.

### Step 8: View Chronological Incident Timeline
1. Click the **Timeline & Evidence** tab and choose **Incident Timeline**.
2. Select your incident from the dropdown.
3. Review the chronological, read-only audit chain generated by `get_incident_timeline()`:
   - Sequential event log: ingestion, match proposals, analyst confirmations, blast radius queries, evidence uploads.
   - Expand each event to view the immutable SHA-256 record hash and payload hash.

### Step 9: Evidence Locker & Cryptographic Custody Verification
1. Click **Evidence Locker & Custody** in the view switcher.
2. Select a log file or packet capture (e.g. `scada_dump.pcap`).
3. Notice the Web Crypto engine computes the SHA-256 hash in-browser before any network transmission.
4. Click **Upload to Secure Locker**:
   - Uploads to private storage under `<org_id>/...`.
   - Downloads the object back and re-hashes to guarantee zero upload corruption.
   - Calls `record_evidence()` RPC to log metadata and an initial `INTAKE` custody event.
5. In the evidence list, click the **Verify** button:
   - Downloads the file from storage and computes SHA-256 via `crypto.subtle.digest`.
   - Confirms matching hash with a green **INTEGRITY VERIFIED** banner.
   - Logs an append-only `VERIFY_HASH` custody event to `public.custody_events`.

### Step 10: Switch Workspaces & Verify Zero Cross-Tenant Leakage
1. In the top navigation bar, use the **Workspace Switcher** to switch to the competing firm or client workspace (e.g. `Vanguard Resilience Partners` or `Archipelago Energy`).
2. Navigate to **Map**, **Dependencies**, **Intake**, **Blast Radius**, and **Timeline & Evidence**:
   - Notice that 0 assets, 0 dependency edges, 0 incidents, and 0 evidence records from Aegis are visible.
   - Every query returns strictly isolated rows for the active tenant.

---

## 3. Automated Test Suites

### A. Cryptographic Hash Vectors & Tamper Detection
Tests NIST / RFC 6234 standard test vectors, Web Crypto compatibility, and binary tamper detection:
```bash
npx tsx src/utils/crypto.test.ts
```

### B. Matching Engine Evaluation on Synthetic Labelled Data
Runs the multi-tier matching rules over the 20 benchmark incidents and reports precision, recall, and review volume:
```bash
npx tsx scripts/evaluate_matching.ts
```

### D. PostgreSQL Behavioural Security Test Suite
Run `supabase/tests/security_suite.sql` in the Supabase SQL Editor. It executes 33 test suites inside a transaction that rolls back:
- Tests positive controls and zero cross-tenant reads across all tables and RPCs.
- Verifies composite foreign keys reject cross-tenant relations.
- Verifies analyst role cannot delete assets.
- Verifies audit immutability triggers block UPDATE/DELETE with SQLSTATE `55000` and checkpoints detect tail truncation.
- Verifies incident intake enforces HMAC-SHA256 key signing, key rotation expiry, stale timestamp rejection, and strict field allowlists.
- Verifies rule ordering, scalable `blast_radius()`, and 0.90 auto-confirm threshold.
- Verifies cross-tenant evidence isolation and tamper detection.

---

## 4. What Was Not Done (Out of Scope / Deferred)

To preserve focus on core security, verifiable auditability, and deterministic graph calculations:
1. **No Default External Tile Servers or Mapbox/Google Maps API Keys**: MapLibre renders using a neutral offline vector canvas by default; operators may explicitly attach frontend-only `https://` WMS/WMTS/XYZ/GeoJSON overlays in the local workspace configuration.
2. **HSM/KMS Key Wrapping for Ingest Secrets**: Per-organisation HMAC-SHA256 ingest key creation, rotation, and revocation are enforced in PostgreSQL (`ingest_keys`); hardware HSM key wrapping is deferred to production infrastructure.
3. **No Machine Learning Neural Models or External LLM Calls**: All match scoring, workspace query interrogation, and blast radius calculations are strictly deterministic and explainable. No `@google/genai` or external AI SDKs are included.
4. **No Automated Asset Probing / Port Scanning**: ATLAS does not conduct active scanning; it relies on client-provided, authorised inventory datasets and authenticated signed telemetry senders.
