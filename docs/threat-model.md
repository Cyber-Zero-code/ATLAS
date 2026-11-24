# Project ATLAS: Threat Model & Security Architecture

**Product**: Proprietary Cyber-Physical Risk Intelligence Platform for Multi-Tenant Security Consultancies.  
**Classification**: Evidence Management & Deterministic Impact Evaluation.

---

## 1. System Overview & Trust Boundaries

Project ATLAS links cyber telemetry (incidents from senders like CyberShield X) with physical and operational asset graphs (substations, water pumps, fibre routes, cloud datacenters).

### Trust Boundaries
1. **Client Browser to Supabase API**: HTTPS encrypted, signed JWT with explicit `aal` claim.
2. **Database Execution Boundary (PostgreSQL RLS)**: Every query, table access, and RPC runs under `SECURITY INVOKER` evaluating `auth.uid()`, workspace memberships, and `aal = 'aal2'`.
3. **Storage Bucket (`evidence`)**: Private object storage partitioned by organisation prefix (`<org_id>/...`).
4. **Tenant Boundary**: Strict complete isolation between client organisations and private security service firms.

---

## 2. STRIDE Threat Analysis

| Threat Category | Potential Threat | ATLAS Architecture & Mitigation |
| :--- | :--- | :--- |
| **Spoofing** | • Attacker steals analyst password to impersonate user.<br>• Attacker spoofs tenant identity in user metadata. | • **Mandatory MFA (AAL2)**: Sessions without `aal2` claim are blocked across UI and rejected by RLS RESTRICTIVE policies.<br>• **Database-Authoritative RBAC**: Roles and tenant memberships are resolved exclusively from `public.memberships` using database foreign keys, ignoring `raw_user_meta_data`. |
| **Tampering** | • Malicious analyst or compromised credential modifies historical audit events.<br>• Attacker tampers with stored incident evidence files in bucket.<br>• Man-in-the-middle alters telemetry in transit. | • **Append-Only Hash-Chained Audit Ledger**: Database triggers (`prevent_audit_tampering`) block all `UPDATE`, `DELETE`, and `TRUNCATE` operations (SQLSTATE `55000`). Each record hashes `prev_hash` + row payload (SHA-256).<br>• **Web Crypto Evidence Verification**: Evidence files are hashed in-browser before upload, verified immediately after storage upload, and can be re-hashed on demand via the "Verify" button with append-only custody logs.<br>• **Strict Payload Validation**: Incident intake (`ingest_incident`) validates schema version, allowlists event types, rejects stale timestamps (>10m), and forbids unknown keys (SQLSTATE `22023`). |
| **Repudiation** | • User denies performing actions (e.g. deleting an asset or confirming an incident match). | • **Automated Database Audit Triggers**: All data modifications trigger atomic writes to `public.audit_events` capturing actor ID, actor role, timestamp, action name, target UUID, and payload hash. |
| **Information Disclosure** | • Cross-tenant data leakage between competing security firms or client organisations.<br>• Sensitive physical infrastructure location leakage (see Section 3). | • **Multi-Tenant Row-Level Security (RLS)**: Enforced and enabled across 100% of tables. Composite foreign keys `(org_id, id)` prevent cross-tenant relations.<br>• **Zero Cross-Tenant Reads**: Verified by 35 behavioural test assertions in `security_suite.sql`. Anon role receives 0 rows everywhere. |
| **Denial of Service** | • Attacker submits cyclical dependency graphs causing recursive blast-radius loops.<br>• Massive file upload exhaust storage or memory. | • **Cycle-Guarded BFS with Depth Ceiling**: `blast_radius()` SQL function tracks visited asset IDs and caps traversal depth at 6.<br>• **Hard Upload Limits**: Max 5 MB / 10,000 rows on asset imports; max 50 MB on evidence files, strictly validated before upload and in database RPCs. |
| **Elevation of Privilege** | • Analyst attempts to delete critical assets or modify workspace memberships.<br>• Analyst calls administrative maintenance procedures. | • **Role-Based Row Security Policies**: Analysts can insert/view assets and dependencies, but cannot delete assets (`atlas:admin` required).<br>• **SECURITY INVOKER Functions**: All RPCs run with caller credentials, enforcing member permissions and preventing privilege escalation. |

---

## 3. Sensitive-Location Leakage: Abuse Cases & Mitigations

Critical physical infrastructure (e.g., electrical transmission substations, water treatment facilities, telecommunications fibre landings) presents acute physical security risks if coordinates are harvested or inferred.

### Abuse Case 3.1: Coordinated Physical Attack via Location Harvesting
* **Threat**: An adversary gains low-privilege read access to an organisation's workspace and scrapes exact GPS coordinates of critical power feeds and water pumping stations to plan physical sabotage.
* **Mitigation**:
  1. **Accuracy Classes (`exact_survey`, `facility_approximate`, `regional_approximate`)**: ATLAS requires declaring location precision on ingest.
  2. **Accuracy Halos on Vector Map**: Regional and approximate assets are rendered with generalized accuracy halos rather than pinpoint markers.
  3. **Gateway-Proxied Basemap Tiles / Zero Direct Browser Requests**: MapLibre renders from a neutral/blank offline canvas plus internal GeoJSON/vector sources by default. Public raster or vector tile servers are permitted only when routed through the authenticated `gateway/` tile proxy (which sends viewport `z`/`x`/`y` only, caches responses, strips client IPs/user IDs, and forbids asset/incident metadata); the client browser never contacts external tile servers directly.
  4. **Workspace Segregation**: Only authenticated users with verified AAL2 MFA belonging to that exact organisation can execute GeoJSON queries.

### Abuse Case 3.2: Site Code Enumeration & De-anonymisation
* **Threat**: A contractor or analyst maps internal site codes (e.g. `STE-0492`) to public utility registries or satellite imagery to reveal secret operational facilities.
* **Mitigation**:
  1. **Deterministic Pseudonymisation**: Site codes are validated for workspace-level uniqueness without requiring public cross-referencing.
  2. **Audit Logging of All Views & Exports**: Access to asset metadata and GeoJSON exports creates immutable entries in `public.audit_events`.
  3. **Data Minimisation**: Public identifiers are separated into optional tags; sensitive physical coordinates are restricted to authorized workspaces.

### Abuse Case 3.3: Cross-Tenant Asset Co-location Inference
* **Threat**: An attacker with accounts in two client organisations attempts to create dependency edges between them or infer shared physical feeds.
* **Mitigation**:
  1. **Database Composite Foreign Keys**: Dependency edges enforce `(org_id, from_asset_id)` and `(org_id, to_asset_id)`. Creating an edge between assets of different organisations is rejected by PostgreSQL foreign key validation (`SQLSTATE 23503`).
  2. **Independent Blast Radius Execution**: `blast_radius(incident_id)` filters edge traversals strictly within `v_org_id`, making cross-tenant impact calculation impossible.

### Abuse Case 3.4: Location Leakage via Tile Requests
* **Threat**: Fetching public raster or vector basemap tiles reveals the geographic region and zoom level an analyst is inspecting to external tile providers, CDNs, or network observers; combined with operator IP addresses, user identifiers, or unfiltered query parameters, external providers could correlate tenant identity with sensitive infrastructure locations.
* **Mitigation (Approved Rules)**:
  1. **Viewport `z`/`x`/`y` Only**: Tile requests carry strictly the `z`/`x`/`y` coordinates of the visible viewport and never include asset coordinates, site codes, incident identifiers, or any value derived from a sensitive asset.
  2. **No Direct Client Requests**: The browser never contacts external tile providers directly; every tile request passes through the `gateway/` tile proxy after existing JWT, AAL2, and workspace membership checks.
  3. **Server-Side Caching & Header Stripping**: The `gateway/` tile proxy caches fetched tiles and strips client IP addresses, user identifiers, and authorisation headers before querying an upstream tile provider.
  4. **Existing Precision Controls Preserved**: Sensitive-location controls in Section 3 remain in full force—accuracy classes, accuracy halos, and approximate labels remain unchanged.
* **Residual Risk Accepted by Developer**: Even with cached viewport `z`/`x`/`y` proxying and stripped client identifiers, upstream cache-miss fetches still disclose coarse tile indices (region and zoom level) at the gateway's egress IP to the chosen tile provider. The developer explicitly accepts this coarse viewport exposure in exchange for situational basemap context over a blank canvas, provided all four mitigations above are enforced.

---

## 4. Cryptographic Integrity & Evidence Custody

1. **Web Crypto Exclusivity**: Browser hashing uses standard `window.crypto.subtle.digest('SHA-256')` exclusively. No hand-rolled or unvetted JavaScript hash libraries.
2. **NIST / RFC 6234 Compliance**: Verified by automated test vectors in `src/utils/crypto.test.ts`.
3. **Atomic Custody Chain**:
   - Pre-upload: Browser computes SHA-256 digest $H_1$.
   - Post-upload: Browser downloads stored object from private bucket and recomputes digest $H_2$. If $H_1 \ne H_2$, the file is deleted immediately and intake fails.
   - Database Registration: `record_evidence` atomically registers metadata and an initial `INTAKE` custody event.
   - On-Demand Verification: The "Verify" button re-downloads the object, computes $H_3$, and calls `record_custody_event` (`VERIFY_HASH`), logging whether $H_3 = H_1$ to an append-only table.
