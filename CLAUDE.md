# Project ATLAS: Cyber-Physical Risk Intelligence

ATLAS answers one question: when a cyber event hits, which physical sites, services and people are exposed, what should we act on first, and how sure are we? It links an authorised asset-and-dependency graph to incidents on a map, computes a blast radius, and shows its evidence and uncertainty. Analysts decide; ATLAS shows the working.

This file holds the rules that apply to every session. Read it first, every time. If a request conflicts with it, say so and ask before proceeding.

## Working with me
- I am a solo developer and I review every change. Hand-review security-critical code with me, even if you wrote it.
- Plan before coding. For any non-trivial task, post an ordered task list with dependencies and S/M/L sizes (no dates) and wait for approval.
- Small PRs. Each states what changed, its tests, and its security impact.
- If a requirement is ambiguous, ask. Never guess on tenancy, auth, audit, or sensitive coordinates.
- End each session with a short note: verified progress (code, tests, or deploy records), next three tasks, blockers, new security or data-quality findings.
- Speed comes from strict scope and priority order, never from skipping tests or security.

## Locked decisions
- **Beachhead (H1):** private security service firms (MSSPs, IR and OT/resilience consultancies). Government is a later destination via these partners. Add no government-specific features, accreditation claims, or classified-network language.
- **Tenancy:** shared PostgreSQL with row-level security. The same image must be able to run single-tenant later.
- **Identity:** Supabase Auth with MFA. Never build authentication.
- **Basemap:** neutral/blank style plus our own vector layers. No public tile servers. Licence decision deferred to pre-pilot.
- **Licence:** proprietary.
- **Data:** synthetic only. No real customer data, no real critical-site coordinates, until counsel has cleared the India items and a partner has authorised data. Use fictional locations in all fixtures.

## Architecture (fixed)
Platform: Google AI Studio (React + Vite + TypeScript) for the front end, Supabase for the backend. No custom server.
- Map: MapLibre GL JS, neutral/blank style, our own vector layers. No public tile servers.
- Database: Supabase Postgres + PostGIS. Tenancy enforced by row-level security on every table, plus checks in code.
- Auth: Supabase Auth with MFA. Never build authentication.
- Files and evidence: Supabase Storage.
- Dependency graph: recursive CTEs in Postgres (SQL function). No graph engine.
- Audit: hash-chained audit_events table, written by database triggers, not client code.
- Keep the schema portable plain Postgres. Avoid Supabase-only features where a standard Postgres option exists, so we can self-host later.
- Secrets: only the public anon key in the client. Never the service_role key. Keep keys in .env, never committed.

## Scope
**Current phase: Phase 1, Vertical Slice v2.**
Build, in this order, finishing each before starting the next:
1. Tenancy + auth + audit foundation (RLS, Supabase Auth, hash-chained audit log, cross-tenant test harness)
2. Asset import (CSV, GeoJSON) + map
3. Dependency edges + blast radius
4. Incident intake + rule-based asset matching
5. Audited timeline + SHA-256 evidence hashing

**Do not build, stub, or scaffold (ask first if a task seems to need one):**
- Deferred to Phase 2: saved map views, GeoPackage import, single-tenant packaging test, observability beyond correlation IDs, role-based coordinate generalisation (design and document it, do not build it).
- Deferred stack and formats: GeoServer, Kafka, PyTorch, QGIS as a component; Shapefile, KML, GeoTIFF, 3D.
- Later features: correlation/clustering, copilot, what-if scenarios, SIEM and STIX/TAXII ingest, any LLM calls.
- Custom authentication; separate "security", "admin", or "reports" modules.
- UI polish beyond what the slice needs to function.

If you see a way to finish sooner by cutting scope, propose it. Never cut priority 1 or thin out security tests.

## Data model rules
- Entities: organisation, user/role, asset, dependency edge (from_asset, to_asset, relationship_type, criticality, source, validity_period), incident, asset_match, evidence, audit_event.
- Every record carries: source, timestamp, confidence, sharing policy, correlation ID.
- Keep the original geometry. Log every transformation. A point without accuracy metadata is never treated as exact.

## Ranking and blast radius
- Traversal is deterministic: same input, same output, and every result is explainable as a path through the graph.
- The UI shows factors and a range, not one headline number: I = c x r (criticality x share of dependent services reached), E = exposure, L = likelihood, each 0 to 1. Priority = I x E x L may be computed.
- Evidence confidence and data quality widen or narrow the range. They never move the point estimate.
- Weights and scales live in config, labelled "uncalibrated".

## Asset matching
- Rules first: exact, then fuzzy match on hostnames, IPs/CIDRs, cloud account IDs, and site codes.
- Every match shows its confidence and the rule that fired.
- Below the confidence threshold (default 0.90), a match is a proposal an analyst must confirm. Store confirmations as labelled data.

## Security rules (non-negotiable)
- Write tests first for anything touching authentication, tenancy, or audit.
- Zero successful cross-tenant reads across the API, tiles endpoint, exports, and audit log.
- Hash-chained audit log for sign-in, access, change, export, and approval. SHA-256 on evidence at intake, with custody events recorded.
- Upload safety: size and type limits, CRS and geometry validation, clear errors on malformed files.
- Exports need separate authorisation and are audited.
- No secrets in the client or in the repo. Dependency scanning and an SBOM in CI.
- Model or AI output is never auto-approved. Reports need human approval.

## Claims and language
- Never use "forensic", "defence-grade", or "predictive" in code, docs, UI, or marketing. Use "evidence management".
- Never claim certification, accreditation, or classified-network suitability.
- Outputs are review signals with uncertainty. Never attribute activity to a person or an actor.
- ATLAS does no targeting or attack planning, no covert tracking of individuals, and no unauthorised collection.

## CyberShield X (CSX) interface
- CSX is design partner zero, but the only coupling is a versioned contract. ATLAS must run without CSX.
- Every message carries a schema version, an idempotency key (event ID + signed timestamp) with replay rejection, and a correlation ID.
- Allowlisted event types and fields only. Unknown or malformed fields are rejected safely. Assets are referenced by opaque ID, never by shared database keys.
- Document what "confidence" means for each field that carries it.
- Until a real sender exists, use a mock sender.

## Definition of done for Phase 1
- Demo on realistic synthetic data: upload, map, mock incident, matched assets, blast radius, audited timeline, with no manual database edits.
- Two outside reviewers (ideally from a security firm) complete the demo script unaided.
- Short STRIDE threat model written (`docs/threat-model.md`), including sensitive-location leakage abuse cases.
- Cross-tenant test suite green in CI.
- Matching precision and recall measured on the synthetic labelled set, reported as synthetic-only.
- Every ranking in the UI links to its evidence and shows its uncertainty.

## Repo conventions
- Decisions are logged in `docs/decisions.md` (ADR-style).
- The README keeps a 10-minute demo script.
- The full Phase 1 brief lives in `ATLAS_PHASE1.md`. If it conflicts with this file, this file wins and you flag the conflict.
