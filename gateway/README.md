# Project ATLAS — External Linux Security Execution Gateway

Optional, isolated Linux Security Worker microservice that executes registered defensive utilities (`nmap`, `tshark`, `python3`, Linux diagnostics) for Project ATLAS without touching the Supabase PostgreSQL schema or authentication system.

## Security Architecture
1. **No Privileged Database Access**: Never receives `SUPABASE_SERVICE_ROLE_KEY`. Validates the operator's AAL2 Supabase JWT (`RS256` / `ES256` / `HS256`) and verifies active organisation membership & role directly via Supabase RLS (`GET /rest/v1/memberships`) using ONLY the caller's Bearer token + public `SUPABASE_ANON_KEY`.
2. **Non-Shell Process Spawning**: Zero `exec`, `eval`, or shell interpolation (`shell: false`). Every binary uses a fixed path and structured argument array.
3. **Target Allowlist Enforcement**: `GATEWAY_TARGET_ALLOWLIST` strictly limits scan targets; `127.0.0.0/8`, `::1`, and `169.254.0.0/16` (cloud metadata) are unconditionally rejected.
4. **RBAC & Explicit Approval**: Medium-risk discovery (`nmap -sn`) requires explicit confirmation; High-risk service identification (`nmap -sV`) requires `atlas:admin` role + explicit justification. NSE `--script` flags are prohibited.
5. **Container Isolation**: Runs as non-root `atlasworker`, `read_only: true`, `cap_drop: ALL`, bounded `tmpfs` `/tmp/atlas-worker-sandbox`, `pids_limit: 128`, zero Docker socket mount.

## Quick Start (Standalone Node.js)
```bash
cd gateway
cp .env.example .env
# Edit .env with SUPABASE_URL, SUPABASE_ANON_KEY, JWKS URL, and GATEWAY_TARGET_ALLOWLIST
npm install
npm run build
npm start
```

## Quick Start (Docker Compose)
```bash
cd gateway
cp .env.example .env
docker compose up -d --build
```

## Automated Gateway Tests
```bash
npm test
```
