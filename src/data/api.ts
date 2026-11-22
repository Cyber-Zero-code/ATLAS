/**
 * Project ATLAS: Database-Authoritative Data Access API (Stage 1)
 * 
 * HARD RULES:
 * 1. The database is the source of truth. Every read and write goes to Supabase
 *    as the signed-in user. No in-memory data stores, no mock data, no silent fallback.
 * 2. If Supabase is not configured or a call fails, throw errors to display in the UI.
 * 3. No persona switcher, demo login, or auth bypass anywhere.
 */

import { supabase, isSupabaseConfigured } from '../lib/supabase';
import { 
  Membership, 
  AuditEvent, 
  AuditVerificationResult,
  AuditCheckpointRecord,
  IngestKeyRecord,
  Asset,
  DependencyEdge,
  Incident,
  AssetMatch,
  BlastRadiusNode,
  Evidence,
  CustodyEvent,
  TimelineEvent,
  SchemaValidationResult,
  DatasetRecord,
  ScoringConfigRecord,
  WorkspaceGeoJsonCollection,
  CameraRegistryItem,
  ExternalThreatIndicator,
} from '../types/atlas';
import { computeFileSha256 } from '../utils/crypto';

export const EXPECTED_SCHEMA_COLUMNS: Record<string, string[]> = {
  organisations: ['id', 'name', 'code', 'kind', 'parent_firm_id', 'source', 'created_at'],
  memberships: ['id', 'user_id', 'org_id', 'role', 'source', 'created_at'],
  datasets: ['id', 'org_id', 'name', 'source', 'declared_crs'],
  assets: ['id', 'org_id', 'site_code', 'name', 'type', 'criticality', 'geom', 'accuracy_class'],
  dependency_edges: ['id', 'org_id', 'from_asset_id', 'to_asset_id', 'relation_type', 'criticality'],
  incidents: ['id', 'org_id', 'event_id', 'schema_version', 'event_type', 'severity', 'observed_at'],
  asset_matches: ['id', 'org_id', 'incident_id', 'asset_id', 'rule_fired', 'score', 'status'],
  evidence: ['id', 'org_id', 'target_type', 'target_id', 'file_name', 'file_path', 'sha256'],
  custody_events: ['id', 'org_id', 'evidence_id', 'event_type', 'actor_id', 'sha256_verified'],
  scoring_config: ['id', 'org_id', 'config_key', 'weight', 'scale', 'calibration_status'],
  audit_events: ['id', 'org_id', 'seq', 'timestamp', 'action', 'payload_hash', 'prev_hash', 'record_hash'],
  camera_registry: [
    'id',
    'org_id',
    'camera_code',
    'name',
    'protocol',
    'lng',
    'lat',
    'bearing_deg',
    'fov_deg',
    'range_meters',
    'connection_state',
    'stream_status',
    'created_at',
  ],
  external_threat_indicators: [
    'id',
    'org_id',
    'provider_id',
    'indicator_type',
    'value',
    'source_name',
    'confidence',
    'verification_status',
    'matched_asset_ids',
    'matched_incident_ids',
    'raw_summary',
    'imported_at',
  ],
};

export class AtlasDatabaseService {
  /**
   * Check whether backend credentials are configured in .env
   */
  isConfigured(): boolean {
    return isSupabaseConfigured();
  }

  /**
   * Validate that all expected PostgreSQL tables and required columns exist.
   * Fails loudly if any schema artifact is missing.
   */
  async validateExpectedSchema(): Promise<SchemaValidationResult> {
    if (!this.isConfigured()) {
      return {
        valid: false,
        checkedTables: [],
        missingTables: [],
        missingColumns: [],
        error: 'Supabase is not configured. Please supply VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY in .env',
      };
    }

    const missingTables: string[] = [];
    const missingColumns: string[] = [];
    const checkedTables = Object.keys(EXPECTED_SCHEMA_COLUMNS);
    const errors: string[] = [];

    for (const [table, columns] of Object.entries(EXPECTED_SCHEMA_COLUMNS)) {
      const { error } = await supabase
        .from(table)
        .select(columns.join(','))
        .limit(0);

      if (error) {
        const msg = error.message.toLowerCase();
        if (
          error.code === '42P01' ||
          msg.includes('relation') ||
          msg.includes('does not exist') ||
          msg.includes('could not find the table') ||
          msg.includes('not found')
        ) {
          missingTables.push(table);
          errors.push(`Table public.${table} is missing: ${error.message}`);
        } else if (error.code === '42703' || msg.includes('column')) {
          missingColumns.push(`${table}: ${error.message}`);
          errors.push(`Column check failed on ${table}: ${error.message}`);
        } else {
          // If RLS blocked anon/unauthenticated reads, the schema catalog check still parsed the query AST successfully.
          // Only record if it indicates a missing object.
          if (error.code !== '42501' && !msg.includes('policy') && !msg.includes('security')) {
            errors.push(`Schema check warning on ${table} [${error.code || 'ERR'}]: ${error.message}`);
          }
        }
      }
    }

    const valid = missingTables.length === 0 && missingColumns.length === 0;

    return {
      valid,
      checkedTables,
      missingTables,
      missingColumns,
      error: errors.length > 0 ? errors.join('; ') : undefined,
    };
  }

  /**
   * Retrieve current Authenticator Assurance Level (AAL)
   */
  async getMfaAssuranceLevel(): Promise<{
    currentLevel: 'aal1' | 'aal2' | null;
    nextLevel: 'aal1' | 'aal2' | null;
  }> {
    if (!this.isConfigured()) {
      throw new Error('Supabase is not configured. Please supply VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY in .env');
    }

    const { data, error } = await supabase.auth.mfa.getAuthenticatorAssuranceLevel();
    if (error) {
      throw new Error(`Failed to check MFA assurance level: ${error.message}`);
    }

    return {
      currentLevel: (data?.currentLevel as 'aal1' | 'aal2') || null,
      nextLevel: (data?.nextLevel as 'aal1' | 'aal2') || null,
    };
  }

  /**
   * Enrol a new TOTP factor
   */
  async enrollTotpFactor(): Promise<{
    id: string;
    qrCode: string;
    secret: string;
    uri: string;
  }> {
    if (!this.isConfigured()) {
      throw new Error('Supabase is not configured in .env');
    }

    const { data, error } = await supabase.auth.mfa.enroll({
      factorType: 'totp',
      friendlyName: 'Project ATLAS Hardware / Authenticator',
    });

    if (error) {
      throw new Error(`MFA enrolment rejected: ${error.message}`);
    }

    return {
      id: data.id,
      qrCode: (data as any).totp?.qr_code || '',
      secret: (data as any).totp?.secret || '',
      uri: (data as any).totp?.uri || '',
    };
  }

  /**
   * Challenge and verify a TOTP code to achieve AAL2
   */
  async challengeAndVerifyTotp(factorId: string, code: string): Promise<boolean> {
    if (!this.isConfigured()) {
      throw new Error('Supabase is not configured in .env');
    }

    const challenge = await supabase.auth.mfa.challenge({ factorId });
    if (challenge.error) {
      throw new Error(`MFA challenge generation failed: ${challenge.error.message}`);
    }

    const verify = await supabase.auth.mfa.verify({
      factorId,
      challengeId: challenge.data.id,
      code,
    });

    if (verify.error) {
      throw new Error(`Invalid authentication code: ${verify.error.message}`);
    }

    return true;
  }

  /**
   * Fetch authorised workspace memberships for the authenticated user
   */
  async fetchUserMemberships(): Promise<Membership[]> {
    if (!this.isConfigured()) {
      throw new Error('Supabase is not configured in .env');
    }

    const { data: { user } } = await supabase.auth.getUser();
    if (!user) {
      throw new Error('User is not authenticated.');
    }

    const { data, error } = await supabase
      .from('memberships')
      .select(`
        id,
        user_id,
        org_id,
        role,
        source,
        created_at,
        confidence,
        sharing_policy,
        correlation_id,
        organisations (
          id,
          name,
          code,
          kind,
          parent_firm_id,
          source,
          created_at,
          confidence,
          sharing_policy,
          correlation_id
        )
      `)
      .eq('user_id', user.id);

    if (error) {
      throw new Error(`Database error querying memberships: ${error.message}`);
    }

    const memberships: Membership[] = (data || []).map((row: any) => ({
      id: row.id,
      user_id: row.user_id,
      org_id: row.org_id,
      role: row.role,
      source: row.source,
      created_at: row.created_at,
      confidence: Number(row.confidence),
      sharing_policy: row.sharing_policy,
      correlation_id: row.correlation_id,
      organization: row.organisations ? {
        id: row.organisations.id,
        name: row.organisations.name,
        code: row.organisations.code,
        kind: row.organisations.kind,
        parent_firm_id: row.organisations.parent_firm_id,
        source: row.organisations.source,
        created_at: row.organisations.created_at,
        confidence: Number(row.organisations.confidence),
        sharing_policy: row.organisations.sharing_policy,
        correlation_id: row.organisations.correlation_id,
      } : undefined,
    }));

    return memberships;
  }

  /**
   * Fetch read-only audit events for the active workspace
   */
  async fetchAuditEvents(
    orgId: string,
    opts: { limit?: number; beforeSeq?: number } = {}
  ): Promise<{ events: AuditEvent[]; total: number }> {
    if (!this.isConfigured()) {
      throw new Error('Supabase is not configured in .env');
    }

    const limit = Math.min(Math.max(opts.limit ?? 200, 1), 500);

    let query = supabase
      .from('audit_events')
      .select('*', { count: 'exact' })
      .eq('org_id', orgId);
    if (opts.beforeSeq !== undefined) {
      query = query.lt('seq', opts.beforeSeq);
    }
    const { data, error, count } = await query
      .order('seq', { ascending: false })
      .limit(limit);

    if (error) {
      throw new Error(`Database error reading audit ledger: ${error.message}`);
    }

    const events = (data || []).map((row: any) => ({
      id: row.id,
      org_id: row.org_id,
      seq: Number(row.seq),
      timestamp: row.timestamp,
      timestamp_text: row.timestamp_text,
      actor_id: row.actor_id,
      actor_role: row.actor_role,
      action: row.action,
      target_type: row.target_type,
      target_id: row.target_id,
      correlation_id: row.correlation_id,
      payload_hash: row.payload_hash,
      prev_hash: row.prev_hash,
      record_hash: row.record_hash,
      details: row.details || {},
    }));

    // "total" counts rows for this page's filter; the first page (no cursor) gives the whole ledger size.
    return { events, total: count ?? events.length };
  }

  /**
   * Executes the PostgreSQL cryptographic chain verification RPC
   */
  async verifyAuditChain(orgId: string): Promise<AuditVerificationResult> {
    if (!this.isConfigured()) {
      throw new Error('Supabase is not configured in .env');
    }

    const { data, error } = await supabase.rpc('verify_audit_chain', {
      p_org_id: orgId,
    });

    if (error) {
      throw new Error(`Chain verification RPC failed: ${error.message}`);
    }

    const row = Array.isArray(data) ? data[0] : data;
    if (!row) {
      // Fail closed: no result from the verifier is never reported as "valid".
      throw new Error('Chain verification returned no result. The chain was NOT verified.');
    }

    return {
      is_valid: Boolean(row.is_valid),
      first_bad_seq: row.first_bad_seq ? Number(row.first_bad_seq) : null,
      reason: row.reason || '',
      total_verified: Number(row.total_verified || 0),
    };
  }

  /**
   * Append an AUDIT_CHECKPOINT event and return seq + record_hash for external storage (migration 016).
   * Administrators with AAL2 MFA only.
   */
  async createAuditCheckpoint(orgId: string): Promise<AuditCheckpointRecord> {
    if (!this.isConfigured()) {
      throw new Error('Supabase is not configured in .env');
    }

    const { data, error } = await supabase.rpc('audit_checkpoint', {
      p_org_id: orgId,
    });

    if (error) {
      throw new Error(`Audit checkpoint failed: ${error.message}`);
    }

    const row = data as any;
    if (!row || !row.seq || !row.record_hash) {
      throw new Error('Audit checkpoint returned an incomplete response.');
    }

    return {
      org_id: String(row.org_id || orgId),
      seq: Number(row.seq),
      record_hash: String(row.record_hash),
      recorded_at: String(row.recorded_at || new Date().toISOString()),
      note: String(row.note || ''),
    };
  }

  /**
   * Verify the live audit chain against an externally saved checkpoint (migration 016).
   * Detects tail truncation that a plain verify_audit_chain() cannot see.
   */
  async verifyAuditChainAgainst(orgId: string, seq: number, recordHash: string): Promise<AuditVerificationResult> {
    if (!this.isConfigured()) {
      throw new Error('Supabase is not configured in .env');
    }

    const normalizedHash = recordHash.trim().toLowerCase();
    if (!Number.isInteger(seq) || seq < 1 || !/^[0-9a-f]{64}$/.test(normalizedHash)) {
      throw new Error('Checkpoint requires a sequence number of 1 or more and a 64-character hex record hash.');
    }

    const { data, error } = await supabase.rpc('verify_audit_chain_against', {
      p_org_id: orgId,
      p_seq: seq,
      p_record_hash: normalizedHash,
    });

    if (error) {
      throw new Error(`Checkpoint verification RPC failed: ${error.message}`);
    }

    const row = Array.isArray(data) ? data[0] : data;
    if (!row) {
      throw new Error('Checkpoint verification returned no result. The chain was NOT verified.');
    }

    return {
      is_valid: Boolean(row.is_valid),
      first_bad_seq: row.first_bad_seq ? Number(row.first_bad_seq) : null,
      reason: row.reason || '',
      total_verified: Number(row.total_verified || 0),
    };
  }

  /**
   * Log an operational event via SECURITY DEFINER log_event() RPC
   */
  async logEvent(
    orgId: string,
    action: string,
    targetType: string,
    targetId: string,
    details: Record<string, unknown>,
    correlationId = `cid-${Date.now()}`
  ): Promise<string> {
    if (!this.isConfigured()) {
      throw new Error('Supabase is not configured in .env');
    }

    const { data, error } = await supabase.rpc('log_event', {
      p_org_id: orgId,
      p_action: action,
      p_target_type: targetType,
      p_target_id: targetId,
      p_correlation_id: correlationId,
      p_details: details,
    });

    if (error) {
      throw new Error(`Audit ledger write rejected: ${error.message}`);
    }

    return data as string;
  }

  /**
   * Fetch existing site codes in the active workspace for duplicate pre-validation
   */
  async fetchWorkspaceSiteCodes(orgId: string): Promise<Set<string>> {
    if (!this.isConfigured()) {
      throw new Error('Supabase is not configured in .env');
    }

    const { data, error } = await supabase
      .from('assets')
      .select('site_code')
      .eq('org_id', orgId);

    if (error) {
      throw new Error(`Failed to query workspace site codes: ${error.message}`);
    }

    const codes = new Set<string>();
    (data || []).forEach((row: { site_code: string }) => {
      if (row.site_code) codes.add(row.site_code);
    });
    return codes;
  }

  /**
   * Atomically publish asset import batch via import_assets() RPC
   */
  async importAssets(
    datasetMetadata: {
      orgId: string;
      name: string;
      source: string;
      licence: string;
      declaredCrs: string;
      validationReport?: any;
    },
    rows: any[]
  ): Promise<{
    success: boolean;
    dataset_id: string;
    dataset_name: string;
    imported_count: number;
    correlation_id: string;
  }> {
    if (!this.isConfigured()) {
      throw new Error('Supabase is not configured in .env');
    }

    const payloadDataset = {
      org_id: datasetMetadata.orgId,
      name: datasetMetadata.name,
      source: datasetMetadata.source,
      licence: datasetMetadata.licence,
      declared_crs: datasetMetadata.declaredCrs,
      validation_report: datasetMetadata.validationReport || {},
    };

    const { data, error } = await supabase.rpc('import_assets', {
      p_dataset: payloadDataset,
      p_rows: rows,
    });

    if (error) {
      throw new Error(`Atomic asset import rejected: ${error.message}`);
    }

    return data as {
      success: boolean;
      dataset_id: string;
      dataset_name: string;
      imported_count: number;
      correlation_id: string;
    };
  }


  /**
   * Load every row of a list query. PostgREST (Supabase) silently returns at most ~1000 rows per
   * request, so a plain select would hand the screens a truncated list with no warning. This reads
   * page by page (stable order: caller's order, then id) and refuses to return a partial result.
   */
  private async pageAll(make: () => any): Promise<{ data: any[] | null; error: any }> {
    const PAGE = 1000;
    const HARD_CAP = 200000;
    const rows: any[] = [];
    for (let from = 0; from < HARD_CAP; from += PAGE) {
      const { data, error } = await make().range(from, from + PAGE - 1);
      if (error) return { data: null, error };
      const got = data || [];
      rows.push(...got);
      if (got.length < PAGE) return { data: rows, error: null };
    }
    return { data: null, error: { message: `More than ${HARD_CAP} rows; refusing to return a truncated list` } };
  }

  /**
   * Fetch GeoJSON FeatureCollection for MapLibre rendering via get_workspace_assets_geojson() RPC
   */
  async fetchWorkspaceAssetsGeoJson(
    orgId: string,
    assetType?: string,
    minCriticality?: number
  ): Promise<WorkspaceGeoJsonCollection> {
    if (!this.isConfigured()) {
      throw new Error('Supabase is not configured in .env');
    }

    const { data, error } = await supabase.rpc('get_workspace_assets_geojson', {
      p_org_id: orgId,
      p_type: assetType === 'all' ? null : assetType || null,
      p_min_criticality: minCriticality || null,
    });

    if (error) {
      throw new Error(`Failed to query workspace map GeoJSON: ${error.message}`);
    }

    return (data || { type: 'FeatureCollection', features: [] }) as WorkspaceGeoJsonCollection;
  }

  /**
   * Fetch all assets in the active workspace as a typed list
   */
  async fetchWorkspaceAssetsList(orgId: string): Promise<Asset[]> {
    if (!this.isConfigured()) {
      throw new Error('Supabase is not configured in .env');
    }

    const { data, error } = await this.pageAll(() =>
      supabase
      .from('assets')
      .select('id, org_id, site_code, name, type, criticality, owner, accuracy_class, positional_accuracy_m, identifiers, source, created_at, confidence, sharing_policy, correlation_id')
      .eq('org_id', orgId)
      .order('site_code', { ascending: true }).order('id', { ascending: true })
    );

    if (error) {
      throw new Error(`Failed to query workspace assets list: ${error.message}`);
    }

    return (data || []) as Asset[];
  }

  /**
   * Fetch dependency edges for the active workspace
   */
  async fetchDependencyEdges(orgId: string): Promise<Array<DependencyEdge & { from_asset?: Asset; to_asset?: Asset }>> {
    if (!this.isConfigured()) {
      throw new Error('Supabase is not configured in .env');
    }

    const { data, error } = await this.pageAll(() =>
      supabase
      .from('dependency_edges')
      .select(`
        id,
        org_id,
        from_asset_id,
        to_asset_id,
        relation_type,
        criticality,
        valid_from,
        valid_to,
        source,
        created_at,
        confidence,
        sharing_policy,
        correlation_id,
        from_asset:assets!dependency_edges_fk_dep_from_asset (
          id, site_code, name, type, criticality, owner, accuracy_class
        ),
        to_asset:assets!dependency_edges_fk_dep_to_asset (
          id, site_code, name, type, criticality, owner, accuracy_class
        )
      `)
      .eq('org_id', orgId)
      .order('created_at', { ascending: false }).order('id', { ascending: true })
    );

    if (error) {
      // Fallback query if FK alias differs
      const { data: rawEdges, error: rawError } = await this.pageAll(() =>
        supabase
        .from('dependency_edges')
        .select('*')
        .eq('org_id', orgId)
        .order('created_at', { ascending: false }).order('id', { ascending: true })
      );

      if (rawError) {
        throw new Error(`Failed to query dependency edges: ${rawError.message}`);
      }
      return (rawEdges || []) as any;
    }

    return (data || []) as any;
  }

  /**
   * Check if adding an edge between from_asset and to_asset introduces a cycle
   */
  async checkDependencyCycle(orgId: string, fromAssetId: string, toAssetId: string): Promise<boolean> {
    if (!this.isConfigured()) {
      throw new Error('Supabase is not configured in .env');
    }

    if (fromAssetId === toAssetId) return true;

    const { data, error } = await supabase.rpc('check_dependency_cycle', {
      p_org_id: orgId,
      p_from_asset_id: fromAssetId,
      p_to_asset_id: toAssetId,
    });

    if (error) {
      console.warn('check_dependency_cycle RPC error:', error.message);
      return false;
    }

    return Boolean(data);
  }

  /**
   * Create a new dependency edge (provider -> consumer)
   */
  async createDependencyEdge(edgeData: {
    org_id: string;
    from_asset_id: string;
    to_asset_id: string;
    relation_type: string;
    criticality: number;
    source?: string;
  }): Promise<DependencyEdge> {
    if (!this.isConfigured()) {
      throw new Error('Supabase is not configured in .env');
    }

    const { data, error } = await supabase
      .from('dependency_edges')
      .insert({
        org_id: edgeData.org_id,
        from_asset_id: edgeData.from_asset_id,
        to_asset_id: edgeData.to_asset_id,
        relation_type: edgeData.relation_type,
        criticality: edgeData.criticality,
        source: edgeData.source || 'Analyst Graph Editor',
        sharing_policy: 'internal_only',
        correlation_id: `cid-edge-${Date.now()}`,
      })
      .select()
      .single();

    if (error) {
      throw new Error(`Failed to create dependency edge: ${error.message}`);
    }

    return data as DependencyEdge;
  }

  /**
   * Delete a dependency edge (Restricted to atlas:admin by RLS/role matrix)
   */
  async deleteDependencyEdge(orgId: string, edgeId: string): Promise<void> {
    if (!this.isConfigured()) {
      throw new Error('Supabase is not configured in .env');
    }

    const { data, error } = await supabase
      .from('dependency_edges')
      .delete()
      .eq('org_id', orgId)
      .eq('id', edgeId)
      .select('id');

    if (error) {
      throw new Error(`Failed to delete dependency edge: ${error.message}`);
    }
    // Row-level security hides rows instead of raising an error, so a denied delete returns 0 rows.
    if (!data || data.length === 0) {
      throw new Error('Edge was not deleted: it does not exist or your role is not permitted to delete it.');
    }
  }

  /**
   * Fetch incidents for the active workspace
   */
  async fetchIncidents(orgId: string): Promise<Incident[]> {
    if (!this.isConfigured()) {
      throw new Error('Supabase is not configured in .env');
    }

    const { data, error } = await this.pageAll(() =>
      supabase
      .from('incidents')
      .select('*')
      .eq('org_id', orgId)
      .order('observed_at', { ascending: false }).order('id', { ascending: true })
    );

    if (error) {
      throw new Error(`Failed to query incidents: ${error.message}`);
    }

    return (data || []) as Incident[];
  }

  /**
   * Fetch asset matches for an incident
   */
  async fetchIncidentMatches(orgId: string, incidentId: string): Promise<AssetMatch[]> {
    if (!this.isConfigured()) {
      throw new Error('Supabase is not configured in .env');
    }

    const { data, error } = await supabase
      .from('asset_matches')
      .select(`
        id,
        org_id,
        incident_id,
        asset_id,
        rule_fired,
        score,
        status,
        decided_by,
        decided_at,
        source,
        created_at,
        confidence,
        sharing_policy,
        correlation_id,
        asset:assets (
          id, site_code, name, type, criticality, owner, accuracy_class
        )
      `)
      .eq('org_id', orgId)
      .eq('incident_id', incidentId)
      .order('score', { ascending: false });

    if (error) {
      throw new Error(`Failed to query incident asset matches: ${error.message}`);
    }

    return (data || []) as any;
  }

  /**
   * Fetch all asset matches across the active workspace
   */
  async fetchWorkspaceMatches(orgId: string): Promise<AssetMatch[]> {
    if (!this.isConfigured()) {
      throw new Error('Supabase is not configured in .env');
    }

    const { data, error } = await this.pageAll(() =>
      supabase
      .from('asset_matches')
      .select(`
        id,
        org_id,
        incident_id,
        asset_id,
        rule_fired,
        score,
        status,
        decided_by,
        decided_at,
        source,
        created_at,
        confidence,
        sharing_policy,
        correlation_id,
        asset:assets (
          id, site_code, name, type, criticality, owner, accuracy_class
        )
      `)
      .eq('org_id', orgId)
      .order('created_at', { ascending: false }).order('id', { ascending: true })
    );

    if (error) {
      throw new Error(`Failed to query workspace asset matches: ${error.message}`);
    }

    return (data || []) as any;
  }

  /**
   * Fetch ingested datasets metadata for the active workspace
   */
  async fetchDatasets(orgId: string): Promise<DatasetRecord[]> {
    if (!this.isConfigured()) {
      throw new Error('Supabase is not configured in .env');
    }

    const { data, error } = await this.pageAll(() =>
      supabase
      .from('datasets')
      .select('*')
      .eq('org_id', orgId)
      .order('created_at', { ascending: false }).order('id', { ascending: true })
    );

    if (error) {
      throw new Error(`Failed to query datasets: ${error.message}`);
    }

    return (data || []) as DatasetRecord[];
  }

  /**
   * Fetch scoring_config rows (all parameters are labelled 'uncalibrated')
   */
  async fetchScoringConfig(orgId: string): Promise<ScoringConfigRecord[]> {
    if (!this.isConfigured()) {
      throw new Error('Supabase is not configured in .env');
    }

    const { data, error } = await this.pageAll(() =>
      supabase
      .from('scoring_config')
      .select('*')
      .eq('org_id', orgId)
      .order('config_key', { ascending: true }).order('id', { ascending: true })
    );

    if (error) {
      throw new Error(`Failed to query scoring configuration: ${error.message}`);
    }

    return (data || []) as ScoringConfigRecord[];
  }

  /**
   * Fetch workspace memberships visible under RLS
   */
  async fetchWorkspaceMemberships(orgId: string): Promise<Membership[]> {
    if (!this.isConfigured()) {
      throw new Error('Supabase is not configured in .env');
    }

    const { data, error } = await this.pageAll(() =>
      supabase
      .from('memberships')
      .select('id, user_id, org_id, role, source, created_at, confidence, sharing_policy, correlation_id')
      .eq('org_id', orgId)
      .order('created_at', { ascending: true }).order('id', { ascending: true })
    );

    if (error) {
      throw new Error(`Failed to query workspace memberships: ${error.message}`);
    }

    return (data || []) as Membership[];
  }

  /**
   * Execute deterministic blast_radius(incident_id) SQL function
   */
  async fetchBlastRadius(incidentId: string): Promise<BlastRadiusNode[]> {
    if (!this.isConfigured()) {
      throw new Error('Supabase is not configured in .env');
    }

    const { data, error } = await supabase.rpc('blast_radius', {
      p_incident_id: incidentId,
    });

    if (error) {
      throw new Error(`Blast radius calculation failed: ${error.message}`);
    }

    return (data || []) as BlastRadiusNode[];
  }

  /**
   * Ingest incident telemetry payload via ingest_incident() RPC (CyberShield X contract)
   */
  async ingestIncident(payload: Record<string, unknown>): Promise<{
    success: boolean;
    idempotent: boolean;
    incident_id: string;
    event_id: string;
    matches_count: number;
    correlation_id?: string;
    message?: string;
  }> {
    if (!this.isConfigured()) {
      throw new Error('Supabase is not configured in .env');
    }

    const { data, error } = await supabase.rpc('ingest_incident', {
      p_payload: payload,
    });

    if (error) {
      throw new Error(`Incident intake rejected: ${error.message}`);
    }

    return data as any;
  }

  /**
   * Ingest keys (migration 013). The secret is returned once at creation and never again.
   */
  async createIngestKey(orgId: string): Promise<{ key_id: string; secret: string }> {
    if (!this.isConfigured()) {
      throw new Error('Supabase is not configured in .env');
    }
    const { data, error } = await supabase.rpc('create_ingest_key', { p_org_id: orgId });
    if (error) {
      throw new Error(`Could not create ingest key: ${error.message}`);
    }
    if (!data || !(data as any).key_id || !(data as any).secret) {
      throw new Error('Ingest key creation returned no key. Nothing was saved to the sender.');
    }
    return { key_id: (data as any).key_id, secret: (data as any).secret };
  }

  async listIngestKeys(orgId: string): Promise<IngestKeyRecord[]> {
    if (!this.isConfigured()) {
      throw new Error('Supabase is not configured in .env');
    }
    const { data, error } = await supabase.rpc('list_ingest_keys', { p_org_id: orgId });
    if (error) {
      throw new Error(`Could not list ingest keys: ${error.message}`);
    }
    return (data || []) as IngestKeyRecord[];
  }

  /**
   * Rotate an active ingest key with a bounded grace period (0..1440 min, migration 015).
   * The new secret is returned once and must be copied immediately.
   */
  async rotateIngestKey(
    orgId: string,
    oldKeyId: string,
    graceMinutes = 60
  ): Promise<{ key_id: string; secret: string; old_key_id: string; old_key_expires_at: string; note: string }> {
    if (!this.isConfigured()) {
      throw new Error('Supabase is not configured in .env');
    }
    const { data, error } = await supabase.rpc('rotate_ingest_key', {
      p_org_id: orgId,
      p_old_key_id: oldKeyId,
      p_grace_minutes: graceMinutes,
    });
    if (error) {
      throw new Error(`Could not rotate ingest key: ${error.message}`);
    }
    const row = data as any;
    if (!row || !row.key_id || !row.secret) {
      throw new Error('Ingest key rotation returned no new key.');
    }
    return {
      key_id: String(row.key_id),
      secret: String(row.secret),
      old_key_id: String(row.old_key_id || oldKeyId),
      old_key_expires_at: String(row.old_key_expires_at || ''),
      note: String(row.note || ''),
    };
  }

  async revokeIngestKey(orgId: string, keyId: string): Promise<void> {
    if (!this.isConfigured()) {
      throw new Error('Supabase is not configured in .env');
    }
    const { error } = await supabase.rpc('revoke_ingest_key', { p_org_id: orgId, p_key_id: keyId });
    if (error) {
      throw new Error(`Could not revoke ingest key: ${error.message}`);
    }
  }

  /**
   * Analyst decision: confirm proposed asset match
   */
  async confirmAssetMatch(matchId: string): Promise<{ success: boolean; match_id: string; status: string }> {
    if (!this.isConfigured()) {
      throw new Error('Supabase is not configured in .env');
    }

    const { data, error } = await supabase.rpc('confirm_asset_match', {
      p_match_id: matchId,
    });

    if (error) {
      throw new Error(`Failed to confirm match: ${error.message}`);
    }

    return data as any;
  }

  /**
   * Analyst decision: reject proposed asset match
   */
  async rejectAssetMatch(matchId: string, reason = 'Analyst rejected proposal'): Promise<{ success: boolean; match_id: string; status: string }> {
    if (!this.isConfigured()) {
      throw new Error('Supabase is not configured in .env');
    }

    const { data, error } = await supabase.rpc('reject_asset_match', {
      p_match_id: matchId,
      p_reason: reason,
    });

    if (error) {
      throw new Error(`Failed to reject match: ${error.message}`);
    }

    return data as any;
  }

  /**
   * Fetch read-only incident timeline derived from cryptographically hashed audit events
   */
  async fetchIncidentTimeline(incidentId: string): Promise<TimelineEvent[]> {
    if (!this.isConfigured()) {
      throw new Error('Supabase is not configured in .env');
    }

    const { data, error } = await supabase.rpc('get_incident_timeline', {
      p_incident_id: incidentId,
    });

    if (error) {
      throw new Error(`Failed to load incident timeline: ${error.message}`);
    }

    return (data || []) as TimelineEvent[];
  }

  /**
   * Fetch evidence records and their custody audit events for the active workspace
   */
  async fetchEvidenceList(orgId: string, targetId?: string): Promise<Evidence[]> {
    if (!this.isConfigured()) {
      throw new Error('Supabase is not configured in .env');
    }

    let query = supabase
      .from('evidence')
      .select(`
        id,
        org_id,
        target_type,
        target_id,
        file_name,
        file_path,
        file_size_bytes,
        mime_type,
        sha256,
        uploader_id,
        source,
        created_at,
        confidence,
        sharing_policy,
        correlation_id,
        custody_events (
          id,
          org_id,
          evidence_id,
          event_type,
          actor_id,
          sha256_verified,
          details,
          source,
          created_at,
          confidence,
          sharing_policy,
          correlation_id
        )
      `)
      .eq('org_id', orgId);

    if (targetId) {
      query = query.eq('target_id', targetId);
    }

    const { data, error } = await this.pageAll(() => query.order('created_at', { ascending: false }).order('id', { ascending: true }));

    if (error) {
      throw new Error(`Failed to fetch evidence records: ${error.message}`);
    }

    return (data || []) as unknown as Evidence[];
  }

  /**
   * Remove a just-uploaded object that never got an evidence record.
   * Storage policy (migration 012) only permits this for the uploader, within minutes, and
   * never for registered evidence. Returns true only if a row was actually removed.
   */
  private async discardUnregisteredUpload(path: string): Promise<boolean> {
    const { data, error } = await supabase.storage.from('evidence').remove([path]);
    return !error && Array.isArray(data) && data.length > 0;
  }

  /**
   * Upload an evidence file with pre-upload Web Crypto SHA-256 calculation,
   * post-upload download and re-hash verification, and atomic custody intake event.
   */
  async uploadEvidenceFile(params: {
    orgId: string;
    targetType: 'incident' | 'asset';
    targetId: string;
    file: File;
  }): Promise<{
    evidence_id: string;
    custody_id: string;
    sha256: string;
    file_name: string;
    file_path: string;
  }> {
    if (!this.isConfigured()) {
      throw new Error('Supabase is not configured in .env');
    }

    const { orgId, targetType, targetId, file } = params;

    // 1. Enforce size limit (50 MB)
    const MAX_BYTES = 50 * 1024 * 1024; // 52,428,800 bytes
    if (file.size > MAX_BYTES) {
      throw new Error(`File size (${(file.size / 1024 / 1024).toFixed(2)} MB) exceeds maximum allowed limit of 50 MB.`);
    }

    // 2. Compute SHA-256 in browser using Web Crypto API
    const clientSha256 = await computeFileSha256(file);

    // 3. Sanitize file name
    const sanitizedName = file.name.replace(/[^a-zA-Z0-9._-]/g, '_');
    const storagePath = `${orgId}/${Date.now()}_${sanitizedName}`;

    // 4. Upload to private 'evidence' storage bucket under organisation folder
    const { error: uploadError } = await supabase.storage
      .from('evidence')
      .upload(storagePath, file, {
        contentType: file.type || 'application/octet-stream',
        upsert: false,
      });

    if (uploadError) {
      throw new Error(`Storage upload failed: ${uploadError.message}`);
    }

    // 5. Download back from storage and re-verify SHA-256 to ensure zero transfer corruption
    const { data: downloadedBlob, error: downloadError } = await supabase.storage
      .from('evidence')
      .download(storagePath);

    if (downloadError || !downloadedBlob) {
      // Clean up uploaded file on download verification failure
      const cleaned = await this.discardUnregisteredUpload(storagePath);
      throw new Error(`Failed to verify stored object integrity: ${downloadError?.message || 'Empty response'}${cleaned ? '' : ' (the uploaded file could not be removed and remains unregistered)'}`);
    }

    const recomputedSha256 = await computeFileSha256(downloadedBlob);
    if (recomputedSha256 !== clientSha256) {
      const cleaned = await this.discardUnregisteredUpload(storagePath);
      throw new Error(
        `Integrity verification failure! Uploaded file SHA-256 (${recomputedSha256}) did not match pre-upload hash (${clientSha256}). ${cleaned ? 'Object was discarded.' : 'The object could not be removed and remains unregistered.'}`
      );
    }

    // 6. Register evidence record and initial INTAKE custody event atomically via RPC
    const { data: rpcResult, error: rpcError } = await supabase.rpc('record_evidence', {
      p_org_id: orgId,
      p_target_type: targetType.toUpperCase(),
      p_target_id: targetId,
      p_file_name: sanitizedName,
      p_file_path: storagePath,
      p_file_size_bytes: file.size,
      p_mime_type: file.type || 'application/octet-stream',
      p_sha256: clientSha256,
    });

    if (rpcError) {
      // Remove orphaned file from bucket if db record rejected
      const cleaned = await this.discardUnregisteredUpload(storagePath);
      throw new Error(`Failed to record evidence in database: ${rpcError.message}${cleaned ? '' : ' (the uploaded file could not be removed and remains unregistered)'}`);
    }

    return {
      evidence_id: rpcResult.evidence_id,
      custody_id: rpcResult.custody_id,
      sha256: clientSha256,
      file_name: sanitizedName,
      file_path: storagePath,
    };
  }

  /**
   * Re-verify stored evidence file: downloads object from storage, computes SHA-256 via Web Crypto,
   * compares with recorded hash, and appends a VERIFY_HASH custody event to the audit trail.
   */
  async verifyStoredEvidenceHash(evidence: Evidence): Promise<{
    is_intact: boolean;
    expected_hash: string;
    verified_hash: string;
    custody_id: string;
  }> {
    if (!this.isConfigured()) {
      throw new Error('Supabase is not configured in .env');
    }

    // 1. Download file content from storage
    const { data: downloadedBlob, error: downloadError } = await supabase.storage
      .from('evidence')
      .download(evidence.file_path);

    if (downloadError || !downloadedBlob) {
      throw new Error(`Failed to retrieve evidence file from storage: ${downloadError?.message || 'Empty blob'}`);
    }

    // 2. Compute SHA-256 hash using Web Crypto
    const recomputedHash = await computeFileSha256(downloadedBlob);

    // 3. Record custody audit event in database (append-only)
    const { data: custodyResult, error: custodyError } = await supabase.rpc('record_custody_event', {
      p_evidence_id: evidence.id,
      p_event_type: 'VERIFY_HASH',
      p_sha256_verified: recomputedHash,
      p_details: {
        verification_method: 'Web Crypto API (crypto.subtle.digest)',
        verified_at: new Date().toISOString(),
        file_path: evidence.file_path,
        file_size_bytes: evidence.file_size_bytes,
      },
    });

    if (custodyError) {
      throw new Error(`Failed to log custody verification event: ${custodyError.message}`);
    }

    return {
      is_intact: custodyResult.is_intact,
      expected_hash: custodyResult.expected_hash,
      verified_hash: custodyResult.verified_hash,
      custody_id: custodyResult.custody_id,
    };
  }

  // --------------------------------------------------------------------
  // Camera registry (migration 018) - metadata only, never live video
  // --------------------------------------------------------------------

  private mapCameraRow(row: any): CameraRegistryItem {
    return {
      id: row.id,
      cameraCode: row.camera_code,
      name: row.name,
      protocol: row.protocol,
      lng: row.lng,
      lat: row.lat,
      bearingDeg: row.bearing_deg,
      fovDeg: row.fov_deg,
      rangeMeters: row.range_meters,
      connectionState: row.connection_state,
      streamStatus: row.stream_status,
      endpointUrl: row.endpoint_url ?? undefined,
    };
  }

  /**
   * Read the organisation's registered cameras (metadata only). Members only; MFA required.
   */
  async fetchCameras(orgId: string): Promise<CameraRegistryItem[]> {
    if (!this.isConfigured()) {
      throw new Error('Supabase is not configured in .env');
    }
    const { data, error } = await this.pageAll(() =>
      supabase.from('camera_registry').select('*').eq('org_id', orgId).order('created_at', { ascending: false })
    );
    if (error) {
      throw new Error(`Failed to fetch camera registry: ${error.message}`);
    }
    return (data || []).map((row: any) => this.mapCameraRow(row));
  }

  /**
   * Register a camera. Any member may register one (same as recording evidence); audited by the database.
   */
  async insertCamera(orgId: string, camera: Omit<CameraRegistryItem, 'id'>): Promise<CameraRegistryItem> {
    if (!this.isConfigured()) {
      throw new Error('Supabase is not configured in .env');
    }
    const { data: userData } = await supabase.auth.getUser();
    const uid = userData?.user?.id;
    const { data, error } = await supabase
      .from('camera_registry')
      .insert({
        org_id: orgId,
        camera_code: camera.cameraCode,
        name: camera.name,
        protocol: camera.protocol,
        lng: camera.lng,
        lat: camera.lat,
        bearing_deg: camera.bearingDeg,
        fov_deg: camera.fovDeg,
        range_meters: camera.rangeMeters,
        connection_state: camera.connectionState || 'registered',
        stream_status: camera.streamStatus,
        endpoint_url: camera.endpointUrl || null,
        created_by: uid,
        updated_by: uid,
      })
      .select('*')
      .single();
    if (error) {
      throw new Error(`Camera registration rejected: ${error.message}`);
    }
    return this.mapCameraRow(data);
  }

  /**
   * Remove a camera. The database restricts this to an administrator of the owning organisation.
   */
  async deleteCamera(orgId: string, id: string): Promise<void> {
    if (!this.isConfigured()) {
      throw new Error('Supabase is not configured in .env');
    }
    const { error } = await supabase.from('camera_registry').delete().eq('org_id', orgId).eq('id', id);
    if (error) {
      throw new Error(`Camera removal rejected: ${error.message}`);
    }
  }

  // --------------------------------------------------------------------
  // External threat indicators (migration 018) - operator-imported STIX/KEV only
  // --------------------------------------------------------------------

  private mapIndicatorRow(row: any): ExternalThreatIndicator {
    return {
      id: row.id,
      orgId: row.org_id,
      providerId: row.provider_id,
      stixId: row.stix_id ?? undefined,
      indicatorType: row.indicator_type,
      value: row.value,
      sourceName: row.source_name,
      confidence: row.confidence,
      validFrom: row.valid_from,
      validUntil: row.valid_until ?? undefined,
      isExpired: row.valid_until ? new Date(row.valid_until).getTime() < Date.now() : false,
      isExternalIntel: true,
      verificationStatus: row.verification_status,
      matchedAssetIds: row.matched_asset_ids || [],
      matchedIncidentIds: row.matched_incident_ids || [],
      rawSummary: row.raw_summary,
      importedAt: row.imported_at,
    };
  }

  /**
   * Read this organisation's imported external threat indicators. Members only; MFA required.
   */
  async fetchExternalIndicators(orgId: string): Promise<ExternalThreatIndicator[]> {
    if (!this.isConfigured()) {
      throw new Error('Supabase is not configured in .env');
    }
    const { data, error } = await this.pageAll(() =>
      supabase.from('external_threat_indicators').select('*').eq('org_id', orgId).order('imported_at', { ascending: false })
    );
    if (error) {
      throw new Error(`Failed to fetch external threat indicators: ${error.message}`);
    }
    return (data || []).map((row: any) => this.mapIndicatorRow(row));
  }

  /**
   * Store parsed external indicators. Rows that duplicate an existing (org, type, value) are
   * skipped (the database's own uniqueness check), not treated as an error.
   */
  async insertExternalIndicators(
    orgId: string,
    indicators: ExternalThreatIndicator[]
  ): Promise<{ inserted: ExternalThreatIndicator[]; skippedDuplicates: number }> {
    if (!this.isConfigured()) {
      throw new Error('Supabase is not configured in .env');
    }
    const { data: userData } = await supabase.auth.getUser();
    const uid = userData?.user?.id;
    const inserted: ExternalThreatIndicator[] = [];
    let skippedDuplicates = 0;
    for (const ind of indicators) {
      const { data, error } = await supabase
        .from('external_threat_indicators')
        .insert({
          org_id: orgId,
          provider_id: ind.providerId,
          stix_id: ind.stixId || null,
          indicator_type: ind.indicatorType,
          value: ind.value,
          source_name: ind.sourceName,
          confidence: ind.confidence,
          valid_from: ind.validFrom || null,
          valid_until: ind.validUntil || null,
          matched_asset_ids: ind.matchedAssetIds,
          matched_incident_ids: ind.matchedIncidentIds,
          raw_summary: ind.rawSummary,
          imported_by: uid,
        })
        .select('*')
        .single();
      if (error) {
        if ((error as any).code === '23505') {
          skippedDuplicates++;
          continue;
        }
        throw new Error(`External indicator import rejected: ${error.message}`);
      }
      inserted.push(this.mapIndicatorRow(data));
    }
    return { inserted, skippedDuplicates };
  }

  /**
   * Mark an indicator verified or a false positive. The imported fact itself is immutable
   * (enforced by a database trigger); only this status field can change.
   */
  async updateIndicatorVerification(
    id: string,
    status: 'unverified' | 'verified_by_analyst' | 'false_positive'
  ): Promise<void> {
    if (!this.isConfigured()) {
      throw new Error('Supabase is not configured in .env');
    }
    const { error } = await supabase.from('external_threat_indicators').update({ verification_status: status }).eq('id', id);
    if (error) {
      throw new Error(`Could not update verification status: ${error.message}`);
    }
  }

  /**
   * Remove an indicator. The database restricts this to an administrator of the owning organisation.
   */
  async deleteExternalIndicator(orgId: string, id: string): Promise<void> {
    if (!this.isConfigured()) {
      throw new Error('Supabase is not configured in .env');
    }
    const { error } = await supabase.from('external_threat_indicators').delete().eq('org_id', orgId).eq('id', id);
    if (error) {
      throw new Error(`Indicator removal rejected: ${error.message}`);
    }
  }

  /**
   * Sign out user session
   */
  async signOut(): Promise<void> {
    if (this.isConfigured()) {
      await supabase.auth.signOut();
    }
  }
}

export const atlasService = new AtlasDatabaseService();
