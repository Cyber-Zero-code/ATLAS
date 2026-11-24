import React, { useEffect, useState } from 'react';
import type {
  CtiProviderId,
  CtiProxySourceStatus,
  ExternalThreatIndicator,
  SelectedEntity,
} from '../../types/atlas';
import type { WorkspaceIntelligenceState } from '../../hooks/useWorkspaceIntelligence';
import {
  CTI_ADAPTER_CATALOG,
  fetchCtiProxyIndicators,
  parseCtiJsonBundle,
  probeCtiProxySources,
  type ProxyCtiSourceId,
} from '../../adapters/ctiAdapters';
import { validateGatewayEndpointUrl } from '../../adapters/gatewayClient';
import { atlasService } from '../../data/api';
import { loadOrgScopedValue, saveOrgScopedValue } from '../../utils/orgStorage';
import {
  Rss,
  Upload,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  Server,
  Trash2,
} from 'lucide-react';

interface ThreatIntelAdaptersPanelProps {
  intel: WorkspaceIntelligenceState;
  onSelectEntity: (entity: SelectedEntity) => void;
  onSendToAttribution?: (indicatorValue: string) => void;
  onIndicatorsChange?: (next: ExternalThreatIndicator[]) => void;
}

export const ThreatIntelAdaptersPanel: React.FC<ThreatIntelAdaptersPanelProps> = ({
  intel,
  onSelectEntity,
  onSendToAttribution,
  onIndicatorsChange,
}) => {
  const [indicators, setIndicators] = useState<ExternalThreatIndicator[]>([]);
  const [providerFilter, setProviderFilter] = useState<'all' | CtiProviderId>('all');
  const [bundleText, setBundleText] = useState('');
  const [selectedProvider, setSelectedProvider] = useState<CtiProviderId>('STIX_2_1');
  const [parseFeedback, setParseFeedback] = useState<{ kind: 'ok' | 'err'; text: string } | null>(null);

  const [gatewayUrl, setGatewayUrl] = useState('');
  const [proxyProbing, setProxyProbing] = useState(false);
  const [proxySyncing, setProxySyncing] = useState<string | null>(null);
  const [sourceStatuses, setSourceStatuses] = useState<Record<string, CtiProxySourceStatus>>({});
  const [proxyFeedback, setProxyFeedback] = useState<{ kind: 'ok' | 'err'; text: string } | null>(null);

  useEffect(() => {
    let cancelled = false;
    atlasService
      .fetchExternalIndicators(intel.orgId)
      .then((rows) => {
        if (!cancelled) {
          setIndicators(rows);
          onIndicatorsChange?.(rows);
        }
      })
      .catch((err) => console.error('Could not load external threat indicators:', err));

    const saved = loadOrgScopedValue<{ endpointUrl: string }>('gateway_preferences', intel.orgId, {
      endpointUrl: '',
    });
    setGatewayUrl(saved.endpointUrl || '');
    setSourceStatuses({});
    setProxyFeedback(null);
    setBundleText('');
    setParseFeedback(null);
    setProviderFilter('all');
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [intel.orgId]);

  const handleProbeProxy = async (targetUrl = gatewayUrl) => {
    setProxyFeedback(null);
    const trimmed = targetUrl.trim();
    if (!trimmed) {
      saveOrgScopedValue('gateway_preferences', intel.orgId, { endpointUrl: '' });
      setSourceStatuses({});
      setProxyFeedback({ kind: 'err', text: 'Enter the ATLAS Execution Gateway URL before probing.' });
      return;
    }
    const urlCheck = validateGatewayEndpointUrl(trimmed);
    if (!urlCheck.valid || !urlCheck.normalized) {
      setProxyFeedback({ kind: 'err', text: urlCheck.reason || 'Invalid gateway URL.' });
      return;
    }
    saveOrgScopedValue('gateway_preferences', intel.orgId, { endpointUrl: urlCheck.normalized });
    setGatewayUrl(urlCheck.normalized);
    setProxyProbing(true);
    try {
      const list = await probeCtiProxySources(urlCheck.normalized, intel.orgId);
      const map: Record<string, CtiProxySourceStatus> = {};
      for (const s of list) map[s.id] = s;
      setSourceStatuses(map);
      const configuredCount = list.filter((s) => s.configured).length;
      setProxyFeedback({
        kind: 'ok',
        text: `Gateway reachable: ${configuredCount}/${list.length} server-side CTI source(s) configured.`,
      });
    } catch (err: any) {
      setProxyFeedback({ kind: 'err', text: err?.message || 'Unable to probe gateway CTI proxy.' });
    } finally {
      setProxyProbing(false);
    }
  };

  const handleSyncProxy = async (sourceFilter?: ProxyCtiSourceId) => {
    setProxyFeedback(null);
    const urlCheck = validateGatewayEndpointUrl(gatewayUrl.trim());
    if (!urlCheck.valid || !urlCheck.normalized) {
      setProxyFeedback({ kind: 'err', text: urlCheck.reason || 'Configure a valid gateway URL first.' });
      return;
    }
    saveOrgScopedValue('gateway_preferences', intel.orgId, { endpointUrl: urlCheck.normalized });
    setGatewayUrl(urlCheck.normalized);
    setProxySyncing(sourceFilter || 'ALL');
    try {
      const res = await fetchCtiProxyIndicators({
        endpointUrl: urlCheck.normalized,
        orgId: intel.orgId,
        source: sourceFilter,
        assets: intel.assets,
        incidents: intel.incidents,
        existingIndicators: indicators,
      });

      setSourceStatuses((prev) => {
        const nextMap = { ...prev };
        for (const s of res.sources) nextMap[s.id] = s;
        return nextMap;
      });

      let insertedCount = 0;
      let dbDupes = 0;
      if (res.indicators.length > 0) {
        const saved = await atlasService.insertExternalIndicators(intel.orgId, res.indicators);
        insertedCount = saved.inserted.length;
        dbDupes = saved.skippedDuplicates;
        const next = [...saved.inserted, ...indicators];
        setIndicators(next);
        onIndicatorsChange?.(next);
      }

      const failNote =
        res.failedSources.length > 0
          ? ` Partial failures: ${res.failedSources.map((f) => `${f.source} (${f.reason})`).join('; ')}.`
          : '';

      setProxyFeedback({
        kind: res.failedSources.length > 0 && insertedCount === 0 ? 'err' : 'ok',
        text: `Synced ${insertedCount} new indicator(s) via gateway CTI proxy (${res.skippedDuplicates + dbDupes} duplicates skipped; 15m server cache TTL).${failNote}`,
      });
    } catch (err: any) {
      setProxyFeedback({ kind: 'err', text: err?.message || 'CTI proxy sync failed.' });
    } finally {
      setProxySyncing(null);
    }
  };

  const handleIngestText = async (e: React.FormEvent) => {
    e.preventDefault();
    setParseFeedback(null);
    if (!bundleText.trim()) return;
    try {
      const report = parseCtiJsonBundle(
        bundleText,
        selectedProvider,
        intel.orgId,
        intel.assets,
        intel.incidents,
        indicators
      );
      if (report.indicators.length === 0) {
        setParseFeedback({
          kind: 'err',
          text: `Parsed bundle: 0 new indicators added (${report.skippedDuplicates} duplicate(s) skipped). ${report.warnings.join(' ')}`,
        });
        return;
      }
      const { inserted, skippedDuplicates } = await atlasService.insertExternalIndicators(intel.orgId, report.indicators);
      const next = [...inserted, ...indicators];
      setIndicators(next);
      onIndicatorsChange?.(next);
      setBundleText('');
      setParseFeedback({
        kind: 'ok',
        text: `Ingested ${inserted.length} external indicator(s) (${report.skippedDuplicates + skippedDuplicates} duplicates skipped). Tagged as EXTERNAL INTEL pending analyst verification.`,
      });
    } catch (err: any) {
      setParseFeedback({ kind: 'err', text: err.message || 'CTI bundle parse or import failure.' });
    }
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      const text = await file.text();
      setBundleText(text);
    } catch {
      setParseFeedback({ kind: 'err', text: 'Failed to read uploaded JSON file.' });
    }
  };

  const setVerification = (id: string, status: ExternalThreatIndicator['verificationStatus']) => {
    const previous = indicators;
    const next = indicators.map((i) => (i.id === id ? { ...i, verificationStatus: status } : i));
    setIndicators(next);
    onIndicatorsChange?.(next);
    atlasService.updateIndicatorVerification(id, status).catch((err) => {
      console.error(err);
      setIndicators(previous);
      onIndicatorsChange?.(previous);
      setParseFeedback({ kind: 'err', text: err?.message || 'Could not update verification status.' });
    });
  };

  const clearAll = async () => {
    const previous = indicators;
    setIndicators([]);
    onIndicatorsChange?.([]);
    let failed = 0;
    for (const ind of previous) {
      try {
        await atlasService.deleteExternalIndicator(intel.orgId, ind.id);
      } catch {
        failed++;
      }
    }
    if (failed > 0) {
      try {
        const rows = await atlasService.fetchExternalIndicators(intel.orgId);
        setIndicators(rows);
        onIndicatorsChange?.(rows);
      } catch {
        setIndicators(previous);
        onIndicatorsChange?.(previous);
      }
      setParseFeedback({ kind: 'err', text: `${failed} indicator(s) could not be removed (administrators only).` });
    }
  };

  const removeIndicator = (id: string) => {
    const previous = indicators;
    const next = indicators.filter((i) => i.id !== id);
    setIndicators(next);
    onIndicatorsChange?.(next);
    atlasService.deleteExternalIndicator(intel.orgId, id).catch((err) => {
      console.error(err);
      setIndicators(previous);
      onIndicatorsChange?.(previous);
      setParseFeedback({ kind: 'err', text: err?.message || 'Indicator removal was rejected (administrators only).' });
    });
  };

  const visibleIndicators = indicators.filter(
    (i) => providerFilter === 'all' || i.providerId === providerFilter
  );

  return (
    <div className="flex-1 overflow-y-auto bg-[#0b0d10] p-4 space-y-4">
      {/* Header & Strict Boundary Notice */}
      <div className="bg-[#12151b] border border-[#252b36] p-3 flex flex-wrap items-center justify-between gap-2">
        <div>
          <div className="font-mono text-[10px] tracking-[0.12em] text-[#8fa36d]">
            MODULE D // THREAT INTELLIGENCE FEED ADAPTERS
          </div>
          <h1 className="text-sm font-semibold text-[#e8ecf1] flex items-center gap-2 mt-0.5">
            <Rss className="w-4 h-4 text-[#4a9eb0]" />
            <span>CTI Feed Adapters &amp; Gateway Proxy Sync</span>
          </h1>
        </div>
        <span className="font-mono text-[10px] text-[#c88b32] border border-[#c88b32]/40 bg-[#c88b32]/10 px-2 py-0.5">
          EXTERNAL INTEL STRICTLY SEPARATED FROM AUTHORISED ATLAS DB
        </span>
      </div>

      {/* Gateway CTI Proxy Controls */}
      <div className="bg-[#12151b] border border-[#252b36] p-3 space-y-2.5">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2 font-mono text-xs font-semibold text-[#e8ecf1]">
            <Server className="w-3.5 h-3.5 text-[#4a9eb0]" />
            <span>SERVER-SIDE CTI PROXY RELAY (GET /api/v1/cti/indicators)</span>
          </div>
          <span className="font-mono text-[10px] text-[#8c97a8]">
            Feed API keys remain on the Linux gateway; browser sends only your AAL2 session JWT
          </span>
        </div>

        <div className="flex flex-wrap items-center gap-2 font-mono text-[11px]">
          <input
            type="url"
            value={gatewayUrl}
            onChange={(e) => setGatewayUrl(e.target.value)}
            placeholder="https://gateway.internal:8443 or http://127.0.0.1:8443"
            className="flex-1 min-w-[260px] bg-[#0b0d10] border border-[#252b36] px-2.5 py-1.5 text-xs text-[#e8ecf1] focus:outline-none focus:border-[#6f8054]"
          />
          <button
            type="button"
            disabled={proxyProbing || Boolean(proxySyncing)}
            onClick={() => handleProbeProxy()}
            className="px-2.5 py-1.5 bg-[#181c24] hover:bg-[#222834] border border-[#252b36] text-[#e8ecf1] cursor-pointer disabled:opacity-40"
          >
            {proxyProbing ? 'Probing…' : 'Probe Gateway'}
          </button>
          <button
            type="button"
            disabled={!gatewayUrl.trim() || proxyProbing || Boolean(proxySyncing)}
            onClick={() => handleSyncProxy()}
            className="px-3 py-1.5 bg-[#6f8054] hover:bg-[#7d905f] text-[#0b0d10] font-semibold flex items-center gap-1.5 cursor-pointer disabled:opacity-40"
          >
            <RefreshCw className={`w-3 h-3 ${proxySyncing === 'ALL' ? 'animate-spin' : ''}`} />
            <span>{proxySyncing === 'ALL' ? 'Syncing Proxy Feeds…' : 'Sync Configured Feeds'}</span>
          </button>
        </div>

        {proxyFeedback && (
          <div
            className={`p-2 border font-mono text-[11px] flex items-center gap-2 ${
              proxyFeedback.kind === 'ok'
                ? 'bg-[#4f8f66]/10 border-[#4f8f66]/40 text-[#4f8f66]'
                : 'bg-[#c94a4a]/10 border-[#c94a4a]/40 text-[#c94a4a]'
            }`}
          >
            {proxyFeedback.kind === 'ok' ? (
              <CheckCircle2 className="w-3.5 h-3.5 shrink-0" />
            ) : (
              <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
            )}
            <span>{proxyFeedback.text}</span>
          </div>
        )}
      </div>

      {/* Adapter Catalog Matrix */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
        {CTI_ADAPTER_CATALOG.map((adp) => {
          const count = indicators.filter((i) => i.providerId === adp.id).length;
          const liveStatus = adp.requiresServerProxy ? sourceStatuses[adp.id] : undefined;

          let badgeLabel = 'LOCAL FILE INGEST (UNVERIFIED)';
          let badgeColor = 'text-[#4a9eb0]';
          if (adp.requiresServerProxy) {
            if (!liveStatus) {
              badgeLabel = 'PROXY READY (NOT PROBED)';
              badgeColor = 'text-[#8c97a8]';
            } else if (!liveStatus.configured || liveStatus.state === 'unconfigured') {
              badgeLabel = 'UNCONFIGURED ON GATEWAY';
              badgeColor = 'text-[#8c97a8]';
            } else if (liveStatus.state === 'configured') {
              badgeLabel = 'PROXY CONFIGURED';
              badgeColor = 'text-[#4a9eb0]';
            } else if (liveStatus.state === 'live') {
              badgeLabel = liveStatus.cached ? 'LIVE (CACHED)' : 'LIVE';
              badgeColor = 'text-[#4f8f66]';
            } else if (liveStatus.state === 'failing') {
              badgeLabel = 'FAILING';
              badgeColor = 'text-[#c94a4a]';
            }
          }

          return (
            <div key={adp.id} className="bg-[#12151b] border border-[#252b36] p-3 space-y-1.5 flex flex-col justify-between">
              <div className="space-y-1">
                <div className="flex items-center justify-between gap-2 font-mono text-[11px]">
                  <span className="text-[#e8ecf1] font-semibold truncate">{adp.name}</span>
                  <span className={`text-[10px] shrink-0 font-semibold ${badgeColor}`}>{badgeLabel}</span>
                </div>
                <div className="font-mono text-[10px] text-[#4a9eb0]">{adp.protocol}</div>
                <p className="text-[11px] text-[#8c97a8] leading-relaxed">{adp.description}</p>
                {liveStatus?.error && (
                  <p className="text-[11px] text-[#c94a4a] font-mono leading-snug">{liveStatus.error}</p>
                )}
              </div>
              <div className="pt-2 border-t border-[#1e242e] font-mono text-[10px] space-y-1">
                <div className="text-[#8c97a8]">{adp.credentialRequirement}</div>
                <div className="flex items-center justify-between gap-2 pt-0.5">
                  <span className="text-[#e8ecf1] tabular-nums">LOADED INDICATORS: {count}</span>
                  {adp.requiresServerProxy && gatewayUrl.trim() && (
                    <button
                      type="button"
                      disabled={Boolean(proxySyncing) || liveStatus?.configured === false}
                      onClick={() => handleSyncProxy(adp.id as ProxyCtiSourceId)}
                      className="px-2 py-0.5 bg-[#0b0d10] hover:bg-[#181c24] border border-[#252b36] text-[#4a9eb0] cursor-pointer disabled:opacity-40"
                    >
                      {proxySyncing === adp.id ? 'Syncing…' : 'Sync Feed'}
                    </button>
                  )}
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Local STIX 2.1 / CISA KEV Bundle Ingestor */}
      <div className="bg-[#12151b] border border-[#252b36] p-3 space-y-2.5">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <span className="font-mono text-xs font-semibold text-[#e8ecf1]">
            INGEST OPERATOR-SUPPLIED STIX 2.1 BUNDLE OR CISA KEV SNAPSHOT (JSON)
          </span>
          <label className="px-2.5 py-1 bg-[#181c24] hover:bg-[#222834] border border-[#252b36] font-mono text-[11px] text-[#e8ecf1] flex items-center gap-1.5 cursor-pointer">
            <Upload className="w-3 h-3 text-[#4a9eb0]" />
            <span>Load JSON File</span>
            <input type="file" accept=".json,application/json" onChange={handleFileUpload} className="hidden" />
          </label>
        </div>

        <form onSubmit={handleIngestText} className="space-y-2 font-mono text-[11px]">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[10px] text-[#8c97a8]">TARGET ADAPTER TAG:</span>
            <select
              value={selectedProvider}
              onChange={(e) => setSelectedProvider(e.target.value as CtiProviderId)}
              className="bg-[#0b0d10] border border-[#252b36] px-2 py-1 text-[#e8ecf1]"
            >
              <option value="STIX_2_1">STIX 2.1 Bundle</option>
              <option value="CISA_KEV">CISA KEV Snapshot</option>
              <option value="MISP">MISP Exported STIX/JSON</option>
              <option value="TAXII_2_1">TAXII 2.1 Offline Export</option>
              <option value="ALIENVAULT_OTX">OTX Exported STIX Bundle</option>
              <option value="ABUSE_CH">Abuse.ch Exported STIX</option>
            </select>
          </div>
          <textarea
            rows={4}
            value={bundleText}
            onChange={(e) => setBundleText(e.target.value)}
            placeholder='Paste RFC-compliant STIX 2.1 bundle JSON ({"type":"bundle","objects":[...]}) or CISA KEV JSON ({"vulnerabilities":[...]})...'
            className="w-full bg-[#0b0d10] border border-[#252b36] p-2 text-xs text-[#e8ecf1] focus:outline-none focus:border-[#6f8054]"
          />
          <div className="flex items-center justify-between gap-2">
            <span className="text-[10px] text-[#8c97a8] font-sans">
              Automatically validates expiry, deduplicates indicators, and cross-correlates against {intel.assets.length} ATLAS assets and {intel.incidents.length} incidents.
            </span>
            <button
              type="submit"
              disabled={!bundleText.trim()}
              className="px-3 py-1 bg-[#6f8054] hover:bg-[#7d905f] text-[#0b0d10] font-semibold cursor-pointer disabled:opacity-40"
            >
              Parse &amp; Correlate Bundle
            </button>
          </div>
        </form>

        {parseFeedback && (
          <div
            className={`p-2 border font-mono text-[11px] flex items-center gap-2 ${
              parseFeedback.kind === 'ok'
                ? 'bg-[#4f8f66]/10 border-[#4f8f66]/40 text-[#4f8f66]'
                : 'bg-[#c94a4a]/10 border-[#c94a4a]/40 text-[#c94a4a]'
            }`}
          >
            {parseFeedback.kind === 'ok' ? (
              <CheckCircle2 className="w-3.5 h-3.5 shrink-0" />
            ) : (
              <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
            )}
            <span>{parseFeedback.text}</span>
          </div>
        )}
      </div>

      {/* Correlated External Indicator Table */}
      <div className="bg-[#12151b] border border-[#252b36]">
        <div className="px-3 py-2 border-b border-[#252b36] flex flex-wrap items-center justify-between gap-2 font-mono text-[11px]">
          <span className="font-semibold text-[#e8ecf1]">
            LOADED EXTERNAL INTEL INDICATORS ({visibleIndicators.length}) · UNCONFIRMED BY ATLAS DB
          </span>
          <div className="flex items-center gap-2">
            {indicators.length > 0 && (
              <button
                type="button"
                onClick={() => clearAll()}
                className="px-2 py-0.5 bg-[#0b0d10] hover:bg-[#181c24] border border-[#252b36] text-[10px] text-[#c94a4a] cursor-pointer"
              >
                Clear Org Cache
              </button>
            )}
            <select
              value={providerFilter}
              onChange={(e) => setProviderFilter(e.target.value as any)}
              className="bg-[#0b0d10] border border-[#252b36] px-2 py-0.5 text-[10px] text-[#e8ecf1]"
            >
              <option value="all">All Adapters</option>
              {CTI_ADAPTER_CATALOG.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.id}
                </option>
              ))}
            </select>
          </div>
        </div>

        <table className="w-full text-left font-mono text-[11px] border-collapse">
          <thead className="bg-[#0e1116] border-b border-[#252b36] text-[#8c97a8] text-[10px]">
            <tr>
              <th className="py-1.5 px-3">ORIGIN / TRUST BOUNDARY</th>
              <th className="py-1.5 px-2">INDICATOR</th>
              <th className="py-1.5 px-2">TYPE</th>
              <th className="py-1.5 px-2">ATLAS DB CORRELATION</th>
              <th className="py-1.5 px-2 text-right">CONF</th>
              <th className="py-1.5 px-2">EXPIRY</th>
              <th className="py-1.5 px-3 text-right">LOCAL TRIAGE (UNVERIFIED EXT)</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#181c24]">
            {visibleIndicators.length === 0 ? (
              <tr>
                <td colSpan={7} className="py-6 text-center text-[#8c97a8] font-sans">
                  No external threat intelligence indicators loaded yet. Sync configured feeds through the gateway proxy or load a local STIX 2.1 / CISA KEV JSON bundle above.
                </td>
              </tr>
            ) : (
              visibleIndicators.map((ind) => (
                <tr key={ind.id} className={`hover:bg-[#181c24] ${ind.isExpired ? 'bg-[#c94a4a]/5' : ''}`}>
                  <td className="py-1.5 px-3">
                    <div className="text-[#c88b32] font-semibold">EXTERNAL:{ind.providerId}</div>
                    <div className="text-[9px] text-[#8c97a8]">
                      {ind.verificationStatus === 'verified_by_analyst'
                        ? 'LOCAL TRIAGED (NON-DB)'
                        : ind.verificationStatus === 'false_positive'
                        ? 'FALSE POSITIVE'
                        : 'UNVERIFIED EXTERNAL'}
                    </div>
                  </td>
                  <td className="py-1.5 px-2 text-[#e8ecf1] font-semibold">
                    <div className={ind.isExpired ? 'line-through text-[#8c97a8]' : ''}>{ind.value}</div>
                    <div className="text-[10px] text-[#8c97a8] font-sans truncate max-w-[220px]">
                      {ind.rawSummary}
                    </div>
                  </td>
                  <td className="py-1.5 px-2 text-[#4a9eb0]">{ind.indicatorType.toUpperCase()}</td>
                  <td className="py-1.5 px-2">
                    <div className="flex flex-wrap gap-1.5">
                      {ind.matchedAssetIds.length === 0 && ind.matchedIncidentIds.length === 0 ? (
                        <span className="text-[#5d6778]">No ATLAS DB hit</span>
                      ) : (
                        <>
                          {ind.matchedAssetIds.map((aid) => (
                            <button
                              key={aid}
                              onClick={() => onSelectEntity({ kind: 'asset', id: aid })}
                              className="text-[#4f8f66] underline cursor-pointer"
                            >
                              Asset:{aid.slice(0, 6)}
                            </button>
                          ))}
                          {ind.matchedIncidentIds.map((iid) => (
                            <button
                              key={iid}
                              onClick={() => onSelectEntity({ kind: 'incident', id: iid })}
                              className="text-[#c94a4a] underline cursor-pointer"
                            >
                              Inc:{iid.slice(0, 6)}
                            </button>
                          ))}
                        </>
                      )}
                    </div>
                  </td>
                  <td className="py-1.5 px-2 text-right tabular-nums text-[#e8ecf1]">{ind.confidence}%</td>
                  <td className="py-1.5 px-2">
                    {ind.isExpired ? (
                      <span className="px-1.5 py-0.5 bg-[#c94a4a]/20 border border-[#c94a4a]/50 text-[#c94a4a] text-[10px] font-semibold">
                        EXPIRED
                      </span>
                    ) : ind.validUntil ? (
                      <span className="text-[#8c97a8] tabular-nums">{ind.validUntil.slice(0, 10)}</span>
                    ) : (
                      <span className="text-[#8c97a8]">Active</span>
                    )}
                  </td>
                  <td className="py-1.5 px-3 text-right">
                    <div className="inline-flex items-center gap-1">
                      <button
                        onClick={() => setVerification(ind.id, 'verified_by_analyst')}
                        className={`px-1.5 py-0.5 border text-[10px] cursor-pointer ${
                          ind.verificationStatus === 'verified_by_analyst'
                            ? 'bg-[#4a9eb0]/25 border-[#4a9eb0] text-[#4a9eb0]'
                            : 'bg-[#0b0d10] border-[#252b36] text-[#8c97a8]'
                        }`}
                        title="Mark external indicator locally triaged (does NOT promote to confirmed ATLAS DB record)"
                      >
                        Reviewed
                      </button>
                      <button
                        onClick={() => setVerification(ind.id, 'false_positive')}
                        className={`px-1.5 py-0.5 border text-[10px] cursor-pointer ${
                          ind.verificationStatus === 'false_positive'
                            ? 'bg-[#c94a4a]/25 border-[#c94a4a] text-[#c94a4a]'
                            : 'bg-[#0b0d10] border-[#252b36] text-[#8c97a8]'
                        }`}
                      >
                        FP
                      </button>
                      {onSendToAttribution && (
                        <button
                          onClick={() => onSendToAttribution(ind.value)}
                          className="px-1.5 py-0.5 bg-[#0b0d10] border border-[#252b36] text-[10px] text-[#4a9eb0] hover:text-[#e8ecf1] cursor-pointer"
                        >
                          Attr→
                        </button>
                      )}
                      <button
                        onClick={() => removeIndicator(ind.id)}
                        className="p-0.5 text-[#8c97a8] hover:text-[#c94a4a] cursor-pointer"
                        title="Remove"
                      >
                        <Trash2 className="w-3 h-3" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
