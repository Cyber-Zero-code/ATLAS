import React, { useEffect, useMemo, useRef, useState } from 'react';
import type {
  AppRole,
  AttributionRecord,
  ExternalThreatIndicator,
  GatewayConnectionState,
  GatewayHealthSnapshot,
  GatewayJobRecord,
  SelectedEntity,
  TerminalCommandResult,
  TerminalEnvironment,
} from '../../types/atlas';
import type { WorkspaceIntelligenceState } from '../../hooks/useWorkspaceIntelligence';
import {
  executeDefensiveTerminalCommand,
  REMOTE_TERMINAL_ADAPTERS,
} from '../../adapters/terminalAdapter';
import {
  COMMAND_POLICY_REGISTRY,
  evaluateCommandPolicy,
  type PolicyEvaluation,
} from '../../adapters/terminalPolicy';
import {
  cancelGatewayJob,
  checkGatewayHealth,
  submitGatewayJob,
  uploadGatewayPcap,
  validateGatewayEndpointUrl,
} from '../../adapters/gatewayClient';
import { atlasService } from '../../data/api';
import {
  loadOrgScopedList,
  loadOrgScopedValue,
  saveOrgScopedList,
  saveOrgScopedValue,
} from '../../utils/orgStorage';
import {
  Terminal,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Trash2,
  ArrowUpRight,
  Lock,
  Cpu,
  Download,
  Copy,
  RefreshCw,
  PlugZap,
  StopCircle,
  Upload,
  ChevronDown,
  ChevronRight,
  CheckCircle2,
  XCircle,
} from 'lucide-react';

interface DefensiveTerminalProps {
  intel: WorkspaceIntelligenceState;
  activeRole?: AppRole;
  userEmail?: string;
  onSelectEntity: (entity: SelectedEntity) => void;
  externalIndicators?: ExternalThreatIndicator[];
  attributionRecords?: AttributionRecord[];
}

const ATLAS_QUICK_PRESETS = [
  'help',
  'status',
  'whoami',
  'assets',
  'incidents critical',
  'cti status',
  'geo cluster',
  'network status',
];

const LINUX_QUICK_PRESETS = [
  'sysinfo',
  'interfaces',
  'disk',
  'memory',
  'processes',
  'services',
  'nmap --help',
];

export const DefensiveTerminal: React.FC<DefensiveTerminalProps> = ({
  intel,
  activeRole = 'atlas:analyst',
  userEmail = '',
  onSelectEntity,
  externalIndicators = [],
  attributionRecords = [],
}) => {
  const [environment, setEnvironment] = useState<TerminalEnvironment>('atlas_native');
  const [input, setInput] = useState('');
  const [cmdIndex, setCmdIndex] = useState<number>(-1);
  const [history, setHistory] = useState<TerminalCommandResult[]>(() =>
    loadOrgScopedList<TerminalCommandResult>('terminal_history', intel.orgId)
  );
  const [expandedEntries, setExpandedEntries] = useState<Record<string, boolean>>({});
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // External Linux Execution Gateway State
  const [gatewayUrlInput, setGatewayUrlInput] = useState<string>(() =>
    loadOrgScopedValue<{ endpointUrl?: string }>('gateway_preferences', intel.orgId, {}).endpointUrl || ''
  );
  const [gatewayHealth, setGatewayHealth] = useState<GatewayHealthSnapshot>({
    state: 'NOT_CONFIGURED',
    endpointUrl: null,
    authenticatedUserId: null,
    authenticatedOrgId: null,
    authenticatedRole: null,
    checkedAtUtc: null,
    tools: [],
  });
  const [execState, setExecState] = useState<GatewayConnectionState>('NOT_CONFIGURED');
  const [gatewayJobs, setGatewayJobs] = useState<GatewayJobRecord[]>([]);
  const [activeJobId, setActiveJobId] = useState<string | null>(null);
  const [gatewayBusy, setGatewayBusy] = useState(false);

  // Explicit Policy Approval Modal / Banner State
  const [pendingApproval, setPendingApproval] = useState<{
    rawCommand: string;
    evaluation: PolicyEvaluation;
  } | null>(null);
  const [approvalJustification, setApprovalJustification] = useState('');

  // PCAP upload feedback
  const [pcapNotice, setPcapNotice] = useState<string | null>(null);
  const pcapInputRef = useRef<HTMLInputElement>(null);

  // Strictly reset transient states & reload org-scoped history/preferences on org switch
  useEffect(() => {
    const savedHistory = loadOrgScopedList<TerminalCommandResult>('terminal_history', intel.orgId);
    const savedUrl =
      loadOrgScopedValue<{ endpointUrl?: string }>('gateway_preferences', intel.orgId, {}).endpointUrl || '';
    setHistory(savedHistory);
    setGatewayUrlInput(savedUrl);
    setGatewayJobs([]);
    setActiveJobId(null);
    setPendingApproval(null);
    setApprovalJustification('');
    setPcapNotice(null);
    setCmdIndex(-1);
    setInput('');
    setGatewayHealth({
      state: savedUrl ? 'OFFLINE' : 'NOT_CONFIGURED',
      endpointUrl: savedUrl || null,
      authenticatedUserId: null,
      authenticatedOrgId: null,
      authenticatedRole: null,
      checkedAtUtc: null,
      tools: [],
    });
    setExecState(savedUrl ? 'OFFLINE' : 'NOT_CONFIGURED');
  }, [intel.orgId]);

  const effectiveDisplayState: GatewayConnectionState = useMemo(() => {
    if (execState === 'EXECUTING' || execState === 'CONNECTING' || execState === 'BLOCKED_BY_POLICY') {
      return execState;
    }
    return gatewayHealth.state;
  }, [execState, gatewayHealth.state]);

  const probeGateway = async (targetUrl = gatewayUrlInput) => {
    const trimmed = targetUrl.trim();
    if (!trimmed) {
      saveOrgScopedValue('gateway_preferences', intel.orgId, { endpointUrl: '' });
      setGatewayHealth({
        state: 'NOT_CONFIGURED',
        endpointUrl: null,
        authenticatedUserId: null,
        authenticatedOrgId: null,
        authenticatedRole: null,
        checkedAtUtc: new Date().toISOString(),
        tools: [],
      });
      setExecState('NOT_CONFIGURED');
      return;
    }

    const urlCheck = validateGatewayEndpointUrl(trimmed);
    if (!urlCheck.valid || !urlCheck.normalized) {
      setGatewayHealth({
        state: 'BLOCKED_BY_POLICY',
        endpointUrl: trimmed,
        authenticatedUserId: null,
        authenticatedOrgId: null,
        authenticatedRole: null,
        checkedAtUtc: new Date().toISOString(),
        tools: [],
        errorMessage: urlCheck.reason,
      });
      setExecState('BLOCKED_BY_POLICY');
      return;
    }

    saveOrgScopedValue('gateway_preferences', intel.orgId, { endpointUrl: urlCheck.normalized });
    setGatewayBusy(true);
    setExecState('CONNECTING');
    const snapshot = await checkGatewayHealth(urlCheck.normalized, intel.orgId);
    setGatewayHealth(snapshot);
    setExecState(snapshot.state);
    setGatewayBusy(false);
  };

  const appendHistory = (entry: TerminalCommandResult) => {
    const updated = [entry, ...history].slice(0, 50);
    setHistory(updated);
    saveOrgScopedList('terminal_history', intel.orgId, updated);
  };

  const runAtlasNativeCommand = (raw: string) => {
    if (raw.trim().toLowerCase() === 'clear') {
      clearHistory();
      setInput('');
      return;
    }
    const res = executeDefensiveTerminalCommand(raw, intel, externalIndicators, attributionRecords, {
      userEmail,
      userRole: activeRole,
      commandHistory: history.map((h) => h.command),
      gatewayHealth,
      gatewayJobs,
    });
    appendHistory(res);
    setInput('');
    setCmdIndex(-1);
  };

  const executeLinuxWorkerCommand = async (
    raw: string,
    opts: { approvalConfirmed?: boolean; justification?: string } = {}
  ) => {
    const evalRes = evaluateCommandPolicy(raw, 'linux_worker', activeRole, {
      approvalGranted: opts.approvalConfirmed,
    });
    const timestampUtc = new Date().toISOString().slice(11, 19) + ' UTC';
    const entryId = `gw-term-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;

    if (!evalRes.allowed) {
      if (evalRes.requiresApproval) {
        setPendingApproval({ rawCommand: raw, evaluation: evalRes });
        setExecState('BLOCKED_BY_POLICY');
        appendHistory({
          id: entryId,
          command: raw,
          environment: 'linux_worker',
          policyId: evalRes.policy?.id,
          riskLevel: evalRes.riskLevel,
          timestampUtc,
          scopeLabel: 'APPROVAL REQUIRED',
          status: 'approval_required',
          lines: [
            { text: evalRes.reason || 'Operator confirmation required.', tone: 'warn' },
            { text: 'Confirm execution and provide operational justification in the Approval Gate above.', tone: 'muted' },
          ],
        });
        return;
      }

      setExecState('BLOCKED_BY_POLICY');
      appendHistory({
        id: entryId,
        command: raw,
        environment: 'linux_worker',
        policyId: evalRes.policy?.id,
        riskLevel: evalRes.riskLevel,
        timestampUtc,
        scopeLabel: 'POLICY BLOCKED',
        status: 'blocked_by_policy',
        lines: [{ text: evalRes.reason || 'Blocked by central security policy.', tone: 'err' }],
      });
      return;
    }

    // Fail closed if external Linux Execution Gateway is not verified READY
    if (gatewayHealth.state !== 'READY' || !gatewayHealth.endpointUrl) {
      appendHistory({
        id: entryId,
        command: raw,
        environment: 'linux_worker',
        policyId: evalRes.policy?.id,
        riskLevel: evalRes.riskLevel,
        timestampUtc,
        scopeLabel: `GATEWAY ${gatewayHealth.state}`,
        status: 'unavailable',
        lines: [
          {
            text: `EXECUTION UNAVAILABLE: Linux Security Worker Gateway state is ${gatewayHealth.state}.`,
            tone: 'warn',
          },
          {
            text:
              gatewayHealth.errorMessage ||
              'Connect and authenticate an external Linux Execution Gateway (`/gateway`) before executing Linux security tools. ATLAS never simulates tool output.',
            tone: 'muted',
          },
        ],
      });
      setInput('');
      return;
    }

    // Best-effort log 'APPROVAL' in existing authorised Supabase log_event() RPC without failing offline/disconnected checks
    if (opts.approvalConfirmed && opts.justification) {
      atlasService
        .logEvent(intel.orgId, 'APPROVAL', 'GATEWAY_EXECUTION', raw.slice(0, 64), {
          tool: evalRes.normalizedTool,
          target: evalRes.target,
          riskLevel: evalRes.riskLevel,
          justification: opts.justification,
        })
        .catch(() => {});
    }

    setGatewayBusy(true);
    setExecState('EXECUTING');
    setPendingApproval(null);
    setApprovalJustification('');

    try {
      const job = await submitGatewayJob({
        endpointUrl: gatewayHealth.endpointUrl,
        orgId: intel.orgId,
        tool: evalRes.normalizedTool || raw.split(/\s+/)[0],
        args: evalRes.normalizedArgs || [],
        target: evalRes.target,
        approvalConfirmed: Boolean(opts.approvalConfirmed),
        approvalJustification: opts.justification,
        intel,
        externalIndicators,
      });

      setGatewayJobs((prev) => [job, ...prev].slice(0, 25));
      setActiveJobId(job.jobId);
      setExecState(job.status === 'completed' ? 'COMPLETED' : 'FAILED');

      const outLines = [
        {
          text: `JOB ${job.jobId} | STATUS=${job.status.toUpperCase()} | EXIT=${job.exitCode ?? 'N/A'} | DURATION=${job.durationMs ?? 0}ms [${job.recordClassification}]`,
          tone: job.status === 'completed' ? ('ok' as const) : ('err' as const),
        },
        ...job.stdoutLines.map((l) => ({ text: `  ${l}`, tone: 'normal' as const })),
        ...job.stderrLines.map((l) => ({ text: `  [STDERR] ${l}`, tone: 'err' as const })),
      ];

      if (job.correlation) {
        outLines.push({
          text: `ATLAS CORRELATION: Matched Assets=${job.correlation.matchedAssetIds.length} | Unmatched IPs=${job.correlation.unmatchedObservedIps.length} | Incidents=${job.correlation.matchedIncidentIds.length} | CTI=${job.correlation.matchedCtiValues.length} | Downstream Impacted=${job.correlation.downstreamAssetCount}`,
          tone: 'warn' as any,
        });
      }

      appendHistory({
        id: entryId,
        command: raw,
        environment: 'linux_worker',
        policyId: evalRes.policy?.id,
        riskLevel: evalRes.riskLevel,
        timestampUtc,
        scopeLabel: `GATEWAY JOB:${job.jobId}`,
        status: job.status === 'completed' ? 'ok' : 'failed',
        durationMs: job.durationMs,
        correlation: job.correlation,
        lines: outLines,
      });
      setInput('');
      setCmdIndex(-1);
    } catch (err: any) {
      setExecState('FAILED');
      appendHistory({
        id: entryId,
        command: raw,
        environment: 'linux_worker',
        policyId: evalRes.policy?.id,
        riskLevel: evalRes.riskLevel,
        timestampUtc,
        scopeLabel: 'GATEWAY ERROR',
        status: 'failed',
        lines: [{ text: err?.message || 'Gateway request failed.', tone: 'err' }],
      });
    } finally {
      setGatewayBusy(false);
    }
  };

  const runCommand = (raw: string) => {
    if (!raw.trim()) return;
    if (environment === 'atlas_native') {
      runAtlasNativeCommand(raw);
    } else {
      void executeLinuxWorkerCommand(raw);
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    runCommand(input);
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (history.length === 0) return;
    if (e.key === 'ArrowUp') {
      e.preventDefault();
      const nextIdx = Math.min(history.length - 1, cmdIndex + 1);
      setCmdIndex(nextIdx);
      setInput(history[nextIdx]?.command || '');
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      const nextIdx = cmdIndex - 1;
      setCmdIndex(nextIdx);
      setInput(nextIdx < 0 ? '' : history[nextIdx]?.command || '');
    }
  };

  const clearHistory = () => {
    setHistory([]);
    saveOrgScopedList('terminal_history', intel.orgId, []);
  };

  const handleCancelActiveJob = async () => {
    if (!activeJobId || !gatewayHealth.endpointUrl) return;
    try {
      const updated = await cancelGatewayJob({
        endpointUrl: gatewayHealth.endpointUrl,
        orgId: intel.orgId,
        jobId: activeJobId,
      });
      setGatewayJobs((prev) => prev.map((j) => (j.jobId === updated.jobId ? updated : j)));
      setExecState('FAILED');
    } catch {
      // ignore cleanly
    }
  };

  const handlePcapUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file || !gatewayHealth.endpointUrl || gatewayHealth.state !== 'READY') return;
    setPcapNotice('Validating and uploading PCAP to org-isolated sandbox...');
    try {
      const uploaded = await uploadGatewayPcap({
        endpointUrl: gatewayHealth.endpointUrl,
        orgId: intel.orgId,
        file,
      });
      setPcapNotice(
        `Uploaded ${uploaded.fileName} (${(uploaded.sizeBytes / 1024).toFixed(1)} KB). Run: \`pcap summary ${uploaded.fileName}\``
      );
    } catch (err: any) {
      setPcapNotice(`Upload blocked: ${err?.message || 'Unknown error'}`);
    } finally {
      if (pcapInputRef.current) pcapInputRef.current.value = '';
    }
  };

  const handleExportEntry = (entry: TerminalCommandResult) => {
    const content =
      entry.exportReportMarkdown ||
      [
        `# ATLAS Terminal Export — ${entry.command}`,
        `- Environment: ${entry.environment || 'atlas_native'}`,
        `- Timestamp: ${entry.timestampUtc}`,
        `- Scope: ${entry.scopeLabel}`,
        `- Status: ${entry.status}`,
        '',
        ...entry.lines.map((l) => l.text),
      ].join('\n');

    const blob = new Blob([content], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `atlas-terminal-${entry.id}.md`;
    a.click();
    URL.revokeObjectURL(url);

    atlasService
      .logEvent(intel.orgId, 'EXPORT', 'TERMINAL_REPORT', entry.id, {
        command: entry.command,
        scopeLabel: entry.scopeLabel,
      })
      .catch(() => {});
  };

  const handleCopyEntry = (entry: TerminalCommandResult) => {
    const text = [`$ ${entry.command}`, ...entry.lines.map((l) => l.text)].join('\n');
    navigator.clipboard?.writeText(text).then(() => {
      setCopiedId(entry.id);
      setTimeout(() => setCopiedId(null), 1500);
    });
  };

  const stateBadgeClass =
    effectiveDisplayState === 'READY' || effectiveDisplayState === 'COMPLETED'
      ? 'text-[#4f8f66] border-[#4f8f66]/40 bg-[#4f8f66]/10'
      : effectiveDisplayState === 'EXECUTING' || effectiveDisplayState === 'CONNECTING'
      ? 'text-[#4a9eb0] border-[#4a9eb0]/40 bg-[#4a9eb0]/10'
      : effectiveDisplayState === 'FAILED' || effectiveDisplayState === 'BLOCKED_BY_POLICY'
      ? 'text-[#c94a4a] border-[#c94a4a]/40 bg-[#c94a4a]/10'
      : 'text-[#c88b32] border-[#c88b32]/40 bg-[#c88b32]/10';

  const presets = environment === 'atlas_native' ? ATLAS_QUICK_PRESETS : LINUX_QUICK_PRESETS;
  const activePolicies = COMMAND_POLICY_REGISTRY.filter((p) => p.environment === environment);

  return (
    <div className="flex-1 flex flex-col overflow-hidden bg-[#0b0d10]">
      {/* Header: Dual Environment Selector + Gateway Connection State + Session Controls */}
      <div className="px-3 py-2 border-b border-[#252b36] bg-[#12151b] flex flex-wrap items-center justify-between gap-2 shrink-0">
        <div className="flex flex-wrap items-center gap-2">
          <Terminal className="w-3.5 h-3.5 text-[#4a9eb0]" />
          <span className="font-mono text-xs font-semibold text-[#e8ecf1]">
            HYBRID CYBERSECURITY TERMINAL
          </span>

          {/* Execution Environment Switcher */}
          <div className="flex items-center border border-[#252b36] bg-[#0b0d10] font-mono text-[10px]">
            <button
              onClick={() => setEnvironment('atlas_native')}
              className={`px-2 py-1 cursor-pointer ${
                environment === 'atlas_native'
                  ? 'bg-[#6f8054]/30 text-[#e8ecf1] font-semibold'
                  : 'text-[#8c97a8] hover:text-[#e8ecf1]'
              }`}
            >
              ATLAS NATIVE (atlas@soc)
            </button>
            <button
              onClick={() => setEnvironment('linux_worker')}
              className={`px-2 py-1 border-l border-[#252b36] cursor-pointer ${
                environment === 'linux_worker'
                  ? 'bg-[#4a9eb0]/25 text-[#e8ecf1] font-semibold'
                  : 'text-[#8c97a8] hover:text-[#e8ecf1]'
              }`}
            >
              LINUX WORKER (atlas@linux-worker)
            </button>
          </div>

          <span className={`font-mono text-[10px] border px-1.5 py-0.5 flex items-center gap-1 ${stateBadgeClass}`}>
            <ShieldCheck className="w-3 h-3" />
            <span>GATEWAY: {effectiveDisplayState}</span>
          </span>
        </div>

        <div className="flex items-center gap-2 font-mono text-[10px]">
          <span className="text-[#8c97a8] tabular-nums">
            ROLE:{activeRole} · HISTORY:{history.length} · ORG:{intel.orgId.slice(0, 8)}
          </span>
          {gatewayBusy && activeJobId && (
            <button
              onClick={handleCancelActiveJob}
              className="px-2 py-0.5 bg-[#c94a4a]/20 hover:bg-[#c94a4a]/30 border border-[#c94a4a]/50 text-[#c94a4a] flex items-center gap-1 cursor-pointer"
            >
              <StopCircle className="w-3 h-3" />
              <span>Cancel Job</span>
            </button>
          )}
          {history.length > 0 && (
            <button
              onClick={clearHistory}
              className="px-2 py-0.5 bg-[#0b0d10] hover:bg-[#181c24] border border-[#252b36] text-[#8c97a8] hover:text-[#c94a4a] flex items-center gap-1 cursor-pointer"
            >
              <Trash2 className="w-3 h-3" />
              <span>Reset Session</span>
            </button>
          )}
        </div>
      </div>

      {/* Explicit Policy Approval Gate Banner */}
      {pendingApproval && (
        <div className="px-4 py-2.5 border-b border-[#c88b32]/60 bg-[#c88b32]/10 shrink-0 space-y-2">
          <div className="flex flex-wrap items-center justify-between gap-2 font-mono text-xs">
            <div className="flex items-center gap-2 text-[#c88b32] font-semibold">
              <ShieldAlert className="w-4 h-4 shrink-0" />
              <span>
                APPROVAL GATE ({pendingApproval.evaluation.riskLevel} RISK): `{pendingApproval.rawCommand}`
              </span>
            </div>
            <button
              onClick={() => {
                setPendingApproval(null);
                setApprovalJustification('');
              }}
              className="text-[11px] font-mono text-[#8c97a8] hover:text-[#e8ecf1] cursor-pointer"
            >
              Cancel Request
            </button>
          </div>
          <p className="text-[11px] text-[#e8ecf1]/90">{pendingApproval.evaluation.reason}</p>
          <div className="flex flex-wrap items-center gap-2">
            <input
              type="text"
              value={approvalJustification}
              onChange={(e) => setApprovalJustification(e.target.value)}
              placeholder="Enter operational justification (e.g., Authorised SOC triage ticket #412)..."
              className="flex-1 min-w-[260px] bg-[#0b0d10] border border-[#c88b32]/50 px-2.5 py-1 text-xs font-mono text-[#e8ecf1] focus:outline-none"
            />
            <button
              disabled={!approvalJustification.trim() || gatewayBusy}
              onClick={() =>
                executeLinuxWorkerCommand(pendingApproval.rawCommand, {
                  approvalConfirmed: true,
                  justification: approvalJustification.trim(),
                })
              }
              className="px-3 py-1 bg-[#c88b32] hover:bg-[#d6983d] text-[#0b0d10] font-mono text-[11px] font-semibold cursor-pointer disabled:opacity-50"
            >
              Approve &amp; Execute on Gateway
            </button>
          </div>
        </div>
      )}

      {/* Main Split: Interactive Console + Tool Availability & Gateway Management Panel */}
      <div className="flex-1 flex min-h-0 overflow-hidden">
        <div className="flex-1 flex flex-col min-w-0">
          {/* Quick Presets / Command Suggestions */}
          <div className="px-3 py-1.5 border-b border-[#252b36] bg-[#0e1116] flex flex-wrap items-center gap-1.5 font-mono text-[10px] shrink-0">
            <span className="text-[#8c97a8]">
              {environment === 'atlas_native' ? 'ATLAS COMMANDS:' : 'LINUX TOOLS:'}
            </span>
            {presets.map((cmd) => (
              <button
                key={cmd}
                onClick={() => runCommand(cmd)}
                className="px-2 py-0.5 bg-[#12151b] hover:bg-[#181c24] border border-[#252b36] text-[#4a9eb0] cursor-pointer"
              >
                {cmd}
              </button>
            ))}

            {environment === 'linux_worker' && (
              <div className="ml-auto flex items-center gap-2">
                <input
                  ref={pcapInputRef}
                  type="file"
                  accept=".pcap,.pcapng"
                  onChange={handlePcapUpload}
                  className="hidden"
                />
                <button
                  disabled={gatewayHealth.state !== 'READY'}
                  onClick={() => pcapInputRef.current?.click()}
                  className="px-2 py-0.5 bg-[#12151b] hover:bg-[#181c24] border border-[#252b36] text-[#8fa36d] flex items-center gap-1 cursor-pointer disabled:opacity-40"
                  title="Upload validated .pcap / .pcapng file to gateway sandbox"
                >
                  <Upload className="w-3 h-3" />
                  <span>Stage PCAP</span>
                </button>
              </div>
            )}
          </div>

          {pcapNotice && (
            <div className="px-3 py-1 bg-[#12151b] border-b border-[#252b36] font-mono text-[10px] text-[#4a9eb0] flex items-center justify-between">
              <span>{pcapNotice}</span>
              <button onClick={() => setPcapNotice(null)} className="underline cursor-pointer">
                Dismiss
              </button>
            </div>
          )}

          {/* Terminal Prompt Input */}
          <form onSubmit={handleSubmit} className="px-3 py-2 border-b border-[#252b36] bg-[#0b0d10] flex items-center gap-2 shrink-0">
            <span
              className={`font-mono text-xs font-semibold select-none ${
                environment === 'atlas_native' ? 'text-[#8fa36d]' : 'text-[#4a9eb0]'
              }`}
            >
              {environment === 'atlas_native' ? 'atlas@soc:~$' : 'atlas@linux-worker:~$'}
            </span>
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder={
                environment === 'atlas_native'
                  ? 'e.g., geo blast-radius EV-01 | resilience assess SUB-01 | threat correlate 198.51.100.10 | report incident EV-01'
                  : 'e.g., sysinfo | interfaces | nmap -sn 192.168.10.0/24 | nmap -sV -p 22,443 192.168.10.15 | pcap summary cap.pcap'
              }
              className="flex-1 bg-transparent font-mono text-xs text-[#e8ecf1] placeholder-[#5d6778] focus:outline-none"
            />
            <button
              type="submit"
              disabled={gatewayBusy}
              className="px-3 py-1 bg-[#6f8054] hover:bg-[#7d905f] text-[#0b0d10] font-mono text-[11px] font-semibold cursor-pointer disabled:opacity-50"
            >
              {gatewayBusy ? 'Executing...' : 'Execute'}
            </button>
          </form>

          {/* Terminal Output Scrollback */}
          <div className="flex-1 overflow-y-auto p-3 space-y-2.5 font-mono text-xs bg-[#080a0d]">
            {history.length === 0 ? (
              <div className="p-4 bg-[#12151b] border border-[#252b36] text-[#8c97a8] space-y-2">
                <div className="text-[#e8ecf1] font-semibold">
                  Project ATLAS Hybrid Cybersecurity Operations Terminal Ready
                </div>
                <p className="text-[11px] leading-relaxed">
                  <strong>ATLAS NATIVE (atlas@soc)</strong> executes structured intelligence commands across Supabase workspace assets, incidents, CTI indicators, geospatial buffers, resilience cascades, and Markdown reports.
                </p>
                <p className="text-[11px] leading-relaxed">
                  <strong>LINUX WORKER (atlas@linux-worker)</strong> dispatches allowlisted Nmap, TShark PCAP, Linux diagnostics, and isolated Python 3 tasks ONLY when an authenticated external Linux Execution Gateway is connected and passes health checks.
                </p>
              </div>
            ) : (
              history.map((entry) => {
                const isCollapsed = expandedEntries[entry.id] === false;
                return (
                  <div key={entry.id} className="bg-[#0e1116] border border-[#1e242e] p-2.5 space-y-1.5">
                    <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[#181c24] pb-1 text-[10px]">
                      <div className="flex items-center gap-1.5 min-w-0">
                        <button
                          onClick={() =>
                            setExpandedEntries((prev) => ({ ...prev, [entry.id]: isCollapsed }))
                          }
                          className="text-[#8c97a8] hover:text-[#e8ecf1] cursor-pointer"
                          title={isCollapsed ? 'Expand output' : 'Collapse output'}
                        >
                          {isCollapsed ? <ChevronRight className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                        </button>
                        <span
                          className={
                            entry.environment === 'linux_worker'
                              ? 'text-[#4a9eb0] font-semibold'
                              : 'text-[#8fa36d] font-semibold'
                          }
                        >
                          {entry.environment === 'linux_worker' ? 'linux$' : '$'} {entry.command}
                        </span>
                        {entry.riskLevel && (
                          <span className="px-1 border border-[#252b36] text-[#8c97a8] text-[9px]">
                            {entry.riskLevel}
                          </span>
                        )}
                      </div>
                      <div className="flex items-center gap-2 text-[#5d6778] tabular-nums">
                        <span>
                          {entry.scopeLabel}
                          {entry.durationMs !== undefined ? ` · ${entry.durationMs}ms` : ''} · {entry.timestampUtc}
                        </span>
                        <button
                          onClick={() => handleCopyEntry(entry)}
                          className="text-[#8c97a8] hover:text-[#e8ecf1] cursor-pointer"
                          title="Copy output"
                        >
                          <Copy className="w-3 h-3" />
                        </button>
                        <button
                          onClick={() => handleExportEntry(entry)}
                          className="text-[#8c97a8] hover:text-[#4a9eb0] cursor-pointer"
                          title="Export Markdown report"
                        >
                          <Download className="w-3 h-3" />
                        </button>
                        {copiedId === entry.id && <span className="text-[#4f8f66]">COPIED</span>}
                      </div>
                    </div>

                    {!isCollapsed && (
                      <div className="space-y-0.5 text-[11px]">
                        {entry.lines.map((line, i) => {
                          const toneClass =
                            line.tone === 'accent'
                              ? 'text-[#4a9eb0] font-semibold'
                              : line.tone === 'ok'
                              ? 'text-[#4f8f66]'
                              : line.tone === 'warn'
                              ? 'text-[#c88b32]'
                              : line.tone === 'err'
                              ? 'text-[#c94a4a]'
                              : line.tone === 'muted'
                              ? 'text-[#8c97a8]'
                              : 'text-[#e8ecf1]';

                          return (
                            <div key={i} className="flex items-center justify-between gap-2">
                              <span className={`${toneClass} whitespace-pre-wrap break-words`}>{line.text}</span>
                              {line.entityRef && (
                                <button
                                  onClick={() => onSelectEntity(line.entityRef!)}
                                  className="px-1.5 py-0.5 bg-[#12151b] hover:bg-[#181c24] border border-[#252b36] text-[10px] text-[#4a9eb0] flex items-center gap-0.5 shrink-0 cursor-pointer"
                                >
                                  <span>Inspect</span>
                                  <ArrowUpRight className="w-2.5 h-2.5" />
                                </button>
                              )}
                            </div>
                          );
                        })}

                        {entry.correlation && (
                          <div className="mt-1.5 p-2 bg-[#12151b] border border-[#252b36] space-y-1 text-[10px]">
                            <div className="text-[#c88b32] font-semibold">
                              ATLAS CORRELATION SUMMARY ({entry.correlation.sourceTool.toUpperCase()})
                            </div>
                            {entry.correlation.notes.map((n, idx) => (
                              <div key={idx} className="text-[#e8ecf1]">
                                • {n}
                              </div>
                            ))}
                            <div className="text-[#8c97a8]">{entry.correlation.provenanceNote}</div>
                            <div className="flex flex-wrap gap-1 pt-0.5">
                              {entry.correlation.matchedAssetIds.map((aid) => (
                                <button
                                  key={aid}
                                  onClick={() => onSelectEntity({ kind: 'asset', id: aid })}
                                  className="px-1.5 py-0.5 bg-[#0b0d10] border border-[#252b36] text-[#4a9eb0] cursor-pointer"
                                >
                                  Asset {aid.slice(0, 8)}
                                </button>
                              ))}
                              {entry.correlation.matchedIncidentIds.map((iid) => (
                                <button
                                  key={iid}
                                  onClick={() => onSelectEntity({ kind: 'incident', id: iid })}
                                  className="px-1.5 py-0.5 bg-[#0b0d10] border border-[#252b36] text-[#c88b32] cursor-pointer"
                                >
                                  Incident {iid.slice(0, 8)}
                                </button>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Right Panel: Gateway Endpoint Config, Real Tool Management Panel, and Policy Guardrails */}
        <aside className="w-80 border-l border-[#252b36] bg-[#0e1116] p-3 space-y-3 overflow-y-auto shrink-0 hidden lg:block">
          {/* Gateway Connection Config */}
          <div className="space-y-1.5">
            <div className="font-mono text-[10px] tracking-[0.12em] text-[#8c97a8] font-semibold flex items-center justify-between">
              <span>LINUX EXECUTION GATEWAY</span>
              <PlugZap className="w-3 h-3 text-[#4a9eb0]" />
            </div>
            <div className="p-2.5 bg-[#12151b] border border-[#252b36] space-y-2 font-mono text-[10px]">
              <div className="flex items-center justify-between">
                <span className="text-[#8c97a8]">STATE:</span>
                <span className="font-semibold text-[#e8ecf1]">{effectiveDisplayState}</span>
              </div>
              <input
                type="url"
                value={gatewayUrlInput}
                onChange={(e) => setGatewayUrlInput(e.target.value)}
                placeholder="https://gw.internal:8443 or http://127.0.0.1:8443"
                className="w-full bg-[#0b0d10] border border-[#252b36] px-2 py-1 text-[11px] text-[#e8ecf1] focus:outline-none focus:border-[#4a9eb0]"
              />
              <button
                onClick={() => probeGateway()}
                disabled={gatewayBusy}
                className="w-full py-1 bg-[#181c24] hover:bg-[#222834] border border-[#252b36] text-[#e8ecf1] flex items-center justify-center gap-1.5 cursor-pointer disabled:opacity-50"
              >
                <RefreshCw className={`w-3 h-3 ${gatewayBusy ? 'animate-spin' : ''}`} />
                <span>Verify Auth &amp; Tool Health</span>
              </button>
              {gatewayHealth.errorMessage && (
                <div className="text-[#c94a4a] leading-snug break-words">{gatewayHealth.errorMessage}</div>
              )}
              {gatewayHealth.checkedAtUtc && (
                <div className="text-[#5d6778]">
                  Checked: {gatewayHealth.checkedAtUtc.slice(11, 19)} UTC
                </div>
              )}
            </div>
          </div>

          {/* Tool Availability & Management Panel */}
          <div className="space-y-1.5">
            <div className="font-mono text-[10px] tracking-[0.12em] text-[#8c97a8] font-semibold flex items-center justify-between">
              <span>TOOL MANAGEMENT PANEL</span>
              <Cpu className="w-3 h-3 text-[#8fa36d]" />
            </div>

            {gatewayHealth.tools.length === 0 ? (
              <div className="p-2.5 bg-[#12151b] border border-[#252b36] font-mono text-[10px] text-[#8c97a8] space-y-1">
                <div className="text-[#c88b32] font-semibold">NO LIVE GATEWAY HEALTH CHECK</div>
                <p className="font-sans text-[11px] leading-relaxed">
                  Linux tools (`nmap`, `tshark`, `python3`, `sysinfo`, `zeek`, `suricata`, `osquery`, `yara`) show UNAVAILABLE until `/health` succeeds against an authenticated external `/gateway` service.
                </p>
              </div>
            ) : (
              <div className="space-y-1.5">
                {gatewayHealth.tools.map((t) => (
                  <div key={t.id} className="p-2 bg-[#12151b] border border-[#252b36] font-mono text-[10px] space-y-1">
                    <div className="flex items-center justify-between gap-1">
                      <span className="text-[#e8ecf1] font-semibold truncate">{t.name}</span>
                      {t.available ? (
                        <CheckCircle2 className="w-3 h-3 text-[#4f8f66] shrink-0" />
                      ) : (
                        <XCircle className="w-3 h-3 text-[#8c97a8] shrink-0" />
                      )}
                    </div>
                    <div className="flex items-center justify-between">
                      <span className={t.available ? 'text-[#4f8f66]' : 'text-[#c88b32]'}>
                        {t.available ? 'READY' : t.installed ? 'DISABLED / ADAPTER' : 'NOT INSTALLED'}
                      </span>
                      <span className="text-[#5d6778]">PERM: {t.requiredPermission}</span>
                    </div>
                    {t.version && <div className="text-[#8c97a8] truncate">{t.version}</div>}
                    {!t.available && t.unavailableReason && (
                      <div className="text-[#5d6778] font-sans text-[10px]">{t.unavailableReason}</div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Policy Scope & External Record Notice */}
          <div className="space-y-1.5">
            <div className="font-mono text-[10px] tracking-[0.12em] text-[#8c97a8] font-semibold">
              POLICY ENGINE ({activePolicies.length} RULES)
            </div>
            {REMOTE_TERMINAL_ADAPTERS.map((adp) => (
              <div key={adp.id} className="p-2 bg-[#12151b] border border-[#252b36] space-y-1 font-mono text-[10px]">
                <div className="flex items-center justify-between gap-1">
                  <span className="text-[#e8ecf1] font-semibold truncate">{adp.label}</span>
                  <Lock className="w-3 h-3 text-[#c88b32] shrink-0" />
                </div>
                <div className="text-[#8c97a8] font-sans text-[10px]">{adp.requiredConfiguration}</div>
              </div>
            ))}
          </div>

          <div className="p-2.5 bg-[#c88b32]/10 border border-[#c88b32]/30 text-[11px] text-[#c88b32] space-y-1">
            <div className="font-mono text-[10px] font-semibold flex items-center gap-1">
              <AlertTriangle className="w-3 h-3" />
              <span>PROVENANCE &amp; STORAGE NOTICE</span>
            </div>
            <p className="text-[11px] leading-relaxed text-[#e8ecf1]/80 font-sans">
              Terminal history stays in org-scoped browser storage (`atlas:terminal_history:{intel.orgId.slice(0, 6)}...`). Gateway executions are classified as EXTERNAL_GATEWAY_EXECUTION_RECORD; formal archival requires Evidence &amp; Custody upload.
            </p>
          </div>
        </aside>
      </div>
    </div>
  );
};
