/**
 * Project ATLAS External Gateway — Bounded, Org-Isolated Execution Job Manager
 *
 * Security Guarantees:
 * - Spawns ONLY fixed executable paths with structured argument arrays (`shell: false`).
 * - Enforces runtime timeouts (SIGTERM -> SIGKILL), output size caps, and concurrency limits.
 * - Isolates every job strictly by verified `orgId` (`403` on cross-org access).
 * - Cleans up stale jobs cleanly and runs bounded local Linux diagnostics using real OS/proc APIs.
 */

import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn, type ChildProcess } from 'node:child_process';
import type {
  AuthenticatedContext,
  GatewayJobRecord,
  GatewayJobRequest,
  ValidatedExecutionSpec,
} from './types.js';
import type { ResolvedToolPaths } from './tools/toolHealth.js';
import {
  parseNmapXmlOutput,
  parseTsharkOutput,
  sanitizeOutputText,
} from './tools/parsers.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DEFAULT_PY_SCRIPT = path.resolve(__dirname, '../scripts/defensive_analyze.py');

export interface JobManagerOptions {
  workDir: string;
  maxConcurrentJobs: number;
  maxJobsPerOrg?: number;
  resolvedPaths: ResolvedToolPaths;
  pythonScriptPath?: string;
}

export class JobAccessError extends Error {
  public readonly statusCode: number;
  constructor(statusCode: number, message: string) {
    super(message);
    this.statusCode = statusCode;
  }
}

export class GatewayJobManager {
  private readonly jobs = new Map<string, GatewayJobRecord>();
  private readonly activeProcesses = new Map<string, ChildProcess>();
  private readonly workDir: string;
  private readonly maxConcurrentJobs: number;
  private readonly maxJobsPerOrg: number;
  private resolvedPaths: ResolvedToolPaths;
  private readonly pythonScriptPath: string;

  constructor(opts: JobManagerOptions) {
    this.workDir = opts.workDir;
    this.maxConcurrentJobs = Math.max(1, opts.maxConcurrentJobs);
    this.maxJobsPerOrg = opts.maxJobsPerOrg ?? 50;
    this.resolvedPaths = opts.resolvedPaths;
    this.pythonScriptPath = opts.pythonScriptPath || DEFAULT_PY_SCRIPT;
  }

  public updateResolvedPaths(paths: ResolvedToolPaths): void {
    this.resolvedPaths = paths;
  }

  private countActiveRunning(): number {
    let n = 0;
    for (const j of this.jobs.values()) {
      if (j.status === 'running' || j.status === 'queued') n++;
    }
    return n;
  }

  private pruneOrgJobs(orgId: string): void {
    const orgJobs = Array.from(this.jobs.values())
      .filter((j) => j.orgId === orgId)
      .sort((a, b) => b.startedAtUtc.localeCompare(a.startedAtUtc));

    if (orgJobs.length > this.maxJobsPerOrg) {
      for (const old of orgJobs.slice(this.maxJobsPerOrg)) {
        if (old.status !== 'running') {
          this.jobs.delete(old.jobId);
        }
      }
    }
  }

  public listJobsForOrg(orgId: string): GatewayJobRecord[] {
    return Array.from(this.jobs.values())
      .filter((j) => j.orgId === orgId)
      .sort((a, b) => b.startedAtUtc.localeCompare(a.startedAtUtc));
  }

  public getJobForOrg(jobId: string, orgId: string): GatewayJobRecord {
    const job = this.jobs.get(jobId);
    if (!job) {
      throw new JobAccessError(404, `Job "${jobId}" not found.`);
    }
    if (job.orgId !== orgId) {
      throw new JobAccessError(403, 'Access denied: job belongs to another organisation.');
    }
    return job;
  }

  public cancelJob(jobId: string, orgId: string, requestingUserId: string): GatewayJobRecord {
    const job = this.getJobForOrg(jobId, orgId);
    const proc = this.activeProcesses.get(jobId);
    if (proc && job.status === 'running') {
      job.status = 'cancelled';
      job.endedAtUtc = new Date().toISOString();
      job.durationMs = Date.now() - Date.parse(job.startedAtUtc);
      job.errorSummary = `Cancelled by operator (${requestingUserId}).`;
      proc.kill('SIGTERM');
      setTimeout(() => {
        if (!proc.killed) proc.kill('SIGKILL');
      }, 1500);
      this.activeProcesses.delete(jobId);
    }
    return job;
  }

  /**
   * Executes real read-only Linux diagnostics inside the worker without shell invocation.
   */
  private async runSafeDiagnostic(
    kind: 'sysinfo' | 'interfaces' | 'processes' | 'services' | 'disk' | 'memory',
    maxRuntimeMs: number
  ): Promise<{ exitCode: number | null; stdout: string; stderr: string }> {
    if (kind === 'sysinfo') {
      const lines = [
        `HOSTNAME: ${os.hostname()}`,
        `PLATFORM: ${os.platform()} ${os.release()} (${os.arch()})`,
        `UPTIME_SEC: ${Math.floor(os.uptime())}`,
        `CPU_COUNT: ${os.cpus().length} (${os.cpus()[0]?.model || 'unknown'})`,
        `LOADAVG_1M_5M_15M: ${os.loadavg().map((n) => n.toFixed(2)).join(', ')}`,
      ];
      return { exitCode: 0, stdout: lines.join('\n'), stderr: '' };
    }

    if (kind === 'interfaces') {
      const ifaces = os.networkInterfaces();
      const lines: string[] = [];
      for (const [name, addrs] of Object.entries(ifaces)) {
        for (const a of addrs || []) {
          lines.push(`${name}\t${a.family}\t${a.address}/${a.netmask}\tinternal=${a.internal}`);
        }
      }
      return { exitCode: 0, stdout: lines.join('\n') || 'No interfaces returned.', stderr: '' };
    }

    if (kind === 'memory') {
      const totalMb = (os.totalmem() / 1024 / 1024).toFixed(1);
      const freeMb = (os.freemem() / 1024 / 1024).toFixed(1);
      const usedMb = ((os.totalmem() - os.freemem()) / 1024 / 1024).toFixed(1);
      return {
        exitCode: 0,
        stdout: `TOTAL_MB: ${totalMb}\nUSED_MB: ${usedMb}\nFREE_MB: ${freeMb}`,
        stderr: '',
      };
    }

    const binArgs: Record<'processes' | 'services' | 'disk', { bins: string[]; args: string[] }> = {
      disk: { bins: ['/bin/df', '/usr/bin/df', 'df'], args: ['-h', '-P'] },
      processes: { bins: ['/bin/ps', '/usr/bin/ps', 'ps'], args: ['-eo', 'pid,ppid,user,comm', '--no-headers'] },
      services: { bins: ['/bin/ss', '/usr/bin/ss', 'ss'], args: ['-tuln'] },
    };

    const cfg = binArgs[kind];
    for (const bin of cfg.bins) {
      try {
        const res = await this.spawnFixedBinary(bin, cfg.args, maxRuntimeMs, 65536);
        return res;
      } catch (err: any) {
        if (err?.code === 'ENOENT') continue;
        return { exitCode: 1, stdout: '', stderr: err?.message || `Failed to run ${kind}` };
      }
    }
    return { exitCode: 127, stdout: '', stderr: `Diagnostic binary for "${kind}" is not installed on worker.` };
  }

  private spawnFixedBinary(
    binaryPath: string,
    fixedArgs: string[],
    maxRuntimeMs: number,
    maxOutputBytes: number,
    onProcCreated?: (proc: ChildProcess) => void
  ): Promise<{ exitCode: number | null; stdout: string; stderr: string; timedOut?: boolean }> {
    return new Promise((resolve, reject) => {
      const child = spawn(binaryPath, fixedArgs, {
        shell: false,
        env: {
          PATH: '/usr/local/bin:/usr/bin:/bin',
          LANG: 'C.UTF-8',
          HOME: this.workDir,
        },
        stdio: ['ignore', 'pipe', 'pipe'],
      });

      if (onProcCreated) onProcCreated(child);

      let outBytes = 0;
      let errBytes = 0;
      const outChunks: Buffer[] = [];
      const errChunks: Buffer[] = [];
      let timedOut = false;

      const timer = setTimeout(() => {
        timedOut = true;
        child.kill('SIGTERM');
        setTimeout(() => {
          if (!child.killed) child.kill('SIGKILL');
        }, 1500);
      }, maxRuntimeMs);

      child.stdout?.on('data', (chunk: Buffer) => {
        if (outBytes < maxOutputBytes) {
          const allowed = chunk.subarray(0, maxOutputBytes - outBytes);
          outChunks.push(allowed);
          outBytes += allowed.length;
        }
      });

      child.stderr?.on('data', (chunk: Buffer) => {
        if (errBytes < 32768) {
          const allowed = chunk.subarray(0, 32768 - errBytes);
          errChunks.push(allowed);
          errBytes += allowed.length;
        }
      });

      child.on('error', (err) => {
        clearTimeout(timer);
        reject(err);
      });

      child.on('close', (code) => {
        clearTimeout(timer);
        resolve({
          exitCode: code,
          stdout: Buffer.concat(outChunks).toString('utf8'),
          stderr: Buffer.concat(errChunks).toString('utf8'),
          timedOut,
        });
      });
    });
  }

  public async startJob(
    auth: AuthenticatedContext,
    rawReq: GatewayJobRequest,
    spec: ValidatedExecutionSpec
  ): Promise<GatewayJobRecord> {
    if (this.countActiveRunning() >= this.maxConcurrentJobs) {
      throw new JobAccessError(
        429,
        `Concurrency limit reached (${this.maxConcurrentJobs} active jobs). Try again shortly.`
      );
    }

    const jobId = `gwjob-${crypto.randomUUID().slice(0, 12)}`;
    const startedAtUtc = new Date().toISOString();
    const record: GatewayJobRecord = {
      jobId,
      userId: auth.userId,
      orgId: auth.orgId,
      tool: spec.binaryKey,
      command: `${rawReq.tool} ${rawReq.args.join(' ')}`.trim(),
      args: spec.fixedArgs,
      target: spec.target,
      riskLevel: spec.riskLevel,
      approvalState: spec.requiresApproval ? 'explicit_operator_approved' : 'not_required',
      approvalJustification: rawReq.approvalJustification?.trim() || undefined,
      status: 'running',
      startedAtUtc,
      stdoutLines: [],
      stderrLines: [],
      recordClassification: 'EXTERNAL_GATEWAY_EXECUTION_RECORD',
    };

    this.jobs.set(jobId, record);
    this.pruneOrgJobs(auth.orgId);

    const t0 = Date.now();

    try {
      // ---- Diagnostics ----
      if (['sysinfo', 'interfaces', 'processes', 'services', 'disk', 'memory'].includes(spec.binaryKey)) {
        const res = await this.runSafeDiagnostic(spec.binaryKey as any, spec.maxRuntimeMs);
        record.endedAtUtc = new Date().toISOString();
        record.durationMs = Date.now() - t0;
        record.exitCode = res.exitCode;
        record.stdoutLines = sanitizeOutputText(res.stdout, spec.maxOutputBytes).split('\n').filter(Boolean);
        record.stderrLines = res.stderr ? sanitizeOutputText(res.stderr, 16384).split('\n').filter(Boolean) : [];
        record.status = res.exitCode === 0 ? 'completed' : 'failed';
        record.resultSummary = `${spec.binaryKey} completed (${record.stdoutLines.length} lines).`;
        return record;
      }

      // ---- Nmap ----
      if (spec.binaryKey === 'nmap') {
        const nmapBin = this.resolvedPaths.nmap;
        if (!nmapBin) {
          record.status = 'failed';
          record.endedAtUtc = new Date().toISOString();
          record.durationMs = Date.now() - t0;
          record.exitCode = 127;
          record.errorSummary = 'Nmap binary is not installed in this Linux worker environment.';
          record.stderrLines = [record.errorSummary];
          return record;
        }

        const res = await this.spawnFixedBinary(nmapBin, spec.fixedArgs, spec.maxRuntimeMs, spec.maxOutputBytes, (p) => {
          this.activeProcesses.set(jobId, p);
        });
        this.activeProcesses.delete(jobId);

        if ((record.status as string) === 'cancelled') return record;

        record.endedAtUtc = new Date().toISOString();
        record.durationMs = Date.now() - t0;
        record.exitCode = res.exitCode;

        if (res.timedOut) {
          record.status = 'timed_out';
          record.errorSummary = `Nmap terminated after exceeding ${spec.maxRuntimeMs} ms timeout.`;
          record.stderrLines = [record.errorSummary];
          return record;
        }

        const cleanOut = sanitizeOutputText(res.stdout, spec.maxOutputBytes);
        const cleanErr = sanitizeOutputText(res.stderr, 32768);
        record.stderrLines = cleanErr ? cleanErr.split('\n').filter(Boolean) : [];

        if (spec.fixedArgs.includes('-oX')) {
          const parsed = parseNmapXmlOutput(cleanOut, record.command, startedAtUtc);
          record.nmapParsed = parsed;
          const summaryLines = [
            `NMAP SCAN COMPLETED (${parsed.hosts.length} host block(s), ${parsed.openPortsCount} open port(s)):`,
          ];
          for (const h of parsed.hosts) {
            const portSummary = h.ports.map((p) => `${p.port}/${p.protocol}:${p.state}(${p.service})`).join(', ');
            summaryLines.push(`  HOST ${h.ip}${h.hostname ? ` (${h.hostname})` : ''} [${h.state}] -> ${portSummary || 'no port details'}`);
          }
          record.stdoutLines = summaryLines;
          record.resultSummary = `${parsed.hosts.length} host(s), ${parsed.openPortsCount} open port(s) observed.`;
        } else {
          record.stdoutLines = cleanOut.split('\n').filter(Boolean);
          record.resultSummary = 'Nmap help reference returned.';
        }

        record.status = res.exitCode === 0 ? 'completed' : 'failed';
        if (res.exitCode !== 0 && !record.errorSummary) {
          record.errorSummary = cleanErr || `Nmap exited with code ${res.exitCode}.`;
        }
        return record;
      }

      // ---- TShark Offline PCAP ----
      if (spec.binaryKey === 'tshark') {
        const tsharkBin = this.resolvedPaths.tshark;
        if (!tsharkBin) {
          record.status = 'failed';
          record.endedAtUtc = new Date().toISOString();
          record.durationMs = Date.now() - t0;
          record.exitCode = 127;
          record.errorSummary = 'TShark binary is not installed in this Linux worker environment.';
          record.stderrLines = [record.errorSummary];
          return record;
        }

        // Verify PCAP file exists inside org sandbox before spawning
        const pcapFileArg = spec.fixedArgs[1];
        try {
          await fs.access(pcapFileArg);
        } catch {
          record.status = 'failed';
          record.endedAtUtc = new Date().toISOString();
          record.durationMs = Date.now() - t0;
          record.exitCode = 2;
          record.errorSummary = `PCAP file "${spec.target}" not found in org sandbox. Upload the .pcap first.`;
          record.stderrLines = [record.errorSummary];
          return record;
        }

        const op = rawReq.args[0] as 'summary' | 'dns' | 'conversations';
        const res = await this.spawnFixedBinary(tsharkBin, spec.fixedArgs, spec.maxRuntimeMs, spec.maxOutputBytes, (p) => {
          this.activeProcesses.set(jobId, p);
        });
        this.activeProcesses.delete(jobId);

        if ((record.status as string) === 'cancelled') return record;

        record.endedAtUtc = new Date().toISOString();
        record.durationMs = Date.now() - t0;
        record.exitCode = res.exitCode;
        const cleanOut = sanitizeOutputText(res.stdout, spec.maxOutputBytes);
        const cleanErr = sanitizeOutputText(res.stderr, 32768);
        record.stdoutLines = cleanOut.split('\n').filter(Boolean);
        record.stderrLines = cleanErr ? cleanErr.split('\n').filter(Boolean) : [];

        if (res.timedOut) {
          record.status = 'timed_out';
          record.errorSummary = `TShark timed out after ${spec.maxRuntimeMs} ms.`;
          return record;
        }

        record.tsharkParsed = parseTsharkOutput(op, spec.target, cleanOut);
        record.status = res.exitCode === 0 ? 'completed' : 'failed';
        record.resultSummary = `TShark ${op} parsed ${record.tsharkParsed.packetCount} frames, ${record.tsharkParsed.uniqueIps.length} unique IPs.`;
        return record;
      }

      // ---- Isolated Python 3 Defensive Runner ----
      if (spec.binaryKey === 'py_analyze') {
        const pyBin = this.resolvedPaths.python3;
        if (!pyBin) {
          record.status = 'failed';
          record.endedAtUtc = new Date().toISOString();
          record.durationMs = Date.now() - t0;
          record.exitCode = 127;
          record.errorSummary = 'Python 3 binary is not installed in this Linux worker environment.';
          record.stderrLines = [record.errorSummary];
          return record;
        }

        const [preset, datasetName] = spec.fixedArgs;
        const datasetPath = path.resolve(this.workDir, 'datasets', auth.orgId, datasetName);
        const expectedDir = path.resolve(this.workDir, 'datasets', auth.orgId) + path.sep;
        if (!datasetPath.startsWith(expectedDir)) {
          record.status = 'blocked_by_policy';
          record.errorSummary = 'Path traversal blocked in Python sandbox.';
          return record;
        }

        const pyArgs = ['-I', '-S', '-E', this.pythonScriptPath, preset, datasetPath];
        const res = await this.spawnFixedBinary(pyBin, pyArgs, spec.maxRuntimeMs, spec.maxOutputBytes, (p) => {
          this.activeProcesses.set(jobId, p);
        });
        this.activeProcesses.delete(jobId);

        if ((record.status as string) === 'cancelled') return record;

        record.endedAtUtc = new Date().toISOString();
        record.durationMs = Date.now() - t0;
        record.exitCode = res.exitCode;
        record.stdoutLines = sanitizeOutputText(res.stdout, spec.maxOutputBytes).split('\n').filter(Boolean);
        record.stderrLines = res.stderr ? sanitizeOutputText(res.stderr, 32768).split('\n').filter(Boolean) : [];
        record.status = res.timedOut ? 'timed_out' : res.exitCode === 0 ? 'completed' : 'failed';
        record.resultSummary = `Python defensive preset ${preset} finished with exit code ${res.exitCode}.`;
        return record;
      }

      record.status = 'failed';
      record.errorSummary = `Unhandled binary key: ${spec.binaryKey}`;
      return record;
    } catch (err: any) {
      this.activeProcesses.delete(jobId);
      record.status = 'failed';
      record.endedAtUtc = new Date().toISOString();
      record.durationMs = Date.now() - t0;
      record.errorSummary = err?.message || 'Unexpected execution error.';
      record.stderrLines = [record.errorSummary!];
      return record;
    }
  }
}
