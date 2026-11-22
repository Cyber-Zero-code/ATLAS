/**
 * Project ATLAS External Gateway — Server-Authoritative Command Policy & Target Allowlist Engine
 */

import path from 'node:path';
import type { AppRole, GatewayJobRequest, ValidatedExecutionSpec } from './types.js';

const SHELL_METACHARS = /[;|&`$><()\\{}\n\r\0]/;

function ipToInt(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let val = 0;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return null;
    const n = Number(p);
    if (n < 0 || n > 255) return null;
    val = (val << 8) + n;
  }
  return val >>> 0;
}

function ipInCidr(ipInt: number, cidr: string): boolean {
  const [netStr, bitsStr] = cidr.split('/');
  const netInt = ipToInt(netStr);
  if (netInt === null) return false;
  const bits = bitsStr !== undefined ? Number(bitsStr) : 32;
  if (!Number.isInteger(bits) || bits < 0 || bits > 32) return false;
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  return (ipInt & mask) === (netInt & mask);
}

export function isUnsafeInfrastructureTarget(target: string): string | null {
  const lower = target.trim().toLowerCase();
  if (
    lower === 'localhost' ||
    lower.endsWith('.localhost') ||
    lower === '::1' ||
    lower.startsWith('fe80:') ||
    lower === 'metadata.google.internal' ||
    lower === '169.254.169.254' ||
    lower === '100.100.100.200'
  ) {
    return `Target "${target}" rejected: loopback, link-local, or cloud metadata host.`;
  }

  const m = target.trim().match(/^(\d{1,3}(?:\.\d{1,3}){3})(?:\/(\d{1,2}))?$/);
  if (m) {
    const ipInt = ipToInt(m[1]);
    if (ipInt === null) return `Malformed IPv4 target "${target}".`;
    const prefix = m[2] !== undefined ? Number(m[2]) : 32;
    if (prefix < 22 || prefix > 32) {
      return `CIDR /${prefix} blocked: maximum scan prefix width is /22.`;
    }
    const o1 = (ipInt >>> 24) & 0xff;
    const o2 = (ipInt >>> 16) & 0xff;
    if (o1 === 127) return 'Loopback IPv4 range 127.0.0.0/8 is unconditionally blocked.';
    if (o1 === 0) return 'Unspecified IPv4 range 0.0.0.0/8 is blocked.';
    if (o1 === 169 && o2 === 254) return 'Link-local / cloud metadata range 169.254.0.0/16 is unconditionally blocked.';
    if (o1 >= 224) return 'Multicast/reserved range 224.0.0.0+ is blocked.';
  }
  return null;
}

export function isTargetInAllowlist(target: string, allowlist: string[]): { allowed: boolean; reason?: string } {
  if (!allowlist || allowlist.length === 0) {
    return {
      allowed: false,
      reason: 'Target rejected: GATEWAY_TARGET_ALLOWLIST is empty (fail-closed policy).',
    };
  }
  const unsafeReason = isUnsafeInfrastructureTarget(target);
  if (unsafeReason) return { allowed: false, reason: unsafeReason };

  const clean = target.trim();
  const targetMatch = clean.match(/^(\d{1,3}(?:\.\d{1,3}){3})(?:\/(\d{1,2}))?$/);
  if (targetMatch) {
    const targetIpInt = ipToInt(targetMatch[1])!;
    const targetPrefix = targetMatch[2] !== undefined ? Number(targetMatch[2]) : 32;

    for (const rule of allowlist) {
      const trimmedRule = rule.trim();
      const ruleMatch = trimmedRule.match(/^(\d{1,3}(?:\.\d{1,3}){3})(?:\/(\d{1,2}))?$/);
      if (!ruleMatch) continue;
      const rulePrefix = ruleMatch[2] !== undefined ? Number(ruleMatch[2]) : 32;
      if (targetPrefix >= rulePrefix && ipInCidr(targetIpInt, trimmedRule)) {
        return { allowed: true };
      }
    }
    return {
      allowed: false,
      reason: `Target "${clean}" is outside configured GATEWAY_TARGET_ALLOWLIST.`,
    };
  }

  // Hostname matching against explicit hostnames or `.domain` suffixes
  const lowerHost = clean.toLowerCase();
  if (!/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/.test(lowerHost)) {
    return { allowed: false, reason: `Invalid target format "${clean}".` };
  }

  for (const rule of allowlist) {
    const r = rule.trim().toLowerCase();
    if (!r) continue;
    if (r === lowerHost) return { allowed: true };
    if (r.startsWith('*.') && lowerHost.endsWith(r.slice(1))) return { allowed: true };
  }

  return { allowed: false, reason: `Hostname "${clean}" is not in GATEWAY_TARGET_ALLOWLIST.` };
}

function validatePorts(spec: string): string | null {
  if (!/^[0-9,-]{1,120}$/.test(spec)) return 'Malformed port specification.';
  const segs = spec.split(',').filter(Boolean);
  if (segs.length === 0 || segs.length > 64) return 'Port spec must contain 1–64 segments.';
  let total = 0;
  for (const s of segs) {
    if (s.includes('-')) {
      const parts = s.split('-');
      if (parts.length !== 2) return `Invalid port range "${s}".`;
      const a = Number(parts[0]);
      const b = Number(parts[1]);
      if (!Number.isInteger(a) || !Number.isInteger(b) || a < 1 || b > 65535 || a > b) {
        return `Invalid port range "${s}".`;
      }
      total += b - a + 1;
    } else {
      const p = Number(s);
      if (!Number.isInteger(p) || p < 1 || p > 65535) return `Invalid port "${s}".`;
      total += 1;
    }
    if (total > 128) return 'Port count exceeds maximum limit of 128 ports per job.';
  }
  return null;
}

/**
 * Validates and compiles an incoming GatewayJobRequest into a strictly bounded non-shell binary spec.
 */
export function validateGatewayJobRequest(
  req: GatewayJobRequest,
  role: AppRole,
  orgId: string,
  targetAllowlist: string[],
  workDir: string
): ValidatedExecutionSpec {
  const deny = (
    reason: string,
    riskLevel: ValidatedExecutionSpec['riskLevel'] = 'RESTRICTED',
    requiresApproval = false
  ): ValidatedExecutionSpec => ({
    allowed: false,
    binaryKey: 'sysinfo',
    fixedArgs: [],
    target: req.target || '',
    riskLevel,
    maxRuntimeMs: 0,
    maxOutputBytes: 0,
    requiresApproval,
    rejectionReason: reason,
  });

  if (!req || typeof req.tool !== 'string' || !Array.isArray(req.args)) {
    return deny('Malformed job request payload.');
  }

  const tool = req.tool.trim().toLowerCase();
  const args = req.args.map((a) => String(a).trim());

  for (const a of args) {
    if (SHELL_METACHARS.test(a) || a.length > 160) {
      return deny('Shell metacharacter or oversized argument rejected.');
    }
  }

  // ---- 1. Diagnostics (LOW risk, any_member, no target args) ----
  if (['sysinfo', 'interfaces', 'processes', 'services', 'disk', 'memory'].includes(tool)) {
    if (args.length > 0) {
      return deny(`Diagnostic command "${tool}" accepts zero arbitrary arguments.`);
    }
    return {
      allowed: true,
      binaryKey: tool as ValidatedExecutionSpec['binaryKey'],
      fixedArgs: [],
      target: 'linux-worker-container',
      riskLevel: 'LOW',
      maxRuntimeMs: 8000,
      maxOutputBytes: 65536,
      requiresApproval: false,
    };
  }

  // ---- 2. Nmap ----
  if (tool === 'nmap') {
    if (args.length === 1 && args[0] === '--help') {
      return {
        allowed: true,
        binaryKey: 'nmap',
        fixedArgs: ['--help'],
        target: 'local-help',
        riskLevel: 'LOW',
        maxRuntimeMs: 5000,
        maxOutputBytes: 65536,
        requiresApproval: false,
      };
    }

    for (const a of args) {
      const la = a.toLowerCase();
      if (la.includes('script') || la === '-sc' || la === '-a' || la.startsWith('--datadir')) {
        return deny(`Prohibited Nmap flag "${a}": NSE scripts and aggressive OS flags are disabled.`);
      }
    }

    // Allowed Profile A: ['-sn', '-oX', '-', '<target>'] OR ['-sn', '<target>']
    if (
      (args.length === 2 && args[0] === '-sn') ||
      (args.length === 4 && args[0] === '-sn' && args[1] === '-oX' && args[2] === '-')
    ) {
      const target = args[args.length - 1];
      const allowRes = isTargetInAllowlist(target, targetAllowlist);
      if (!allowRes.allowed) return deny(allowRes.reason || 'Target blocked.');

      if (!req.approvalConfirmed) {
        return deny('Explicit operator approval is required before launching network discovery (-sn).', 'MEDIUM', true);
      }

      return {
        allowed: true,
        binaryKey: 'nmap',
        fixedArgs: ['-sn', '-oX', '-', target],
        target,
        riskLevel: 'MEDIUM',
        maxRuntimeMs: 30000,
        maxOutputBytes: 262144,
        requiresApproval: true,
      };
    }

    // Allowed Profile B: ['-sV', '-Pn', '--version-light', '-p', '<ports>', '-oX', '-', '<target>'] or ['-sV', '-p', '<ports>', '<target>']
    const isShortSv = args.length === 4 && args[0] === '-sV' && args[1] === '-p';
    const isLongSv =
      args.length === 8 &&
      args[0] === '-sV' &&
      args[1] === '-Pn' &&
      args[2] === '--version-light' &&
      args[3] === '-p' &&
      args[5] === '-oX' &&
      args[6] === '-';

    if (isShortSv || isLongSv) {
      if (role !== 'atlas:admin') {
        return deny('PERMISSION DENIED: Service version scans (-sV) require `atlas:admin` role.', 'HIGH');
      }
      const ports = isShortSv ? args[2] : args[4];
      const portErr = validatePorts(ports);
      if (portErr) return deny(portErr);

      const target = args[args.length - 1];
      const allowRes = isTargetInAllowlist(target, targetAllowlist);
      if (!allowRes.allowed) return deny(allowRes.reason || 'Target blocked.');

      if (!req.approvalConfirmed || !(req.approvalJustification || '').trim()) {
        return deny('Explicit Admin approval + justification is required for HIGH-risk TCP service scan (-sV).', 'HIGH', true);
      }

      return {
        allowed: true,
        binaryKey: 'nmap',
        fixedArgs: ['-sV', '-Pn', '--version-light', '-p', ports, '-oX', '-', target],
        target,
        riskLevel: 'HIGH',
        maxRuntimeMs: 45000,
        maxOutputBytes: 262144,
        requiresApproval: true,
      };
    }

    return deny('Unsupported Nmap argument structure. Only `--help`, `-sn <target>`, and `-sV -p <ports> <target>` are permitted.');
  }

  // ---- 3. TShark Offline PCAP ----
  if (tool === 'tshark') {
    if (args.length !== 2 || !['summary', 'dns', 'conversations'].includes(args[0])) {
      return deny('Unsupported tshark operation. Usage: summary|dns|conversations <file.pcap>');
    }
    const op = args[0];
    const fileName = args[1];
    if (
      fileName.includes('/') ||
      fileName.includes('\\') ||
      fileName.includes('..') ||
      !/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,95}\.(pcap|pcapng)$/i.test(fileName)
    ) {
      return deny('Invalid or unsafe PCAP filename.');
    }

    const orgPcapPath = path.resolve(workDir, 'pcap', orgId, fileName);
    const expectedBase = path.resolve(workDir, 'pcap', orgId) + path.sep;
    if (!orgPcapPath.startsWith(expectedBase)) {
      return deny('Path traversal detected in PCAP sandbox resolution.');
    }

    const tsharkArgs =
      op === 'summary'
        ? ['-r', orgPcapPath, '-q', '-z', 'io,phs']
        : op === 'dns'
        ? ['-r', orgPcapPath, '-Y', 'dns.qry.name', '-T', 'fields', '-e', 'ip.src', '-e', 'ip.dst', '-e', 'dns.qry.name', '-e', 'dns.qry.type']
        : ['-r', orgPcapPath, '-q', '-z', 'conv,ip'];

    return {
      allowed: true,
      binaryKey: 'tshark',
      fixedArgs: tsharkArgs,
      target: fileName,
      riskLevel: 'MEDIUM',
      maxRuntimeMs: 25000,
      maxOutputBytes: 262144,
      requiresApproval: false,
    };
  }

  // ---- 4. Isolated Python Defensive Analysis ----
  if (tool === 'py_analyze') {
    if (args.length !== 2 || !['ioc_stats', 'log_summary', 'csv_correlate'].includes(args[0])) {
      return deny('Unsupported Python preset. Allowed presets: ioc_stats, log_summary, csv_correlate.');
    }
    const dataset = args[1];
    if (/[/\\]|\.\./.test(dataset) || !/^[a-zA-Z0-9._-]{1,96}$/.test(dataset)) {
      return deny('Invalid Python dataset identifier.');
    }
    return {
      allowed: true,
      binaryKey: 'py_analyze',
      fixedArgs: [args[0], dataset],
      target: dataset,
      riskLevel: 'MEDIUM',
      maxRuntimeMs: 15000,
      maxOutputBytes: 131072,
      requiresApproval: false,
    };
  }

  return deny(`Tool "${tool}" is not registered in the approved gateway execution registry.`);
}
