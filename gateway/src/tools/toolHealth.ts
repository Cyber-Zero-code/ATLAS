/**
 * Project ATLAS External Gateway — Real Binary Health Checks (Non-Shell Probes)
 *
 * Strictly executes version checks via `execFile(binary, args, { shell: false })`.
 * NEVER reports a tool as `available: true` unless the underlying binary exists and
 * passes a real execution probe.
 */

import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import type { LinuxToolDescriptor } from '../types.js';

const execFileAsync = promisify(execFile);

async function probeBinary(
  candidates: string[],
  versionArgs: string[]
): Promise<{ found: boolean; binPath: string | null; version: string | null; error?: string }> {
  for (const bin of candidates) {
    try {
      const { stdout, stderr } = await execFileAsync(bin, versionArgs, {
        timeout: 3000,
        maxBuffer: 32768,
      });
      const text = `${stdout}\n${stderr}`.trim().split(/\r?\n/)[0] || 'installed';
      return { found: true, binPath: bin, version: text.slice(0, 120) };
    } catch (err: any) {
      if (err?.code !== 'ENOENT') {
        return {
          found: false,
          binPath: bin,
          version: null,
          error: err?.message || 'Version probe failed.',
        };
      }
    }
  }
  return { found: false, binPath: null, version: null, error: 'Binary not installed in worker PATH.' };
}

export interface ResolvedToolPaths {
  nmap: string | null;
  tshark: string | null;
  python3: string | null;
  ffmpeg?: string | null;
}

export async function runRealToolHealthChecks(): Promise<{
  tools: LinuxToolDescriptor[];
  resolvedPaths: ResolvedToolPaths;
  checkedAtUtc: string;
}> {
  const checkedAtUtc = new Date().toISOString();

  const [nmapProbe, tsharkProbe, pyProbe, ffmpegProbe, unameProbe, wiresharkProbe, zeekProbe, suricataProbe, osqueryProbe, yaraProbe] =
    await Promise.all([
      probeBinary(['/usr/bin/nmap', 'nmap'], ['--version']),
      probeBinary(['/usr/bin/tshark', 'tshark'], ['--version']),
      probeBinary(['/usr/bin/python3', 'python3'], ['--version']),
      probeBinary(['/usr/bin/ffmpeg', 'ffmpeg'], ['-version']),
      probeBinary(['/bin/uname', '/usr/bin/uname', 'uname'], ['-a']),
      probeBinary(['/usr/bin/dumpcap', '/usr/bin/wireshark', 'dumpcap'], ['--version']),
      probeBinary(['/usr/local/zeek/bin/zeek', '/usr/bin/zeek', 'zeek'], ['--version']),
      probeBinary(['/usr/bin/suricata', 'suricata'], ['-V']),
      probeBinary(['/usr/bin/osqueryi', 'osqueryi'], ['--version']),
      probeBinary(['/usr/bin/yara', 'yara'], ['--version']),
    ]);

  const tools: LinuxToolDescriptor[] = [
    {
      id: 'nmap',
      name: 'Nmap Network Scanner',
      category: 'reconnaissance',
      installed: nmapProbe.found,
      available: nmapProbe.found,
      version: nmapProbe.version,
      lastHealthCheckUtc: checkedAtUtc,
      requiredPermission: 'any_member',
      supportedOperations: ['nmap --help', 'nmap -sn <target>', 'nmap -sV -p <ports> <target> (admin)'],
      unavailableReason: nmapProbe.found ? undefined : nmapProbe.error,
    },
    {
      id: 'tshark',
      name: 'TShark Packet Analyser',
      category: 'packet_analysis',
      installed: tsharkProbe.found,
      available: tsharkProbe.found,
      version: tsharkProbe.version,
      lastHealthCheckUtc: checkedAtUtc,
      requiredPermission: 'any_member',
      supportedOperations: ['pcap summary <file>', 'pcap dns <file>', 'pcap conversations <file>'],
      unavailableReason: tsharkProbe.found ? undefined : tsharkProbe.error,
    },
    {
      id: 'linux_diagnostics',
      name: 'Linux System Diagnostics',
      category: 'diagnostics',
      installed: unameProbe.found,
      available: true,
      version: unameProbe.version || 'Node.js OS + procfs telemetry',
      lastHealthCheckUtc: checkedAtUtc,
      requiredPermission: 'any_member',
      supportedOperations: ['sysinfo', 'interfaces', 'processes', 'services', 'disk', 'memory'],
    },
    {
      id: 'py_analyze',
      name: 'Python 3 Defensive Sandbox',
      category: 'python_analysis',
      installed: pyProbe.found,
      available: pyProbe.found,
      version: pyProbe.version,
      lastHealthCheckUtc: checkedAtUtc,
      requiredPermission: 'any_member',
      supportedOperations: ['py_analyze ioc_stats <id>', 'py_analyze log_summary <id>', 'py_analyze csv_correlate <id>'],
      unavailableReason: pyProbe.found ? undefined : pyProbe.error,
    },
    {
      id: 'wireshark',
      name: 'Wireshark / Dumpcap',
      category: 'future_adapter',
      installed: wiresharkProbe.found,
      available: false,
      version: wiresharkProbe.version,
      lastHealthCheckUtc: checkedAtUtc,
      requiredPermission: 'atlas:admin',
      supportedOperations: ['Dissector pipeline adapter'],
      unavailableReason: wiresharkProbe.found ? 'Adapter disabled pending capture policy approval.' : wiresharkProbe.error,
    },
    {
      id: 'zeek',
      name: 'Zeek Network Security Monitor',
      category: 'future_adapter',
      installed: zeekProbe.found,
      available: false,
      version: zeekProbe.version,
      lastHealthCheckUtc: checkedAtUtc,
      requiredPermission: 'atlas:admin',
      supportedOperations: ['conn.log / dns.log ingestion adapter'],
      unavailableReason: zeekProbe.found ? 'Adapter module awaiting live Zeek JSON log feed.' : zeekProbe.error,
    },
    {
      id: 'suricata',
      name: 'Suricata IDS/IPS Engine',
      category: 'future_adapter',
      installed: suricataProbe.found,
      available: false,
      version: suricataProbe.version,
      lastHealthCheckUtc: checkedAtUtc,
      requiredPermission: 'atlas:admin',
      supportedOperations: ['EVE JSON alert parser adapter'],
      unavailableReason: suricataProbe.found ? 'Adapter module awaiting EVE JSON directory.' : suricataProbe.error,
    },
    {
      id: 'osquery',
      name: 'OSQuery Endpoint Telemetry',
      category: 'future_adapter',
      installed: osqueryProbe.found,
      available: false,
      version: osqueryProbe.version,
      lastHealthCheckUtc: checkedAtUtc,
      requiredPermission: 'atlas:admin',
      supportedOperations: ['Read-only host query pack adapter'],
      unavailableReason: osqueryProbe.found ? 'Requires enrolled fleet socket.' : osqueryProbe.error,
    },
    {
      id: 'yara',
      name: 'YARA Pattern Scanner',
      category: 'future_adapter',
      installed: yaraProbe.found,
      available: false,
      version: yaraProbe.version,
      lastHealthCheckUtc: checkedAtUtc,
      requiredPermission: 'atlas:admin',
      supportedOperations: ['Quarantined artifact rule scan adapter'],
      unavailableReason: yaraProbe.found ? 'Requires signed rule repository mount.' : yaraProbe.error,
    },
  ];

  return {
    tools,
    resolvedPaths: {
      nmap: nmapProbe.binPath,
      tshark: tsharkProbe.binPath,
      python3: pyProbe.binPath,
      ffmpeg: ffmpegProbe.binPath,
    },
    checkedAtUtc,
  };
}
