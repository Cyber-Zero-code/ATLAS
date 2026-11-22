/**
 * Project ATLAS External Gateway — Output Sanitization & Structured Nmap/TShark Parsers
 */

import type { NmapDiscoveredHost, NmapParsedResult, TsharkParsedResult } from '../types.js';

const ANSI_ESCAPE_RE = /\x1b\[[0-9;]*[a-zA-Z]/g;
const SECRET_LINE_RE = /(Authorization:\s*Bearer\s+\S+|SUPABASE_SERVICE_ROLE_KEY=\S+|-----BEGIN [A-Z ]+PRIVATE KEY-----)/gi;

export function sanitizeOutputText(raw: string, maxBytes = 262144): string {
  let clean = raw
    .replace(ANSI_ESCAPE_RE, '')
    .replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, '')
    .replace(SECRET_LINE_RE, '[REDACTED_SENSITIVE_MATERIAL]');

  if (Buffer.byteLength(clean, 'utf8') > maxBytes) {
    const buf = Buffer.from(clean, 'utf8').subarray(0, maxBytes);
    clean = buf.toString('utf8') + '\n[OUTPUT TRUNCATED BY GATEWAY SIZE POLICY]';
  }
  return clean;
}

/**
 * Parses Nmap XML (`-oX -`) output deterministically using regex block extraction
 * (zero external XML dependencies, immune to XXE/entity expansion).
 */
export function parseNmapXmlOutput(
  xmlText: string,
  scannerArgs: string,
  startedAtUtc: string
): NmapParsedResult {
  const hosts: NmapDiscoveredHost[] = [];
  let openPortsCount = 0;

  const hostBlockRe = /<host\b[^>]*>([\s\S]*?)<\/host>/gi;
  let hm: RegExpExecArray | null;

  while ((hm = hostBlockRe.exec(xmlText)) !== null) {
    const block = hm[1];
    const statusMatch = block.match(/<status\b[^>]*\bstate="([^"]+)"/i);
    const addrMatch = block.match(/<address\b[^>]*\baddr="([^"]+)"[^>]*\baddrtype="ipv[46]"/i);
    const hostNameMatch = block.match(/<hostname\b[^>]*\bname="([^"]+)"/i);
    if (!addrMatch) continue;

    const host: NmapDiscoveredHost = {
      ip: addrMatch[1],
      hostname: hostNameMatch?.[1],
      state: statusMatch?.[1] || 'unknown',
      ports: [],
    };

    const portRe = /<port\b[^>]*\bprotocol="(tcp|udp)"[^>]*\bportid="(\d+)"[^>]*>([\s\S]*?)<\/port>/gi;
    let pm: RegExpExecArray | null;
    while ((pm = portRe.exec(block)) !== null) {
      const protocol = pm[1].toLowerCase() as 'tcp' | 'udp';
      const portNum = Number(pm[2]);
      const pBody = pm[3];
      const pStateMatch = pBody.match(/<state\b[^>]*\bstate="([^"]+)"/i);
      const svcMatch = pBody.match(/<service\b[^>]*\bname="([^"]+)"([^>]*)\/?>/i);
      const state = pStateMatch?.[1] || 'unknown';
      const service = svcMatch?.[1] || 'unknown';
      const svcAttrs = svcMatch?.[2] || '';
      const prodMatch = svcAttrs.match(/\bproduct="([^"]+)"/i);
      const verMatch = svcAttrs.match(/\bversion="([^"]+)"/i);
      const version = [prodMatch?.[1], verMatch?.[1]].filter(Boolean).join(' ') || undefined;

      if (state === 'open') openPortsCount++;
      host.ports.push({ port: portNum, protocol, state, service, version });
    }

    hosts.push(host);
  }

  return { scannerArgs, startedAtUtc, hosts, openPortsCount };
}

/**
 * Parses TShark output across `summary`, `dns`, and `conversations` modes.
 */
export function parseTsharkOutput(
  operation: 'summary' | 'dns' | 'conversations',
  fileName: string,
  rawStdout: string
): TsharkParsedResult {
  const uniqueIps = new Set<string>();
  const dnsMap = new Map<string, { query: string; type?: string; count: number }>();
  const conversations: TsharkParsedResult['conversations'] = [];
  const protocols: TsharkParsedResult['protocols'] = [];
  let packetCount = 0;

  const lines = rawStdout.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);

  if (operation === 'summary') {
    for (const line of lines) {
      // Matches io,phs lines like: `eth   frames:120 bytes:14520`
      const m = line.match(/^([a-z0-9_.-]+)\s+frames:(\d+)\s+bytes:(\d+)/i);
      if (m) {
        const name = m[1];
        const frames = Number(m[2]);
        protocols.push({ name, frames });
        if (name === 'frame' || packetCount === 0) {
          packetCount = Math.max(packetCount, frames);
        }
      }
    }
  } else if (operation === 'dns') {
    for (const line of lines) {
      const cols = line.split('\t');
      if (cols.length < 3) continue;
      const [src, dst, qry, qType] = cols;
      if (src) uniqueIps.add(src.trim());
      if (dst) uniqueIps.add(dst.trim());
      const q = (qry || '').trim();
      if (!q) continue;
      packetCount++;
      const existing = dnsMap.get(q);
      if (existing) {
        existing.count++;
      } else {
        dnsMap.set(q, { query: q, type: qType?.trim() || undefined, count: 1 });
      }
    }
  } else if (operation === 'conversations') {
    for (const line of lines) {
      // Matches `192.168.10.5 <-> 203.0.113.45   12   1024   4   512   16   1536`
      const m = line.match(/^([0-9a-f.:]+)\s+<->\s+([0-9a-f.:]+)\s+\d+\s+\d+\s+\d+\s+\d+\s+(\d+)\s+(\d+)/i);
      if (m) {
        const src = m[1];
        const dst = m[2];
        const frames = Number(m[3]);
        const bytes = Number(m[4]);
        uniqueIps.add(src);
        uniqueIps.add(dst);
        packetCount += frames;
        conversations.push({ src, dst, protocol: 'IP', frames, bytes });
      }
    }
  }

  return {
    operation,
    fileName,
    packetCount,
    uniqueIps: Array.from(uniqueIps),
    dnsQueries: Array.from(dnsMap.values()).sort((a, b) => b.count - a.count),
    conversations: conversations.sort((a, b) => b.frames - a.frames),
    protocols,
  };
}
