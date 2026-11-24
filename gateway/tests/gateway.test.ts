/**
 * Project ATLAS — External Linux Execution Gateway Independent Test Suite
 *
 * Exercises:
 *  - Cryptographic JWT verification (valid RS256, expired, tampered sig, missing AAL2, wrong audience)
 *  - RLS Membership / Organisation isolation (403 non-member, cross-org job read/cancel block)
 *  - Target allowlist & safety bounds (RFC1918 allowlist vs 127.0.0.1 / 169.254.169.254 / out-of-scope)
 *  - Shell injection & NSE script blocking
 *  - Role & explicit approval enforcement (`atlas:analyst` vs `atlas:admin` for `-sV`)
 *  - Nmap XML parser & TShark summary/dns/conversations parsers
 *  - Output sanitization (ANSI strip + secret redaction + byte cap)
 *  - Real HTTP server `/health`, `/api/v1/tools`, `/api/v1/jobs`, `/api/v1/pcap/upload`, and diagnostics execution
 */

import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { PassThrough } from 'node:stream';
import { GatewayAuthenticator, GatewayAuthError } from '../src/auth.js';
import { CameraAnalyticsCoordinator } from '../src/cameraAnalytics.js';
import {
  CameraStreamManager,
  isValidJpegBuffer,
  MAX_CONCURRENT_STREAMS_PER_ORG,
} from '../src/cameraManager.js';
import {
  CTI_MAX_RESPONSE_BYTES,
  CtiProxyService,
  isPrivateOrReservedIp,
  readBoundedHttpStream,
  validateAndResolveEgressUrl,
} from '../src/ctiProxy.js';
import { GatewayJobManager, JobAccessError } from '../src/jobManager.js';
import { validateGatewayJobRequest, isTargetInAllowlist } from '../src/policy.js';
import { createGatewayServer, isValidPcapMagicBytes } from '../src/server.js';
import { parseNmapXmlOutput, parseTsharkOutput, sanitizeOutputText } from '../src/tools/parsers.js';
import { runRealToolHealthChecks } from '../src/tools/toolHealth.js';
import type { CameraAuditRecord, GatewayConfig } from '../src/types.js';

let passed = 0;
let failed = 0;

async function check(name: string, fn: () => Promise<void> | void) {
  try {
    await fn();
    passed++;
    console.log(`  PASS: ${name}`);
  } catch (err: any) {
    failed++;
    console.error(`  FAIL: ${name} -> ${err?.message || err}`);
  }
}

function b64u(input: Buffer | string): string {
  return Buffer.from(input)
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function signRs256Jwt(
  claims: Record<string, unknown>,
  privateKey: crypto.KeyObject,
  kid = 'atlas-test-kid'
): string {
  const header = b64u(JSON.stringify({ alg: 'RS256', typ: 'JWT', kid }));
  const body = b64u(JSON.stringify(claims));
  const input = `${header}.${body}`;
  const sig = crypto.sign('sha256', Buffer.from(input, 'utf8'), privateKey);
  return `${input}.${b64u(sig)}`;
}

const ORG_A = '11111111-1111-4111-8111-111111111111';
const ORG_B = '22222222-2222-4222-8222-222222222222';
const USER_ADMIN = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const USER_ANALYST = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';

async function main() {
  console.log('=== ATLAS LINUX EXECUTION GATEWAY TEST SUITE ===');

  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = { ...(publicKey.export({ format: 'jwk' }) as Record<string, unknown>), kid: 'atlas-test-kid', alg: 'RS256' };
  const tmpWorkDir = await fs.mkdtemp(path.join(os.tmpdir(), 'atlas-gw-test-'));

  const testConfig: GatewayConfig = {
    host: '127.0.0.1',
    port: 0,
    corsOrigin: 'http://localhost:3000',
    supabaseUrl: 'https://test.supabase.co',
    supabaseAnonKey: 'anon-test-key',
    jwtIssuer: 'https://test.supabase.co/auth/v1',
    jwtAudience: 'authenticated',
    jwksJson: JSON.stringify({ keys: [jwk] }),
    targetAllowlist: ['192.168.10.0/24', '10.20.0.0/22', '*.internal.corp'],
    workDir: tmpWorkDir,
    maxConcurrentJobs: 2,
    maxPcapBytes: 1024 * 1024,
  };

  const membershipMatrix: Record<string, Record<string, 'atlas:admin' | 'atlas:analyst'>> = {
    [USER_ADMIN]: { [ORG_A]: 'atlas:admin' },
    [USER_ANALYST]: { [ORG_A]: 'atlas:analyst' },
  };

  const authenticator = new GatewayAuthenticator(testConfig, async (_jwt, userId, requestedOrgId) => {
    const role = membershipMatrix[userId]?.[requestedOrgId];
    return role ? { orgId: requestedOrgId, role } : null;
  });

  const now = Math.floor(Date.now() / 1000);

  // ---- 1. Authentication & JWT Verification ----
  console.log('1. Authentication & Organisation Isolation');
  const validAdminJwt = signRs256Jwt(
    {
      sub: USER_ADMIN,
      email: 'admin@atlas.test',
      iss: testConfig.jwtIssuer,
      aud: 'authenticated',
      aal: 'aal2',
      exp: now + 600,
    },
    privateKey
  );

  await check('valid RS256 AAL2 JWT authenticates admin for ORG_A', async () => {
    const ctx = await authenticator.authenticateRequest(`Bearer ${validAdminJwt}`, ORG_A, now);
    assert.equal(ctx.userId, USER_ADMIN);
    assert.equal(ctx.orgId, ORG_A);
    assert.equal(ctx.role, 'atlas:admin');
  });

  await check('expired JWT is rejected with 401', async () => {
    const expiredJwt = signRs256Jwt(
      { sub: USER_ADMIN, iss: testConfig.jwtIssuer, aud: 'authenticated', aal: 'aal2', exp: now - 10 },
      privateKey
    );
    await assert.rejects(
      () => authenticator.authenticateRequest(`Bearer ${expiredJwt}`, ORG_A, now),
      (e: unknown) => e instanceof GatewayAuthError && e.statusCode === 401
    );
  });

  await check('tampered signature JWT is rejected with 401', async () => {
    const parts = validAdminJwt.split('.');
    const tampered = `${parts[0]}.${parts[1]}.${b64u('tampered-signature')}`;
    await assert.rejects(
      () => authenticator.authenticateRequest(`Bearer ${tampered}`, ORG_A, now),
      (e: unknown) => e instanceof GatewayAuthError && e.statusCode === 401
    );
  });

  await check('missing AAL2 (aal1 session) is rejected with 403', async () => {
    const aal1Jwt = signRs256Jwt(
      { sub: USER_ADMIN, iss: testConfig.jwtIssuer, aud: 'authenticated', aal: 'aal1', exp: now + 600 },
      privateKey
    );
    await assert.rejects(
      () => authenticator.authenticateRequest(`Bearer ${aal1Jwt}`, ORG_A, now),
      (e: unknown) => e instanceof GatewayAuthError && e.statusCode === 403
    );
  });

  await check('valid JWT for non-member ORG_B is rejected with 403 (org isolation)', async () => {
    await assert.rejects(
      () => authenticator.authenticateRequest(`Bearer ${validAdminJwt}`, ORG_B, now),
      (e: unknown) => e instanceof GatewayAuthError && e.statusCode === 403
    );
  });

  // ---- 2. Policy Engine, Allowlists, Shell Injection, RBAC ----
  console.log('2. Policy Engine, Target Allowlist, Shell Injection & RBAC');
  await check('allowlist accepts RFC1918 subnet 192.168.10.15 and rejects out-of-scope IP', () => {
    assert.equal(isTargetInAllowlist('192.168.10.15', testConfig.targetAllowlist).allowed, true);
    assert.equal(isTargetInAllowlist('8.8.8.8', testConfig.targetAllowlist).allowed, false);
  });

  await check('safety guard blocks loopback 127.0.0.1 and metadata 169.254.169.254 even if allowlisted', () => {
    assert.equal(isTargetInAllowlist('127.0.0.1', ['127.0.0.0/8']).allowed, false);
    assert.equal(isTargetInAllowlist('169.254.169.254', ['169.254.0.0/16']).allowed, false);
  });

  await check('blocks shell chaining, NSE --script, and path traversal', () => {
    const inj = validateGatewayJobRequest(
      { tool: 'nmap', args: ['-sn', '192.168.10.1; rm -rf /'] },
      'atlas:admin',
      ORG_A,
      testConfig.targetAllowlist,
      tmpWorkDir
    );
    assert.equal(inj.allowed, false);

    const nse = validateGatewayJobRequest(
      { tool: 'nmap', args: ['--script=vuln', '192.168.10.15'], approvalConfirmed: true },
      'atlas:admin',
      ORG_A,
      testConfig.targetAllowlist,
      tmpWorkDir
    );
    assert.equal(nse.allowed, false);

    const trav = validateGatewayJobRequest(
      { tool: 'tshark', args: ['summary', '../../etc/passwd.pcap'] },
      'atlas:admin',
      ORG_A,
      testConfig.targetAllowlist,
      tmpWorkDir
    );
    assert.equal(trav.allowed, false);
  });

  await check('enforces atlas:admin RBAC + approval justification for nmap -sV', () => {
    const analystAttempt = validateGatewayJobRequest(
      { tool: 'nmap', args: ['-sV', '-p', '22,443', '192.168.10.15'], approvalConfirmed: true, approvalJustification: 'SOC triage' },
      'atlas:analyst',
      ORG_A,
      testConfig.targetAllowlist,
      tmpWorkDir
    );
    assert.equal(analystAttempt.allowed, false);

    const adminNoApproval = validateGatewayJobRequest(
      { tool: 'nmap', args: ['-sV', '-p', '22,443', '192.168.10.15'], approvalConfirmed: false },
      'atlas:admin',
      ORG_A,
      testConfig.targetAllowlist,
      tmpWorkDir
    );
    assert.equal(adminNoApproval.allowed, false);
    assert.equal(adminNoApproval.requiresApproval, true);

    const adminApproved = validateGatewayJobRequest(
      { tool: 'nmap', args: ['-sV', '-p', '22,443', '192.168.10.15'], approvalConfirmed: true, approvalJustification: 'Approved maintenance window' },
      'atlas:admin',
      ORG_A,
      testConfig.targetAllowlist,
      tmpWorkDir
    );
    assert.equal(adminApproved.allowed, true);
    assert.deepEqual(adminApproved.fixedArgs, ['-sV', '-Pn', '--version-light', '-p', '22,443', '-oX', '-', '192.168.10.15']);
  });

  // ---- 3. Parsers & Output Sanitization ----
  console.log('3. Nmap / TShark Parsers & Output Sanitization');
  await check('Nmap XML parser extracts hosts, open ports, and service versions cleanly', () => {
    const sampleXml = `
      <nmaprun>
        <host>
          <status state="up"/>
          <address addr="192.168.10.15" addrtype="ipv4"/>
          <hostnames><hostname name="plc-gw.internal.corp"/></hostnames>
          <ports>
            <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.2"/></port>
            <port protocol="tcp" portid="502"><state state="open"/><service name="modbus"/></port>
          </ports>
        </host>
      </nmaprun>
    `;
    const parsed = parseNmapXmlOutput(sampleXml, 'nmap -sV -p 22,502 192.168.10.15', '2026-11-16T08:00:00Z');
    assert.equal(parsed.hosts.length, 1);
    assert.equal(parsed.hosts[0].ip, '192.168.10.15');
    assert.equal(parsed.hosts[0].hostname, 'plc-gw.internal.corp');
    assert.equal(parsed.openPortsCount, 2);
    assert.equal(parsed.hosts[0].ports[0].version, 'OpenSSH 9.2');
  });

  await check('TShark parser extracts protocol summary, DNS queries, and conversations', () => {
    const summary = parseTsharkOutput('summary', 'cap.pcap', 'eth frames:50 bytes:4200\ntcp frames:35 bytes:3000\n');
    assert.equal(summary.packetCount, 50);
    assert.equal(summary.protocols.length, 2);

    const dns = parseTsharkOutput('dns', 'cap.pcap', '192.168.10.15\t8.8.8.8\tc2.bad.example\t1\n192.168.10.15\t8.8.8.8\tc2.bad.example\t1\n');
    assert.equal(dns.dnsQueries[0].query, 'c2.bad.example');
    assert.equal(dns.dnsQueries[0].count, 2);
    assert.ok(dns.uniqueIps.includes('192.168.10.15'));

    const conv = parseTsharkOutput('conversations', 'cap.pcap', '192.168.10.15 <-> 203.0.113.45  5 500 5 500 10 1000\n');
    assert.equal(conv.conversations[0].frames, 10);
    assert.ok(conv.uniqueIps.includes('203.0.113.45'));
  });

  await check('sanitizeOutputText strips ANSI codes and redacts secret/Bearer headers', () => {
    const dirty = '\x1b[31mALERT\x1b[0m Authorization: Bearer super.secret.token';
    const clean = sanitizeOutputText(dirty);
    assert.ok(!clean.includes('\x1b'));
    assert.ok(!clean.includes('super.secret.token'));
    assert.ok(clean.includes('[REDACTED_SENSITIVE_MATERIAL]'));
  });

  // ---- 4. HTTP Gateway, Real Tool Health Probes, Job Execution & Cross-Org Access ----
  console.log('4. HTTP Server, Real Tool Health Checks, Job Store & Cross-Org Blocking');
  const handle = await createGatewayServer(testConfig, authenticator);
  await new Promise<void>((resolve) => handle.server.listen(0, '127.0.0.1', resolve));
  const addr = handle.server.address();
  const port = typeof addr === 'object' && addr ? addr.port : 0;
  const baseUrl = `http://127.0.0.1:${port}`;

  try {
    await check('real tool health probe runs accurately and never claims missing tools are available', async () => {
      const probe = await runRealToolHealthChecks();
      const zeek = probe.tools.find((t) => t.id === 'zeek');
      assert.ok(probe.tools.length >= 6);
      assert.equal(zeek?.available, false);
    });

    await check('unauthenticated /health fails closed with 401', async () => {
      const r = await fetch(`${baseUrl}/health`);
      assert.equal(r.status, 401);
    });

    await check('authenticated /health returns READY and verified org/role context', async () => {
      const r = await fetch(`${baseUrl}/health`, {
        headers: { Authorization: `Bearer ${validAdminJwt}`, 'x-atlas-org-id': ORG_A },
      });
      assert.equal(r.status, 200);
      const body = (await r.json()) as any;
      assert.equal(body.status, 'READY');
      assert.equal(body.authenticatedOrgId, ORG_A);
      assert.equal(body.authenticatedRole, 'atlas:admin');
    });

    let createdJobId = '';
    await check('POST /api/v1/jobs executes real sysinfo diagnostic and records EXTERNAL_GATEWAY_EXECUTION_RECORD', async () => {
      const r = await fetch(`${baseUrl}/api/v1/jobs`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${validAdminJwt}`,
          'x-atlas-org-id': ORG_A,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ tool: 'sysinfo', args: [] }),
      });
      assert.equal(r.status, 200);
      const data = (await r.json()) as any;
      createdJobId = data.job.jobId;
      assert.equal(data.job.status, 'completed');
      assert.equal(data.job.recordClassification, 'EXTERNAL_GATEWAY_EXECUTION_RECORD');
      assert.ok(data.job.stdoutLines.some((l: string) => l.includes('HOSTNAME:')));
    });

    await check('JobManager prevents cross-organisation read and cancel with 403 JobAccessError', () => {
      assert.throws(
        () => handle.jobManager.getJobForOrg(createdJobId, ORG_B),
        (e: unknown) => e instanceof JobAccessError && e.statusCode === 403
      );
      assert.throws(
        () => handle.jobManager.cancelJob(createdJobId, ORG_B, USER_ADMIN),
        (e: unknown) => e instanceof JobAccessError && e.statusCode === 403
      );
    });

    await check('PCAP upload rejects non-pcap magic bytes and accepts valid libpcap magic header', async () => {
      const bad = await fetch(`${baseUrl}/api/v1/pcap/upload`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${validAdminJwt}`,
          'x-atlas-org-id': ORG_A,
          'x-atlas-filename': 'fake.pcap',
        },
        body: Buffer.from('THIS_IS_NOT_A_VALID_PCAP_FILE_HEADER'),
      });
      assert.equal(bad.status, 400);

      const goodHeader = Buffer.alloc(32);
      goodHeader.writeUInt32BE(0xa1b2c3d4, 0);
      assert.equal(isValidPcapMagicBytes(goodHeader), true);

      const good = await fetch(`${baseUrl}/api/v1/pcap/upload`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${validAdminJwt}`,
          'x-atlas-org-id': ORG_A,
          'x-atlas-filename': 'capture.pcap',
        },
        body: goodHeader,
      });
      assert.equal(good.status, 201);
    });

    await check('JobManager terminates and marks timed_out when a child exceeds maxRuntimeMs', async () => {
      const mgr = new GatewayJobManager({
        workDir: tmpWorkDir,
        maxConcurrentJobs: 2,
        resolvedPaths: { nmap: null, tshark: null, python3: process.execPath },
        pythonScriptPath: '-e',
      });
      // Inject a clean timeout test via spawnFixedBinary simulation through nmap/python timeout test:
      // Even simpler: verify direct python script invocation fails safely if script rejects inline -e when -I/-S/-E run!
      // Instead, verify job cancel + timeout contract using a short script in tmpWorkDir:
      const sleepScript = path.join(tmpWorkDir, 'sleep.py');
      await fs.writeFile(sleepScript, 'import time\ntime.sleep(5)\n');
      const pyProbe = await runRealToolHealthChecks();
      const pyPath = pyProbe.resolvedPaths.python3;
      if (pyPath) {
        const timeoutMgr = new GatewayJobManager({
          workDir: tmpWorkDir,
          maxConcurrentJobs: 2,
          resolvedPaths: { nmap: null, tshark: null, python3: pyPath },
          pythonScriptPath: sleepScript,
        });
        await fs.mkdir(path.join(tmpWorkDir, 'datasets', ORG_A), { recursive: true });
        await fs.writeFile(path.join(tmpWorkDir, 'datasets', ORG_A, 'test.csv'), 'ip\n192.168.10.1\n');
        const res = await timeoutMgr.startJob(
          { userId: USER_ADMIN, orgId: ORG_A, role: 'atlas:admin', aal: 'aal2', tokenExpiresAt: now + 60 },
          { tool: 'py_analyze', args: ['ioc_stats', 'test.csv'] },
          {
            allowed: true,
            binaryKey: 'py_analyze',
            fixedArgs: ['ioc_stats', 'test.csv'],
            target: 'test.csv',
            riskLevel: 'MEDIUM',
            maxRuntimeMs: 150,
            maxOutputBytes: 4096,
            requiresApproval: false,
          }
        );
        assert.equal(res.status, 'timed_out');
      }

      // Also verify HTTP /api/v1/jobs/:jobId/cancel kills a running job and cross-org HTTP POST returns 403
      if (pyPath) {
        await fs.mkdir(path.join(tmpWorkDir, 'datasets', ORG_A), { recursive: true });
        await fs.writeFile(path.join(tmpWorkDir, 'datasets', ORG_A, 'cancel_test.csv'), 'ip\n192.168.10.2\n');
        const slowMgr = new GatewayJobManager({
          workDir: tmpWorkDir,
          maxConcurrentJobs: 2,
          resolvedPaths: { nmap: null, tshark: null, python3: pyPath },
          pythonScriptPath: sleepScript,
        });
        // Exercise slowMgr direct start + cancel while running
        const jobPromise = slowMgr.startJob(
          { userId: USER_ADMIN, orgId: ORG_A, role: 'atlas:admin', aal: 'aal2', tokenExpiresAt: now + 60 },
          { tool: 'py_analyze', args: ['ioc_stats', 'cancel_test.csv'] },
          {
            allowed: true,
            binaryKey: 'py_analyze',
            fixedArgs: ['ioc_stats', 'cancel_test.csv'],
            target: 'cancel_test.csv',
            riskLevel: 'MEDIUM',
            maxRuntimeMs: 5000,
            maxOutputBytes: 4096,
            requiresApproval: false,
          }
        );
        await new Promise((r) => setTimeout(r, 80));
        const runningList = slowMgr.listJobsForOrg(ORG_A);
        const activeJob = runningList.find((j) => j.status === 'running');
        assert.ok(activeJob, 'Expected running child job before cancel');
        assert.throws(
          () => slowMgr.cancelJob(activeJob!.jobId, ORG_B, USER_ADMIN),
          (e: unknown) => e instanceof JobAccessError && e.statusCode === 403
        );
        const cancelledSnapshot = slowMgr.cancelJob(activeJob!.jobId, ORG_A, USER_ADMIN);
        assert.equal(cancelledSnapshot.status, 'cancelled');
        const finishedJob = await jobPromise;
        assert.equal(finishedJob.status, 'cancelled');
      }
      void mgr;
    });
  } finally {
    await handle.close();
  }

  // ---- 5. Server-Side CTI Proxy Security, Caching, Egress & Partial Failures ----
  console.log('5. CTI Proxy Endpoint, Egress Blocking, Secret Redaction & Caching');
  const dummyOtxSecret = 'otx-secret-99887766';
  const dummyAbuseSecret = 'abusech-secret-55443322';
  const dummyMispSecret = 'misp-secret-11223344';
  const capturedLogs: string[] = [];

  await check('egress validator refuses hostnames whose DNS resolves to private/loopback/ULA IPs before connecting', async () => {
    assert.ok(isPrivateOrReservedIp('10.24.5.12'));
    assert.ok(isPrivateOrReservedIp('172.16.0.5'));
    assert.ok(isPrivateOrReservedIp('192.168.1.10'));
    assert.ok(isPrivateOrReservedIp('169.254.169.254'));
    assert.ok(isPrivateOrReservedIp('::ffff:10.0.0.1'));
    assert.ok(isPrivateOrReservedIp('fd00::1'));
    assert.equal(isPrivateOrReservedIp('93.184.216.34'), null);

    await assert.rejects(
      () =>
        validateAndResolveEgressUrl(
          'https://misp-private.example.test/attributes/restSearch',
          new Set(['misp-private.example.test']),
          async () => [{ address: '10.24.5.12', family: 4 }]
        ),
      /Private RFC1918/
    );
  });

  let upstreamClockMs = 1_794_800_000_000;
  let otxCallCount = 0;
  let mispTransportCallCount = 0;
  let forceOtxOversized = false;

  const mockCtiService = new CtiProxyService(
    {
      otxApiKey: dummyOtxSecret,
      abuseChAuthKey: dummyAbuseSecret,
      mispUrl: 'https://misp-private.example.test',
      mispApiKey: dummyMispSecret,
      taxiiApiRoot: 'https://taxii.example.test/taxii2',
      taxiiCollectionId: 'col-1',
    },
    {
      now: () => upstreamClockMs,
      logger: (_level, msg) => {
        capturedLogs.push(msg);
      },
      dnsLookup: async (host) => {
        if (host === 'misp-private.example.test') {
          return [{ address: '10.24.5.12', family: 4 }];
        }
        return [{ address: '93.184.216.34', family: 4 }];
      },
      transport: async ({ url, maxBytes }) => {
        assert.equal(maxBytes, CTI_MAX_RESPONSE_BYTES);
        if (url.hostname === 'misp-private.example.test') {
          mispTransportCallCount++;
          throw new Error('Should never connect to private MISP host');
        }
        if (url.hostname === 'otx.alienvault.com') {
          otxCallCount++;
          if (forceOtxOversized) {
            const bigStream = new PassThrough();
            const promise = readBoundedHttpStream(bigStream, {}, 200, maxBytes);
            bigStream.write(Buffer.alloc(3 * 1024 * 1024, 0x61));
            bigStream.write(Buffer.alloc(3 * 1024 * 1024, 0x62)); // > 5 MB total
            bigStream.end();
            return promise;
          }
          return {
            statusCode: 200,
            bodyText: JSON.stringify({
              results: [
                {
                  id: 'pulse-1',
                  created: '2026-11-10T00:00:00Z',
                  modified: '2026-11-12T00:00:00Z',
                  tags: ['ics', 'scanner'],
                  indicators: [
                    { id: 'ind-1', type: 'IPv4', indicator: '198.51.100.10', created: '2026-11-10T00:00:00Z' },
                    { id: 'ind-2', type: 'domain', indicator: 'c2.bad.example', created: '2026-11-11T00:00:00Z' },
                  ],
                },
              ],
            }),
          };
        }
        if (url.hostname === 'taxii.example.test') {
          // Simulate upstream failure whose raw error includes the OTX/Abuse secret to prove redaction + partial isolation
          throw new Error(`Upstream TAXII auth rejected with token=${dummyAbuseSecret}`);
        }
        if (url.hostname === 'threatfox-api.abuse.ch') {
          return {
            statusCode: 200,
            bodyText: JSON.stringify({
              data: [
                {
                  id: 'tf-99',
                  ioc: '203.0.113.88:443',
                  ioc_type: 'ip:port',
                  malware_printable: 'CobaltStrike',
                  confidence_level: 90,
                  first_seen: '2026-11-12 01:00:00 UTC',
                  tags: ['c2'],
                },
              ],
            }),
          };
        }
        return { statusCode: 200, bodyText: JSON.stringify({ urls: [] }) };
      },
    }
  );

  const ctiHandle = await createGatewayServer(testConfig, authenticator, { ctiService: mockCtiService });
  await new Promise<void>((resolve) => ctiHandle.server.listen(0, '127.0.0.1', resolve));
  const ctiAddr = ctiHandle.server.address();
  const ctiPort = typeof ctiAddr === 'object' && ctiAddr ? ctiAddr.port : 0;
  const ctiBaseUrl = `http://127.0.0.1:${ctiPort}`;

  try {
    await check('GET /api/v1/cti/indicators rejects unauthenticated (401), aal1 (403), and non-member ORG_B (403)', async () => {
      const noAuth = await fetch(`${ctiBaseUrl}/api/v1/cti/indicators`);
      assert.equal(noAuth.status, 401);

      const aal1Jwt = signRs256Jwt(
        { sub: USER_ADMIN, iss: testConfig.jwtIssuer, aud: 'authenticated', aal: 'aal1', exp: Math.floor(Date.now() / 1000) + 600 },
        privateKey
      );
      const aal1Res = await fetch(`${ctiBaseUrl}/api/v1/cti/indicators`, {
        headers: { Authorization: `Bearer ${aal1Jwt}`, 'x-atlas-org-id': ORG_A },
      });
      assert.equal(aal1Res.status, 403);

      const nonMemberRes = await fetch(`${ctiBaseUrl}/api/v1/cti/indicators`, {
        headers: { Authorization: `Bearer ${validAdminJwt}`, 'x-atlas-org-id': ORG_B },
      });
      assert.equal(nonMemberRes.status, 403);
    });

    await check('GET /api/v1/cti/indicators normalizes healthy sources, isolates partial failures, blocks private DNS without connecting, and redacts secrets', async () => {
      const res = await fetch(`${ctiBaseUrl}/api/v1/cti/indicators`, {
        headers: { Authorization: `Bearer ${validAdminJwt}`, 'x-atlas-org-id': ORG_A },
      });
      assert.equal(res.status, 200);
      const rawText = await res.text();
      assert.ok(!rawText.includes(dummyOtxSecret), 'OTX key must never appear in response');
      assert.ok(!rawText.includes(dummyAbuseSecret), 'Abuse.ch key must never appear in response');
      assert.ok(!rawText.includes(dummyMispSecret), 'MISP key must never appear in response');

      const body = JSON.parse(rawText) as any;
      assert.equal(mispTransportCallCount, 0, 'MISP private DNS target must be blocked before connecting');
      assert.ok(Array.isArray(body.indicators) && body.indicators.length === 3);
      for (const ind of body.indicators) {
        assert.ok(ind.type && ind.value && ind.source && ind.source_ref && ind.first_seen);
        assert.ok(typeof ind.confidence === 'number' && Array.isArray(ind.tags));
      }
      assert.ok(body.failedSources.some((f: any) => f.source === 'MISP'));
      assert.ok(body.failedSources.some((f: any) => f.source === 'TAXII_2_1'));
      const joinedLogs = capturedLogs.join('\n');
      assert.ok(!joinedLogs.includes(dummyOtxSecret) && !joinedLogs.includes(dummyAbuseSecret) && !joinedLogs.includes(dummyMispSecret));
    });

    await check('second identical GET /api/v1/cti/indicators within 15 minutes uses cached OTX results', async () => {
      const callsBefore = otxCallCount;
      upstreamClockMs += 5 * 60 * 1000; // +5 min (< 15 min TTL)
      const res = await fetch(`${ctiBaseUrl}/api/v1/cti/indicators?source=ALIENVAULT_OTX&type=ip`, {
        headers: { Authorization: `Bearer ${validAdminJwt}`, 'x-atlas-org-id': ORG_A },
      });
      assert.equal(res.status, 200);
      const body = (await res.json()) as any;
      assert.equal(otxCallCount, callsBefore, 'OTX upstream should not be called again within 15m cache window');
      assert.equal(body.sources[0].cached, true);
      assert.equal(body.indicators.length, 1);
      assert.equal(body.indicators[0].value, '198.51.100.10');
    });

    await check('oversized upstream response (>5 MB) is refused cleanly with redacted reason', async () => {
      upstreamClockMs += 20 * 60 * 1000; // expire 15m cache
      forceOtxOversized = true;
      const res = await fetch(`${ctiBaseUrl}/api/v1/cti/indicators?source=ALIENVAULT_OTX`, {
        headers: { Authorization: `Bearer ${validAdminJwt}`, 'x-atlas-org-id': ORG_A },
      });
      assert.equal(res.status, 200);
      const text = await res.text();
      assert.ok(!text.includes(dummyOtxSecret));
      const body = JSON.parse(text) as any;
      assert.equal(body.indicators.length, 0);
      assert.equal(body.failedSources[0].source, 'ALIENVAULT_OTX');
      assert.ok(body.failedSources[0].reason.includes('5242880'));
      forceOtxOversized = false;
    });

    await check('per-org CTI proxy rate limiter returns 429 after 30 requests/minute', async () => {
      upstreamClockMs += 120_000; // fresh 60s window
      let got429 = false;
      for (let i = 0; i < 31; i++) {
        const r = await fetch(`${ctiBaseUrl}/api/v1/cti/indicators?source=ALIENVAULT_OTX`, {
          headers: { Authorization: `Bearer ${validAdminJwt}`, 'x-atlas-org-id': ORG_A },
        });
        if (r.status === 429) {
          got429 = true;
          break;
        }
      }
      assert.equal(got429, true);
    });
  } finally {
    await ctiHandle.close();
  }

  // ---- 6. Bounded Registered Camera Streams & Biometric/Person Analytics ----
  console.log('6. Bounded Camera Stream Decoding, Access Control, Redaction & Analytics');
  const USER_ORG_B = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
  const USER_RESTRICTED = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd';
  const camWorkDir = await fs.mkdtemp(path.join(os.tmpdir(), 'atlas-cam-test-'));
  const camLogs: string[] = [];
  const externalAuditEvents: CameraAuditRecord[] = [];
  let camClockMs = 1_795_000_000_000;
  let grabShouldFail = false;

  const validJpegFrame = Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, 0xff, 0xd9]);
  const secretRtspPass = 'SuperSecretCamPass99!';
  const secretRtspUrl = `rtsp://camuser:${secretRtspPass}@192.168.10.50:554/stream1`;

  const camAuthMatrix: Record<string, Record<string, string>> = {
    [USER_ADMIN]: { [ORG_A]: 'atlas:admin' },
    [USER_ANALYST]: { [ORG_A]: 'atlas:analyst' },
    [USER_ORG_B]: { [ORG_B]: 'atlas:admin' },
    [USER_RESTRICTED]: { [ORG_A]: 'atlas:restricted' },
  };
  const camAuthenticator = new GatewayAuthenticator(testConfig, async (_jwt, userId, requestedOrgId) => {
    const role = camAuthMatrix[userId]?.[requestedOrgId];
    return role ? { orgId: requestedOrgId, role: role as any } : null;
  });

  const validOrgBJwt = signRs256Jwt(
    { sub: USER_ORG_B, iss: testConfig.jwtIssuer, aud: 'authenticated', aal: 'aal2', exp: Math.floor(Date.now() / 1000) + 600 },
    privateKey
  );
  const validAnalystJwt = signRs256Jwt(
    { sub: USER_ANALYST, iss: testConfig.jwtIssuer, aud: 'authenticated', aal: 'aal2', exp: Math.floor(Date.now() / 1000) + 600 },
    privateKey
  );
  const validRestrictedJwt = signRs256Jwt(
    { sub: USER_RESTRICTED, iss: testConfig.jwtIssuer, aud: 'authenticated', aal: 'aal2', exp: Math.floor(Date.now() / 1000) + 600 },
    privateKey
  );

  // Also test honest ANALYTICS_UNAVAILABLE on unconfigured coordinator
  await check('unconfigured vision analytics coordinator returns ANALYTICS_UNAVAILABLE without fabricated detections', async () => {
    const unconfiguredCoord = new CameraAnalyticsCoordinator({});
    const res = await unconfiguredCoord.analyzeFrame({
      orgId: ORG_A,
      cameraId: 'cam-test',
      cameraCode: 'CAM-TEST',
      frameBuffer: validJpegFrame,
    });
    assert.equal(res.status, 'ANALYTICS_UNAVAILABLE');
    assert.equal(res.faceCount, 0);
    assert.equal(res.personCount, 0);
    assert.equal(res.alerts.length, 0);
    assert.ok(res.unavailableReason && res.unavailableReason.length > 0);
  });

  await check('GatewayJobManager.runCameraFrameCapture invokes real ffmpeg safely when installed', async () => {
    const probe = await runRealToolHealthChecks();
    if (probe.resolvedPaths.ffmpeg) {
      const jm = new GatewayJobManager({
        workDir: camWorkDir,
        maxConcurrentJobs: 2,
        resolvedPaths: probe.resolvedPaths,
      });
      const res = await jm.runCameraFrameCapture(
        probe.resolvedPaths.ffmpeg,
        ['-hide_banner', '-loglevel', 'error', '-f', 'lavfi', '-i', 'color=c=black:s=64x64:d=0.1', '-frames:v', '1', '-f', 'image2pipe', '-vcodec', 'mjpeg', 'pipe:1'],
        10_000,
        1024 * 1024
      );
      assert.equal(res.exitCode, 0);
      assert.equal(isValidJpegBuffer(res.frameBuffer), true);
    }
  });

  const sharedCamJobManager = new GatewayJobManager({
    workDir: camWorkDir,
    maxConcurrentJobs: 2,
    resolvedPaths: { nmap: null, tshark: null, python3: null },
  });

  const analyticsCoord = new CameraAnalyticsCoordinator(
    {},
    {
      now: () => camClockMs,
      analyzer: async ({ cameraCode }) => ({
        faces: [
          {
            confidence: 0.96,
            box: { x: 100, y: 80, w: 60, h: 60 },
            embedding: [1, 0, 0, 0],
          },
        ],
        persons: [
          {
            trackId: 'trk-person-1',
            confidence: 0.93,
            box: { x: 80, y: 60, w: 120, h: 260 },
            embedding: [1, 0, 0, 0],
          },
          {
            trackId: `trk-unidentified-${cameraCode}`,
            confidence: 0.88,
            box: { x: 300, y: 70, w: 100, h: 240 },
          },
        ],
      }),
    }
  );

  const enrolledIdentity = analyticsCoord.enrollIdentity({
    orgId: ORG_A,
    personLabel: 'Authorized Technician A',
    personRef: 'EMP-1042',
    embedding: [0.99, 0.05, 0, 0],
    legalBasisRef: 'GDPR-6-1-F',
  });

  const testCameraManager = new CameraStreamManager({
    workDir: camWorkDir,
    jobManager: sharedCamJobManager,
    analyticsCoordinator: analyticsCoord,
    now: () => camClockMs,
    decodeIntervalMs: 60_000, // keep tests deterministic
    logger: (_level, msg) => {
      camLogs.push(msg);
    },
    auditSink: (entry) => {
      externalAuditEvents.push(entry);
    },
    frameGrabber: async (streamUrl) => {
      if (grabShouldFail) {
        throw new Error(`Connection refused while polling ${streamUrl}`);
      }
      return validJpegFrame;
    },
  });

  const camHandle = await createGatewayServer(
    { ...testConfig, workDir: camWorkDir },
    camAuthenticator,
    {
      cameraAnalyticsCoordinator: analyticsCoord,
      cameraManager: testCameraManager,
    }
  );
  await new Promise<void>((resolve) => camHandle.server.listen(0, '127.0.0.1', resolve));
  const camAddr = camHandle.server.address();
  const camPort = typeof camAddr === 'object' && camAddr ? camAddr.port : 0;
  const camBaseUrl = `http://127.0.0.1:${camPort}`;

  try {
    let cam1Id = '';
    let cam2Id = '';

    await check('registered camera start returns live frame, never leaks stream URL/password, and writes zero disk files for retention=none', async () => {
      const regRes = await fetch(`${camBaseUrl}/api/v1/cameras`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${validAdminJwt}`,
          'x-atlas-org-id': ORG_A,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          cameraCode: 'CAM-GATE-01',
          name: 'Main Gate Feed',
          protocol: 'RTSP_HLS',
          streamUrl: secretRtspUrl,
          retentionSetting: 'none',
          legalBasisRef: 'DPIA-2026-01',
          autoStart: true,
        }),
      });
      assert.equal(regRes.status, 201);
      const regText = await regRes.text();
      assert.ok(!regText.includes(secretRtspPass), 'RTSP password must never appear in HTTP response');
      assert.ok(!regText.includes(secretRtspUrl), 'RTSP stream URL must never appear in HTTP response');

      const regBody = JSON.parse(regText) as any;
      cam1Id = regBody.camera.cameraId;
      assert.equal(regBody.camera.status, 'streaming');
      assert.equal(regBody.camera.hasLatestFrame, true);
      assert.equal(regBody.camera.retentionSetting, 'none');

      // Assert zero frame files written under camWorkDir/camera_frames
      let framesDirExists = true;
      try {
        await fs.access(path.join(camWorkDir, 'camera_frames'));
      } catch {
        framesDirExists = false;
      }
      assert.equal(framesDirExists, false, 'Zero frames should be written to disk when retention === none');

      // Fetch live frame
      const frameRes = await fetch(`${camBaseUrl}/api/v1/cameras/${cam1Id}/frame`, {
        headers: { Authorization: `Bearer ${validAdminJwt}`, 'x-atlas-org-id': ORG_A },
      });
      assert.equal(frameRes.status, 200);
      assert.equal(frameRes.headers.get('content-type'), 'image/jpeg');
      const frameBytes = Buffer.from(await frameRes.arrayBuffer());
      assert.equal(isValidJpegBuffer(frameBytes), true);
    });

    await check('camera from another organisation (ORG_B) cannot be viewed or started (403)', async () => {
      const frameRes = await fetch(`${camBaseUrl}/api/v1/cameras/${cam1Id}/frame`, {
        headers: { Authorization: `Bearer ${validOrgBJwt}`, 'x-atlas-org-id': ORG_B },
      });
      assert.equal(frameRes.status, 403);

      const analyticsRes = await fetch(`${camBaseUrl}/api/v1/cameras/${cam1Id}/analytics`, {
        headers: { Authorization: `Bearer ${validOrgBJwt}`, 'x-atlas-org-id': ORG_B },
      });
      assert.equal(analyticsRes.status, 403);

      const startRes = await fetch(`${camBaseUrl}/api/v1/cameras/${cam1Id}/start`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${validOrgBJwt}`, 'x-atlas-org-id': ORG_B },
      });
      assert.equal(startRes.status, 403);
    });

    await check('disallowed role (atlas:restricted) cannot view camera frames (403)', async () => {
      const restrictedRes = await fetch(`${camBaseUrl}/api/v1/cameras/${cam1Id}/frame`, {
        headers: { Authorization: `Bearer ${validRestrictedJwt}`, 'x-atlas-org-id': ORG_A },
      });
      assert.equal(restrictedRes.status, 403);
    });

    await check('camera without legal_basis_ref fails unless atlas:admin explicitly accepts it', async () => {
      const regNoLegal = await fetch(`${camBaseUrl}/api/v1/cameras`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${validAnalystJwt}`,
          'x-atlas-org-id': ORG_A,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          cameraCode: 'CAM-NORTH-02',
          name: 'North Perimeter Camera',
          protocol: 'RTSP_HLS',
          streamUrl: 'rtsp://user2:pass2@192.168.10.51:554/stream1',
          retentionSetting: 'none',
        }),
      });
      assert.equal(regNoLegal.status, 201);
      cam2Id = ((await regNoLegal.json()) as any).camera.cameraId;

      // Without acceptance -> 412
      const startUnaccepted = await fetch(`${camBaseUrl}/api/v1/cameras/${cam2Id}/start`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${validAdminJwt}`,
          'x-atlas-org-id': ORG_A,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ adminAcceptWithoutLegalBasis: false }),
      });
      assert.equal(startUnaccepted.status, 412);

      // Analyst cannot override -> 403
      const analystOverride = await fetch(`${camBaseUrl}/api/v1/cameras/${cam2Id}/start`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${validAnalystJwt}`,
          'x-atlas-org-id': ORG_A,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ adminAcceptWithoutLegalBasis: true }),
      });
      assert.equal(analystOverride.status, 403);

      // Admin explicit acceptance succeeds -> 200 and records CAMERA_LEGAL_OVERRIDE audit
      const adminOverride = await fetch(`${camBaseUrl}/api/v1/cameras/${cam2Id}/start`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${validAdminJwt}`,
          'x-atlas-org-id': ORG_A,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ adminAcceptWithoutLegalBasis: true }),
      });
      assert.equal(adminOverride.status, 200);
      const overrideBody = (await adminOverride.json()) as any;
      assert.equal(overrideBody.camera.status, 'streaming');
      assert.equal(overrideBody.camera.adminAcceptedWithoutLegalBasis, true);
      assert.ok(
        externalAuditEvents.some((e) => e.action === 'CAMERA_LEGAL_OVERRIDE' && e.cameraId === cam2Id)
      );
    });

    await check('analytics pipeline detects faces/persons, matches enrolled biometrics, tracks cross-camera, and records CAMERA_PERSON_ALERT', async () => {
      const aRes = await fetch(`${camBaseUrl}/api/v1/cameras/${cam2Id}/analytics`, {
        headers: { Authorization: `Bearer ${validAdminJwt}`, 'x-atlas-org-id': ORG_A },
      });
      assert.equal(aRes.status, 200);
      const body = (await aRes.json()) as any;
      const analytics = body.camera.latestAnalytics;
      assert.equal(analytics.status, 'ANALYZED');
      assert.equal(analytics.faceCount, 1);
      assert.equal(analytics.personCount, 2);
      assert.equal(analytics.faces[0].recognizedIdentityId, enrolledIdentity.id);
      assert.equal(analytics.faces[0].recognizedLabel, 'Authorized Technician A');

      const trackedPerson = analytics.persons.find((p: any) => p.identityId === enrolledIdentity.id);
      assert.ok(trackedPerson);
      assert.ok(trackedPerson.crossCameraSeenIn.includes('CAM-GATE-01'));
      assert.ok(trackedPerson.crossCameraSeenIn.includes('CAM-NORTH-02'));
      assert.ok(analytics.alerts.length >= 1);
      assert.ok(
        externalAuditEvents.some((e) => e.action === 'CAMERA_PERSON_ALERT' && e.cameraId === cam2Id)
      );
    });

    await check('mandatory CAMERA_FRAME_VIEW audit ledger records user, camera, and time on every frame request', async () => {
      const frameAudit = externalAuditEvents.find(
        (e) => e.action === 'CAMERA_FRAME_VIEW' && e.cameraId === cam1Id && e.userId === USER_ADMIN
      );
      assert.ok(frameAudit);
      assert.equal(frameAudit.details.user, USER_ADMIN);
      assert.equal(frameAudit.details.camera, cam1Id);
      assert.ok(typeof frameAudit.details.time === 'string' && frameAudit.details.time.length > 0);
    });

    await check('concurrency limit holds at 4 active streams per organisation (5th rejected with 429)', async () => {
      assert.equal(MAX_CONCURRENT_STREAMS_PER_ORG, 4);
      // Already 2 active streams in ORG_A (cam1Id, cam2Id); add #3 and #4
      for (const idx of [3, 4]) {
        const r = await fetch(`${camBaseUrl}/api/v1/cameras`, {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${validAdminJwt}`,
            'x-atlas-org-id': ORG_A,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            cameraCode: `CAM-EXTRA-0${idx}`,
            name: `Extra Cam ${idx}`,
            protocol: 'RTSP_HLS',
            streamUrl: `rtsp://192.168.10.${60 + idx}:554/stream1`,
            retentionSetting: 'none',
            legalBasisRef: 'DPIA-2026-01',
            autoStart: true,
          }),
        });
        assert.equal(r.status, 201);
      }

      // 5th stream must fail with 429
      const fifth = await fetch(`${camBaseUrl}/api/v1/cameras`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${validAdminJwt}`,
          'x-atlas-org-id': ORG_A,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          cameraCode: 'CAM-EXTRA-05',
          name: 'Extra Cam 5',
          protocol: 'RTSP_HLS',
          streamUrl: 'rtsp://192.168.10.65:554/stream1',
          retentionSetting: 'none',
          legalBasisRef: 'DPIA-2026-01',
          autoStart: true,
        }),
      });
      assert.equal(fifth.status, 429);
    });

    await check('3 consecutive decode failures stop stream, mark camera offline, and redact stream URL/secrets in offlineReason and logs', async () => {
      // Trigger failure directly on cam1 via CameraStreamManager
      grabShouldFail = true;
      const internalList = testCameraManager.listCamerasForOrg(ORG_A);
      assert.equal(internalList.length, 5); // 5th was registered, not started

      // Access cam1 internal record via private map is avoided; call decodeOneFrame via stop+start or test helper:
      // Stop one extra cam so we can test re-start or simulate 3 consecutive failures cleanly
      const allCamsRes = await fetch(`${camBaseUrl}/api/v1/cameras`, {
        headers: { Authorization: `Bearer ${validAdminJwt}`, 'x-atlas-org-id': ORG_A },
      });
      const allCamsBody = (await allCamsRes.json()) as any;
      const extra3 = allCamsBody.cameras.find((c: any) => c.cameraCode === 'CAM-EXTRA-03');
      await fetch(`${camBaseUrl}/api/v1/cameras/${extra3.cameraId}/stop`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${validAdminJwt}`, 'x-atlas-org-id': ORG_A },
      });

      // Start extra3 (1st failure happens in startStream), then trigger 2 more failures
      const startFailRes = await fetch(`${camBaseUrl}/api/v1/cameras/${extra3.cameraId}/start`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${validAdminJwt}`, 'x-atlas-org-id': ORG_A },
      });
      assert.equal(startFailRes.status, 200);
      const after1 = ((await startFailRes.json()) as any).camera;
      assert.equal(after1.consecutiveFailures, 1);

      // Re-invoking startStream isn't needed if we invoke decodeOneFrame directly for the 2nd & 3rd failure, or stop/start;
      // Calling decodeOneFrame on the manager's camera triggers exact timer path:
      const camObj = (testCameraManager as any).cameras.get(cam1Id);
      await testCameraManager.decodeOneFrame(camObj);
      await testCameraManager.decodeOneFrame(camObj);
      await testCameraManager.decodeOneFrame(camObj);

      const offlineCheckRes = await fetch(`${camBaseUrl}/api/v1/cameras/${cam1Id}/analytics`, {
        headers: { Authorization: `Bearer ${validAdminJwt}`, 'x-atlas-org-id': ORG_A },
      });
      const offlineText = await offlineCheckRes.text();
      assert.ok(!offlineText.includes(secretRtspPass), 'Secret password must be redacted in offlineReason');
      assert.ok(!offlineText.includes(secretRtspUrl), 'Secret stream URL must be redacted in offlineReason');
      const offlineJson = JSON.parse(offlineText) as any;
      assert.equal(offlineJson.camera.status, 'offline');
      assert.equal(offlineJson.camera.consecutiveFailures, 3);
      assert.ok(offlineJson.camera.offlineReason.includes('[REDACTED_STREAM_URL]'));

      const joinedCamLogs = camLogs.join('\n');
      assert.ok(!joinedCamLogs.includes(secretRtspPass), 'Secret password must never appear in logs');
      assert.ok(!joinedCamLogs.includes(secretRtspUrl), 'Secret stream URL must never appear in logs');
      grabShouldFail = false;
    });

    await check('retention setting stores frames to disk, prunes after expiry, and records CAMERA_RETENTION_DELETE', async () => {
      // Stop remaining streaming cams so we stay under 4 cap cleanly
      await fetch(`${camBaseUrl}/api/v1/cameras/${cam2Id}/stop`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${validAdminJwt}`, 'x-atlas-org-id': ORG_A },
      });

      const retRes = await fetch(`${camBaseUrl}/api/v1/cameras`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${validAdminJwt}`,
          'x-atlas-org-id': ORG_A,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          cameraCode: 'CAM-RET-1H',
          name: 'Retention 1H Cam',
          protocol: 'RTSP_HLS',
          streamUrl: 'rtsp://192.168.10.90:554/stream1',
          retentionSetting: '1h',
          legalBasisRef: 'DPIA-2026-RET',
          autoStart: true,
        }),
      });
      assert.equal(retRes.status, 201);
      const retCamId = ((await retRes.json()) as any).camera.cameraId;

      const camFrameDir = path.join(camWorkDir, 'camera_frames', ORG_A, retCamId);
      const storedFiles = await fs.readdir(camFrameDir);
      assert.equal(storedFiles.length, 1);

      // Advance clock past 1h and trigger prune endpoint
      camClockMs += 65 * 60 * 1000;
      const pruneRes = await fetch(`${camBaseUrl}/api/v1/cameras/${retCamId}/retention/prune`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${validAdminJwt}`, 'x-atlas-org-id': ORG_A },
      });
      assert.equal(pruneRes.status, 200);
      const pruneBody = (await pruneRes.json()) as any;
      assert.equal(pruneBody.deletedCount, 1);

      const remainingFiles = await fs.readdir(camFrameDir);
      assert.equal(remainingFiles.length, 0);
      assert.ok(
        externalAuditEvents.some((e) => e.action === 'CAMERA_RETENTION_DELETE' && e.cameraId === retCamId)
      );
    });
  } finally {
    await camHandle.close();
    await fs.rm(camWorkDir, { recursive: true, force: true });
    await fs.rm(tmpWorkDir, { recursive: true, force: true });
  }

  console.log(`\nGATEWAY TEST SUMMARY: ${passed} passed, ${failed} failed`);
  if (failed > 0) process.exit(1);
}

main().catch((err) => {
  console.error('Unhandled gateway test error:', err);
  process.exit(1);
});
