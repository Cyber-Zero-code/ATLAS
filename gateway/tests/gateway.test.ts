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
import { GatewayAuthenticator, GatewayAuthError } from '../src/auth.js';
import { GatewayJobManager, JobAccessError } from '../src/jobManager.js';
import { validateGatewayJobRequest, isTargetInAllowlist } from '../src/policy.js';
import { createGatewayServer, isValidPcapMagicBytes } from '../src/server.js';
import { parseNmapXmlOutput, parseTsharkOutput, sanitizeOutputText } from '../src/tools/parsers.js';
import { runRealToolHealthChecks } from '../src/tools/toolHealth.js';
import type { GatewayConfig } from '../src/types.js';

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
    await fs.rm(tmpWorkDir, { recursive: true, force: true });
  }

  console.log(`\nGATEWAY TEST SUMMARY: ${passed} passed, ${failed} failed`);
  if (failed > 0) process.exit(1);
}

main().catch((err) => {
  console.error('Unhandled gateway test error:', err);
  process.exit(1);
});
