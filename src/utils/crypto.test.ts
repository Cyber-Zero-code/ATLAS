/**
 * Project ATLAS: Cryptographic Hash Vectors & Tamper Detection Unit Tests
 * 
 * Verifies:
 * 1. Standard NIST / RFC 6234 SHA-256 test vectors
 * 2. Single-byte tampering alters hash digest (tamper detection)
 * 3. verifyWebCryptoEngine runs without failure
 */

import {
  computeSha256Hex,
  SHA256_TEST_VECTORS,
  verifyWebCryptoEngine,
  buildIngestSigningString,
  signIngestPayload,
  INGEST_SIGNING_TEST_VECTOR,
} from './crypto';

async function runCryptoTestSuite() {
  console.log('=== PROJECT ATLAS: Cryptographic Unit Tests ===\n');
  let failures = 0;

  // Test 1: RFC 6234 Test Vectors
  console.log('[TEST 1] RFC 6234 / NIST SHA-256 Test Vectors:');
  for (const vector of SHA256_TEST_VECTORS) {
    const computed = await computeSha256Hex(vector.input);
    if (computed === vector.expected) {
      console.log(`  PASS: "${vector.description}" -> ${computed.slice(0, 16)}...`);
    } else {
      console.error(`  FAIL: "${vector.description}" -> expected ${vector.expected}, got ${computed}`);
      failures++;
    }
  }

  // Test 2: Engine self-verification
  console.log('\n[TEST 2] verifyWebCryptoEngine():');
  const engineResult = await verifyWebCryptoEngine();
  if (engineResult.passed) {
    console.log('  PASS: Web Crypto engine passed all built-in test vectors.');
  } else {
    console.error(`  FAIL: Web Crypto engine failed: ${engineResult.error}`);
    failures++;
  }

  // Test 3: Tamper Detection (Avalanche Effect)
  console.log('\n[TEST 3] Tamper Detection & Integrity Verification:');
  const originalData = 'CONFIDENTIAL_OT_SCADA_LOGS_20261109_ASSET_10492_TELEMETRY';
  const originalHash = await computeSha256Hex(originalData);

  // Alter 1 character
  const tamperedData = 'CONFIDENTIAL_OT_SCADA_LOGS_20261109_ASSET_10492_tELEMETRY';
  const tamperedHash = await computeSha256Hex(tamperedData);

  if (originalHash !== tamperedHash) {
    console.log(`  PASS: Single character modification altered hash:`);
    console.log(`        Original: ${originalHash}`);
    console.log(`        Tampered: ${tamperedHash}`);
  } else {
    console.error('  FAIL: Hash collision or unchanged digest on tampered input!');
    failures++;
  }

  // Test 4: Binary buffer tampering
  const originalBytes = new Uint8Array([0x41, 0x54, 0x4c, 0x41, 0x53, 0x01, 0x02, 0x03]);
  const originalByteHash = await computeSha256Hex(originalBytes);
  const tamperedBytes = new Uint8Array([0x41, 0x54, 0x4c, 0x41, 0x53, 0x01, 0x02, 0x04]); // byte 7: 0x03 -> 0x04
  const tamperedByteHash = await computeSha256Hex(tamperedBytes);

  if (originalByteHash !== tamperedByteHash) {
    console.log(`  PASS: Binary 1-bit alteration altered hash.`);
  } else {
    console.error('  FAIL: Binary 1-bit alteration did not alter hash!');
    failures++;
  }

  // Test 5: Incident signing matches the independent reference vector (same one asserted in SQL)
  console.log('\n[TEST 5] Incident intake signing (HMAC-SHA256, Web Crypto):');
  {
    const v = INGEST_SIGNING_TEST_VECTOR;
    const ss = buildIngestSigningString(v.orgId, v.payload);
    if (ss === v.expectedSigningString) {
      console.log('  PASS: signing string matches the reference.');
    } else {
      console.error('  FAIL: signing string differs from the reference.\n' + ss);
      failures++;
    }
    const signed = await signIngestPayload(v.orgId, { ...v.payload, key_id: undefined }, 'k_test0001', v.secret);
    if (signed.signature === v.expectedSignature) {
      console.log('  PASS: HMAC matches the reference value.');
    } else {
      console.error(`  FAIL: HMAC ${signed.signature} != ${v.expectedSignature}`);
      failures++;
    }
    const other = await signIngestPayload(v.orgId, { ...v.payload, severity: 'low' }, 'k_test0001', v.secret);
    if (other.signature !== v.expectedSignature) {
      console.log('  PASS: changing one field changes the signature.');
    } else {
      console.error('  FAIL: tampered payload produced the same signature.');
      failures++;
    }
  }

  console.log('\n===============================================');
  if (failures === 0) {
    console.log('ALL CRYPTO TESTS PASSED.');
  } else {
    console.error(`TOTAL FAILURES: ${failures}`);
    process.exit(1);
  }
}

runCryptoTestSuite().catch((err) => {
  console.error('Test execution failed:', err);
  process.exit(1);
});
